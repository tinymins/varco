//! TCP accept loop and per-connection tasks around the [`hub::Hub`].
pub mod admin;
pub mod config;
pub mod hub;
pub mod state;

use crate::core::device;
use crate::credential::{decode_secret, encode_secret, generate_secret, Credential};
use crate::proto::{
    read_frame, write_frame, Frame, Hello, RejectReason, Welcome, MAX_CLIENT_FRAME, MTU, VERSION,
};
use crate::tls;
use anyhow::{Context, Result};
use config::Config;
use hub::{Details, Forward, Hub, Session};
use state::{Reservation, Store, UseDetails};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{split, AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Clients ping every 10 s, so this means several consecutive heartbeats were lost.
const IDLE_TIMEOUT: Duration = Duration::from_secs(45);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_PENDING_HANDSHAKES: usize = 256;

pub fn identity_path(config_path: &Path) -> PathBuf {
    config_path.with_file_name("varco-server.key")
}

pub fn configure_socket(stream: &TcpStream) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(10));
    socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive)
}

/// Runs from a config file until the process exits.
pub async fn run_from_config(config_path: &Path) -> Result<()> {
    let config = Config::load(config_path)?;
    let identity = tls::load_or_create_identity(&identity_path(config_path))?;
    let listener = TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("binding {}", config.listen))?;
    info!(listen = %config.listen, networks = config.networks.len(), "server started");
    // Loaded with or without the console: its bans and used Codes still apply.
    let store = Store::load(state::state_path(config_path), state::unix_now())?;
    let hub = Arc::new(Hub::new(config.networks).with_store(Arc::new(store)));
    if let Some(settings) = config.admin {
        let console = admin::Console::new(
            settings.clone(),
            hub.clone(),
            config.public_addr,
            identity.pin,
        );
        admin::spawn(&settings.listen, console).await?;
    }
    serve(listener, hub, tls::server_config(&identity)?).await
}

pub async fn serve(
    listener: TcpListener,
    hub: Arc<Hub>,
    tls_config: Arc<rustls::ServerConfig>,
) -> Result<()> {
    let acceptor = TlsAcceptor::from(tls_config);
    let pending = Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            // Running out of file descriptors and the like must not end the server.
            Err(error) => {
                warn!(%error, "accept failed");
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        // Before TLS, so a banned address costs almost nothing and learns nothing.
        if hub.store().is_some_and(|store| store.ip_banned(peer.ip())) {
            debug!(%peer, "banned address, dropping");
            continue;
        }
        let Ok(permit) = pending.clone().try_acquire_owned() else {
            debug!(%peer, "too many pending handshakes, dropping");
            continue;
        };
        let hub = hub.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            if let Err(error) = configure_socket(&stream) {
                debug!(%peer, %error, "socket options not applied");
            }
            let admitted =
                tokio::time::timeout(HANDSHAKE_TIMEOUT, admit(&hub, &acceptor, stream, peer.ip()))
                    .await;
            drop(permit);
            match admitted {
                Ok(Ok(Some(joined))) => run_session(hub, joined).await,
                Ok(Ok(None)) => info!(%peer, "connection rejected"),
                Ok(Err(error)) => debug!(%peer, %error, "handshake failed"),
                Err(_) => debug!(%peer, "handshake timed out"),
            }
        });
    }
}

type TlsStream = tokio_rustls::server::TlsStream<TcpStream>;

struct Joined<S> {
    session: Session,
    reader: ReadHalf<S>,
    writer: WriteHalf<S>,
    reservation: Option<Reservation>,
    peer: IpAddr,
    device: Option<String>,
}

/// The network a Hello may join. Everything that can refuse it, in order.
fn authorize(hub: &Hub, hello: &Hello, device: Option<&str>) -> Result<Authorized, RejectReason> {
    if hello.version != VERSION {
        return Err(RejectReason::UnsupportedVersion);
    }
    if let Some(store) = hub.store() {
        if store.removed(&hello.client_id, device) {
            return Err(RejectReason::Removed);
        }
    }
    let secret = decode_secret(&hello.secret).ok_or(RejectReason::InvalidCredential)?;
    if let Some(network) = hub.authenticate(&secret) {
        return Ok(Authorized {
            network,
            code_id: None,
            reservation: None,
        });
    }
    let store = hub.store().ok_or(RejectReason::InvalidCredential)?;
    let admitted = store
        .admit_code(&secret, &hello.client_id, state::unix_now())?
        .ok_or(RejectReason::InvalidCredential)?;
    // The network can be gone from the config since the Code was made.
    let network = hub
        .network_index(&admitted.network)
        .ok_or(RejectReason::InvalidCredential)?;
    Ok(Authorized {
        network,
        code_id: Some(admitted.code_id),
        reservation: admitted.reservation,
    })
}

struct Authorized {
    network: usize,
    code_id: Option<String>,
    reservation: Option<Reservation>,
}

fn join_member(
    hub: &Hub,
    hello: &Hello,
    peer: IpAddr,
) -> Result<(Session, Authorized), RejectReason> {
    let device = hello.device_id.as_deref().filter(|id| device::is_valid(id));
    let authorized = authorize(hub, hello, device)?;
    let session = hub.join(
        authorized.network,
        &hello.client_id,
        &hello.hostname,
        hello.prev_ip,
        Instant::now(),
    )?;
    hub.describe(
        &session,
        Details {
            peer: Some(peer.to_canonical()),
            device: device.map(str::to_owned),
            code: authorized.code_id.clone(),
            since: state::unix_now(),
        },
    );
    // A ban recorded after the checks above found no member to disconnect.
    let allowed = hub.store().is_none_or(|store| {
        store.still_allowed(
            peer,
            &hello.client_id,
            device,
            authorized.code_id.as_deref(),
        )
    });
    if !allowed {
        hub.leave(&session, Instant::now());
        return Err(RejectReason::Removed);
    }
    Ok((session, authorized))
}

async fn admit(
    hub: &Hub,
    acceptor: &TlsAcceptor,
    stream: TcpStream,
    peer: IpAddr,
) -> Result<Option<Joined<TlsStream>>> {
    let tls_stream = acceptor.accept(stream).await?;
    let (mut reader, mut writer) = split(tls_stream);
    let Frame::Hello(hello) = read_frame(&mut reader, MAX_CLIENT_FRAME).await? else {
        anyhow::bail!("expected Hello");
    };
    let (session, authorized) = match join_member(hub, &hello, peer) {
        Ok(joined) => joined,
        Err(reason) => {
            write_frame(&mut writer, &Frame::Reject(reason)).await?;
            return Ok(None);
        }
    };
    let welcome = Welcome {
        network: session.network_name.clone(),
        ip: session.ip,
        prefix: session.prefix,
        mtu: MTU,
    };
    if let Err(error) = write_frame(&mut writer, &Frame::Welcome(welcome)).await {
        hub.leave(&session, Instant::now());
        return Err(error.into());
    }
    Ok(Some(Joined {
        session,
        reader,
        writer,
        reservation: authorized.reservation,
        peer,
        device: hello.device_id.filter(|id| device::is_valid(id)),
    }))
}

/// A client sends its first frame once its NIC is up. Until then a Code it brought
/// is not used up and nothing is sent to it, so a client that never gets that far
/// neither costs anyone a Code nor gets to see the network for free.
async fn confirm_first_use<S: AsyncRead + Unpin>(
    joined: &mut Joined<S>,
    kick: &tokio::sync::Notify,
) -> Option<Frame> {
    let reservation = joined.reservation.as_ref()?;
    let first = tokio::select! {
        frame = tokio::time::timeout(IDLE_TIMEOUT, read_frame(&mut joined.reader, MAX_CLIENT_FRAME)) => frame,
        _ = kick.notified() => {
            debug!(ip = %joined.session.ip, "disconnected before first use");
            return None;
        }
    };
    let Ok(Ok(frame)) = first else {
        debug!(ip = %joined.session.ip, "ended before first use");
        return None;
    };
    let details = UseDetails {
        device: joined.device.as_deref(),
        hostname: &joined.session.hostname,
        peer: joined.peer,
    };
    if let Err(error) = reservation.commit(&details, state::unix_now()) {
        // Letting it through would make this use forgotten at the next restart.
        warn!(%error, "first use of a Code not recorded, closing");
        return None;
    }
    Some(frame)
}

async fn run_session<S>(hub: Arc<Hub>, mut joined: Joined<S>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let kick = joined.session.kick.clone();
    let needs_confirming = joined.reservation.is_some();
    let first = confirm_first_use(&mut joined, &kick).await;
    if needs_confirming && first.is_none() {
        hub.leave(&joined.session, Instant::now());
        return;
    }
    // Only held for the check above; the use is on record now.
    joined.reservation = None;
    let Joined {
        mut session,
        reader,
        writer,
        ..
    } = joined;
    info!(network = %session.network_name, hostname = %session.hostname, ip = %session.ip, "member online");
    let (pong_tx, pong_rx) = tokio::sync::mpsc::channel(8);
    let packets = std::mem::replace(&mut session.rx, tokio::sync::mpsc::channel(1).1);
    let members = session.members.clone();
    let network = hub.network(&session);
    let ip = session.ip;
    let mut read_task = tokio::spawn(read_loop(hub.clone(), network, ip, reader, pong_tx, first));
    let mut write_task = tokio::spawn(write_loop(writer, packets, members, pong_rx));
    tokio::select! {
        _ = &mut read_task => {}
        _ = &mut write_task => {}
        _ = kick.notified() => debug!(ip = %session.ip, "disconnected by a newer connection or the console"),
    }
    read_task.abort();
    write_task.abort();
    hub.leave(&session, Instant::now());
    info!(network = %session.network_name, hostname = %session.hostname, ip = %session.ip, "member offline");
}

async fn read_loop<R: AsyncRead + Unpin>(
    hub: Arc<Hub>,
    network: usize,
    ip: std::net::Ipv4Addr,
    mut reader: R,
    pong_tx: tokio::sync::mpsc::Sender<u64>,
    mut first: Option<Frame>,
) {
    loop {
        let frame = if let Some(frame) = first.take() {
            frame
        } else {
            match tokio::time::timeout(IDLE_TIMEOUT, read_frame(&mut reader, MAX_CLIENT_FRAME))
                .await
            {
                Ok(Ok(frame)) => frame,
                Ok(Err(error)) => {
                    debug!(%ip, %error, "read ended");
                    return;
                }
                Err(_) => {
                    info!(%ip, "no heartbeat, closing");
                    return;
                }
            }
        };
        match frame {
            Frame::Packet(packet) => match hub.forward(network, ip, packet) {
                Forward::Sent | Forward::NoRoute | Forward::QueueFull | Forward::NotIpv4 => {}
                Forward::SpoofedSource => debug!(%ip, "dropped packet with forged source"),
            },
            Frame::Ping(nonce) => {
                // A full channel means pongs are not draining; the idle timer handles that.
                let _ = pong_tx.try_send(nonce);
            }
            other => {
                debug!(%ip, ?other, "unexpected frame, closing");
                return;
            }
        }
    }
}

async fn write_loop<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut packets: tokio::sync::mpsc::Receiver<bytes::Bytes>,
    mut members: tokio::sync::watch::Receiver<Arc<Vec<crate::proto::Member>>>,
    mut pongs: tokio::sync::mpsc::Receiver<u64>,
) {
    members.mark_changed();
    loop {
        let frame = tokio::select! {
            Some(packet) = packets.recv() => Frame::Packet(packet),
            Some(nonce) = pongs.recv() => Frame::Pong(nonce),
            Ok(()) = members.changed() => Frame::Members((**members.borrow_and_update()).clone()),
            else => return,
        };
        match tokio::time::timeout(WRITE_TIMEOUT, write_frame(&mut writer, &frame)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                debug!(%error, "write ended");
                return;
            }
            Err(_) => {
                info!("peer not draining, closing");
                return;
            }
        }
    }
}

/// `gen-credential`: creates a secret and the full string for that network.
/// `ssh_pubkey` goes into the Code only. It is the client that acts on it, so
/// nothing about it reaches this server's configuration.
pub fn generate_credential(
    config_path: &Path,
    network: &str,
    ssh_pubkey: Option<russh::keys::PublicKey>,
) -> Result<(String, String)> {
    let config = Config::load(config_path)?;
    anyhow::ensure!(
        config.networks.iter().any(|n| n.name == network),
        "no network named {network:?} in {}",
        config_path.display()
    );
    let identity = tls::load_or_create_identity(&identity_path(config_path))?;
    let secret = generate_secret();
    let credential = Credential {
        server: config.public_addr,
        pin: identity.pin,
        secret,
        ssh_pubkey: None,
    };
    let credential = match ssh_pubkey {
        Some(key) => credential.with_ssh_pubkey(key),
        None => credential,
    };
    Ok((encode_secret(&secret), credential.encode()))
}
