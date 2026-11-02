//! TCP accept loop and per-connection tasks around the [`hub::Hub`].
pub mod config;
pub mod hub;

use crate::credential::{decode_secret, encode_secret, generate_secret, Credential};
use crate::proto::{
    read_frame, write_frame, Frame, RejectReason, Welcome, MAX_CLIENT_FRAME, MTU, VERSION,
};
use crate::tls;
use anyhow::{Context, Result};
use config::Config;
use hub::{Forward, Hub, Session};
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
    let hub = Arc::new(Hub::new(config.networks));
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
                tokio::time::timeout(HANDSHAKE_TIMEOUT, admit(&hub, &acceptor, stream)).await;
            drop(permit);
            match admitted {
                Ok(Ok(Some((session, reader, writer)))) => {
                    run_session(hub, session, reader, writer).await
                }
                Ok(Ok(None)) => info!(%peer, "connection rejected"),
                Ok(Err(error)) => debug!(%peer, %error, "handshake failed"),
                Err(_) => debug!(%peer, "handshake timed out"),
            }
        });
    }
}

type TlsStream = tokio_rustls::server::TlsStream<TcpStream>;

async fn admit(
    hub: &Hub,
    acceptor: &TlsAcceptor,
    stream: TcpStream,
) -> Result<Option<(Session, ReadHalf<TlsStream>, WriteHalf<TlsStream>)>> {
    let tls_stream = acceptor.accept(stream).await?;
    let (mut reader, mut writer) = split(tls_stream);
    let Frame::Hello(hello) = read_frame(&mut reader, MAX_CLIENT_FRAME).await? else {
        anyhow::bail!("expected Hello");
    };
    let joined = if hello.version != VERSION {
        Err(RejectReason::UnsupportedVersion)
    } else {
        decode_secret(&hello.secret)
            .and_then(|secret| hub.authenticate(&secret))
            .ok_or(RejectReason::InvalidCredential)
            .and_then(|network| {
                hub.join(
                    network,
                    &hello.client_id,
                    &hello.hostname,
                    hello.prev_ip,
                    Instant::now(),
                )
            })
    };
    let session = match joined {
        Ok(session) => session,
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
    Ok(Some((session, reader, writer)))
}

async fn run_session<S>(
    hub: Arc<Hub>,
    mut session: Session,
    reader: ReadHalf<S>,
    writer: WriteHalf<S>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    info!(network = %session.network_name, hostname = %session.hostname, ip = %session.ip, "member online");
    let (pong_tx, pong_rx) = tokio::sync::mpsc::channel(8);
    let packets = std::mem::replace(&mut session.rx, tokio::sync::mpsc::channel(1).1);
    let members = session.members.clone();
    let kick = session.kick.clone();
    let network = hub.network(&session);
    let ip = session.ip;
    let mut read_task = tokio::spawn(read_loop(hub.clone(), network, ip, reader, pong_tx));
    let mut write_task = tokio::spawn(write_loop(writer, packets, members, pong_rx));
    tokio::select! {
        _ = &mut read_task => {}
        _ = &mut write_task => {}
        _ = kick.notified() => debug!(ip = %session.ip, "replaced by a newer connection"),
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
) {
    loop {
        let frame =
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
