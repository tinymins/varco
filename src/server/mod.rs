//! TCP accept loop and per-connection tasks around the [`hub::Hub`].
pub mod admin;
pub mod hub;
pub mod store;

use crate::core::device;
use crate::credential::decode_secret;
use crate::proto::{
    read_frame, write_frame, Frame, Hello, RejectReason, Welcome, MAX_CLIENT_FRAME, MTU, VERSION,
};
use crate::tls;
use anyhow::{Context, Result};
use hub::{Details, Forward, Hub, Network, Session, Traffic};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use store::{
    unix_now, AdmitError, NewConnection, Reservation, Store, UseDetails, WorkspaceId,
    SETTING_RELAY_LISTEN,
};
use tokio::io::{split, AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Clients ping every 10 s, so this means several consecutive heartbeats were lost.
const IDLE_TIMEOUT: Duration = Duration::from_secs(45);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_PENDING_HANDSHAKES: usize = 256;
const PURGE_INTERVAL: Duration = Duration::from_secs(3600);
pub const DEFAULT_ADMIN_LISTEN: &str = "127.0.0.1:8444";

const DATABASE_FILE: &str = "varco.db";
const IDENTITY_FILE: &str = "varco-server.key";

pub fn default_data_dir() -> PathBuf {
    if cfg!(target_os = "linux") {
        return PathBuf::from("/var/lib/varco");
    }
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("varco-server")
}

fn prepare_data_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("securing {}", dir.display()))?;
    }
    Ok(())
}

pub fn open_store(data_dir: &Path) -> Result<Store> {
    prepare_data_dir(data_dir)?;
    Store::open(&data_dir.join(DATABASE_FILE))
}

pub fn configure_socket(stream: &TcpStream) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(10));
    socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive)
}

/// Runs until the process exits. The relay starts once it has been given an address,
/// which on a new installation happens in the console.
pub async fn run(data_dir: &Path, admin_listen: &str) -> Result<()> {
    let store = Arc::new(open_store(data_dir)?);
    store.close_stale_connections(unix_now())?;
    let identity = tls::load_or_create_identity(&data_dir.join(IDENTITY_FILE))?;
    let hub = Arc::new(Hub::new(&store.workspaces()?).with_store(store.clone()));
    let relay = Arc::new(Relay::new(hub.clone(), tls::server_config(&identity)?));
    if let Some(listen) = store.setting(SETTING_RELAY_LISTEN)? {
        // Not fatal: the console is where this gets corrected.
        if let Err(detail) = relay.listen(&listen).await {
            error!(%listen, error = %format!("{detail:#}"), "relay not started");
        }
    }
    let console = admin::Console::new(hub, relay, identity.pin);
    admin::spawn(admin_listen, console).await?;
    info!(data_dir = %data_dir.display(), "server started");
    loop {
        tokio::time::sleep(PURGE_INTERVAL).await;
        if let Err(detail) = store.purge(unix_now()) {
            warn!(%detail, "old records not removed");
        }
    }
}

/// The relay's listening socket, which the console can move while members stay
/// connected: a connection's tasks do not depend on the task that accepted it.
pub struct Relay {
    hub: Arc<Hub>,
    tls_config: Arc<rustls::ServerConfig>,
    running: tokio::sync::Mutex<Option<(String, tokio::task::JoinHandle<()>)>>,
}

impl Relay {
    pub fn new(hub: Arc<Hub>, tls_config: Arc<rustls::ServerConfig>) -> Self {
        Self {
            hub,
            tls_config,
            running: tokio::sync::Mutex::new(None),
        }
    }

    /// The new socket is bound first, so a bad address leaves the old one working.
    pub async fn listen(&self, listen: &str) -> Result<()> {
        let mut running = self.running.lock().await;
        if running
            .as_ref()
            .is_some_and(|(current, _)| current == listen)
        {
            return Ok(());
        }
        let listener = TcpListener::bind(listen)
            .await
            .with_context(|| format!("binding {listen}"))?;
        let hub = self.hub.clone();
        let tls_config = self.tls_config.clone();
        let task = tokio::spawn(async move {
            if let Err(detail) = serve(listener, hub, tls_config).await {
                error!(error = %format!("{detail:#}"), "relay stopped");
            }
        });
        if let Some((_, old)) = running.replace((listen.to_owned(), task)) {
            old.abort();
        }
        info!(%listen, "relay listening");
        Ok(())
    }

    pub async fn listening_on(&self) -> Option<String> {
        self.running
            .lock()
            .await
            .as_ref()
            .filter(|(_, task)| !task.is_finished())
            .map(|(listen, _)| listen.clone())
    }
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
        if hub
            .store()
            .is_some_and(|store| store.globally_banned_ip(peer.ip(), unix_now()))
        {
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
    client_id: String,
    code_id: String,
}

struct Authorized {
    workspace: WorkspaceId,
    code_id: String,
    reservation: Option<Reservation>,
}

enum Refusal {
    Reject(RejectReason),
    /// The server failed, which says nothing about the client, so it is not told
    /// anything it would take as final.
    Internal(rusqlite::Error),
}

impl From<RejectReason> for Refusal {
    fn from(reason: RejectReason) -> Self {
        Self::Reject(reason)
    }
}

impl From<rusqlite::Error> for Refusal {
    fn from(detail: rusqlite::Error) -> Self {
        Self::Internal(detail)
    }
}

/// The workspace a Hello may join. Its bans are only consulted once the Code has
/// shown which workspace this is, and a bad Code learns nothing about them.
fn authorize(
    store: &Arc<Store>,
    hello: &Hello,
    device: Option<&str>,
    peer: IpAddr,
) -> Result<Authorized, Refusal> {
    if hello.version != VERSION {
        return Err(RejectReason::UnsupportedVersion.into());
    }
    let secret = decode_secret(&hello.secret).ok_or(RejectReason::InvalidCredential)?;
    let now = unix_now();
    let admitted = match store.admit_code(&secret, &hello.client_id, now) {
        Ok(Some(admitted)) => admitted,
        Ok(None) => return Err(RejectReason::InvalidCredential.into()),
        Err(AdmitError::Reject(reason)) => {
            // A banned client is told it is banned, not that the Code ran out.
            let blocked = match store.lookup_code_workspace(&secret)? {
                Some(workspace) => store.blocked(workspace, &hello.client_id, device, peer, now)?,
                None => false,
            };
            return Err(if blocked {
                RejectReason::Removed
            } else {
                reason
            }
            .into());
        }
        Err(AdmitError::Db(detail)) => return Err(detail.into()),
    };
    if store.blocked(admitted.workspace, &hello.client_id, device, peer, now)? {
        return Err(RejectReason::Removed.into());
    }
    Ok(Authorized {
        workspace: admitted.workspace,
        code_id: admitted.code_id,
        reservation: admitted.reservation,
    })
}

fn join_member(hub: &Hub, hello: &Hello, peer: IpAddr) -> Result<(Session, Authorized), Refusal> {
    let store = hub.store().ok_or(RejectReason::InvalidCredential)?;
    let device = hello.device_id.as_deref().filter(|id| device::is_valid(id));
    let authorized = authorize(store, hello, device, peer)?;
    let session = hub.join(
        authorized.workspace,
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
            code: Some(authorized.code_id.clone()),
            since: unix_now(),
        },
    );
    // A ban or revocation recorded after the checks above found no member to
    // disconnect, so look again now that this one can be found.
    let now = unix_now();
    let allowed = !store.blocked(authorized.workspace, &hello.client_id, device, peer, now)?
        && store.code_is_live(&authorized.code_id)?
        && !store.globally_banned_ip(peer, now);
    if !allowed {
        hub.leave(&session, Instant::now());
        return Err(RejectReason::Removed.into());
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
        Err(Refusal::Reject(reason)) => {
            write_frame(&mut writer, &Frame::Reject(reason)).await?;
            return Ok(None);
        }
        Err(Refusal::Internal(detail)) => {
            error!(%detail, "cannot read the database, closing connection");
            anyhow::bail!("database error");
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
        client_id: hello.client_id,
        code_id: authorized.code_id,
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
    if let Err(error) = reservation.commit(&details, unix_now()) {
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
        peer,
        device,
        client_id,
        code_id,
        ..
    } = joined;
    info!(network = %session.network_name, hostname = %session.hostname, ip = %session.ip, "member online");
    let record = hub.store().and_then(|store| {
        let connection = NewConnection {
            workspace: session.network.id(),
            client: &client_id,
            hostname: &session.hostname,
            ip: session.ip,
            peer,
            device: device.as_deref(),
            code_id: Some(&code_id),
        };
        // History is not worth refusing a working connection over.
        store
            .open_connection(&connection, unix_now())
            .inspect_err(|detail| warn!(%detail, "connection not recorded"))
            .ok()
    });
    let (pong_tx, pong_rx) = tokio::sync::mpsc::channel(8);
    let packets = std::mem::replace(&mut session.rx, tokio::sync::mpsc::channel(1).1);
    let members = session.members.clone();
    let network = session.network.clone();
    let ip = session.ip;
    let traffic = session.traffic.clone();
    let mut read_task = tokio::spawn(read_loop(
        network.clone(),
        traffic.clone(),
        ip,
        reader,
        pong_tx,
        first,
    ));
    let mut write_task = tokio::spawn(write_loop(
        writer,
        packets,
        members,
        pong_rx,
        network,
        traffic.clone(),
    ));
    tokio::select! {
        _ = &mut read_task => {}
        _ = &mut write_task => {}
        _ = kick.notified() => debug!(ip = %session.ip, "disconnected by a newer connection or the console"),
    }
    read_task.abort();
    write_task.abort();
    hub.leave(&session, Instant::now());
    if let (Some(id), Some(store)) = (record, hub.store()) {
        if let Err(detail) = store.close_connection(id, traffic.rx(), traffic.tx(), unix_now()) {
            warn!(%detail, "connection end not recorded");
        }
    }
    info!(network = %session.network_name, hostname = %session.hostname, ip = %session.ip, "member offline");
}

async fn read_loop<R: AsyncRead + Unpin>(
    network: Arc<Network>,
    traffic: Arc<Traffic>,
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
            Frame::Packet(packet) => {
                traffic.add_rx(packet.len());
                network.traffic().add_rx(packet.len());
                match network.forward(ip, packet) {
                    Forward::Sent | Forward::NoRoute | Forward::QueueFull | Forward::NotIpv4 => {}
                    Forward::SpoofedSource => debug!(%ip, "dropped packet with forged source"),
                }
            }
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
    network: Arc<Network>,
    traffic: Arc<Traffic>,
) {
    members.mark_changed();
    loop {
        let frame = tokio::select! {
            Some(packet) = packets.recv() => {
                traffic.add_tx(packet.len());
                network.traffic().add_tx(packet.len());
                Frame::Packet(packet)
            }
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
