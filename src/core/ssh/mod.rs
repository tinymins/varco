//! Built-in SSH server for remote debugging. Off by default on every start,
//! listens only on the mesh address, and accepts exactly one public key.
//! Connections come from the system's sockets, or from the in-process stack on
//! a machine running without a virtual NIC.
#[cfg(windows)]
mod firewall;
mod process;
mod server;
mod sftp;
pub mod store;

use super::engine::Status;
use super::netstack::{MeshEndpoint, MeshListener};
use anyhow::Result;
use ipnet::Ipv4Net;
use russh::keys::{PrivateKey, PublicKey};
use serde::{Deserialize, Serialize};
pub use server::config as server_config;
use server::SessionHandler;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::runtime::Handle;
use tokio::sync::{watch, Semaphore};
use tracing::{debug, info, warn};

pub const PORT: u16 = 2222;
pub(crate) const MAX_CONNECTIONS: usize = 8;
const AUTH_TIMEOUT: Duration = Duration::from_secs(30);
/// A polite goodbye may have nowhere to go if the network has already gone.
const DISCONNECT_WAIT: Duration = Duration::from_secs(2);
const BIND_RETRY: Duration = Duration::from_secs(1);
/// Bind failures this long are worth telling the user about. Shorter ones are
/// just the adapter still coming up.
const BIND_GRACE: Duration = Duration::from_secs(5);

#[cfg(windows)]
pub(crate) const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// True when a remote shell run as `user` has full administrator rights.
pub fn shell_is_admin(user: &str) -> bool {
    cfg!(windows) || user == "root"
}

/// Who remote sessions run as: whoever this process is running as.
pub fn effective_user() -> String {
    #[cfg(unix)]
    return process::account().map_or_else(
        // SAFETY: geteuid has no preconditions and cannot fail.
        || unsafe { libc::geteuid() }.to_string(),
        |account| account.name.to_string_lossy().into_owned(),
    );
    #[cfg(windows)]
    return std::env::var("USERNAME").unwrap_or_else(|_| "user".to_owned());
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SshState {
    Off,
    /// Waiting for the mesh address.
    Starting,
    Listening {
        ip: Ipv4Addr,
        connections: usize,
        /// The account remote sessions run as.
        user: String,
    },
    Error(String),
}

/// Where connections come from, decided by how this machine joined the mesh.
#[derive(Clone)]
pub enum ListenSource {
    /// A system socket on the virtual NIC's address.
    Os,
    /// The in-process stack, published each time it starts.
    Mesh(watch::Receiver<Option<MeshEndpoint>>),
}

pub enum SshListener {
    Os(TcpListener),
    Mesh(MeshListener),
}

impl From<TcpListener> for SshListener {
    fn from(listener: TcpListener) -> Self {
        Self::Os(listener)
    }
}

impl From<MeshListener> for SshListener {
    fn from(listener: MeshListener) -> Self {
        Self::Mesh(listener)
    }
}

trait SshStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> SshStream for T {}

impl SshListener {
    async fn accept(&self) -> std::io::Result<(Box<dyn SshStream>, SocketAddr)> {
        match self {
            Self::Os(listener) => {
                let (stream, peer) = listener.accept().await?;
                Ok((Box::new(stream), peer))
            }
            Self::Mesh(listener) => {
                let (stream, peer) = listener.accept().await?;
                Ok((Box::new(stream), peer))
            }
        }
    }
}

pub struct SshService {
    pub state: watch::Receiver<SshState>,
    pub host_fingerprint: String,
    stop: Stop,
}

enum Stop {
    Local {
        signal: watch::Sender<bool>,
        task: tokio::task::JoinHandle<()>,
    },
    /// Asks the process that runs the server to turn it off.
    #[cfg(unix)]
    Remote(Box<dyn FnOnce() + Send>),
}

impl SshService {
    /// Follows the mesh address in `net` until stopped.
    pub fn start(
        runtime: &Handle,
        allowed: PublicKey,
        host_key: PrivateKey,
        net: watch::Receiver<Status>,
        source: ListenSource,
    ) -> Self {
        let host_fingerprint = store::fingerprint(host_key.public_key());
        let (state_tx, state) = watch::channel(SshState::Starting);
        let (stop, stop_rx) = watch::channel(false);
        let config = Arc::new(server::config(host_key));
        let task = runtime.spawn(follow_mesh(
            net,
            source,
            Arc::new(allowed),
            config,
            state_tx,
            stop_rx,
        ));
        Self {
            state,
            host_fingerprint,
            stop: Stop::Local { signal: stop, task },
        }
    }

    /// A server run by another process: `state` follows its reports, and `off`
    /// asks it to stop.
    #[cfg(unix)]
    pub(crate) fn remote(
        host_fingerprint: String,
        state: watch::Receiver<SshState>,
        off: impl FnOnce() + Send + 'static,
    ) -> Self {
        Self {
            state,
            host_fingerprint,
            stop: Stop::Remote(Box::new(off)),
        }
    }

    /// The future returns once every session and its processes are gone. The
    /// request goes out right away, so it is never overtaken by a later start.
    pub fn stop(self) -> impl Future<Output = ()> + Send {
        let mut state = self.state;
        let task = match self.stop {
            Stop::Local { signal, task } => {
                let _ = signal.send(true);
                Some(task)
            }
            #[cfg(unix)]
            Stop::Remote(off) => {
                off();
                None
            }
        };
        async move {
            match task {
                Some(task) => {
                    let _ = task.await;
                }
                None => {
                    let _ = state.wait_for(|s| *s == SshState::Off).await;
                }
            }
        }
    }
}

async fn follow_mesh(
    mut net: watch::Receiver<Status>,
    mut source: ListenSource,
    allowed: Arc<PublicKey>,
    config: Arc<russh::server::Config>,
    state: watch::Sender<SshState>,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        let address = net
            .borrow_and_update()
            .net
            .as_ref()
            .map(|n| (n.ip, n.cidr()));
        let Some((ip, cidr)) = address else {
            state.send_replace(SshState::Starting);
            tokio::select! {
                changed = net.changed() => if changed.is_err() { break },
                _ = stop.changed() => break,
            }
            continue;
        };

        let listener = match &mut source {
            ListenSource::Os => bind_with_retry(ip, &state, &mut net, &mut stop)
                .await
                .map(SshListener::from),
            ListenSource::Mesh(endpoint) => wait_for_endpoint(ip, endpoint, &mut net, &mut stop)
                .await
                .map(SshListener::from),
        };
        let Some(listener) = listener else {
            if *stop.borrow() {
                break;
            }
            continue;
        };
        info!(%ip, port = PORT, "ssh server listening");
        // The in-process stack has no system socket for a firewall to govern.
        #[cfg(windows)]
        let _firewall = matches!(source, ListenSource::Os)
            .then(|| firewall::FirewallRule::open(ip, cidr, PORT));

        // Ends all sessions with it when the address changes or on stop.
        let (session_stop, session_stop_rx) = watch::channel(false);
        let mut serving = tokio::spawn(serve(
            listener,
            cidr,
            allowed.clone(),
            config.clone(),
            state.clone(),
            ip,
            session_stop_rx,
        ));
        let stopped = loop {
            tokio::select! {
                changed = net.changed() => {
                    if changed.is_err() {
                        break true;
                    }
                    // Reconnecting keeps the address, and with it the sessions.
                    let current = net.borrow().net.as_ref().map(|n| n.ip);
                    if current != Some(ip) {
                        break false;
                    }
                }
                _ = stop.changed() => break true,
                _ = &mut serving => break false,
                // A new stack means the listener being served has gone.
                _ = endpoint_replaced(&mut source) => break false,
            }
        };
        let _ = session_stop.send(true);
        let _ = (&mut serving).await;
        if stopped {
            break;
        }
    }
    state.send_replace(SshState::Off);
}

/// Waits for the stack serving `ip`. It is published before the address shows
/// up in the status, so it may already be there.
async fn wait_for_endpoint(
    ip: Ipv4Addr,
    endpoint: &mut watch::Receiver<Option<MeshEndpoint>>,
    net: &mut watch::Receiver<Status>,
    stop: &mut watch::Receiver<bool>,
) -> Option<MeshListener> {
    loop {
        if let Some(current) = endpoint.borrow_and_update().as_ref() {
            if current.ip == ip {
                return Some(current.listener.clone());
            }
        }
        tokio::select! {
            changed = endpoint.changed() => {
                if changed.is_err() {
                    // The connection has ended; only stopping is left.
                    let _ = stop.changed().await;
                    return None;
                }
            }
            changed = net.changed() => {
                if changed.is_err() {
                    let _ = stop.changed().await;
                    return None;
                }
                if net.borrow().net.as_ref().map(|n| n.ip) != Some(ip) {
                    return None;
                }
            }
            _ = stop.changed() => return None,
        }
    }
}

async fn endpoint_replaced(source: &mut ListenSource) {
    if let ListenSource::Mesh(endpoint) = source {
        if endpoint.changed().await.is_ok() {
            return;
        }
    }
    std::future::pending().await
}

async fn bind_with_retry(
    ip: Ipv4Addr,
    state: &watch::Sender<SshState>,
    net: &mut watch::Receiver<Status>,
    stop: &mut watch::Receiver<bool>,
) -> Option<TcpListener> {
    let started = std::time::Instant::now();
    loop {
        match TcpListener::bind((ip, PORT)).await {
            Ok(listener) => return Some(listener),
            Err(error) => {
                debug!(%ip, %error, "ssh bind failed");
                if started.elapsed() >= BIND_GRACE {
                    let message = if error.kind() == std::io::ErrorKind::AddrInUse {
                        format!("端口 {PORT} 已被占用")
                    } else {
                        format!("无法监听 {ip}:{PORT}（{error}）")
                    };
                    state.send_replace(SshState::Error(message));
                }
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(BIND_RETRY) => {}
            _ = net.changed() => {
                if net.borrow().net.as_ref().map(|n| n.ip) != Some(ip) {
                    return None;
                }
            }
            _ = stop.changed() => return None,
        }
    }
}

/// Accepts until `stop`, then disconnects everyone before returning.
pub async fn serve(
    listener: impl Into<SshListener>,
    cidr: Ipv4Net,
    allowed: Arc<PublicKey>,
    config: Arc<russh::server::Config>,
    state: watch::Sender<SshState>,
    ip: Ipv4Addr,
    mut stop: watch::Receiver<bool>,
) {
    let listener = listener.into();
    state.send_replace(SshState::Listening {
        ip,
        connections: 0,
        user: effective_user(),
    });
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut sessions = tokio::task::JoinSet::new();
    loop {
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(error) => {
                    warn!(%error, "ssh accept failed");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            },
            _ = stop.changed() => break,
        };
        // The bind address already limits this; checked again because a route
        // added on this machine could still deliver other traffic here.
        if !peer_allowed(peer, cidr) {
            warn!(%peer, "ssh connection from outside the mesh dropped");
            continue;
        }
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            warn!(%peer, "too many ssh connections");
            continue;
        };
        while sessions.try_join_next().is_some() {}
        let (config, allowed, state, stop) =
            (config.clone(), allowed.clone(), state.clone(), stop.clone());
        sessions.spawn(async move {
            let _slot = slot;
            run_connection(stream, peer, config, allowed, state, stop).await;
        });
    }
    // Sessions see the same stop signal; this waits until they have ended.
    while sessions.join_next().await.is_some() {}
}

fn peer_allowed(peer: SocketAddr, cidr: Ipv4Net) -> bool {
    match peer.ip() {
        IpAddr::V4(ip) => cidr.contains(&ip),
        IpAddr::V6(ip) => ip.to_ipv4_mapped().is_some_and(|ip| cidr.contains(&ip)),
    }
}

/// Counts only logged-in connections, which is what the window reports.
struct LoginCount(watch::Sender<SshState>);

impl LoginCount {
    fn change(state: &watch::Sender<SshState>, delta: isize) {
        state.send_if_modified(|current| match current {
            SshState::Listening { connections, .. } => {
                *connections = connections.saturating_add_signed(delta);
                true
            }
            _ => false,
        });
    }
}

impl Drop for LoginCount {
    fn drop(&mut self) {
        Self::change(&self.0, -1);
    }
}

async fn run_connection(
    stream: Box<dyn SshStream>,
    peer: SocketAddr,
    config: Arc<russh::server::Config>,
    allowed: Arc<PublicKey>,
    state: watch::Sender<SshState>,
    mut stop: watch::Receiver<bool>,
) {
    let authenticated = Arc::new(AtomicBool::new(false));
    let count: Arc<std::sync::Mutex<Option<LoginCount>>> = Arc::default();
    let on_login = {
        let (count, state) = (count.clone(), state.clone());
        Box::new(move || {
            LoginCount::change(&state, 1);
            if let Ok(mut slot) = count.lock() {
                *slot = Some(LoginCount(state));
            }
        })
    };
    let tasks: server::SessionTasks = Arc::default();
    let handler = SessionHandler::new(
        allowed,
        peer,
        authenticated.clone(),
        on_login,
        tasks.clone(),
    );
    let mut running = match russh::server::run_stream(config, stream, handler).await {
        Ok(running) => running,
        Err(error) => {
            debug!(%peer, %error, "ssh handshake failed");
            return;
        }
    };
    let handle = running.handle();
    let auth_deadline = tokio::time::sleep(AUTH_TIMEOUT);
    tokio::pin!(auth_deadline);
    let mut deadline_armed = true;
    loop {
        tokio::select! {
            result = &mut running => {
                if let Err(error) = result {
                    debug!(%peer, %error, "ssh session ended");
                }
                break;
            }
            _ = &mut auth_deadline, if deadline_armed => {
                deadline_armed = false;
                if !authenticated.load(Ordering::SeqCst) {
                    debug!(%peer, "ssh login timed out");
                    disconnect(&handle).await;
                }
            }
            _ = stop.changed() => {
                // Local work ends first: this must not depend on the peer, which
                // may be unreachable by now. The session itself times out on
                // keepalive if the goodbye never gets an answer.
                server::shut_down_tasks(&tasks).await;
                disconnect(&handle).await;
                let _ = tokio::time::timeout(DISCONNECT_WAIT, &mut running).await;
                break;
            }
        }
    }
    info!(%peer, "ssh connection closed");
    drop(count);
}

async fn disconnect(handle: &russh::server::Handle) {
    let _ = handle
        .disconnect(
            russh::Disconnect::ByApplication,
            "server stopped".to_owned(),
            "en".to_owned(),
        )
        .await;
}

/// Parses a key from the front ends and loads the host key.
pub fn prepare(text: &str) -> Result<(PublicKey, PrivateKey)> {
    let allowed = store::parse_public_key(text)?;
    let host_key = store::Store::open_default()?.load_or_create_host_key()?;
    Ok((allowed, host_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_mesh_peers_are_allowed() {
        let cidr: Ipv4Net = "10.77.1.0/24".parse().unwrap();
        let peer = |ip: &str| SocketAddr::new(ip.parse().unwrap(), 1);
        assert!(peer_allowed(peer("10.77.1.9"), cidr));
        assert!(peer_allowed(peer("::ffff:10.77.1.9"), cidr));
        for outside in ["10.77.2.1", "192.168.1.1", "127.0.0.1", "::1"] {
            assert!(!peer_allowed(peer(outside), cidr), "{outside}");
        }
    }
}
