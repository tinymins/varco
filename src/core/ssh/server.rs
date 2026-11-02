//! SSH policy: who may log in and what a session may do.
use super::process::{self, PtyRequest, SharedMaster};
use super::sftp::SftpSession;
use super::store::fingerprint;
use portable_pty::PtySize;
use russh::keys::PublicKey;
use russh::server::{Auth, ChannelOpenHandle, Handler, Msg, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId, MethodKind, MethodSet};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tracing::{info, warn};

const MAX_AUTH_ATTEMPTS: usize = 3;
const KEEPALIVE: Duration = Duration::from_secs(30);
const KEEPALIVE_MAX: usize = 3;
const FORWARD_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SFTP_PIPE: usize = 512 * 1024;

pub fn config(host_key: russh::keys::PrivateKey) -> russh::server::Config {
    russh::server::Config {
        // Public keys only: no password, keyboard-interactive or none.
        methods: MethodSet::from(&[MethodKind::PublicKey][..]),
        max_auth_attempts: MAX_AUTH_ATTEMPTS,
        auth_rejection_time: Duration::from_secs(1),
        auth_rejection_time_initial: Some(Duration::ZERO),
        keys: vec![host_key],
        // An idle debugging shell should stay open. Dead peers are found by keepalive.
        inactivity_timeout: None,
        keepalive_interval: Some(KEEPALIVE),
        keepalive_max: KEEPALIVE_MAX,
        nodelay: true,
        ..Default::default()
    }
}

/// Whether `ssh -L` may reach this destination, and where to actually connect.
/// Only this machine itself, never a name that DNS could point elsewhere:
/// the tunnel must not become a way into the customer's LAN.
pub fn loopback_target(host: &str, port: u32) -> Option<SocketAddr> {
    let port = u16::try_from(port).ok().filter(|port| *port != 0)?;
    match host {
        "127.0.0.1" | "localhost" => Some(SocketAddr::from(([127, 0, 0, 1], port))),
        "::1" | "[::1]" => Some(SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port))),
        _ => None,
    }
}

#[derive(Default)]
struct ChannelState {
    channel: Option<Channel<Msg>>,
    pty: Option<PtyRequest>,
    master: Option<SharedMaster>,
}

pub type SessionTasks = Arc<std::sync::Mutex<JoinSet<()>>>;

/// Ends everything a session started and waits until it has actually gone.
pub async fn shut_down_tasks(tasks: &SessionTasks) {
    let mut taken = match tasks.lock() {
        Ok(mut guard) => std::mem::take(&mut *guard),
        Err(_) => return,
    };
    taken.shutdown().await;
}

pub struct SessionHandler {
    allowed: Arc<PublicKey>,
    peer: SocketAddr,
    authenticated: Arc<AtomicBool>,
    on_login: Option<Box<dyn FnOnce() + Send>>,
    channels: HashMap<ChannelId, ChannelState>,
    /// Dropped with the connection, which aborts every task and so ends every
    /// process and tunnel belonging to it. Shared so that stopping can do the
    /// same at once, without depending on a peer that may be unreachable.
    tasks: SessionTasks,
}

impl SessionHandler {
    pub fn new(
        allowed: Arc<PublicKey>,
        peer: SocketAddr,
        authenticated: Arc<AtomicBool>,
        on_login: Box<dyn FnOnce() + Send>,
        tasks: SessionTasks,
    ) -> Self {
        Self {
            allowed,
            peer,
            authenticated,
            on_login: Some(on_login),
            channels: HashMap::new(),
            tasks,
        }
    }

    fn is_allowed(&self, key: &PublicKey) -> bool {
        key.key_data() == self.allowed.key_data()
    }

    /// Finished tasks would otherwise pile up in a long session.
    fn reap(&mut self) {
        if let Ok(mut tasks) = self.tasks.lock() {
            while tasks.try_join_next().is_some() {}
        }
    }

    fn spawn_task(&self, task: impl std::future::Future<Output = ()> + Send + 'static) {
        if let Ok(mut tasks) = self.tasks.lock() {
            tasks.spawn(task);
        }
    }

    fn start_process(
        &mut self,
        id: ChannelId,
        command: Option<String>,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        self.reap();
        let state = self.channels.entry(id).or_default();
        let Some(channel) = state.channel.take() else {
            return session.channel_failure(id);
        };
        let pty = state.pty.take();
        let stream = channel.into_stream();
        let handle = session.handle();
        let spawned = match self.tasks.lock() {
            Ok(mut tasks) => match pty {
                Some(request) => {
                    process::spawn_pty(&mut tasks, stream, handle, id, request, command).map(Some)
                }
                None => {
                    process::spawn_piped(&mut tasks, stream, handle, id, command).map(|()| None)
                }
            },
            Err(_) => Err(anyhow::anyhow!("session is shutting down")),
        };
        match spawned {
            Ok(master) => {
                if let Some(state) = self.channels.get_mut(&id) {
                    state.master = master;
                }
                session.channel_success(id)
            }
            Err(error) => {
                warn!(%error, "starting a process failed");
                session.channel_failure(id)
            }
        }
    }
}

fn pty_size(cols: u32, rows: u32, pix_width: u32, pix_height: u32) -> PtySize {
    let clamp = |value: u32| u16::try_from(value).unwrap_or(u16::MAX);
    PtySize {
        rows: clamp(rows).max(1),
        cols: clamp(cols).max(1),
        pixel_width: clamp(pix_width),
        pixel_height: clamp(pix_height),
    }
}

impl Handler for SessionHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::reject())
    }

    async fn auth_password(&mut self, _user: &str, _password: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::reject())
    }

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        offer: russh::server::PublicKeyOffer<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(if self.is_allowed(offer.public_key) {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        key: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        if !self.is_allowed(key.public_key) {
            warn!(peer = %self.peer, key = %fingerprint(key.public_key), "ssh login refused");
            return Ok(Auth::reject());
        }
        info!(peer = %self.peer, key = %fingerprint(key.public_key), "ssh login");
        self.authenticated.store(true, Ordering::SeqCst);
        if let Some(on_login) = self.on_login.take() {
            on_login();
        }
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.insert(
            channel.id(),
            ChannelState {
                channel: Some(channel),
                ..Default::default()
            },
        );
        reply.accept().await;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(target) = loopback_target(host_to_connect, port_to_connect) else {
            warn!(peer = %self.peer, host = host_to_connect, "ssh forward refused");
            return Ok(()); // Dropping `reply` refuses the channel.
        };
        self.reap();
        let peer = self.peer;
        self.spawn_task(async move {
            let connected =
                tokio::time::timeout(FORWARD_CONNECT_TIMEOUT, TcpStream::connect(target)).await;
            let Ok(Ok(mut tcp)) = connected else {
                return; // Nothing is listening there; the channel is refused.
            };
            info!(%peer, %target, "ssh forward");
            reply.accept().await;
            let mut stream = channel.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await;
        });
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let size = pty_size(col_width, row_height, pix_width, pix_height);
        self.channels.entry(channel).or_default().pty = Some(PtyRequest {
            term: term.to_owned(),
            size,
        });
        session.channel_success(channel)
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!(peer = %self.peer, "ssh shell");
        self.start_process(channel, None, session)
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).into_owned();
        info!(peer = %self.peer, %command, "ssh exec");
        self.start_process(channel, Some(command), session)
    }

    async fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let channel = self.channels.entry(channel_id).or_default().channel.take();
        match (name, channel) {
            ("sftp", Some(channel)) => {
                info!(peer = %self.peer, "ssh sftp");
                self.reap();
                let handle = session.handle();
                self.spawn_task(async move {
                    // The library runs a detached task nobody can wait for or
                    // stop. Behind this pipe it ends when the pipe closes, which
                    // lets this task report an exit status (scp fails without
                    // one) and lets aborting the session stop it.
                    let (mut ours, theirs) = tokio::io::duplex(SFTP_PIPE);
                    russh_sftp::server::run(theirs, SftpSession::new()).await;
                    let mut stream = channel.into_stream();
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut ours).await;
                    process::finish(&handle, channel_id, 0).await;
                });
                session.channel_success(channel_id)
            }
            _ => session.channel_failure(channel_id),
        }
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(state) = self.channels.get_mut(&channel) else {
            return Ok(());
        };
        let size = pty_size(col_width, row_height, pix_width, pix_height);
        if let Some(request) = &mut state.pty {
            request.size = size;
        }
        if let Some(master) = &state.master {
            if let Ok(guard) = master.lock() {
                if let Some(master) = guard.as_ref() {
                    let _ = master.resize(size);
                }
            }
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.remove(&channel);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarding_reaches_only_this_machine() {
        let v4 = SocketAddr::from(([127, 0, 0, 1], 80));
        assert_eq!(loopback_target("127.0.0.1", 80), Some(v4));
        assert_eq!(loopback_target("localhost", 80), Some(v4));
        assert!(loopback_target("::1", 80).is_some());
        for host in [
            "192.168.1.1",
            "10.77.1.1",
            "0.0.0.0",
            "example.com",
            "127.0.0.2",
            "",
        ] {
            assert_eq!(loopback_target(host, 80), None, "{host}");
        }
        assert_eq!(loopback_target("127.0.0.1", 0), None);
        assert_eq!(loopback_target("127.0.0.1", 70000), None);
    }

    #[test]
    fn pty_size_survives_absurd_values() {
        let size = pty_size(0, u32::MAX, 0, 0);
        assert_eq!((size.cols, size.rows), (1, u16::MAX));
    }
}
