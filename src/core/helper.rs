//! macOS / Linux: the window stays an ordinary user process and only this small
//! helper is elevated. It owns the NIC, the connection and the SSH server, reports
//! over a Unix socket, and exits when the socket closes, so a crashed GUI leaves
//! nothing behind.
//!
//! The socket sits in a fresh 0700 directory: only this user and root can reach it.
//! The first line from the GUI is the Code; after it come [`Request`]s.
use super::backend::{hostname, Connection, SshHost};
use super::engine::{self, Counters, DeviceFactory, Phase, Status};
use super::error::FailReason;
use super::netstack::NetstackFactory;
use super::ssh::{store, SshService, SshState};
use crate::credential::Credential;
use russh::keys::ssh_key::LineEnding;
use russh::keys::{PrivateKey, PublicKey};
use serde::{Deserialize, Serialize};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::{Child, Command};
use tokio::runtime::Handle;
use tokio::sync::{mpsc, watch};

const REPORT_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Debug, Serialize, Deserialize)]
struct Update {
    status: Status,
    tx_bytes: u64,
    rx_bytes: u64,
    ssh: SshState,
}

/// What the GUI asks of the helper once the Code has been sent. Keys travel as
/// OpenSSH text; the host key is the user's own, so the fingerprint stays the same.
#[derive(Serialize, Deserialize)]
enum Request {
    SshOn {
        allowed_key: String,
        host_key: String,
    },
    SshOff,
}

pub fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

// ---- GUI side ----

/// The GUI's end of an SSH server run by the helper.
pub(crate) struct SshLink {
    requests: mpsc::UnboundedSender<Request>,
    state: watch::Receiver<SshState>,
}

impl SshLink {
    pub(crate) fn start(&self, allowed: PublicKey, host_key: &PrivateKey) -> SshService {
        // Encoding keys that parsed cannot fail; if it ever did, the helper
        // reports the empty text as an invalid key.
        let _ = self.requests.send(Request::SshOn {
            allowed_key: allowed.to_openssh().unwrap_or_default(),
            host_key: host_key
                .to_openssh(LineEnding::LF)
                .map(|text| text.to_string())
                .unwrap_or_default(),
        });
        let requests = self.requests.clone();
        SshService::remote(
            store::fingerprint(host_key.public_key()),
            self.state.clone(),
            move || {
                let _ = requests.send(Request::SshOff);
            },
        )
    }
}

pub fn start_elevated(runtime: &Handle, credential: Credential, ssh_only: bool) -> Connection {
    let (status_tx, status) = watch::channel(Status::default());
    let (stop, stop_rx) = watch::channel(false);
    let counters = Arc::new(Counters::default());
    let (requests, requests_rx) = mpsc::unbounded_channel();
    let (ssh_tx, ssh_state) = watch::channel(SshState::Off);
    let task_counters = counters.clone();
    runtime.spawn(async move {
        let reports = GuiReports {
            status: &status_tx,
            ssh: &ssh_tx,
        };
        let final_status = supervise(
            credential,
            ssh_only,
            &reports,
            &task_counters,
            stop_rx,
            requests_rx,
        )
        .await;
        // Whatever ran the server is gone with the connection.
        ssh_tx.send_replace(SshState::Off);
        status_tx.send_modify(|s| s.phase = final_status);
    });
    Connection {
        status,
        counters,
        stop,
        ssh: SshHost::Helper(SshLink {
            requests,
            state: ssh_state,
        }),
    }
}

async fn supervise(
    credential: Credential,
    ssh_only: bool,
    reports: &GuiReports<'_>,
    counters: &Counters,
    mut stop: watch::Receiver<bool>,
    requests: mpsc::UnboundedReceiver<Request>,
) -> Phase {
    let failed = |detail: String| Phase::Failed(FailReason::DeviceFailed(detail));
    let dir = match private_dir() {
        Ok(dir) => dir,
        Err(error) => return failed(error.to_string()),
    };
    let _cleanup = RemoveDir(dir.clone());
    let socket = dir.join("helper.sock");
    let listener = match UnixListener::bind(&socket) {
        Ok(listener) => listener,
        Err(error) => return failed(error.to_string()),
    };
    let mut child = match spawn_elevated(&socket, ssh_only) {
        Ok(child) => Some(child),
        Err(error) if !ssh_only => return failed(error.to_string()),
        Err(_) => None,
    };
    let accepted = match &mut child {
        // Open while the system password prompt is showing, so there is no timeout.
        Some(child) => tokio::select! {
            accepted = listener.accept() => accepted.map(|(stream, _)| Some(stream)),
            // The prompt was cancelled or authentication failed.
            _ = child.wait() => Ok(None),
            _ = stop.changed() => return Phase::Stopped,
        },
        None => Ok(None),
    };
    match accepted {
        Ok(Some(stream)) => talk(stream, &credential, reports, counters, stop, requests).await,
        // Without a NIC nothing needs root: the server then runs as this user.
        Ok(None) if ssh_only => {
            let (gui, local) = tokio::io::duplex(64 * 1024);
            let local = tokio::spawn(serve(local, NetstackFactory::new().0));
            let phase = talk(gui, &credential, reports, counters, stop, requests).await;
            let _ = local.await;
            phase
        }
        Ok(None) => Phase::Failed(FailReason::NoPrivilege),
        Err(error) => failed(error.to_string()),
    }
}

/// Sends the Code, then passes requests one way and reports the other until
/// the connection ends. Returning closes the stream, which stops the helper.
async fn talk<S: AsyncRead + AsyncWrite>(
    stream: S,
    credential: &Credential,
    reports: &GuiReports<'_>,
    counters: &Counters,
    stop: watch::Receiver<bool>,
    mut requests: mpsc::UnboundedReceiver<Request>,
) -> Phase {
    let (reader, mut writer) = tokio::io::split(stream);
    if let Err(error) = send_line(&mut writer, &credential.encode()).await {
        return Phase::Failed(FailReason::DeviceFailed(error.to_string()));
    }
    let forward = async {
        while let Some(request) = requests.recv().await {
            let Ok(line) = serde_json::to_string(&request) else {
                continue;
            };
            if send_line(&mut writer, &line).await.is_err() {
                break;
            }
        }
        std::future::pending().await
    };
    tokio::select! {
        phase = relay_updates(reader, reports, counters, stop) => phase,
        never = forward => never,
    }
}

/// Where the GUI side puts what the helper reports.
trait Reports {
    fn report(&self, update: Update);
}

impl Reports for watch::Sender<Status> {
    fn report(&self, update: Update) {
        self.send_replace(update.status);
    }
}

struct GuiReports<'a> {
    status: &'a watch::Sender<Status>,
    ssh: &'a watch::Sender<SshState>,
}

impl Reports for GuiReports<'_> {
    fn report(&self, update: Update) {
        self.ssh.send_if_modified(|current| {
            let changed = *current != update.ssh;
            *current = update.ssh;
            changed
        });
        self.status.send_replace(update.status);
    }
}

async fn relay_updates<S: AsyncRead + Unpin>(
    stream: S,
    reports: &impl Reports,
    counters: &Counters,
    mut stop: watch::Receiver<bool>,
) -> Phase {
    let mut lines = BufReader::new(stream).lines();
    let mut last = Phase::Stopped;
    loop {
        let line = tokio::select! {
            line = lines.next_line() => line,
            // Dropping the stream on return is what tells the helper to stop.
            _ = stop.changed() => return Phase::Stopped,
        };
        let Ok(Some(line)) = line else {
            return match last {
                Phase::Failed(_) | Phase::Stopped => last,
                _ => Phase::Failed(FailReason::DeviceFailed("提权进程意外退出".to_owned())),
            };
        };
        let Ok(update) = serde_json::from_str::<Update>(&line) else {
            continue;
        };
        counters.tx_bytes.store(update.tx_bytes, Ordering::Relaxed);
        counters.rx_bytes.store(update.rx_bytes, Ordering::Relaxed);
        last = update.status.phase.clone();
        reports.report(update);
    }
}

async fn send_line<W: AsyncWrite + Unpin>(writer: &mut W, line: &str) -> std::io::Result<()> {
    writer.write_all(line.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await
}

struct RemoveDir(PathBuf);

impl Drop for RemoveDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn private_dir() -> std::io::Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!("varco-{}", engine::new_client_id()));
    // create_dir fails if the name exists, so a planted directory cannot be reused.
    std::fs::create_dir(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(dir)
}

fn spawn_elevated(socket: &Path, ssh_only: bool) -> std::io::Result<Child> {
    let exe = std::env::current_exe()?;
    let mut command = elevation_command(&exe, socket, ssh_only);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
}

/// The paths are passed as separate arguments and never spliced into a script,
/// so an unusual install path cannot change what runs as root.
#[cfg(target_os = "macos")]
fn elevation_command(exe: &Path, socket: &Path, ssh_only: bool) -> Command {
    let (flag, prompt) = if ssh_only {
        (" --ssh-only", "varco 需要以 root 身份运行 SSH")
    } else {
        ("", "varco 需要创建虚拟网卡")
    };
    let script = format!(
        "do shell script (quoted form of item 1 of argv) & \" helper --socket \" & \
         (quoted form of item 2 of argv) & \"{flag}\" with prompt \"{prompt}\" with administrator privileges"
    );
    let mut command = Command::new("/usr/bin/osascript");
    command
        .args(["-e", "on run argv"])
        .args(["-e", &script])
        .args(["-e", "end run"])
        .arg(exe)
        .arg(socket);
    command
}

#[cfg(not(target_os = "macos"))]
fn elevation_command(exe: &Path, socket: &Path, ssh_only: bool) -> Command {
    let mut command = Command::new("pkexec");
    command.arg(exe).arg("helper").arg("--socket").arg(socket);
    if ssh_only {
        command.arg("--ssh-only");
    }
    command
}

// ---- Elevated side ----

/// Entry point of `varco helper`.
pub async fn run_helper(socket: &Path, factory: impl DeviceFactory) -> anyhow::Result<()> {
    let stream = UnixStream::connect(socket).await?;
    serve(stream, factory).await;
    Ok(())
}

/// The SSH server as the GUI last asked for it.
enum Server {
    Off,
    On(SshService),
    Failed(String),
}

impl Server {
    fn state(&mut self) -> SshState {
        match self {
            Self::Off => SshState::Off,
            Self::On(service) => service.state.borrow_and_update().clone(),
            Self::Failed(message) => SshState::Error(message.clone()),
        }
    }

    async fn changed(&mut self) {
        if let Self::On(service) = self {
            if service.state.changed().await.is_ok() {
                return;
            }
        }
        std::future::pending().await
    }

    async fn turn_off(&mut self) {
        if let Self::On(service) = std::mem::replace(self, Self::Off) {
            service.stop().await;
        }
    }
}

async fn serve<S, F>(stream: S, factory: F)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
    F: DeviceFactory,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();
    let Ok(Some(code)) = lines.next_line().await else {
        return;
    };
    let Ok(credential) = Credential::parse(&code) else {
        let status = Status {
            phase: Phase::Failed(FailReason::BadCredential),
            ..Status::default()
        };
        let update = Update {
            status,
            tx_bytes: 0,
            rx_bytes: 0,
            ssh: SshState::Off,
        };
        if let Ok(line) = serde_json::to_string(&update) {
            let _ = send_line(&mut writer, &line).await;
        }
        return;
    };
    let source = factory.ssh_source();
    let (status_tx, mut status) = watch::channel(Status::default());
    let (stop, stop_rx) = watch::channel(false);
    let counters = Arc::new(Counters::default());
    let mut engine_task = tokio::spawn(engine::run(
        credential,
        hostname(),
        factory,
        status_tx,
        counters.clone(),
        stop_rx,
    ));
    let mut server = Server::Off;
    let mut engine_done = false;
    let mut ticker = tokio::time::interval(REPORT_INTERVAL);
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = status.changed() => {}
            _ = server.changed() => {}
            _ = &mut engine_task => engine_done = true,
            line = lines.next_line() => {
                // EOF, or a broken socket, ends the session.
                let Ok(Some(line)) = line else { break };
                match serde_json::from_str::<Request>(&line) {
                    Ok(Request::SshOn { allowed_key, host_key }) => {
                        server.turn_off().await;
                        let keys = store::parse_public_key(&allowed_key)
                            .ok()
                            .zip(PrivateKey::from_openssh(&host_key).ok());
                        server = match keys {
                            Some((allowed, host_key)) => Server::On(SshService::start(
                                &Handle::current(),
                                allowed,
                                host_key,
                                status.clone(),
                                source.clone(),
                            )),
                            None => Server::Failed("SSH 密钥无效".to_owned()),
                        };
                    }
                    Ok(Request::SshOff) => server.turn_off().await,
                    Err(_) => continue,
                }
            }
        }
        let update = Update {
            status: status.borrow_and_update().clone(),
            tx_bytes: counters.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: counters.rx_bytes.load(Ordering::Relaxed),
            ssh: server.state(),
        };
        let Ok(line) = serde_json::to_string(&update) else {
            continue;
        };
        if send_line(&mut writer, &line).await.is_err() || engine_done {
            break;
        }
    }
    // Sessions end first, while the network they run over still exists.
    server.turn_off().await;
    if !engine_done {
        let _ = stop.send(true);
        let _ = engine_task.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::engine::{Device, NetInfo};

    struct NullDevice;
    impl Device for NullDevice {
        async fn recv(&self, _buf: &mut [u8]) -> std::io::Result<usize> {
            std::future::pending().await
        }
        async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }
    }
    struct NullFactory;
    impl DeviceFactory for NullFactory {
        type Device = NullDevice;
        fn create(&self, _net: &NetInfo) -> Result<NullDevice, FailReason> {
            Ok(NullDevice)
        }
    }

    fn pair() -> (tokio::io::DuplexStream, tokio::task::JoinHandle<()>) {
        let (gui, helper) = tokio::io::duplex(64 * 1024);
        (gui, tokio::spawn(serve(helper, NullFactory)))
    }

    #[tokio::test]
    async fn malformed_code_is_reported_back_to_the_gui() {
        let (mut gui, task) = pair();
        send_line(&mut gui, "garbage").await.unwrap();
        let (status, _) = watch::channel(Status::default());
        let (_stop, stop_rx) = watch::channel(false);
        let phase = relay_updates(gui, &status, &Counters::default(), stop_rx).await;
        assert_eq!(phase, Phase::Failed(FailReason::BadCredential));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn engine_failure_crosses_the_socket_with_its_reason() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let code = Credential {
            server: addr.to_string(),
            pin: [0; 32],
            secret: [0; 32],
            ssh_pubkey: None,
        };
        let (mut gui, task) = pair();
        send_line(&mut gui, &code.encode()).await.unwrap();
        let (status, _) = watch::channel(Status::default());
        let (_stop, stop_rx) = watch::channel(false);
        let phase = relay_updates(gui, &status, &Counters::default(), stop_rx).await;
        assert!(
            matches!(phase, Phase::Failed(FailReason::ServerUnreachable(_))),
            "{phase:?}"
        );
        task.await.unwrap();
    }

    /// The property that keeps a crashed GUI from leaving a root process and a
    /// live tunnel behind.
    #[tokio::test]
    async fn helper_stops_when_the_gui_goes_away() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Accepts and stalls, so the engine stays busy until told to stop.
        let _hold = tokio::spawn(async move {
            let _conn = listener.accept().await;
            std::future::pending::<()>().await;
        });
        let code = Credential {
            server: addr.to_string(),
            pin: [0; 32],
            secret: [0; 32],
            ssh_pubkey: None,
        };
        let (mut gui, task) = pair();
        send_line(&mut gui, &code.encode()).await.unwrap();
        drop(gui);
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("helper kept running")
            .unwrap();
    }

    #[test]
    fn private_dir_is_owner_only_and_removed() {
        let dir = private_dir().unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        drop(RemoveDir(dir.clone()));
        assert!(!dir.exists());
    }
}
