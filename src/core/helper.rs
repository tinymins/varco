//! macOS / Linux: the window stays an ordinary user process and only this small
//! helper is elevated. It owns the NIC and the connection, reports over a Unix
//! socket, and exits when the socket closes, so a crashed GUI leaves nothing behind.
//!
//! The socket sits in a fresh 0700 directory: only this user and root can reach it.
use super::backend::{hostname, Connection};
use super::engine::{self, Counters, DeviceFactory, Phase, Status};
use super::error::FailReason;
use super::ssh::ListenSource;
use crate::credential::Credential;
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
use tokio::sync::watch;

const REPORT_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Debug, Serialize, Deserialize)]
struct Update {
    status: Status,
    tx_bytes: u64,
    rx_bytes: u64,
}

pub fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

// ---- GUI side ----

pub fn start_elevated(runtime: &Handle, credential: Credential) -> Connection {
    let (status_tx, status) = watch::channel(Status::default());
    let (stop, stop_rx) = watch::channel(false);
    let counters = Arc::new(Counters::default());
    let task_counters = counters.clone();
    runtime.spawn(async move {
        let final_status = supervise(credential, &status_tx, &task_counters, stop_rx).await;
        status_tx.send_modify(|s| s.phase = final_status);
    });
    Connection {
        status,
        counters,
        stop,
        ssh_source: ListenSource::Os,
    }
}

async fn supervise(
    credential: Credential,
    status: &watch::Sender<Status>,
    counters: &Counters,
    mut stop: watch::Receiver<bool>,
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
    let mut child = match spawn_elevated(&socket) {
        Ok(child) => child,
        Err(error) => return failed(error.to_string()),
    };
    // Open while the system password prompt is showing, so there is no timeout.
    let mut stream = tokio::select! {
        accepted = listener.accept() => match accepted {
            Ok((stream, _)) => stream,
            Err(error) => return failed(error.to_string()),
        },
        // The prompt was cancelled or authentication failed.
        _ = child.wait() => return Phase::Failed(FailReason::NoPrivilege),
        _ = stop.changed() => return Phase::Stopped,
    };
    if let Err(error) = send_line(&mut stream, &credential.encode()).await {
        return failed(error.to_string());
    }
    relay_updates(stream, status, counters, stop).await
}

async fn relay_updates<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    status: &watch::Sender<Status>,
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
        status.send_replace(update.status);
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

fn spawn_elevated(socket: &Path) -> std::io::Result<Child> {
    let exe = std::env::current_exe()?;
    let mut command = elevation_command(&exe, socket);
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
fn elevation_command(exe: &Path, socket: &Path) -> Command {
    let mut command = Command::new("/usr/bin/osascript");
    command
        .args(["-e", "on run argv"])
        .args([
            "-e",
            "do shell script (quoted form of item 1 of argv) & \" helper --socket \" & \
             (quoted form of item 2 of argv) with prompt \"varco 需要创建虚拟网卡\" with administrator privileges",
        ])
        .args(["-e", "end run"])
        .arg(exe)
        .arg(socket);
    command
}

#[cfg(not(target_os = "macos"))]
fn elevation_command(exe: &Path, socket: &Path) -> Command {
    let mut command = Command::new("pkexec");
    command.arg(exe).arg("helper").arg("--socket").arg(socket);
    command
}

// ---- Elevated side ----

/// Entry point of `varco helper`.
pub async fn run_helper(socket: &Path, factory: impl DeviceFactory) -> anyhow::Result<()> {
    let stream = UnixStream::connect(socket).await?;
    serve(stream, factory).await;
    Ok(())
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
        };
        if let Ok(line) = serde_json::to_string(&update) {
            let _ = send_line(&mut writer, &line).await;
        }
        return;
    };
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
    let mut ticker = tokio::time::interval(REPORT_INTERVAL);
    loop {
        let finished = tokio::select! {
            _ = ticker.tick() => false,
            _ = status.changed() => false,
            _ = &mut engine_task => true,
            // Anything from the GUI, including EOF, ends the session.
            _ = lines.next_line() => {
                let _ = stop.send(true);
                let _ = (&mut engine_task).await;
                return;
            }
        };
        let update = Update {
            status: status.borrow_and_update().clone(),
            tx_bytes: counters.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: counters.rx_bytes.load(Ordering::Relaxed),
        };
        let Ok(line) = serde_json::to_string(&update) else {
            continue;
        };
        if send_line(&mut writer, &line).await.is_err() || finished {
            if !finished {
                let _ = stop.send(true);
                let _ = (&mut engine_task).await;
            }
            return;
        }
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
