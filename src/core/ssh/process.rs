//! Running what the client asked for, and making sure it dies with the session.
use bytes::Bytes;
use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};
use russh::server::Handle;
use russh::ChannelId;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::mpsc;
use tracing::debug;

/// Output still buffered after the process exits gets this long to arrive.
const DRAIN: Duration = Duration::from_secs(1);
const STDIO_CHUNK: usize = 8192;

pub type SharedMaster = Arc<Mutex<Option<Box<dyn MasterPty + Send>>>>;

/// Our own secrets must not be inherited by a remote shell.
fn scrubbed_env() -> Vec<(OsString, OsString)> {
    std::env::vars_os()
        .filter(|(name, _)| !name.to_string_lossy().starts_with("VARCO_"))
        .collect()
}

fn work_dir() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("."))
}

struct Program {
    shell: OsString,
    args: Vec<OsString>,
}

#[cfg(unix)]
fn default_shell() -> OsString {
    if let Some(shell) = std::env::var_os("SHELL").filter(|s| !s.is_empty()) {
        return shell;
    }
    // A GUI app may start with almost no environment.
    ["/bin/zsh", "/bin/bash"]
        .into_iter()
        .find(|path| std::path::Path::new(path).exists())
        .unwrap_or("/bin/sh")
        .into()
}

fn interactive_program() -> Program {
    #[cfg(unix)]
    return Program {
        shell: default_shell(),
        args: vec!["-l".into()],
    };
    #[cfg(windows)]
    return Program {
        shell: "powershell.exe".into(),
        args: vec!["-NoLogo".into()],
    };
}

fn command_program(command: &str) -> Program {
    #[cfg(unix)]
    return Program {
        shell: default_shell(),
        args: vec!["-c".into(), command.into()],
    };
    #[cfg(windows)]
    return Program {
        shell: "cmd.exe".into(),
        args: vec!["/S".into(), "/C".into(), command.into()],
    };
}

/// Ends the whole process tree when dropped, so a dropped session cannot leave
/// anything running on the customer's machine.
struct TreeGuard(Option<u32>);

impl TreeGuard {
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for TreeGuard {
    fn drop(&mut self) {
        let Some(pid) = self.0 else {
            return;
        };
        #[cfg(unix)]
        // SAFETY: killpg takes plain values. The child leads its own process
        // group, and is only signalled while still unreaped (the guard is
        // disarmed right after waiting), so the id cannot have been reused.
        unsafe {
            libc::killpg(pid as libc::pid_t, libc::SIGKILL);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            let _ = std::process::Command::new("taskkill")
                .args(["/F", "/T", "/PID", &pid.to_string()])
                .creation_flags(super::CREATE_NO_WINDOW)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

pub(super) async fn finish(handle: &Handle, id: ChannelId, code: u32) {
    let _ = handle.exit_status_request(id, code).await;
    let _ = handle.eof(id).await;
    let _ = handle.close(id).await;
}

pub struct PtyRequest {
    pub term: String,
    pub size: PtySize,
}

/// `command` of `None` means an interactive shell. Returns the master, which
/// the handler keeps for window size changes.
pub fn spawn_pty<S>(
    tasks: &mut tokio::task::JoinSet<()>,
    stream: S,
    handle: Handle,
    id: ChannelId,
    request: PtyRequest,
    command: Option<String>,
) -> anyhow::Result<SharedMaster>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let program = command
        .as_deref()
        .map_or_else(interactive_program, command_program);
    let pair = native_pty_system().openpty(request.size)?;
    let mut builder = CommandBuilder::new(&program.shell);
    builder.args(&program.args);
    builder.env_clear();
    for (name, value) in scrubbed_env() {
        builder.env(name, value);
    }
    builder.env(
        "TERM",
        if request.term.is_empty() {
            "xterm-256color"
        } else {
            &request.term
        },
    );
    builder.cwd(work_dir());
    let mut child = pair.slave.spawn_command(builder)?;
    drop(pair.slave);

    let mut guard = TreeGuard(child.process_id());
    let mut reader = pair.master.try_clone_reader()?;
    let mut writer = pair.master.take_writer()?;
    let master: SharedMaster = Arc::new(Mutex::new(Some(pair.master)));
    let task_master = master.clone();

    tasks.spawn(async move {
        let (mut from_client, mut to_client) = tokio::io::split(stream);

        // PTY handles only offer blocking I/O, so each direction gets a thread.
        let (output_tx, mut output_rx) = mpsc::channel::<Bytes>(32);
        std::thread::spawn(move || {
            let mut buf = vec![0u8; STDIO_CHUNK];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        if output_tx
                            .blocking_send(Bytes::copy_from_slice(&buf[..n]))
                            .is_err()
                        {
                            return;
                        }
                    }
                }
            }
        });
        let (input_tx, input_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        std::thread::spawn(move || {
            while let Ok(chunk) = input_rx.recv() {
                if writer.write_all(&chunk).is_err() || writer.flush().is_err() {
                    return;
                }
            }
        });
        let input = tokio::spawn(async move {
            let mut buf = vec![0u8; STDIO_CHUNK];
            while let Ok(n) = from_client.read(&mut buf).await {
                if n == 0 || input_tx.send(buf[..n].to_vec()).is_err() {
                    return;
                }
            }
        });
        let _abort_input = AbortOnDrop(input);

        let (exit_tx, mut exit_rx) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            let _ = exit_tx.send(child.wait());
        });

        let code = loop {
            tokio::select! {
                chunk = output_rx.recv() => match chunk {
                    Some(chunk) => {
                        if to_client.write_all(&chunk).await.is_err() {
                            return; // The guard ends the process.
                        }
                        let _ = to_client.flush().await;
                    }
                    // Output closed first; the exit status is still to come.
                    None => match (&mut exit_rx).await {
                        Ok(Ok(status)) => break status.exit_code(),
                        _ => break 1,
                    },
                },
                status = &mut exit_rx => {
                    let code = match status {
                        Ok(Ok(status)) => status.exit_code(),
                        _ => 1,
                    };
                    guard.disarm();
                    // ConPTY only ends the output stream once the master is gone.
                    drop(task_master.lock().ok().and_then(|mut m| m.take()));
                    let _ = tokio::time::timeout(DRAIN, async {
                        while let Some(chunk) = output_rx.recv().await {
                            let _ = to_client.write_all(&chunk).await;
                        }
                    })
                    .await;
                    let _ = to_client.flush().await;
                    break code;
                }
            }
        };
        guard.disarm();
        finish(&handle, id, code).await;
    });
    Ok(master)
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Plain pipes rather than a PTY, which would corrupt binary data such as
/// `ssh host tar c | tar x`. Stderr goes out as SSH extended data.
pub fn spawn_piped<S>(
    tasks: &mut tokio::task::JoinSet<()>,
    stream: S,
    handle: Handle,
    id: ChannelId,
    command: Option<String>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let program = match &command {
        Some(command) => command_program(command),
        None => {
            // `ssh -T`: a shell reading commands from stdin.
            #[cfg(unix)]
            let program = Program {
                shell: default_shell(),
                args: Vec::new(),
            };
            #[cfg(windows)]
            let program = Program {
                shell: "cmd.exe".into(),
                args: Vec::new(),
            };
            program
        }
    };
    let mut cmd = Command::new(&program.shell);
    #[cfg(unix)]
    {
        cmd.args(&program.args);
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        // cmd.exe has its own quoting rules; passed as-is, as a client intends.
        for arg in &program.args {
            cmd.raw_arg(arg);
        }
        cmd.creation_flags(super::CREATE_NO_WINDOW);
    }
    let mut child = cmd
        .env_clear()
        .envs(scrubbed_env())
        .current_dir(work_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut guard = TreeGuard(child.id());
    let mut stdin = child.stdin.take().expect("stdin is piped");
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let mut stderr = child.stderr.take().expect("stderr is piped");

    tasks.spawn(async move {
        let (mut from_client, mut to_client) = tokio::io::split(stream);
        let _abort_input = AbortOnDrop(tokio::spawn(async move {
            if tokio::io::copy(&mut from_client, &mut stdin).await.is_ok() {
                let _ = stdin.shutdown().await;
            }
            // Dropping stdin here delivers EOF to the process.
        }));
        let stderr_handle = handle.clone();
        let stderr_task = tokio::spawn(async move {
            let mut buf = vec![0u8; STDIO_CHUNK];
            while let Ok(n) = stderr.read(&mut buf).await {
                if n == 0 {
                    return;
                }
                let chunk = Bytes::copy_from_slice(&buf[..n]);
                if stderr_handle.extended_data(id, 1, chunk).await.is_err() {
                    return;
                }
            }
        });
        let _abort_stderr = AbortOnDrop(stderr_task);

        let copied = tokio::io::copy(&mut stdout, &mut to_client).await;
        if let Err(error) = &copied {
            debug!(%error, "stdout copy ended");
        }
        let _ = to_client.flush().await;
        let code = match child.wait().await {
            Ok(status) => status.code().unwrap_or(1) as u32,
            Err(_) => 1,
        };
        guard.disarm();
        // Lets the last of stderr reach the client before the channel closes.
        tokio::time::sleep(Duration::from_millis(20)).await;
        finish(&handle, id, code).await;
    });
    Ok(())
}
