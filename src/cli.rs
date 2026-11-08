//! Terminal front end: also the fallback when no window can be shown.
use anyhow::Result;
use std::future::Future;
use std::io::{IsTerminal, Write};
use std::process::ExitCode;
use tokio::runtime::Handle;
use varco::core::backend::{self, Connection};
use varco::core::engine::{Phase, Status};
use varco::core::ssh::{self, store, SshService, SshState};
use varco::credential::Credential;
use varco::launch::Launch;

pub const CREDENTIAL_ENV: &str = "VARCO_CREDENTIAL";
/// Setting this turns the SSH server on, for machines with no window to click.
pub const SSH_PUBKEY_ENV: &str = "VARCO_SSH_PUBKEY";

fn read_code(configured: Option<&str>) -> Result<String> {
    if let Some(code) = configured {
        return Ok(code.to_owned());
    }
    print!("请输入 Code: ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line)
}

/// Stops a double-clicked console window closing before the message can be read.
fn wait_for_key_if_interactive() {
    if std::io::stdin().is_terminal() && std::env::var_os(CREDENTIAL_ENV).is_none() {
        println!("按回车键退出");
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
    }
}

fn describe(status: &Status) -> Option<String> {
    match &status.phase {
        Phase::Connecting => Some("连接中…".to_owned()),
        Phase::Connected => status.net.as_ref().map(|net| {
            format!(
                "已连接  网络 {}  本机 IP {}  网段 {}",
                net.network,
                net.ip,
                net.cidr()
            )
        }),
        Phase::Reconnecting {
            attempt,
            retry_in_secs,
            last_error,
        } => Some(format!(
            "连接中断（{last_error}），{retry_in_secs} 秒后第 {attempt} 次重连"
        )),
        Phase::Failed(reason) => Some(format!("失败：{reason}")),
        Phase::Stopped => Some("已断开".to_owned()),
    }
}

fn fail(message: &str) -> ExitCode {
    println!("失败：{message}");
    wait_for_key_if_interactive();
    ExitCode::FAILURE
}

/// How a terminal run on macOS / Linux is started.
#[cfg(unix)]
pub struct Start {
    pub foreground: bool,
    pub ssh_as: Option<SshAs>,
}

/// Who the SSH server runs as in the background, without a virtual NIC.
#[cfg(unix)]
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum SshAs {
    Root,
    /// 启动 varco 的用户
    User,
}

pub async fn run(launch: Launch, #[cfg(unix)] start: Start) -> Result<ExitCode> {
    if let Some(problem) = &launch.problem {
        return Ok(fail(problem));
    }
    let credential = match launch.credential(&read_code(launch.code.as_deref())?) {
        Ok(credential) => credential,
        Err(message) => return Ok(fail(&message)),
    };
    let ssh_only = launch.ssh_only_for(&credential);
    // Checked before joining: a key that was asked for and cannot work should
    // not leave a connection up that nobody can reach.
    let ssh_keys = match launch.granted_key(&credential) {
        Some(key) => match ssh::prepare(&key) {
            Ok(keys) => Some(keys),
            Err(error) => return Ok(fail(&format!("SSH 无法开启（{error}）"))),
        },
        None => None,
    };
    if let (Some(key), Some((allowed, _))) = (&credential.ssh_pubkey, &ssh_keys) {
        if key.key_data() == allowed.key_data() {
            println!(
                "这个 Code 会允许持有私钥的人远程控制这台电脑（公钥 {}）",
                store::fingerprint(allowed)
            );
        }
    }
    if ssh_only && ssh_keys.is_none() {
        return Ok(fail(&format!(
            "仅 SSH 模式需要公钥（--ssh-pubkey、配置文件或 {SSH_PUBKEY_ENV}）"
        )));
    }
    // Services, containers and scripts keep it in the foreground, as before.
    #[cfg(unix)]
    if !start.foreground && std::io::stdin().is_terminal() {
        return background::launch(credential, ssh_only, ssh_keys, start.ssh_as);
    }
    let runtime = Handle::current();
    // In the foreground it runs in-process: its user can see and answer `sudo` themselves.
    let connection = join(&runtime, credential, ssh_only);
    let ssh_service = ssh_keys.map(|(allowed, host_key)| {
        let service = connection.start_ssh(&runtime, allowed, host_key);
        println!("SSH 主机指纹：{}", service.host_fingerprint);
        service
    });
    let interrupted = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let final_status = follow(connection, ssh_service, interrupted, |_, _| true).await;
    if matches!(final_status.phase, Phase::Failed(_)) {
        wait_for_key_if_interactive();
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

fn join(runtime: &Handle, credential: Credential, ssh_only: bool) -> Connection {
    if ssh_only {
        println!("仅 SSH 模式：不创建网卡，这台电脑不能访问其他成员");
        backend::start_ssh_only(runtime, credential)
    } else {
        backend::start_in_process(runtime, credential)
    }
}

/// Prints each change until the connection ends. `shutdown`, or `watch`
/// returning false, ends it: SSH first, then the network. Returns the last status.
async fn follow(
    connection: Connection,
    mut ssh_service: Option<SshService>,
    shutdown: impl Future<Output = ()>,
    mut watch: impl FnMut(&Status, Option<&SshState>) -> bool,
) -> Status {
    let mut status_rx = connection.status.clone();
    let stop_tx = connection.stop;
    let mut ssh_state = ssh_service.as_ref().map(|service| service.state.clone());
    let mut last_ssh = None;
    tokio::pin!(shutdown);
    let mut stopping = false;

    let mut last_line = None;
    let mut last_members = Vec::new();
    loop {
        {
            let status = status_rx.borrow_and_update();
            let line = describe(&status);
            if line != last_line {
                if let Some(text) = &line {
                    println!("{text}");
                }
                last_line = line;
            }
            if status.members != last_members {
                last_members = status.members.clone();
                let list: Vec<String> = last_members
                    .iter()
                    .map(|m| format!("{} {}", m.hostname, m.ip))
                    .collect();
                println!("在线成员：{}", list.join("，"));
            }
        }
        if let Some(state) = &mut ssh_state {
            let current = state.borrow_and_update().clone();
            if last_ssh.as_ref() != Some(&current) {
                match &current {
                    SshState::Listening {
                        ip, connections, ..
                    } => {
                        println!("SSH 已开启：{ip}:{}，{connections} 个连接", ssh::PORT);
                    }
                    SshState::Error(message) => println!("SSH 出错：{message}"),
                    SshState::Off | SshState::Starting => {}
                }
                last_ssh = Some(current);
            }
        }
        let finished = matches!(status_rx.borrow().phase, Phase::Failed(_) | Phase::Stopped);
        if finished {
            break;
        }
        let keep_going = watch(&status_rx.borrow().clone(), last_ssh.as_ref());
        if !keep_going && !stopping {
            stopping = true;
            stop_all(&mut ssh_service, &mut ssh_state, &stop_tx).await;
        }
        tokio::select! {
            changed = status_rx.changed() => if changed.is_err() { break },
            _ = &mut shutdown, if !stopping => {
                stopping = true;
                stop_all(&mut ssh_service, &mut ssh_state, &stop_tx).await;
            }
            changed = async {
                match &mut ssh_state {
                    Some(state) => state.changed().await,
                    None => std::future::pending().await,
                }
            } => if changed.is_err() { ssh_state = None; },
        }
    }
    // Ends remote sessions before the network goes away under them.
    if let Some(service) = ssh_service.take() {
        service.stop().await;
    }
    let final_status = status_rx.borrow().clone();
    if let Some(line) = describe(&final_status) {
        if Some(&line) != last_line.as_ref() {
            println!("{line}");
        }
    }
    final_status
}

/// While the network still exists, so clients see a clean close.
async fn stop_all(
    ssh_service: &mut Option<SshService>,
    ssh_state: &mut Option<tokio::sync::watch::Receiver<SshState>>,
    stop: &tokio::sync::watch::Sender<bool>,
) {
    if let Some(service) = ssh_service.take() {
        service.stop().await;
    }
    *ssh_state = None;
    let _ = stop.send(true);
}

#[cfg(unix)]
pub use background::{run_worker, stop};

/// macOS / Linux: after joining, the connection carries on in a detached worker
/// process, run with `sudo` when it needs root, until `varco stop`.
#[cfg(unix)]
mod background {
    use super::*;
    use anyhow::Context;
    use russh::keys::ssh_key::LineEnding;
    use russh::keys::{PrivateKey, PublicKey};
    use serde::{Deserialize, Serialize};
    use std::io::{BufRead, BufReader};
    use std::os::fd::{AsFd, OwnedFd};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    use varco::core::helper::is_root;

    const PID_FILE: &str = "client.pid";
    const LOG_FILE: &str = "client.log";
    const STOP_WAIT: Duration = Duration::from_secs(15);

    /// What the worker is to run. Goes over its stdin, never argv or the
    /// environment, which other processes can read.
    #[derive(Serialize, Deserialize)]
    struct Input {
        code: String,
        ssh_only: bool,
        ssh: Option<Keys>,
    }

    /// OpenSSH text. The host key is this user's, so the fingerprint is the one
    /// a window on this machine shows too.
    #[derive(Serialize, Deserialize)]
    struct Keys {
        allowed_key: String,
        host_key: String,
    }

    /// The worker's one message back, once it is up or has given up.
    #[derive(Serialize, Deserialize)]
    enum Report {
        Connected {
            status: Status,
            ssh: Option<SshState>,
        },
        Failed(String),
    }

    /// Owned by the user who starts varco, also when the worker is root.
    fn run_dir() -> Result<PathBuf> {
        let base = dirs::runtime_dir()
            .or_else(dirs::data_local_dir)
            .context("找不到运行目录")?;
        let dir = base.join("varco");
        std::fs::create_dir_all(&dir).with_context(|| format!("无法创建 {}", dir.display()))?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        Ok(dir)
    }

    fn read_pid(path: &Path) -> Option<i32> {
        let pid: i32 = std::fs::read_to_string(path).ok()?.trim().parse().ok()?;
        // 0 and negative numbers would signal whole process groups.
        (pid > 0).then_some(pid)
    }

    /// Also true for a process of another user, such as a root worker.
    fn alive(pid: i32) -> bool {
        // SAFETY: signal 0 only checks that the process exists.
        if unsafe { libc::kill(pid, 0) } == 0 {
            return true;
        }
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }

    fn ask_ssh_as() -> Result<SshAs> {
        print!(
            "SSH 以什么身份运行？[1] root（默认） [2] 当前用户 {} ",
            ssh::effective_user()
        );
        std::io::stdout().flush()?;
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        Ok(if line.trim() == "2" {
            SshAs::User
        } else {
            SshAs::Root
        })
    }

    /// Asks for the password in this terminal, so the worker can be started
    /// with `sudo -n` afterwards.
    fn sudo_validate() -> bool {
        println!("需要 root 权限，请输入 sudo 密码");
        Command::new("sudo")
            .arg("-v")
            .status()
            .is_ok_and(|status| status.success())
    }

    pub(super) fn launch(
        credential: Credential,
        ssh_only: bool,
        ssh_keys: Option<(PublicKey, PrivateKey)>,
        ssh_as: Option<SshAs>,
    ) -> Result<ExitCode> {
        let dir = run_dir()?;
        if let Some(pid) = read_pid(&dir.join(PID_FILE)).filter(|&pid| alive(pid)) {
            return Ok(fail(&format!(
                "已在后台运行（进程 {pid}），请先运行 varco stop"
            )));
        }
        // A virtual NIC needs root anyway, and then SSH runs as root too.
        let mut elevate = false;
        if !is_root() {
            let as_root = !ssh_only
                || match ssh_as {
                    Some(choice) => choice == SshAs::Root,
                    None => ask_ssh_as()? == SshAs::Root,
                };
            if as_root {
                if sudo_validate() {
                    elevate = true;
                } else if ssh_only {
                    println!(
                        "没有取得 root 权限，SSH 改为以当前用户 {} 身份运行",
                        ssh::effective_user()
                    );
                } else {
                    return Ok(fail("虚拟网卡模式需要 root 权限"));
                }
            }
        }
        if ssh_only {
            println!("仅 SSH 模式：不创建网卡，这台电脑不能访问其他成员");
        }
        let fingerprint = ssh_keys
            .as_ref()
            .map(|(_, host_key)| store::fingerprint(host_key.public_key()));
        let ssh = match ssh_keys {
            Some((allowed, host_key)) => Some(Keys {
                allowed_key: allowed.to_openssh().context("公钥无效")?,
                host_key: host_key
                    .to_openssh(LineEnding::LF)
                    .context("主机密钥无效")?
                    .to_string(),
            }),
            None => None,
        };
        let input = Input {
            code: credential.encode(),
            ssh_only,
            ssh,
        };

        let log_path = dir.join(LOG_FILE);
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&log_path)
            .with_context(|| format!("无法打开 {}", log_path.display()))?;
        let (mut link, worker_end) = UnixStream::pair()?;
        let exe = std::env::current_exe()?;
        let mut command = if elevate {
            // -b: sudo itself does not stay behind.
            let mut command = Command::new("sudo");
            command.args(["-n", "-b", "--"]).arg(&exe);
            command
        } else {
            Command::new(&exe)
        };
        command
            .arg("__worker")
            .arg("--run-dir")
            .arg(&dir)
            .stdin(Stdio::from(OwnedFd::from(worker_end)))
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log));
        command.spawn().context("无法启动后台进程")?;
        // Our copy of the worker's end goes with it, so its exit is seen as EOF.
        drop(command);

        writeln!(link, "{}", serde_json::to_string(&input)?)?;
        println!("连接中…");
        let mut line = String::new();
        BufReader::new(&link).read_line(&mut line)?;
        match serde_json::from_str::<Report>(&line) {
            Ok(Report::Connected { status, ssh }) => {
                if let Some(text) = describe(&status) {
                    println!("{text}");
                }
                if let Some(fingerprint) = fingerprint {
                    println!("SSH 主机指纹：{fingerprint}");
                }
                match ssh {
                    Some(SshState::Listening { ip, user, .. }) => {
                        println!("SSH 已开启：ssh -p {} {user}@{ip}", ssh::PORT);
                    }
                    Some(SshState::Error(message)) => println!("SSH 出错：{message}"),
                    _ => {}
                }
                println!("日志：{}", log_path.display());
                println!("已转入后台，结束请运行 varco stop");
                Ok(ExitCode::SUCCESS)
            }
            Ok(Report::Failed(message)) => Ok(fail(&message)),
            Err(_) => Ok(fail(&format!(
                "后台进程意外退出，详见 {}",
                log_path.display()
            ))),
        }
    }

    fn send_report(link: &mut UnixStream, report: &Report) -> Result<()> {
        writeln!(link, "{}", serde_json::to_string(report)?)?;
        Ok(())
    }

    /// Entry point of `varco __worker`. Its output goes to the log.
    pub async fn run_worker(run_dir: PathBuf) -> Result<ExitCode> {
        // SAFETY: setsid takes no arguments. It only fails for a process that
        // already leads a group, which a freshly spawned one does not.
        unsafe {
            libc::setsid();
        }
        let mut link = UnixStream::from(std::io::stdin().as_fd().try_clone_to_owned()?);
        let mut line = String::new();
        BufReader::new(&link).read_line(&mut line)?;
        let input: Input = serde_json::from_str(&line).context("后台进程收到的设置无效")?;
        let credential = Credential::parse(&input.code)?;
        let keys = match input.ssh {
            Some(keys) => Some((
                store::parse_public_key(&keys.allowed_key)?,
                PrivateKey::from_openssh(&keys.host_key)?,
            )),
            None => None,
        };
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let runtime = Handle::current();
        let connection = join(&runtime, credential, input.ssh_only);
        let has_ssh = keys.is_some();
        let ssh_service =
            keys.map(|(allowed, host_key)| connection.start_ssh(&runtime, allowed, host_key));

        let pid_path = run_dir.join(PID_FILE);
        let pid = std::process::id().to_string();
        let mut pending_report = Some(&mut link);
        let terminated = async move {
            terminate.recv().await;
        };
        let final_status = follow(connection, ssh_service, terminated, |status, ssh| {
            let ssh_ready =
                !has_ssh || matches!(ssh, Some(SshState::Listening { .. } | SshState::Error(_)));
            if status.phase != Phase::Connected || !ssh_ready {
                return true;
            }
            let Some(link) = pending_report.take() else {
                return true;
            };
            // Written before the report, so `varco stop` works once the parent says so.
            if let Err(error) = std::fs::write(&pid_path, format!("{pid}\n")) {
                let message = format!("无法写入 {}（{error}）", pid_path.display());
                let _ = send_report(link, &Report::Failed(message));
                return false;
            }
            let report = Report::Connected {
                status: status.clone(),
                ssh: ssh.cloned(),
            };
            // Nobody is waiting any more: the start was abandoned.
            send_report(link, &report).is_ok()
        })
        .await;
        if let Some(link) = pending_report {
            let reason = match &final_status.phase {
                Phase::Failed(reason) => reason.to_string(),
                _ => "已断开".to_owned(),
            };
            let _ = send_report(link, &Report::Failed(reason));
        }
        if std::fs::read_to_string(&pid_path).is_ok_and(|text| text.trim() == pid) {
            let _ = std::fs::remove_file(&pid_path);
        }
        Ok(if matches!(final_status.phase, Phase::Failed(_)) {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        })
    }

    fn wait_until_gone(pid: i32) -> bool {
        let started = Instant::now();
        while alive(pid) {
            if started.elapsed() >= STOP_WAIT {
                return false;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        true
    }

    /// Ends the worker as it would end on Ctrl+C. `pid` is given when this runs
    /// again under `sudo` for a root worker.
    pub fn stop(pid: Option<i32>) -> Result<ExitCode> {
        let sigterm = |pid: i32| {
            // SAFETY: kill takes plain values; pid is positive, so it names one process.
            if unsafe { libc::kill(pid, libc::SIGTERM) } == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        };
        if let Some(pid) = pid {
            sigterm(pid)?;
            return Ok(if wait_until_gone(pid) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            });
        }
        let pid_path = run_dir()?.join(PID_FILE);
        let Some(pid) = read_pid(&pid_path).filter(|&pid| alive(pid)) else {
            let _ = std::fs::remove_file(&pid_path);
            println!("没有在后台运行的 varco");
            return Ok(ExitCode::SUCCESS);
        };
        let stopped = match sigterm(pid) {
            Ok(()) => wait_until_gone(pid),
            Err(error) if error.raw_os_error() == Some(libc::EPERM) => {
                // A root worker: the same, as root.
                Command::new("sudo")
                    .arg("--")
                    .arg(std::env::current_exe()?)
                    .args(["stop", "--pid", &pid.to_string()])
                    .status()
                    .is_ok_and(|status| status.success())
            }
            Err(error) => return Err(error.into()),
        };
        if !stopped {
            println!("后台进程 {pid} 没有退出");
            return Ok(ExitCode::FAILURE);
        }
        let _ = std::fs::remove_file(&pid_path);
        println!("已停止");
        Ok(ExitCode::SUCCESS)
    }
}
