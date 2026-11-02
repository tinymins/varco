//! A real SSH client against the real server. Runs on every CI platform, so the
//! Windows ConPTY and cmd.exe paths are executed too.
use russh::client::{self, AuthResult, Handle};
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use varco::core::ssh::{self, SshState};
use varco::credential::generate_secret;

const WAIT: Duration = Duration::from_secs(30);

fn new_key() -> PrivateKey {
    PrivateKey::from(Ed25519Keypair::from_seed(&generate_secret()))
}

struct Accepting;

impl client::Handler for Accepting {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        _key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

// Only the Unix-only process tests use every field.
#[cfg_attr(windows, allow(dead_code))]
struct Server {
    addr: SocketAddr,
    user_key: PrivateKey,
    state: watch::Receiver<SshState>,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

async fn start() -> Server {
    let user_key = new_key();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (state_tx, state) = watch::channel(SshState::Starting);
    let (stop, stop_rx) = watch::channel(false);
    let config = Arc::new(ssh::server_config(new_key()));
    let task = tokio::spawn(ssh::serve(
        listener,
        "127.0.0.0/8".parse().unwrap(),
        Arc::new(user_key.public_key().clone()),
        config,
        state_tx,
        Ipv4Addr::LOCALHOST,
        stop_rx,
    ));
    Server {
        addr,
        user_key,
        state,
        stop,
        task,
    }
}

async fn connect(addr: SocketAddr) -> Handle<Accepting> {
    let config = Arc::new(client::Config::default());
    client::connect(config, addr, Accepting).await.unwrap()
}

async fn try_key(session: &mut Handle<Accepting>, key: &PrivateKey) -> bool {
    let key = PrivateKeyWithHashAlg::new(Arc::new(key.clone()), None);
    matches!(
        session.authenticate_publickey("anyone", key).await,
        Ok(AuthResult::Success)
    )
}

async fn login(server: &Server) -> Handle<Accepting> {
    let mut session = connect(server.addr).await;
    assert!(
        try_key(&mut session, &server.user_key).await,
        "the right key must work"
    );
    session
}

#[derive(Default, Debug)]
struct Output {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    code: Option<u32>,
}

async fn exec(session: &Handle<Accepting>, command: &str, stdin: Option<&[u8]>) -> Output {
    let mut channel = session.channel_open_session().await.unwrap();
    channel.exec(true, command).await.unwrap();
    if let Some(input) = stdin {
        channel.data(input).await.unwrap();
        channel.eof().await.unwrap();
    }
    let mut output = Output::default();
    tokio::time::timeout(WAIT, async {
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => output.stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, ext: 1 } => output.stderr.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => output.code = Some(exit_status),
                _ => {}
            }
        }
    })
    .await
    .expect("command did not finish");
    output
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_owned()
}

#[tokio::test]
async fn exec_returns_output_stderr_and_exit_code() {
    let server = start().await;
    let session = login(&server).await;
    let command = if cfg!(windows) {
        "echo to-out& echo to-err 1>&2& exit /b 7"
    } else {
        "echo to-out; echo to-err >&2; exit 7"
    };
    let output = exec(&session, command, None).await;
    assert_eq!(text(&output.stdout), "to-out");
    assert_eq!(text(&output.stderr), "to-err");
    assert_eq!(output.code, Some(7));
}

#[cfg(unix)]
#[tokio::test]
async fn piped_exec_is_binary_clean_and_passes_stdin_through() {
    let server = start().await;
    let session = login(&server).await;
    let input: Vec<u8> = (0..=255u8).cycle().take(300_000).collect();
    let output = exec(&session, "cat", Some(&input)).await;
    assert_eq!(output.stdout, input);
    assert_eq!(output.code, Some(0));
}

#[tokio::test]
async fn our_environment_is_not_inherited() {
    // SAFETY: only this test touches this variable, and it is read by child
    // processes, not concurrently through libc by this process.
    unsafe { std::env::set_var("VARCO_CREDENTIAL", "must-not-leak") };
    let server = start().await;
    let session = login(&server).await;
    let command = if cfg!(windows) {
        "echo [%VARCO_CREDENTIAL%]"
    } else {
        "echo \"[$VARCO_CREDENTIAL]\""
    };
    let output = exec(&session, command, None).await;
    assert!(
        !text(&output.stdout).contains("must-not-leak"),
        "{output:?}"
    );
}

#[tokio::test]
async fn wrong_key_password_and_none_are_all_refused() {
    let server = start().await;
    let mut session = connect(server.addr).await;
    assert!(!try_key(&mut session, &new_key()).await);
    let refused = !matches!(
        session.authenticate_password("anyone", "password").await,
        Ok(AuthResult::Success)
    );
    assert!(refused, "password login succeeded");

    let mut session = connect(server.addr).await;
    assert!(!matches!(
        session.authenticate_none("anyone").await,
        Ok(AuthResult::Success)
    ));
    let opened = session.channel_open_session().await;
    assert!(opened.is_err(), "a channel opened without logging in");
}

#[tokio::test]
async fn too_many_wrong_keys_end_the_connection() {
    let server = start().await;
    let mut session = connect(server.addr).await;
    for _ in 0..4 {
        let _ = try_key(&mut session, &new_key()).await;
    }
    let right = try_key(&mut session, &server.user_key).await;
    assert!(!right, "the attempt limit did not apply");
}

async fn read_until(channel: &mut russh::Channel<client::Msg>, needle: &str) -> String {
    let mut seen = Vec::new();
    let found = tokio::time::timeout(WAIT, async {
        while let Some(message) = channel.wait().await {
            if let ChannelMsg::Data { data } = message {
                seen.extend_from_slice(&data);
                if String::from_utf8_lossy(&seen).contains(needle) {
                    return true;
                }
            }
        }
        false
    })
    .await;
    assert!(
        matches!(found, Ok(true)),
        "did not see {needle:?} in {:?}",
        String::from_utf8_lossy(&seen)
    );
    String::from_utf8_lossy(&seen).into_owned()
}

#[tokio::test]
async fn interactive_shell_runs_in_a_pty() {
    let server = start().await;
    let session = login(&server).await;
    let mut channel = session.channel_open_session().await.unwrap();
    channel
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    channel.request_shell(true).await.unwrap();
    // Assembled by the shell, so plain echo of the input cannot satisfy the check.
    let line: &[u8] = if cfg!(windows) {
        b"Write-Output ('mark' + 'er-42')\r\n"
    } else {
        b"echo mark''er-42\n"
    };
    channel.data(line).await.unwrap();
    read_until(&mut channel, "marker-42").await;
}

#[cfg(unix)]
#[tokio::test]
async fn window_size_reaches_the_pty() {
    let server = start().await;
    let session = login(&server).await;
    let mut channel = session.channel_open_session().await.unwrap();
    channel
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    channel.request_shell(true).await.unwrap();
    channel.window_change(133, 47, 0, 0).await.unwrap();
    channel.data(&b"stty size\n"[..]).await.unwrap();
    read_until(&mut channel, "47 133").await;
}

#[tokio::test]
async fn sftp_round_trip() {
    let server = start().await;
    let session = login(&server).await;
    let channel = session.channel_open_session().await.unwrap();
    channel.request_subsystem(true, "sftp").await.unwrap();
    let sftp = russh_sftp::client::SftpSession::new(channel.into_stream())
        .await
        .unwrap();

    let dir = std::env::temp_dir().join(format!("varco-sftp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let wire = |path: &std::path::Path| {
        let text = path.to_string_lossy().replace('\\', "/");
        if text.starts_with('/') {
            text
        } else {
            format!("/{text}")
        }
    };
    let path = wire(&dir.join("blob.bin"));
    let payload: Vec<u8> = (0..=255u8).cycle().take(1_000_000).collect();

    let mut file = sftp.create(&path).await.unwrap();
    file.write_all(&payload).await.unwrap();
    file.shutdown().await.unwrap();
    assert_eq!(
        std::fs::read(dir.join("blob.bin")).unwrap(),
        payload,
        "upload differs on disk"
    );

    let mut back = Vec::new();
    sftp.open(&path)
        .await
        .unwrap()
        .read_to_end(&mut back)
        .await
        .unwrap();
    assert_eq!(back, payload, "download differs");

    assert_eq!(
        sftp.metadata(&path).await.unwrap().len(),
        payload.len() as u64
    );
    let names: Vec<String> = sftp
        .read_dir(wire(&dir))
        .await
        .unwrap()
        .map(|entry| entry.file_name())
        .collect();
    assert!(names.contains(&"blob.bin".to_owned()), "{names:?}");
    let home = sftp.canonicalize(".").await.unwrap();
    assert!(!home.is_empty());

    let renamed = wire(&dir.join("renamed.bin"));
    sftp.rename(&path, &renamed).await.unwrap();
    sftp.remove_file(&renamed).await.unwrap();
    assert!(!dir.join("renamed.bin").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn local_forward_reaches_loopback_only() {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut socket, _) = echo.accept().await.unwrap();
        let mut buf = [0u8; 4];
        socket.read_exact(&mut buf).await.unwrap();
        socket.write_all(&buf).await.unwrap();
    });

    let server = start().await;
    let session = login(&server).await;
    let channel = session
        .channel_open_direct_tcpip("127.0.0.1", port as u32, "x", 1)
        .await
        .unwrap();
    let mut stream = channel.into_stream();
    stream.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    tokio::time::timeout(WAIT, stream.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"ping");

    for host in ["192.0.2.1", "10.77.1.1", "example.com", "127.0.0.2"] {
        let opened = session.channel_open_direct_tcpip(host, 80, "x", 1).await;
        assert!(opened.is_err(), "forward to {host} was allowed");
    }
}

#[tokio::test]
async fn remote_forward_is_refused() {
    let server = start().await;
    let session = login(&server).await;
    assert!(session.tcpip_forward("127.0.0.1", 0).await.is_err());
}

#[tokio::test]
async fn connection_count_follows_logins() {
    let mut server = start().await;
    let session = login(&server).await;
    let count = |n: usize| move |s: &SshState| matches!(s, SshState::Listening { connections, .. } if *connections == n);
    tokio::time::timeout(WAIT, server.state.wait_for(count(1)))
        .await
        .unwrap()
        .unwrap();
    session
        .disconnect(Disconnect::ByApplication, "", "en")
        .await
        .unwrap();
    tokio::time::timeout(WAIT, server.state.wait_for(count(0)))
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn connections_beyond_the_limit_are_dropped() {
    let server = start().await;
    let mut held = Vec::new();
    for _ in 0..8 {
        held.push(login(&server).await);
    }
    let config = Arc::new(client::Config::default());
    let ninth = tokio::time::timeout(WAIT, client::connect(config, server.addr, Accepting))
        .await
        .unwrap();
    assert!(ninth.is_err(), "a ninth connection was accepted");
    drop(held);
}

#[cfg(unix)]
fn alive(pid: i32) -> bool {
    // SAFETY: signal 0 only checks for existence.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// The promise behind the off switch: nothing keeps running on this machine.
#[cfg(unix)]
#[tokio::test]
async fn stopping_ends_sessions_and_their_processes() {
    let server = start().await;
    let session = login(&server).await;

    let mut piped = session.channel_open_session().await.unwrap();
    piped
        .exec(true, "sh -c 'echo $$; sleep 300' & echo started; wait")
        .await
        .unwrap();
    let seen = read_until(&mut piped, "\n").await;
    let seen = seen + &read_until(&mut piped, "\n").await;
    let pid: i32 = seen
        .split_whitespace()
        .find_map(|word| word.parse().ok())
        .expect("pid");
    assert!(alive(pid));

    let mut pty = session.channel_open_session().await.unwrap();
    pty.request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    pty.request_shell(true).await.unwrap();
    // The quotes keep the terminal's echo of this line from matching below.
    pty.data(&b"echo pid=$$-en''d\n"[..]).await.unwrap();
    let seen = read_until(&mut pty, "-end\r\n").await;
    let shell_pid: i32 = seen
        .split("pid=")
        .filter_map(|part| part.split("-end").next()?.parse().ok())
        .next()
        .expect("shell pid");
    assert!(alive(shell_pid));

    server.stop.send(true).unwrap();
    tokio::time::timeout(WAIT, server.task)
        .await
        .expect("server did not stop")
        .unwrap();

    let gone = tokio::time::timeout(WAIT, async {
        while alive(pid) || alive(shell_pid) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(gone.is_ok(), "processes outlived the server");

    TcpListener::bind(server.addr)
        .await
        .expect("port was not released");
}

/// OpenSSH's own client, which uses the protocol differently from russh's:
/// pipelined out-of-order requests and its own idea of what a server must do.
#[cfg(unix)]
#[tokio::test]
async fn openssh_scp_round_trip() {
    use russh::keys::ssh_key::LineEnding;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;
    if Command::new("scp").arg("-V").output().is_err() {
        eprintln!("skipped: no scp on this machine");
        return;
    }
    let server = start().await;
    let dir = std::env::temp_dir().join(format!("varco-scp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let identity = dir.join("id");
    std::fs::write(
        &identity,
        server
            .user_key
            .to_openssh(LineEnding::LF)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    std::fs::set_permissions(&identity, std::fs::Permissions::from_mode(0o600)).unwrap();

    // Not a multiple of any buffer size, and large enough to need many requests.
    let payload: Vec<u8> = (0..3_000_017u32).map(|i| (i % 251) as u8).collect();
    let (up, landed, back) = (dir.join("up"), dir.join("landed"), dir.join("back"));
    std::fs::write(&up, &payload).unwrap();

    let port = server.addr.port().to_string();
    let run = |from: String, to: String| {
        let identity = identity.clone();
        let port = port.clone();
        tokio::task::spawn_blocking(move || {
            Command::new("scp")
                .args(["-i", identity.to_str().unwrap(), "-P", &port])
                .args([
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                ])
                .args(["-o", "BatchMode=yes", "-o", "LogLevel=DEBUG"])
                .args([from, to])
                .output()
                .unwrap()
        })
    };
    let remote = |path: &std::path::Path| format!("root@127.0.0.1:{}", path.display());

    let upload = run(up.display().to_string(), remote(&landed))
        .await
        .unwrap();
    assert!(
        upload.status.success(),
        "upload: {}",
        String::from_utf8_lossy(&upload.stderr)
    );
    assert_eq!(
        std::fs::read(&landed).unwrap(),
        payload,
        "uploaded file differs"
    );

    let download = run(remote(&landed), back.display().to_string())
        .await
        .unwrap();
    assert!(
        download.status.success(),
        "download: {}",
        String::from_utf8_lossy(&download.stderr)
    );
    assert_eq!(
        std::fs::read(&back).unwrap(),
        payload,
        "downloaded file differs"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
