// No extra console window when double-clicked. `--cli` attaches to one instead.
#![cfg_attr(all(windows, feature = "gui"), windows_subsystem = "windows")]

mod cli;
#[cfg(feature = "gui")]
mod gui;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use russh::keys::PublicKey;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use varco::core::ssh::store;
use varco::credential::compose;
use varco::launch::{self, Launch, Options};

#[derive(Parser)]
#[command(name = "varco", version, about = "凭证接入的 TCP 组网工具")]
struct Args {
    /// 使用命令行而不是窗口
    #[arg(long)]
    cli: bool,
    /// 启动后直接加入组网，不用再粘贴
    #[arg(long, value_name = "CODE")]
    code: Option<String>,
    /// 改用这个服务端地址，代替 Code 里的（证书校验不变）
    #[arg(long, value_name = "HOST")]
    server: Option<String>,
    /// 改用这个服务端端口，代替 Code 里的
    #[arg(long, value_name = "PORT")]
    port: Option<u16>,
    /// 允许登录内置 SSH 的公钥，加入后自动开启 SSH
    #[arg(long, value_name = "KEY")]
    ssh_pubkey: Option<String>,
    /// 不创建虚拟网卡，只通过组网提供 SSH。传了公钥时默认开启，可用 --ssh-only=false 关闭
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true", value_name = "BOOL")]
    ssh_only: Option<bool>,
    /// 仅 SSH 模式转入后台时 SSH 以谁的身份运行：root 或 user（当前用户）。不传时询问，默认 root
    #[cfg(unix)]
    #[arg(long, value_enum, value_name = "WHO")]
    ssh_as: Option<cli::SshAs>,
    /// 命令行版连上后留在前台，不转入后台
    #[cfg(unix)]
    #[arg(long)]
    foreground: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// 处理已有的 Code（离线，不需要服务端）
    Code {
        #[command(subcommand)]
        action: CodeAction,
    },
    /// 运行服务端，打开管理后台完成初始化
    Server {
        /// 数据目录，也可用环境变量 VARCO_DATA_DIR
        #[arg(long, value_name = "DIR")]
        data_dir: Option<PathBuf>,
        /// 管理后台监听地址，也可用环境变量 VARCO_ADMIN_LISTEN
        #[arg(long, value_name = "ADDR")]
        admin_listen: Option<String>,
        #[command(subcommand)]
        action: Option<ServerAction>,
    },
    /// 结束在后台运行的命令行客户端
    #[cfg(unix)]
    Stop {
        #[arg(long, hide = true, value_parser = clap::value_parser!(i32).range(1..))]
        pid: Option<i32>,
    },
    /// 内部使用：窗口程序拉起的提权进程
    #[cfg(unix)]
    #[command(hide = true)]
    Helper {
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        ssh_only: bool,
    },
    /// 内部使用：命令行客户端转入后台后的进程
    #[cfg(unix)]
    #[command(name = "__worker", hide = true)]
    Worker {
        #[arg(long)]
        run_dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum ServerAction {
    /// 把 root 的密码恢复成默认值，下次登录时必须修改
    ResetRootPassword,
}

#[derive(Subcommand)]
enum CodeAction {
    /// 把 SSH 公钥编进已有的 Code，不用改服务端配置
    AddSshKey {
        #[arg(long, value_name = "CODE")]
        code: String,
        /// 文件路径或公钥文本
        #[arg(long, value_name = "KEY")]
        ssh_pubkey: String,
    },
}

/// A path or the key itself. Never echoes the input, which could be a private key
/// passed by mistake.
fn read_public_key(argument: &str) -> Result<PublicKey> {
    let path = Path::new(argument);
    let text = if path.is_file() {
        std::fs::read_to_string(path).with_context(|| format!("无法读取 {}", path.display()))?
    } else {
        argument.to_owned()
    };
    Ok(store::parse_public_key(&text)?)
}

fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,varco=info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

#[cfg(all(windows, feature = "gui"))]
fn use_console() {
    use windows_sys::Win32::System::Console::{AllocConsole, AttachConsole, ATTACH_PARENT_PROCESS};
    // SAFETY: both calls take plain values and report failure by return value,
    // which is harmless here: output is simply not shown.
    unsafe {
        if AttachConsole(ATTACH_PARENT_PROCESS) == 0 {
            AllocConsole();
        }
    }
}

#[cfg(not(all(windows, feature = "gui")))]
fn use_console() {}

fn run_client(
    runtime: &tokio::runtime::Runtime,
    force_cli: bool,
    launch: Launch,
    #[cfg(unix)] start: cli::Start,
) -> Result<ExitCode> {
    #[cfg(feature = "gui")]
    if !force_cli && std::env::var_os(cli::CREDENTIAL_ENV).is_none() {
        match gui::run(runtime.handle().clone(), &launch) {
            Ok(()) => return Ok(ExitCode::SUCCESS),
            Err(error) => {
                use_console();
                eprintln!("无法打开窗口（{error}），改用命令行");
            }
        }
    } else {
        use_console();
    }
    #[cfg(not(feature = "gui"))]
    let _ = force_cli;
    runtime.block_on(cli::run(
        launch,
        #[cfg(unix)]
        start,
    ))
}

fn main() -> Result<ExitCode> {
    let args = Args::try_parse().unwrap_or_else(|error| {
        // A window program has nowhere to print this otherwise, and would seem
        // to do nothing at all.
        use_console();
        error.exit()
    });
    let console_needed = args.command.is_some();
    if console_needed {
        use_console();
    }
    init_logging();
    // Built by hand because a GUI event loop has to own the main thread.
    let runtime = tokio::runtime::Runtime::new()?;
    match args.command {
        None => {
            let options = Options {
                code: args.code,
                server: args.server,
                port: args.port,
                ssh_pubkey: args.ssh_pubkey,
                ssh_only: args.ssh_only,
            };
            let environment = Options {
                code: std::env::var(cli::CREDENTIAL_ENV).ok(),
                ssh_pubkey: std::env::var(cli::SSH_PUBKEY_ENV).ok(),
                ..Options::default()
            };
            run_client(
                &runtime,
                args.cli,
                launch::load(options, environment),
                #[cfg(unix)]
                cli::Start {
                    foreground: args.foreground,
                    ssh_as: args.ssh_as,
                },
            )
        }
        Some(Command::Server {
            data_dir,
            admin_listen,
            action,
        }) => {
            let data_dir = data_dir
                .or_else(|| std::env::var_os("VARCO_DATA_DIR").map(PathBuf::from))
                .unwrap_or_else(varco::server::default_data_dir);
            if matches!(action, Some(ServerAction::ResetRootPassword)) {
                varco::server::open_store(&data_dir)?.reset_root_password()?;
                println!("root 的密码已恢复为默认值，下次登录时必须修改。");
                return Ok(ExitCode::SUCCESS);
            }
            let admin_listen = admin_listen
                .or_else(|| std::env::var("VARCO_ADMIN_LISTEN").ok())
                .unwrap_or_else(|| varco::server::DEFAULT_ADMIN_LISTEN.to_owned());
            runtime.block_on(varco::server::run(&data_dir, &admin_listen))?;
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Code {
            action: CodeAction::AddSshKey { code, ssh_pubkey },
        }) => {
            let key = read_public_key(&ssh_pubkey)?;
            let text = key.to_openssh().context("公钥无效")?;
            let composed = compose(&code, &text)?;
            println!("{}", composed.code);
            println!(
                "服务端 {}，公钥 {}",
                composed.server, composed.key_fingerprint
            );
            println!("对方点确认后，持有这把私钥的人能远程控制对方电脑。");
            Ok(ExitCode::SUCCESS)
        }
        #[cfg(unix)]
        Some(Command::Stop { pid }) => cli::stop(pid),
        #[cfg(unix)]
        Some(Command::Helper { socket, ssh_only }) => {
            use varco::core::helper::run_helper;
            if ssh_only {
                let factory = varco::core::netstack::NetstackFactory::new().0;
                runtime.block_on(run_helper(&socket, factory))?;
            } else {
                runtime.block_on(run_helper(&socket, varco::core::tun::TunFactory))?;
            }
            Ok(ExitCode::SUCCESS)
        }
        #[cfg(unix)]
        Some(Command::Worker { run_dir }) => runtime.block_on(cli::run_worker(run_dir)),
    }
}
