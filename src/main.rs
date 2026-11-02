// No extra console window when double-clicked. `--cli` attaches to one instead.
#![cfg_attr(all(windows, feature = "gui"), windows_subsystem = "windows")]

mod cli;
#[cfg(feature = "gui")]
mod gui;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "varco", version, about = "凭证接入的 TCP 组网工具")]
struct Args {
    /// 使用命令行而不是窗口
    #[arg(long)]
    cli: bool,
    /// 不创建虚拟网卡，只通过组网提供 SSH（命令行模式，需要 VARCO_SSH_PUBKEY）
    #[arg(long)]
    ssh_only: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// 运行服务端
    Server {
        #[arg(short, long, default_value = "/etc/varco/config.toml")]
        config: PathBuf,
        #[command(subcommand)]
        action: Option<ServerAction>,
    },
    /// 内部使用：窗口程序拉起的提权进程
    #[cfg(unix)]
    #[command(hide = true)]
    Helper {
        #[arg(long)]
        socket: PathBuf,
    },
}

#[derive(Subcommand)]
enum ServerAction {
    /// 为某个网络生成新凭证
    GenCredential {
        #[arg(long)]
        network: String,
    },
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
    ssh_only: bool,
) -> Result<ExitCode> {
    #[cfg(feature = "gui")]
    if !force_cli && std::env::var_os(cli::CREDENTIAL_ENV).is_none() {
        match gui::run(runtime.handle().clone()) {
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
    runtime.block_on(cli::run(ssh_only))
}

fn main() -> Result<ExitCode> {
    let args = Args::parse();
    let console_needed = args.command.is_some();
    if console_needed {
        use_console();
    }
    init_logging();
    // Built by hand because a GUI event loop has to own the main thread.
    let runtime = tokio::runtime::Runtime::new()?;
    match args.command {
        None => run_client(&runtime, args.cli || args.ssh_only, args.ssh_only),
        Some(Command::Server {
            config,
            action: None,
        }) => {
            runtime.block_on(varco::server::run_from_config(&config))?;
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Server {
            config,
            action: Some(ServerAction::GenCredential { network }),
        }) => {
            let (secret, credential) = varco::server::generate_credential(&config, &network)?;
            println!("1. 把下面这行加入配置里 {network} 的 credentials，然后重启服务端：");
            println!("   \"{secret}\"");
            println!("2. 把下面的 Code 发给对方：");
            println!("   {credential}");
            Ok(ExitCode::SUCCESS)
        }
        #[cfg(unix)]
        Some(Command::Helper { socket }) => {
            runtime.block_on(varco::core::helper::run_helper(
                &socket,
                varco::core::tun::TunFactory,
            ))?;
            Ok(ExitCode::SUCCESS)
        }
    }
}
