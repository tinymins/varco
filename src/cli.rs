//! Terminal front end: also the fallback when no window can be shown.
use anyhow::Result;
use std::io::{IsTerminal, Write};
use varco::core::backend;
use varco::core::engine::{Phase, Status};
use varco::core::error::FailReason;
use varco::credential::Credential;

pub const CREDENTIAL_ENV: &str = "VARCO_CREDENTIAL";

fn read_code() -> Result<String> {
    if let Ok(code) = std::env::var(CREDENTIAL_ENV) {
        return Ok(code);
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

pub async fn run() -> Result<std::process::ExitCode> {
    let credential = match Credential::parse(&read_code()?) {
        Ok(credential) => credential,
        Err(_) => {
            println!("失败：{}", FailReason::BadCredential);
            wait_for_key_if_interactive();
            return Ok(std::process::ExitCode::FAILURE);
        }
    };
    // The CLI always runs in-process: its user can see and answer `sudo` themselves.
    let connection = backend::start_in_process(&tokio::runtime::Handle::current(), credential);
    let mut status_rx = connection.status.clone();
    let stop_tx = connection.stop;

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
        tokio::select! {
            changed = status_rx.changed() => if changed.is_err() { break },
            _ = tokio::signal::ctrl_c() => { let _ = stop_tx.send(true); }
        }
    }
    let final_status = status_rx.borrow().clone();
    if let Some(line) = describe(&final_status) {
        if Some(&line) != last_line.as_ref() {
            println!("{line}");
        }
    }
    if matches!(final_status.phase, Phase::Failed(_)) {
        wait_for_key_if_interactive();
        return Ok(std::process::ExitCode::FAILURE);
    }
    Ok(std::process::ExitCode::SUCCESS)
}
