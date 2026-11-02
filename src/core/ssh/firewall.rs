//! Windows files the mesh adapter under a network profile that blocks inbound
//! connections, so without a rule the server would listen and nobody could
//! connect. The rule covers only this port, on the mesh address, from the mesh.
use super::CREATE_NO_WINDOW;
use ipnet::Ipv4Net;
use std::net::Ipv4Addr;
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use tracing::warn;

const RULE_NAME: &str = "varco SSH";

fn netsh(args: &[String]) -> std::io::Result<bool> {
    Ok(Command::new("netsh")
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?
        .success())
}

fn delete_rule() -> std::io::Result<bool> {
    netsh(&[
        "advfirewall".into(),
        "firewall".into(),
        "delete".into(),
        "rule".into(),
        format!("name={RULE_NAME}"),
    ])
}

pub struct FirewallRule;

impl FirewallRule {
    pub fn open(ip: Ipv4Addr, cidr: Ipv4Net, port: u16) -> Self {
        // Whatever a crashed run left behind goes first.
        let _ = delete_rule();
        let added = netsh(&[
            "advfirewall".into(),
            "firewall".into(),
            "add".into(),
            "rule".into(),
            format!("name={RULE_NAME}"),
            "dir=in".into(),
            "action=allow".into(),
            "protocol=TCP".into(),
            format!("localport={port}"),
            format!("localip={ip}"),
            format!("remoteip={cidr}"),
            "profile=any".into(),
        ]);
        if !matches!(added, Ok(true)) {
            warn!("could not add the firewall rule; inbound SSH may be blocked");
        }
        Self
    }
}

impl Drop for FirewallRule {
    fn drop(&mut self) {
        let _ = delete_rule();
    }
}
