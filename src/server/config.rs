use crate::credential::{decode_secret, Secret};
use anyhow::{bail, ensure, Context, Result};
use ipnet::Ipv4Net;
use serde::Deserialize;
use std::collections::HashSet;
use std::path::Path;

/// Bounds the member list size and leaves room for at least two hosts.
pub const MIN_PREFIX: u8 = 20;
pub const MAX_PREFIX: u8 = 30;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    listen: String,
    public_addr: String,
    admin: Option<RawAdmin>,
    #[serde(default, rename = "network")]
    networks: Vec<RawNetwork>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAdmin {
    listen: String,
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNetwork {
    name: String,
    cidr: Ipv4Net,
    #[serde(default)]
    credentials: Vec<String>,
}

#[derive(Debug)]
pub struct Config {
    pub listen: String,
    pub public_addr: String,
    /// The console only runs when this is set.
    pub admin: Option<AdminConfig>,
    pub networks: Vec<NetworkConfig>,
}

#[derive(Clone)]
pub struct AdminConfig {
    pub listen: String,
    pub username: String,
    pub password: String,
}

// Hand-written so that a stray `{:?}` can never put the password in a log.
impl std::fmt::Debug for AdminConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminConfig")
            .field("listen", &self.listen)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct NetworkConfig {
    pub name: String,
    pub cidr: Ipv4Net,
    pub secrets: Vec<Secret>,
}

fn is_host_port(addr: &str) -> bool {
    addr.rsplit_once(':').is_some_and(|(host, port)| {
        !host.is_empty()
            && !host.contains(char::is_whitespace)
            && !host.contains("://")
            && port.parse::<u16>().is_ok_and(|port| port != 0)
    })
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("in config {}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let raw: RawConfig = toml::from_str(text)?;
        // A bad value here would only surface later, as issued codes that cannot connect.
        ensure!(
            is_host_port(&raw.public_addr),
            "public_addr must be host:port or ip:port, got {:?}",
            raw.public_addr
        );
        let mut names = HashSet::new();
        let mut seen_secrets = HashSet::new();
        let mut networks = Vec::with_capacity(raw.networks.len());
        for net in raw.networks {
            ensure!(
                names.insert(net.name.clone()),
                "duplicate network name {:?}",
                net.name
            );
            ensure!(
                (MIN_PREFIX..=MAX_PREFIX).contains(&net.cidr.prefix_len()),
                "network {:?}: prefix must be /{MIN_PREFIX} to /{MAX_PREFIX}",
                net.name
            );
            let mut secrets = Vec::with_capacity(net.credentials.len());
            for text in &net.credentials {
                // Exactly 32 random bytes are required, which rules out guessable
                // secrets and makes rate limiting unnecessary.
                let Some(secret) = decode_secret(text) else {
                    bail!(
                        "network {:?}: a credential is not a generated 32-byte secret; \
                         use `varco server gen-credential`",
                        net.name
                    );
                };
                ensure!(
                    seen_secrets.insert(secret),
                    "network {:?}: duplicate secret",
                    net.name
                );
                secrets.push(secret);
            }
            networks.push(NetworkConfig {
                name: net.name,
                cidr: net.cidr.trunc(),
                secrets,
            });
        }
        Ok(Self {
            listen: raw.listen,
            public_addr: raw.public_addr,
            admin: raw.admin.map(|admin| AdminConfig {
                listen: admin.listen,
                username: admin.username,
                password: admin.password,
            }),
            networks,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_network(body: &str) -> String {
        format!("listen = \"0.0.0.0:1\"\npublic_addr = \"h:1\"\n{body}")
    }
    const SECRET: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

    #[test]
    fn valid_config_loads() {
        let text = with_network(&format!(
            "[[network]]\nname = \"a\"\ncidr = \"10.0.0.0/24\"\ncredentials = [\"{SECRET}\"]\n"
        ));
        let config = Config::parse(&text).unwrap();
        assert_eq!(config.networks[0].secrets, vec![[1u8; 32]]);
    }

    #[test]
    fn public_addr_accepts_ip_or_domain_and_rejects_anything_else() {
        let with_addr = |addr: &str| format!("listen = \"0.0.0.0:1\"\npublic_addr = \"{addr}\"\n");
        for good in ["203.0.113.7:8443", "vpn.example.com:8443"] {
            let config = Config::parse(&with_addr(good)).unwrap();
            assert_eq!(config.public_addr, good);
        }
        for bad in [
            "203.0.113.7",
            "vpn.example.com",
            ":8443",
            "h:0",
            "h:70000",
            "https://h:443",
            "a b:1",
        ] {
            assert!(Config::parse(&with_addr(bad)).is_err(), "{bad} accepted");
        }
    }

    #[test]
    fn the_committed_example_config_stays_valid() {
        Config::parse(include_str!("../../config.example.toml")).unwrap();
    }

    #[test]
    fn admin_section_is_optional_and_takes_any_password() {
        assert!(Config::parse(&with_network("")).unwrap().admin.is_none());
        let text = with_network(
            "[admin]\nlisten = \"127.0.0.1:1\"\nusername = \"me\"\npassword = \"x\"\n",
        );
        let admin = Config::parse(&text).unwrap().admin.unwrap();
        assert_eq!(
            (admin.username.as_str(), admin.password.as_str()),
            ("me", "x")
        );
    }

    #[test]
    fn admin_section_must_be_complete_and_spelled_right() {
        for body in [
            "[admin]\nlisten = \"127.0.0.1:1\"\nusername = \"me\"\n",
            "[admin]\nlisten = \"127.0.0.1:1\"\nusername = \"me\"\npassword = \"x\"\nextra = 1\n",
        ] {
            assert!(Config::parse(&with_network(body)).is_err(), "{body}");
        }
    }

    #[test]
    fn debug_output_omits_the_admin_password() {
        let admin = AdminConfig {
            listen: "l".into(),
            username: "u".into(),
            password: "topsecret".into(),
        };
        assert!(!format!("{admin:?}").contains("topsecret"));
    }

    #[test]
    fn rejects_weak_secret_bad_prefix_and_duplicates() {
        let weak = "[[network]]\nname=\"a\"\ncidr=\"10.0.0.0/24\"\ncredentials=[\"hunter2\"]\n";
        assert!(Config::parse(&with_network(weak)).is_err());
        let wide = "[[network]]\nname=\"a\"\ncidr=\"10.0.0.0/8\"\n";
        assert!(Config::parse(&with_network(wide)).is_err());
        let dup_name = "[[network]]\nname=\"a\"\ncidr=\"10.0.0.0/24\"\n\
                        [[network]]\nname=\"a\"\ncidr=\"10.0.1.0/24\"\n";
        assert!(Config::parse(&with_network(dup_name)).is_err());
        let dup_secret = format!(
            "[[network]]\nname=\"a\"\ncidr=\"10.0.0.0/24\"\ncredentials=[\"{SECRET}\"]\n\
             [[network]]\nname=\"b\"\ncidr=\"10.0.1.0/24\"\ncredentials=[\"{SECRET}\"]\n"
        );
        assert!(Config::parse(&with_network(&dup_secret)).is_err());
    }
}
