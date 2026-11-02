//! The string a user pastes: it carries the server address, the server key
//! pin and the secret, so the binary itself holds no deployment configuration.
//!
//! `varco://` followed by base64url of a binary form, kept as short as possible
//! because people copy it through chat windows:
//!
//! ```text
//! [pin 32][secret 32][address][key-value pairs...][checksum 4]
//! address:  [0][IPv4 4][port 2]  or  [host length][host][port 2]
//! pair:     [key 1][value length][value]
//! ```
//!
//! Lengths are LEB128. Unknown keys are skipped, so new optional settings need no
//! version number.
use crate::core::ssh::store;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use rand::RngCore;
use russh::keys::ssh_key::public::{Ed25519PublicKey, KeyData};
use russh::keys::PublicKey;
use sha2::{Digest, Sha256};
use std::fmt;
use std::net::Ipv4Addr;
use subtle::ConstantTimeEq;

const PREFIX: &str = "varco://";
const CHECKSUM_LEN: usize = 4;
const KEY_SSH_ED25519: u8 = 1;
const KEY_SSH_OTHER: u8 = 2;

pub type Secret = [u8; 32];
pub type Pin = [u8; 32];

#[derive(Clone, PartialEq, Eq)]
pub struct Credential {
    pub server: String,
    pub pin: Pin,
    pub secret: Secret,
    /// Who may log in over SSH once this Code is used. Holds no comment: a comment
    /// is free text that could only mislead the person pasting the Code.
    pub ssh_pubkey: Option<PublicKey>,
}

// Hand-written so that a stray `{:?}` can never put the secret in a log.
impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("server", &self.server)
            .field("secret", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("missing varco:// prefix")]
    Prefix,
    #[error("not valid base64url")]
    Encoding,
    #[error("too short")]
    Truncated,
    #[error("checksum mismatch")]
    Checksum,
    #[error("server address is invalid")]
    Server,
    #[error("a setting is malformed")]
    Setting,
}

fn write_len(out: &mut Vec<u8>, mut len: usize) {
    while len >= 0x80 {
        out.push((len & 0x7f) as u8 | 0x80);
        len >>= 7;
    }
    out.push(len as u8);
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], ParseError> {
        if len > self.0.len() {
            return Err(ParseError::Truncated);
        }
        let (taken, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(taken)
    }

    fn len(&mut self) -> Result<usize, ParseError> {
        let mut value = 0usize;
        // Three bytes reach 2 MiB, far beyond any value this format carries.
        for shift in [0, 7, 14] {
            let byte = self.take(1)?[0];
            value |= usize::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(ParseError::Setting)
    }

    fn port(&mut self) -> Result<u16, ParseError> {
        let bytes = self.take(2)?;
        match u16::from_be_bytes([bytes[0], bytes[1]]) {
            0 => Err(ParseError::Server),
            port => Ok(port),
        }
    }
}

fn write_address(out: &mut Vec<u8>, server: &str) {
    let (host, port): (&str, u16) = match server.rsplit_once(':') {
        Some((host, port)) => (host, port.parse().unwrap_or(0)),
        None => (server, 0),
    };
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        out.push(0);
        out.extend_from_slice(&ip.octets());
    } else {
        write_len(out, host.len());
        out.extend_from_slice(host.as_bytes());
    }
    out.extend_from_slice(&port.to_be_bytes());
}

fn read_address(reader: &mut Reader<'_>) -> Result<String, ParseError> {
    let server = match reader.len()? {
        0 => {
            let octets: [u8; 4] = reader.take(4)?.try_into().expect("length requested");
            format!("{}:{}", Ipv4Addr::from(octets), reader.port()?)
        }
        len => {
            let host = std::str::from_utf8(reader.take(len)?).map_err(|_| ParseError::Server)?;
            format!("{host}:{}", reader.port()?)
        }
    };
    if server_is_valid(&server) {
        Ok(server)
    } else {
        Err(ParseError::Server)
    }
}

fn write_pair(out: &mut Vec<u8>, key: u8, value: &[u8]) {
    out.push(key);
    write_len(out, value.len());
    out.extend_from_slice(value);
}

fn write_ssh_key(out: &mut Vec<u8>, key: &PublicKey) {
    if let Some(ed25519) = key.key_data().ed25519() {
        write_pair(out, KEY_SSH_ED25519, &ed25519.0);
    } else {
        let bytes = key.to_bytes().expect("a parsed key can be written back");
        write_pair(out, KEY_SSH_OTHER, &bytes);
    }
}

fn read_ssh_key(key: u8, value: &[u8]) -> Result<PublicKey, ParseError> {
    if key == KEY_SSH_ED25519 {
        let raw: [u8; 32] = value.try_into().map_err(|_| ParseError::Setting)?;
        return Ok(KeyData::Ed25519(Ed25519PublicKey(raw)).into());
    }
    PublicKey::from_bytes(value).map_err(|_| ParseError::Setting)
}

fn server_is_valid(server: &str) -> bool {
    server
        .rsplit_once(':')
        .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok())
}

/// Bare IPv6 addresses gain the brackets a `host:port` needs. Anything else with a
/// colon or a space is a mistake, such as a port written into the host setting.
fn normalize_host(host: &str) -> Option<String> {
    let host = host.trim();
    if host.is_empty() || host.contains(|c: char| c.is_whitespace() || c == '/') {
        return None;
    }
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return inner
            .parse::<std::net::Ipv6Addr>()
            .ok()
            .map(|_| host.to_owned());
    }
    if host.contains(':') {
        return host
            .parse::<std::net::Ipv6Addr>()
            .ok()
            .map(|_| format!("[{host}]"));
    }
    Some(host.to_owned())
}

fn checksum(body: &[u8]) -> [u8; CHECKSUM_LEN] {
    let digest = Sha256::digest(body);
    [digest[0], digest[1], digest[2], digest[3]]
}

impl Credential {
    pub fn encode(&self) -> String {
        let mut body = Vec::with_capacity(128 + self.server.len());
        body.extend_from_slice(&self.pin);
        body.extend_from_slice(&self.secret);
        write_address(&mut body, &self.server);
        if let Some(key) = &self.ssh_pubkey {
            write_ssh_key(&mut body, key);
        }
        let sum = checksum(&body);
        body.extend_from_slice(&sum);
        format!("{PREFIX}{}", B64.encode(body))
    }

    pub fn parse(input: &str) -> Result<Self, ParseError> {
        let encoded = input
            .trim()
            .strip_prefix(PREFIX)
            .ok_or(ParseError::Prefix)?;
        let raw = B64.decode(encoded).map_err(|_| ParseError::Encoding)?;
        if raw.len() < 64 + CHECKSUM_LEN {
            return Err(ParseError::Truncated);
        }
        let (body, sum) = raw.split_at(raw.len() - CHECKSUM_LEN);
        if checksum(body) != sum {
            return Err(ParseError::Checksum);
        }
        let mut reader = Reader(body);
        let pin = reader.take(32)?.try_into().expect("length requested");
        let secret = reader.take(32)?.try_into().expect("length requested");
        let server = read_address(&mut reader)?;
        let mut ssh_pubkey = None;
        let mut seen = Vec::new();
        while !reader.0.is_empty() {
            let key = reader.take(1)?[0];
            let len = reader.len()?;
            let value = reader.take(len)?;
            if seen.contains(&key) {
                return Err(ParseError::Setting);
            }
            seen.push(key);
            if key == KEY_SSH_ED25519 || key == KEY_SSH_OTHER {
                if ssh_pubkey.is_some() {
                    return Err(ParseError::Setting);
                }
                ssh_pubkey = Some(read_ssh_key(key, value)?);
            }
        }
        Ok(Self {
            server,
            pin,
            secret,
            ssh_pubkey,
        })
    }

    /// Lets whoever holds the matching private key log in. Replaces any key
    /// already in the Code. The server never sees this, so no restart is needed.
    pub fn with_ssh_pubkey(mut self, mut key: PublicKey) -> Self {
        key.set_comment("");
        self.ssh_pubkey = Some(key);
        self
    }

    pub fn ssh_pubkey_text(&self) -> Option<String> {
        self.ssh_pubkey
            .as_ref()
            .and_then(|key| key.to_openssh().ok())
    }

    /// Points at another address. The pin stays, so a wrong address can only fail
    /// to connect: it can never be used to receive the secret.
    pub fn with_address(
        mut self,
        host: Option<&str>,
        port: Option<u16>,
    ) -> Result<Self, ParseError> {
        if port == Some(0) {
            return Err(ParseError::Server);
        }
        let (current_host, current_port) =
            self.server.rsplit_once(':').ok_or(ParseError::Server)?;
        let host = match host {
            Some(host) => normalize_host(host).ok_or(ParseError::Server)?,
            None => current_host.to_owned(),
        };
        let port = port.map_or_else(|| current_port.to_owned(), |port| port.to_string());
        let server = format!("{host}:{port}");
        if !server_is_valid(&server) {
            return Err(ParseError::Server);
        }
        self.server = server;
        Ok(self)
    }
}

/// A Code that also grants SSH, ready to hand to someone.
pub struct Composed {
    pub code: String,
    pub server: String,
    pub key_fingerprint: String,
    pub replaced_key: bool,
}

/// Works entirely offline: the server only ever checks the secret inside.
pub fn compose(code: &str, key: &str) -> Result<Composed, ComposeError> {
    let credential = Credential::parse(code).map_err(|_| ComposeError::Code)?;
    let key = store::parse_public_key(key).map_err(ComposeError::Key)?;
    let replaced_key = credential.ssh_pubkey.is_some();
    let key_fingerprint = store::fingerprint(&key);
    let server = credential.server.clone();
    Ok(Composed {
        code: credential.with_ssh_pubkey(key).encode(),
        server,
        key_fingerprint,
        replaced_key,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum ComposeError {
    Code,
    Key(store::KeyError),
}

impl fmt::Display for ComposeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Code => write!(f, "Code 格式不正确，请检查是否复制完整"),
            Self::Key(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ComposeError {}

pub fn generate_secret() -> Secret {
    let mut secret = [0u8; 32];
    rand::rng().fill_bytes(&mut secret);
    secret
}

pub fn encode_secret(secret: &Secret) -> String {
    B64.encode(secret)
}

pub fn decode_secret(text: &str) -> Option<Secret> {
    B64.decode(text.trim()).ok()?.try_into().ok()
}

pub fn secret_eq(a: &Secret, b: &Secret) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Credential {
        Credential {
            server: "203.0.113.7:8443".into(),
            pin: [7; 32],
            secret: [9; 32],
            ssh_pubkey: None,
        }
    }

    const ED25519_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl me@host";

    fn ed25519() -> PublicKey {
        store::parse_public_key(ED25519_KEY).unwrap()
    }

    fn with_pairs(pairs: &[(u8, &[u8])]) -> String {
        let mut body = Vec::new();
        body.extend_from_slice(&[7; 32]);
        body.extend_from_slice(&[9; 32]);
        write_address(&mut body, "203.0.113.7:8443");
        for (key, value) in pairs {
            write_pair(&mut body, *key, value);
        }
        let sum = checksum(&body);
        body.extend_from_slice(&sum);
        format!("{PREFIX}{}", B64.encode(body))
    }

    #[test]
    fn stays_short() {
        assert_eq!(sample().encode().len(), 108);
        assert_eq!(sample().with_ssh_pubkey(ed25519()).encode().len(), 154);
    }

    #[test]
    fn every_address_form_round_trips() {
        for server in [
            "203.0.113.7:8443",
            "vpn.example.com:443",
            "[2001:db8::1]:8443",
            "localhost:1",
        ] {
            let credential = Credential {
                server: server.into(),
                ..sample()
            };
            let parsed = Credential::parse(&credential.encode()).unwrap();
            assert_eq!(parsed.server, server);
        }
    }

    #[test]
    fn ssh_key_round_trips_and_loses_its_comment() {
        let parsed = Credential::parse(&sample().with_ssh_pubkey(ed25519()).encode()).unwrap();
        let key = parsed.ssh_pubkey.clone().unwrap();
        assert_eq!(key.key_data(), ed25519().key_data());
        assert!(!parsed.ssh_pubkey_text().unwrap().contains("me@host"));
        assert_eq!(parsed.pin, sample().pin);
        assert_eq!(parsed.secret, sample().secret);
    }

    #[test]
    fn other_key_types_round_trip() {
        let ecdsa = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHkbe7gyLwJD1nv2XyAsLKO1Oqp9Vd1AcTaiYxKFkbYtWNdjfdjSjfmoSYqEIkuBVdTXrLeNmv4DEcPRHW7GN7U=";
        let key = store::parse_public_key(ecdsa).unwrap();
        let parsed = Credential::parse(&sample().with_ssh_pubkey(key.clone()).encode()).unwrap();
        assert_eq!(parsed.ssh_pubkey.unwrap().key_data(), key.key_data());
    }

    #[test]
    fn unknown_settings_are_skipped() {
        let parsed = Credential::parse(&with_pairs(&[(200, b"future")])).unwrap();
        assert_eq!(parsed, sample());
    }

    #[test]
    fn malformed_settings_are_refused() {
        let key = [1u8; 32];
        for pairs in [
            vec![(KEY_SSH_ED25519, &key[..31])],
            vec![(KEY_SSH_OTHER, &b"junk"[..])],
            vec![(KEY_SSH_ED25519, &key[..]), (KEY_SSH_ED25519, &key[..])],
            vec![(200, &b"a"[..]), (200, &b"b"[..])],
        ] {
            assert_eq!(
                Credential::parse(&with_pairs(&pairs)),
                Err(ParseError::Setting)
            );
        }
    }

    #[test]
    fn a_value_running_past_the_end_is_refused() {
        let mut body = Vec::new();
        body.extend_from_slice(&[7; 32]);
        body.extend_from_slice(&[9; 32]);
        write_address(&mut body, "203.0.113.7:8443");
        body.extend_from_slice(&[200, 50, 1]);
        let sum = checksum(&body);
        body.extend_from_slice(&sum);
        let text = format!("{PREFIX}{}", B64.encode(body));
        assert_eq!(Credential::parse(&text), Err(ParseError::Truncated));
    }

    #[test]
    fn the_old_format_is_refused() {
        let old = format!("varco1.{}", B64.encode([0u8; 90]));
        assert_eq!(Credential::parse(&old), Err(ParseError::Prefix));
    }

    #[test]
    fn replacing_the_address_keeps_the_ssh_key() {
        let moved = sample()
            .with_ssh_pubkey(ed25519())
            .with_address(Some("a.example"), None)
            .unwrap();
        assert!(moved.ssh_pubkey.is_some());
    }

    #[test]
    fn compose_builds_a_code_that_grants_ssh() {
        let composed = compose(&sample().encode(), ED25519_KEY).unwrap();
        assert_eq!(composed.server, "203.0.113.7:8443");
        assert!(composed.key_fingerprint.starts_with("SHA256:"));
        assert!(!composed.replaced_key);
        let parsed = Credential::parse(&composed.code).unwrap();
        assert_eq!(parsed.server, sample().server);
        assert_eq!(parsed.pin, sample().pin);
        assert_eq!(parsed.secret, sample().secret);
        assert_eq!(parsed.ssh_pubkey.unwrap().key_data(), ed25519().key_data());
    }

    #[test]
    fn compose_replaces_a_key_already_there() {
        let first = compose(&sample().encode(), ED25519_KEY).unwrap();
        let again = compose(&first.code, ED25519_KEY).unwrap();
        assert!(again.replaced_key);
    }

    #[test]
    fn compose_refuses_bad_input() {
        assert_eq!(
            compose("nonsense", ED25519_KEY).err(),
            Some(ComposeError::Code)
        );
        assert_eq!(
            compose(&sample().encode(), "-----BEGIN OPENSSH PRIVATE KEY-----").err(),
            Some(ComposeError::Key(store::KeyError::PrivateKey))
        );
        assert_eq!(
            compose(&sample().encode(), "ssh-ed25519 nonsense").err(),
            Some(ComposeError::Key(store::KeyError::Invalid))
        );
    }

    #[test]
    fn address_can_be_replaced_in_part_or_whole() {
        let moved = |host, port| sample().with_address(host, port).unwrap().server;
        assert_eq!(moved(None, None), "203.0.113.7:8443");
        assert_eq!(moved(Some("vpn.example.com"), None), "vpn.example.com:8443");
        assert_eq!(moved(None, Some(9000)), "203.0.113.7:9000");
        assert_eq!(moved(Some(" 10.0.0.1 "), Some(1)), "10.0.0.1:1");
        assert_eq!(moved(Some("::1"), Some(1)), "[::1]:1");
        assert_eq!(moved(Some("[::1]"), Some(1)), "[::1]:1");
    }

    #[test]
    fn replacing_the_address_keeps_the_pin_and_secret() {
        let moved = sample().with_address(Some("a.example"), Some(1)).unwrap();
        assert_eq!(moved.pin, sample().pin);
        assert_eq!(moved.secret, sample().secret);
    }

    #[test]
    fn replacing_the_address_on_an_ipv6_code_keeps_it_whole() {
        let credential = Credential {
            server: "[2001:db8::1]:8443".into(),
            ..sample()
        };
        let moved = credential.with_address(None, Some(9000)).unwrap();
        assert_eq!(moved.server, "[2001:db8::1]:9000");
    }

    #[test]
    fn bad_addresses_are_refused() {
        for host in ["", "  ", "a b", "a/b", "host:8443", "[nope]", "1:2:3"] {
            assert!(sample().with_address(Some(host), None).is_err(), "{host:?}");
        }
        assert!(sample().with_address(None, Some(0)).is_err());
    }

    #[test]
    fn round_trip_and_tolerates_surrounding_whitespace() {
        let text = format!("  {}\n", sample().encode());
        assert_eq!(Credential::parse(&text).unwrap(), sample());
    }

    #[test]
    fn rejects_any_single_character_change() {
        let text = sample().encode();
        for i in PREFIX.len()..text.len() {
            let mut bytes = text.clone().into_bytes();
            bytes[i] = if bytes[i] == b'A' { b'B' } else { b'A' };
            let tampered = String::from_utf8(bytes).unwrap();
            if tampered != text {
                assert!(
                    Credential::parse(&tampered).is_err(),
                    "position {i} accepted"
                );
            }
        }
    }

    #[test]
    fn rejects_truncation_at_every_length() {
        let text = sample().with_ssh_pubkey(ed25519()).encode();
        for end in 0..text.len() {
            assert!(
                Credential::parse(&text[..end]).is_err(),
                "length {end} accepted"
            );
        }
    }

    #[test]
    fn rejects_server_without_port() {
        let bad = Credential {
            server: "example.com".into(),
            ..sample()
        };
        assert_eq!(Credential::parse(&bad.encode()), Err(ParseError::Server));
    }

    #[test]
    fn debug_output_omits_the_secret() {
        let shown = format!("{:?}", sample());
        assert!(shown.contains("redacted") && !shown.contains("secret: [9"));
    }
}
