//! The string a user pastes: it carries the server address, the server key
//! pin and the secret, so the binary itself holds no deployment configuration.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fmt;
use subtle::ConstantTimeEq;

const PREFIX: &str = "varco1.";
const CHECKSUM_LEN: usize = 4;

pub type Secret = [u8; 32];
pub type Pin = [u8; 32];

#[derive(Clone, PartialEq, Eq)]
pub struct Credential {
    pub server: String,
    pub pin: Pin,
    pub secret: Secret,
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
    #[error("missing varco1 prefix")]
    Prefix,
    #[error("not valid base64url")]
    Encoding,
    #[error("too short")]
    Truncated,
    #[error("checksum mismatch")]
    Checksum,
    #[error("server address is invalid")]
    Server,
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
        let mut body = Vec::with_capacity(64 + self.server.len() + CHECKSUM_LEN);
        body.extend_from_slice(&self.pin);
        body.extend_from_slice(&self.secret);
        body.extend_from_slice(self.server.as_bytes());
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
        if raw.len() < 64 + CHECKSUM_LEN + 1 {
            return Err(ParseError::Truncated);
        }
        let (body, sum) = raw.split_at(raw.len() - CHECKSUM_LEN);
        if checksum(body) != sum {
            return Err(ParseError::Checksum);
        }
        let server = std::str::from_utf8(&body[64..]).map_err(|_| ParseError::Server)?;
        if !server_is_valid(server) {
            return Err(ParseError::Server);
        }
        Ok(Self {
            server: server.to_owned(),
            pin: body[..32].try_into().expect("length checked"),
            secret: body[32..64].try_into().expect("length checked"),
        })
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
        }
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
        let text = sample().encode();
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
