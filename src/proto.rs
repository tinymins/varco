//! Framing inside the TLS stream: u32 length, u8 type, payload.
use bytes::{BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io;
use std::net::Ipv4Addr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const VERSION: u32 = 1;
pub const MTU: u16 = 1280;
/// Limit before authentication, and for anything a client sends afterwards.
pub const MAX_CLIENT_FRAME: usize = 4096;
/// Member lists can be large; networks are capped at /20 by the server config.
pub const MAX_SERVER_FRAME: usize = 1 << 20;

const T_HELLO: u8 = 1;
const T_WELCOME: u8 = 2;
const T_REJECT: u8 = 3;
const T_PACKET: u8 = 4;
const T_PING: u8 = 5;
const T_PONG: u8 = 6;
const T_MEMBERS: u8 = 7;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Hello {
    pub version: u32,
    pub secret: String,
    pub client_id: String,
    pub hostname: String,
    pub prev_ip: Option<Ipv4Addr>,
    /// Absent from older clients, and ignored by older servers.
    #[serde(default)]
    pub device_id: Option<String>,
}

impl fmt::Debug for Hello {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hello")
            .field("version", &self.version)
            .field("hostname", &self.hostname)
            .field("prev_ip", &self.prev_ip)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Welcome {
    pub network: String,
    pub ip: Ipv4Addr,
    pub prefix: u8,
    pub mtu: u16,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RejectReason {
    InvalidCredential,
    NetworkFull,
    UnsupportedVersion,
    CodeUsed,
    CodeExpired,
    /// Kicked or banned from the admin console.
    Removed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Member {
    pub hostname: String,
    pub ip: Ipv4Addr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Hello(Hello),
    Welcome(Welcome),
    Reject(RejectReason),
    Packet(Bytes),
    Ping(u64),
    Pong(u64),
    Members(Vec<Member>),
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

impl Frame {
    pub fn encode(&self) -> io::Result<BytesMut> {
        let (kind, json): (u8, Option<Vec<u8>>) = match self {
            Frame::Hello(v) => (T_HELLO, Some(serde_json::to_vec(v)?)),
            Frame::Welcome(v) => (T_WELCOME, Some(serde_json::to_vec(v)?)),
            Frame::Reject(v) => (T_REJECT, Some(serde_json::to_vec(v)?)),
            Frame::Members(v) => (T_MEMBERS, Some(serde_json::to_vec(v)?)),
            Frame::Packet(_) => (T_PACKET, None),
            Frame::Ping(_) => (T_PING, None),
            Frame::Pong(_) => (T_PONG, None),
        };
        let body_len = match (self, &json) {
            (_, Some(json)) => json.len(),
            (Frame::Packet(p), None) => p.len(),
            _ => 8,
        };
        let mut out = BytesMut::with_capacity(5 + body_len);
        out.put_u32((1 + body_len) as u32);
        out.put_u8(kind);
        match (self, json) {
            (_, Some(json)) => out.extend_from_slice(&json),
            (Frame::Packet(p), None) => out.extend_from_slice(p),
            (Frame::Ping(n) | Frame::Pong(n), None) => out.put_u64(*n),
            _ => unreachable!("every frame is handled above"),
        }
        Ok(out)
    }

    fn decode(kind: u8, body: Bytes) -> io::Result<Self> {
        fn nonce(body: &[u8]) -> io::Result<u64> {
            let raw: [u8; 8] = body
                .try_into()
                .map_err(|_| invalid("bad heartbeat length"))?;
            Ok(u64::from_be_bytes(raw))
        }
        Ok(match kind {
            T_HELLO => Frame::Hello(serde_json::from_slice(&body)?),
            T_WELCOME => Frame::Welcome(serde_json::from_slice(&body)?),
            T_REJECT => Frame::Reject(serde_json::from_slice(&body)?),
            T_MEMBERS => Frame::Members(serde_json::from_slice(&body)?),
            T_PACKET => Frame::Packet(body),
            T_PING => Frame::Ping(nonce(&body)?),
            T_PONG => Frame::Pong(nonce(&body)?),
            other => return Err(invalid(format!("unknown frame type {other}"))),
        })
    }
}

pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, frame: &Frame) -> io::Result<()> {
    writer.write_all(&frame.encode()?).await?;
    writer.flush().await
}

/// Not cancel-safe: run it in a dedicated task or under a timeout that ends the
/// connection, never as a `select!` branch that may be retried.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R, max: usize) -> io::Result<Frame> {
    let len = reader.read_u32().await? as usize;
    if len == 0 || len > max {
        return Err(invalid(format!("frame length {len} out of range")));
    }
    let mut buf = BytesMut::zeroed(len);
    reader.read_exact(&mut buf).await?;
    let mut body = buf.freeze();
    let kind = body[0];
    Frame::decode(kind, body.split_off(1))
}

/// Source and destination of an IPv4 packet; `None` for anything else.
pub fn ipv4_endpoints(packet: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let src: [u8; 4] = packet[12..16].try_into().ok()?;
    let dst: [u8; 4] = packet[16..20].try_into().ok()?;
    Some((src.into(), dst.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn round_trip(frame: Frame) -> Frame {
        let mut wire = Vec::new();
        write_frame(&mut wire, &frame).await.unwrap();
        read_frame(&mut wire.as_slice(), MAX_SERVER_FRAME)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn every_frame_type_round_trips() {
        let frames = [
            Frame::Hello(Hello {
                version: VERSION,
                secret: "s".into(),
                client_id: "c".into(),
                hostname: "h".into(),
                prev_ip: Some(Ipv4Addr::new(10, 0, 0, 2)),
                device_id: Some("d".into()),
            }),
            Frame::Welcome(Welcome {
                network: "n".into(),
                ip: Ipv4Addr::new(10, 0, 0, 1),
                prefix: 24,
                mtu: MTU,
            }),
            Frame::Reject(RejectReason::NetworkFull),
            Frame::Reject(RejectReason::CodeUsed),
            Frame::Reject(RejectReason::CodeExpired),
            Frame::Reject(RejectReason::Removed),
            Frame::Packet(Bytes::from_static(&[1, 2, 3])),
            Frame::Packet(Bytes::new()),
            Frame::Ping(42),
            Frame::Pong(43),
            Frame::Members(vec![Member {
                hostname: "a".into(),
                ip: Ipv4Addr::new(10, 0, 0, 1),
            }]),
        ];
        for frame in frames {
            assert_eq!(round_trip(frame.clone()).await, frame);
        }
    }

    #[tokio::test]
    async fn oversized_frame_is_refused_before_allocating() {
        let wire = u32::MAX.to_be_bytes();
        assert!(read_frame(&mut wire.as_slice(), MAX_CLIENT_FRAME)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn zero_length_and_unknown_type_are_errors() {
        assert!(read_frame(&mut [0u8, 0, 0, 0].as_slice(), 100)
            .await
            .is_err());
        assert!(read_frame(&mut [0u8, 0, 0, 1, 99].as_slice(), 100)
            .await
            .is_err());
    }

    #[test]
    fn hello_from_an_older_client_still_parses() {
        let old = r#"{"version":1,"secret":"s","client_id":"c","hostname":"h","prev_ip":null}"#;
        let hello: Hello = serde_json::from_str(old).unwrap();
        assert_eq!(hello.device_id, None);
    }

    #[test]
    fn hello_debug_omits_the_secret() {
        let hello = Hello {
            version: 1,
            secret: "topsecret".into(),
            client_id: "idvalue".into(),
            hostname: "h".into(),
            prev_ip: None,
            device_id: None,
        };
        let shown = format!("{hello:?}");
        assert!(!shown.contains("topsecret") && !shown.contains("idvalue"));
    }

    #[test]
    fn endpoints_only_for_ipv4() {
        let mut packet = [0u8; 20];
        packet[0] = 0x45;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
        assert_eq!(
            ipv4_endpoints(&packet),
            Some((Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)))
        );
        packet[0] = 0x60;
        assert_eq!(ipv4_endpoints(&packet), None);
        assert_eq!(ipv4_endpoints(&[0x45; 19]), None);
    }
}
