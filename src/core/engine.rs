//! Connect, keep alive and reconnect. The virtual NIC sits behind [`Device`] so
//! everything here can be tested over real TLS without root.
use super::error::FailReason;
use super::ssh::ListenSource;
use crate::credential::{encode_secret, Credential};
use crate::proto::{
    ipv4_endpoints, read_frame, write_frame, Frame, Hello, Member, RejectReason, Welcome,
    MAX_SERVER_FRAME, VERSION,
};
use crate::tls;
use bytes::Bytes;
use ipnet::Ipv4Net;
use rand::{Rng, RngCore};
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::io;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{split, AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HEARTBEAT: Duration = Duration::from_secs(10);
const READ_TIMEOUT: Duration = Duration::from_secs(30);
const WRITE_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_BACKOFF_SECS: u64 = 30;
/// A session must last this long before the backoff starts over, so a server
/// that accepts and then immediately drops us is not hammered.
const STABLE_SESSION: Duration = Duration::from_secs(10);
const OUT_QUEUE: usize = 256;
const MAX_DEVICE_PACKET: usize = 2048;

pub trait Device: Send + Sync + 'static {
    fn recv(&self, buf: &mut [u8]) -> impl Future<Output = io::Result<usize>> + Send;
    fn send(&self, buf: &[u8]) -> impl Future<Output = io::Result<usize>> + Send;
}

pub trait DeviceFactory: Send + Sync + 'static {
    type Device: Device;
    fn create(&self, net: &NetInfo) -> Result<Self::Device, FailReason>;
    /// Where the SSH server takes connections from on the devices made here.
    fn ssh_source(&self) -> ListenSource {
        ListenSource::Os
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetInfo {
    pub network: String,
    pub ip: Ipv4Addr,
    pub prefix: u8,
    pub mtu: u16,
}

impl NetInfo {
    pub fn cidr(&self) -> Ipv4Net {
        Ipv4Net::new(self.ip, self.prefix)
            .expect("prefix validated on receipt")
            .trunc()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    Connecting,
    Connected,
    Reconnecting {
        attempt: u32,
        retry_in_secs: u64,
        last_error: String,
    },
    Failed(FailReason),
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub phase: Phase,
    /// Stays set while reconnecting, so the screen keeps showing the network.
    pub net: Option<NetInfo>,
    pub members: Vec<Member>,
    pub rtt_ms: Option<u64>,
}

impl Default for Status {
    fn default() -> Self {
        Self {
            phase: Phase::Connecting,
            net: None,
            members: Vec::new(),
            rtt_ms: None,
        }
    }
}

#[derive(Debug, Default)]
pub struct Counters {
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
}

pub fn new_client_id() -> String {
    let mut raw = [0u8; 16];
    rand::rng().fill_bytes(&mut raw);
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

fn set_phase(status: &watch::Sender<Status>, phase: Phase) {
    status.send_modify(|s| s.phase = phase);
}

fn backoff_secs(attempt: u32) -> u64 {
    let base = 1u64
        .checked_shl(attempt.min(16))
        .unwrap_or(u64::MAX)
        .min(MAX_BACKOFF_SECS);
    // Jitter stops every client retrying together after a server restart.
    let jittered = base as f64 * rand::rng().random_range(0.8..1.2);
    (jittered.round() as u64).clamp(1, MAX_BACKOFF_SECS)
}

/// Runs until stopped or a permanent failure; the outcome is left in `status`.
pub async fn run<F: DeviceFactory>(
    credential: Credential,
    hostname: String,
    factory: F,
    status: watch::Sender<Status>,
    counters: Arc<Counters>,
    mut stop: watch::Receiver<bool>,
) {
    let client_id = new_client_id();
    let device_id = super::device::device_id();
    let mut device: Option<Arc<F::Device>> = None;
    let mut current: Option<NetInfo> = None;
    let mut attempt: u32 = 0;
    let mut joined_before = false;

    loop {
        let prev_ip = current.as_ref().map(|net| net.ip);
        let connected = tokio::select! {
            result = connect(&credential, &client_id, device_id.as_deref(), &hostname, prev_ip) => result,
            _ = stop.changed() => break,
        };

        let error = match connected {
            Ok((stream, welcome)) => {
                let net = NetInfo {
                    network: welcome.network,
                    ip: welcome.ip,
                    prefix: welcome.prefix,
                    mtu: welcome.mtu,
                };
                if current.as_ref() != Some(&net) {
                    // Only happens if the address was lost while we were away.
                    device = None;
                }
                let dev = match &device {
                    Some(dev) => dev.clone(),
                    None => match factory.create(&net) {
                        Ok(dev) => {
                            let dev = Arc::new(dev);
                            device = Some(dev.clone());
                            dev
                        }
                        Err(reason) => {
                            set_phase(&status, Phase::Failed(reason));
                            return;
                        }
                    },
                };
                joined_before = true;
                current = Some(net.clone());
                info!(ip = %net.ip, network = %net.network, "joined");
                status.send_modify(|s| {
                    s.phase = Phase::Connected;
                    s.net = Some(net.clone());
                });
                let started = Instant::now();
                let ended = tokio::select! {
                    ended = run_session(stream, dev, &net, &status, &counters) => ended,
                    _ = stop.changed() => break,
                };
                if started.elapsed() >= STABLE_SESSION {
                    attempt = 0;
                }
                if matches!(ended, SessionEnd::Device(_)) {
                    // Recreate the NIC on the next pass; adapters can vanish across sleep.
                    device = None;
                }
                status.send_modify(|s| s.rtt_ms = None);
                let (SessionEnd::Network(detail) | SessionEnd::Device(detail)) = ended;
                warn!(%detail, "session ended");
                detail
            }
            Err(reason) => {
                if reason.is_permanent() || !joined_before {
                    set_phase(&status, Phase::Failed(reason));
                    return;
                }
                debug!(%reason, "reconnect failed");
                reason.to_string()
            }
        };

        attempt = attempt.saturating_add(1);
        let retry_in_secs = backoff_secs(attempt - 1);
        set_phase(
            &status,
            Phase::Reconnecting {
                attempt,
                retry_in_secs,
                last_error: error,
            },
        );
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(retry_in_secs)) => {}
            _ = stop.changed() => break,
        }
    }
    drop(device);
    set_phase(&status, Phase::Stopped);
}

type ClientTls = tokio_rustls::client::TlsStream<TcpStream>;

async fn connect(
    credential: &Credential,
    client_id: &str,
    device_id: Option<&str>,
    hostname: &str,
    prev_ip: Option<Ipv4Addr>,
) -> Result<(ClientTls, Welcome), FailReason> {
    let unreachable = |detail: String| FailReason::ServerUnreachable(detail);
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&credential.server))
        .await
        .map_err(|_| unreachable("连接超时".to_owned()))?
        .map_err(|e| unreachable(e.to_string()))?;
    if let Err(error) = crate::server::configure_socket(&tcp) {
        debug!(%error, "socket options not applied");
    }

    let config =
        tls::client_config(credential.pin).map_err(|e| FailReason::Protocol(e.to_string()))?;
    let name = ServerName::try_from(tls::TLS_NAME).expect("constant is a valid name");
    // The secret is only written after this has verified the pinned key.
    let mut stream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        TlsConnector::from(config).connect(name, tcp),
    )
    .await
    .map_err(|_| unreachable("加密握手超时".to_owned()))?
    .map_err(|e| {
        if tls::is_pin_failure(&e) {
            FailReason::PinMismatch
        } else {
            unreachable(e.to_string())
        }
    })?;

    let hello = Hello {
        version: VERSION,
        secret: encode_secret(&credential.secret),
        client_id: client_id.to_owned(),
        hostname: hostname.to_owned(),
        prev_ip,
        device_id: device_id.map(str::to_owned),
    };
    let protocol = |e: io::Error| FailReason::Protocol(e.to_string());
    write_frame(&mut stream, &Frame::Hello(hello))
        .await
        .map_err(protocol)?;
    let reply = tokio::time::timeout(CONNECT_TIMEOUT, read_frame(&mut stream, MAX_SERVER_FRAME))
        .await
        .map_err(|_| FailReason::Protocol("等待服务器响应超时".to_owned()))?
        .map_err(protocol)?;
    match reply {
        Frame::Welcome(welcome) => {
            if Ipv4Net::new(welcome.ip, welcome.prefix).is_err() {
                return Err(FailReason::Protocol("服务器下发的网段无效".to_owned()));
            }
            Ok((stream, welcome))
        }
        Frame::Reject(RejectReason::InvalidCredential) => Err(FailReason::CredentialRejected),
        Frame::Reject(RejectReason::CodeUsed) => Err(FailReason::CodeUsed),
        Frame::Reject(RejectReason::CodeExpired) => Err(FailReason::CodeExpired),
        Frame::Reject(RejectReason::Removed) => Err(FailReason::Removed),
        Frame::Reject(RejectReason::NetworkFull) => Err(FailReason::NetworkFull),
        Frame::Reject(RejectReason::UnsupportedVersion) => Err(FailReason::VersionMismatch),
        _ => Err(FailReason::Protocol("服务器响应不符合协议".to_owned())),
    }
}

enum SessionEnd {
    Network(String),
    Device(String),
}

async fn run_session<S, D>(
    stream: S,
    device: Arc<D>,
    net: &NetInfo,
    status: &watch::Sender<Status>,
    counters: &Arc<Counters>,
) -> SessionEnd
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    D: Device,
{
    let (reader, writer) = split(stream);
    let (out_tx, out_rx) = mpsc::channel(OUT_QUEUE);
    let origin = Instant::now();
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(pump_device(
        device.clone(),
        net.clone(),
        out_tx,
        counters.clone(),
    ));
    tasks.spawn(write_loop(writer, out_rx, origin));
    tasks.spawn(read_loop(
        reader,
        device,
        status.clone(),
        counters.clone(),
        origin,
    ));
    let ended = match tasks.join_next().await {
        Some(Ok(ended)) => ended,
        Some(Err(error)) => SessionEnd::Network(error.to_string()),
        None => SessionEnd::Network("session had no tasks".to_owned()),
    };
    // Waits for the tasks to finish, so nothing still holds the device afterwards.
    tasks.shutdown().await;
    ended
}

/// Reads the NIC. Forwards only packets for the mesh, and drops rather than
/// waits when the connection is behind, leaving congestion control to inner TCP.
async fn pump_device<D: Device>(
    device: Arc<D>,
    net: NetInfo,
    out: mpsc::Sender<Bytes>,
    counters: Arc<Counters>,
) -> SessionEnd {
    let cidr = net.cidr();
    let broadcast = cidr.broadcast();
    let mut buf = vec![0u8; MAX_DEVICE_PACKET];
    loop {
        let len = match device.recv(&mut buf).await {
            Ok(len) => len,
            Err(error) => return SessionEnd::Device(error.to_string()),
        };
        let Some((_, dst)) = ipv4_endpoints(&buf[..len]) else {
            continue;
        };
        if !cidr.contains(&dst) || dst == net.ip || dst == broadcast {
            continue;
        }
        if out.try_send(Bytes::copy_from_slice(&buf[..len])).is_ok() {
            counters.tx_bytes.fetch_add(len as u64, Ordering::Relaxed);
        }
    }
}

async fn write_loop<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut out: mpsc::Receiver<Bytes>,
    origin: Instant,
) -> SessionEnd {
    let mut heartbeat = tokio::time::interval(HEARTBEAT);
    loop {
        let frame = tokio::select! {
            _ = heartbeat.tick() => Frame::Ping(origin.elapsed().as_millis() as u64),
            packet = out.recv() => match packet {
                Some(packet) => Frame::Packet(packet),
                None => return SessionEnd::Network("device pump stopped".to_owned()),
            },
        };
        match tokio::time::timeout(WRITE_TIMEOUT, write_frame(&mut writer, &frame)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return SessionEnd::Network(error.to_string()),
            Err(_) => return SessionEnd::Network("写入超时".to_owned()),
        }
    }
}

async fn read_loop<R: AsyncRead + Unpin, D: Device>(
    mut reader: R,
    device: Arc<D>,
    status: watch::Sender<Status>,
    counters: Arc<Counters>,
    origin: Instant,
) -> SessionEnd {
    loop {
        let frame =
            match tokio::time::timeout(READ_TIMEOUT, read_frame(&mut reader, MAX_SERVER_FRAME))
                .await
            {
                Ok(Ok(frame)) => frame,
                Ok(Err(error)) => return SessionEnd::Network(error.to_string()),
                Err(_) => return SessionEnd::Network("心跳超时".to_owned()),
            };
        match frame {
            Frame::Packet(packet) => {
                counters
                    .rx_bytes
                    .fetch_add(packet.len() as u64, Ordering::Relaxed);
                if let Err(error) = device.send(&packet).await {
                    // One undeliverable packet is not fatal; a dead NIC shows up in the pump.
                    debug!(%error, "device write failed");
                }
            }
            Frame::Pong(sent_at) => {
                let rtt = (origin.elapsed().as_millis() as u64).saturating_sub(sent_at);
                status.send_if_modified(|s| {
                    let changed = s.rtt_ms != Some(rtt);
                    s.rtt_ms = Some(rtt);
                    changed
                });
            }
            Frame::Members(members) => status.send_modify(|s| s.members = members),
            other => return SessionEnd::Network(format!("unexpected frame: {other:?}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_is_capped() {
        for _ in 0..200 {
            assert!((1..=2).contains(&backoff_secs(0)));
            assert!((6..=10).contains(&backoff_secs(3)));
            assert!(backoff_secs(50) <= MAX_BACKOFF_SECS);
            assert!(backoff_secs(u32::MAX) <= MAX_BACKOFF_SECS);
        }
    }
}
