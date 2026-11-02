//! Real TCP + TLS + server + engine; only the NIC is replaced by channels.
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use varco::core::engine::{self, Counters, Device, DeviceFactory, NetInfo, Phase, Status};
use varco::core::error::FailReason;
use varco::credential::{Credential, Pin, Secret};
use varco::server::config::NetworkConfig;
use varco::server::hub::Hub;
use varco::tls::{self, Identity};

const WAIT: Duration = Duration::from_secs(20);
const SECRET_A: Secret = [1; 32];
const SECRET_B: Secret = [2; 32];

struct FakeDevice {
    from_os: tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    to_os: mpsc::UnboundedSender<Vec<u8>>,
}

impl Device for FakeDevice {
    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let packet = self.from_os.lock().await.recv().await;
        match packet {
            Some(packet) => {
                buf[..packet.len()].copy_from_slice(&packet);
                Ok(packet.len())
            }
            None => std::future::pending().await,
        }
    }
    async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        let _ = self.to_os.send(buf.to_vec());
        Ok(buf.len())
    }
}

struct Peer {
    status: watch::Receiver<Status>,
    counters: Arc<Counters>,
    inject: mpsc::UnboundedSender<Vec<u8>>,
    delivered: mpsc::UnboundedReceiver<Vec<u8>>,
    devices_created: Arc<AtomicUsize>,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

type DeviceParts = (
    mpsc::UnboundedReceiver<Vec<u8>>,
    mpsc::UnboundedSender<Vec<u8>>,
);

struct FakeFactory {
    parts: Mutex<Option<DeviceParts>>,
    created: Arc<AtomicUsize>,
}

impl DeviceFactory for FakeFactory {
    type Device = FakeDevice;
    fn create(&self, _net: &NetInfo) -> Result<FakeDevice, FailReason> {
        self.created.fetch_add(1, Ordering::SeqCst);
        let (from_os, to_os) = self
            .parts
            .lock()
            .unwrap()
            .take()
            .expect("one device per test peer");
        Ok(FakeDevice {
            from_os: tokio::sync::Mutex::new(from_os),
            to_os,
        })
    }
}

fn spawn_peer(server: SocketAddr, pin: Pin, secret: Secret, name: &str) -> Peer {
    let credential = Credential {
        server: server.to_string(),
        pin,
        secret,
    };
    let (inject, from_os) = mpsc::unbounded_channel();
    let (to_os, delivered) = mpsc::unbounded_channel();
    let created = Arc::new(AtomicUsize::new(0));
    let factory = FakeFactory {
        parts: Mutex::new(Some((from_os, to_os))),
        created: created.clone(),
    };
    let (status_tx, status) = watch::channel(Status::default());
    let (stop, stop_rx) = watch::channel(false);
    let counters = Arc::new(Counters::default());
    let task = tokio::spawn(engine::run(
        credential,
        name.to_owned(),
        factory,
        status_tx,
        counters.clone(),
        stop_rx,
    ));
    Peer {
        status,
        counters,
        inject,
        delivered,
        devices_created: created,
        stop,
        task,
    }
}

impl Peer {
    async fn wait_for(&mut self, what: &str, ok: impl Fn(&Status) -> bool) -> Status {
        let found = tokio::time::timeout(WAIT, self.status.wait_for(|s| ok(s)))
            .await
            .map(|result| result.map(|status| status.clone()));
        match found {
            Ok(Ok(status)) => status,
            _ => panic!(
                "timed out waiting for {what}, now {:?}",
                *self.status.borrow()
            ),
        }
    }
    async fn connected(&mut self) -> NetInfo {
        let status = self
            .wait_for("connected", |s| s.phase == Phase::Connected)
            .await;
        status.net.expect("connected implies net")
    }
    async fn failure(&mut self) -> FailReason {
        let status = self
            .wait_for("failure", |s| matches!(s.phase, Phase::Failed(_)))
            .await;
        match status.phase {
            Phase::Failed(reason) => reason,
            _ => unreachable!(),
        }
    }
}

fn packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p.extend_from_slice(payload);
    p
}

fn networks() -> Vec<NetworkConfig> {
    vec![
        NetworkConfig {
            name: "a".into(),
            cidr: "10.1.0.0/24".parse().unwrap(),
            secrets: vec![SECRET_A],
        },
        NetworkConfig {
            name: "b".into(),
            cidr: "10.2.0.0/24".parse().unwrap(),
            secrets: vec![SECRET_B],
        },
    ]
}

async fn start_server_on(
    listener: TcpListener,
    identity: &Identity,
) -> tokio::task::JoinHandle<()> {
    let hub = Arc::new(Hub::new(networks()));
    let config = tls::server_config(identity).unwrap();
    tokio::spawn(async move {
        let _ = varco::server::serve(listener, hub, config).await;
    })
}

async fn start_server() -> (SocketAddr, Identity, tokio::task::JoinHandle<()>) {
    let identity = tls::generate_identity().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = start_server_on(listener, &identity).await;
    (addr, identity, task)
}

async fn assert_nothing_delivered(peer: &mut Peer) {
    let got = tokio::time::timeout(Duration::from_millis(400), peer.delivered.recv()).await;
    assert!(got.is_err(), "unexpected delivery: {got:?}");
}

#[tokio::test]
async fn members_exchange_packets_both_ways_and_see_each_other() {
    let (addr, identity, _server) = start_server().await;
    let mut a = spawn_peer(addr, identity.pin, SECRET_A, "alice");
    let mut b = spawn_peer(addr, identity.pin, SECRET_A, "bob");
    let net_a = a.connected().await;
    let net_b = b.connected().await;
    assert_eq!(net_a.network, "a");
    assert_ne!(net_a.ip, net_b.ip);

    a.wait_for("two members", |s| s.members.len() == 2).await;

    let there = packet(net_a.ip, net_b.ip, b"ping");
    a.inject.send(there.clone()).unwrap();
    assert_eq!(
        tokio::time::timeout(WAIT, b.delivered.recv())
            .await
            .unwrap()
            .unwrap(),
        there
    );

    let back = packet(net_b.ip, net_a.ip, b"pong");
    b.inject.send(back.clone()).unwrap();
    assert_eq!(
        tokio::time::timeout(WAIT, a.delivered.recv())
            .await
            .unwrap()
            .unwrap(),
        back
    );

    assert_eq!(
        a.counters.tx_bytes.load(Ordering::Relaxed),
        there.len() as u64
    );
    assert_eq!(
        a.counters.rx_bytes.load(Ordering::Relaxed),
        back.len() as u64
    );
}

#[tokio::test]
async fn networks_are_isolated_and_forged_sources_are_dropped() {
    let (addr, identity, _server) = start_server().await;
    let mut a = spawn_peer(addr, identity.pin, SECRET_A, "a1");
    let mut a2 = spawn_peer(addr, identity.pin, SECRET_A, "a2");
    let mut b = spawn_peer(addr, identity.pin, SECRET_B, "b1");
    let net_a = a.connected().await;
    let net_a2 = a2.connected().await;
    let net_b = b.connected().await;
    assert_eq!(net_b.network, "b");
    assert_eq!(
        b.wait_for("own member list", |s| !s.members.is_empty())
            .await
            .members
            .len(),
        1
    );

    // Outside the sender's subnet: stopped at the client filter.
    a.inject.send(packet(net_a.ip, net_b.ip, b"cross")).unwrap();
    assert_nothing_delivered(&mut b).await;

    // Forged source inside the subnet: only the server can stop this one.
    a.inject
        .send(packet(Ipv4Addr::new(10, 1, 0, 99), net_a2.ip, b"forged"))
        .unwrap();
    assert_nothing_delivered(&mut a2).await;

    // The session survived, and legitimate traffic still flows.
    let good = packet(net_a.ip, net_a2.ip, b"good");
    a.inject.send(good.clone()).unwrap();
    assert_eq!(
        tokio::time::timeout(WAIT, a2.delivered.recv())
            .await
            .unwrap()
            .unwrap(),
        good
    );
}

#[tokio::test]
async fn wrong_secret_is_rejected_without_creating_a_device() {
    let (addr, identity, _server) = start_server().await;
    let mut peer = spawn_peer(addr, identity.pin, [9; 32], "x");
    assert_eq!(peer.failure().await, FailReason::CredentialRejected);
    assert_eq!(peer.devices_created.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn wrong_pin_fails_and_the_secret_is_never_sent() {
    // A server that logs whatever it receives after the handshake.
    let identity = tls::generate_identity().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(tls::server_config(&identity).unwrap());
    let received = Arc::new(AtomicUsize::new(0));
    let counter = received.clone();
    tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let (tcp, _) = listener.accept().await.unwrap();
        if let Ok(mut tls_stream) = acceptor.accept(tcp).await {
            let mut buf = [0u8; 256];
            while let Ok(n) = tls_stream.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                counter.fetch_add(n, Ordering::SeqCst);
            }
        }
    });
    let mut peer = spawn_peer(addr, [0xAA; 32], SECRET_A, "x");
    assert_eq!(peer.failure().await, FailReason::PinMismatch);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        received.load(Ordering::SeqCst),
        0,
        "plaintext reached the impostor"
    );
    assert_eq!(peer.devices_created.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn unreachable_server_is_reported_on_first_attempt() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let mut peer = spawn_peer(addr, [0; 32], SECRET_A, "x");
    assert!(matches!(
        peer.failure().await,
        FailReason::ServerUnreachable(_)
    ));
}

/// A runtime of its own: dropping it ends every task, connections included,
/// which is what a process restart does and aborting one task does not.
fn start_isolated_server(addr: SocketAddr, identity: &Identity) -> tokio::runtime::Runtime {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let config = tls::server_config(identity).unwrap();
    let hub = Arc::new(Hub::new(networks()));
    runtime.spawn(async move {
        let listener = TcpListener::bind(addr).await.unwrap();
        let _ = varco::server::serve(listener, hub, config).await;
    });
    runtime
}

#[tokio::test(flavor = "multi_thread")]
async fn reconnects_after_server_restart_with_same_ip_and_same_device() {
    let identity = tls::generate_identity().unwrap();
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    let server = start_isolated_server(addr, &identity);

    let mut first = spawn_peer(addr, identity.pin, SECRET_A, "first");
    let _ = first.connected().await;
    let mut second = spawn_peer(addr, identity.pin, SECRET_A, "second");
    let net = second.connected().await;
    assert_eq!(net.ip, Ipv4Addr::new(10, 1, 0, 2));

    // The relay's state is lost entirely. `second` is reconnected alone first,
    // so without prev_ip it would be handed the lowest free address, .1.
    first.stop.send(true).unwrap();
    first.task.await.unwrap();
    server.shutdown_background();
    second
        .wait_for("reconnecting", |s| {
            matches!(s.phase, Phase::Reconnecting { .. })
        })
        .await;
    assert!(
        second.status.borrow().net.is_some(),
        "network info must stay visible"
    );

    let restarted = start_isolated_server(addr, &identity);
    second
        .wait_for("connected again", |s| s.phase == Phase::Connected)
        .await;
    assert_eq!(second.status.borrow().net.as_ref().unwrap().ip, net.ip);
    assert_eq!(
        second.devices_created.load(Ordering::SeqCst),
        1,
        "NIC must survive the outage"
    );
    restarted.shutdown_background();
}

/// Accepts TLS and the Hello, then goes silent, like a half-open connection.
#[tokio::test]
async fn silent_server_is_detected_by_the_heartbeat() {
    let identity = tls::generate_identity().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(tls::server_config(&identity).unwrap());
    tokio::spawn(async move {
        use varco::proto::{read_frame, write_frame, Frame, Welcome, MAX_CLIENT_FRAME, MTU};
        let (tcp, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(tcp).await.unwrap();
        read_frame(&mut stream, MAX_CLIENT_FRAME).await.unwrap();
        let welcome = Welcome {
            network: "a".into(),
            ip: Ipv4Addr::new(10, 1, 0, 5),
            prefix: 24,
            mtu: MTU,
        };
        write_frame(&mut stream, &Frame::Welcome(welcome))
            .await
            .unwrap();
        // Keep the socket open and never answer again.
        std::future::pending::<()>().await;
        drop(stream);
    });
    let mut peer = spawn_peer(addr, identity.pin, SECRET_A, "x");
    peer.connected().await;
    let found = tokio::time::timeout(
        Duration::from_secs(40),
        peer.status
            .wait_for(|s| matches!(s.phase, Phase::Reconnecting { .. })),
    )
    .await;
    assert!(found.is_ok(), "half-open connection was not noticed");
}

#[tokio::test]
async fn stop_ends_the_engine_promptly() {
    let (addr, identity, _server) = start_server().await;
    let mut peer = spawn_peer(addr, identity.pin, SECRET_A, "x");
    peer.connected().await;
    peer.stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(2), &mut peer.task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(peer.status.borrow().phase, Phase::Stopped);
}

#[tokio::test]
async fn departing_member_disappears_from_the_list() {
    let (addr, identity, _server) = start_server().await;
    let mut a = spawn_peer(addr, identity.pin, SECRET_A, "a");
    let mut b = spawn_peer(addr, identity.pin, SECRET_A, "b");
    a.connected().await;
    b.connected().await;
    a.wait_for("both present", |s| s.members.len() == 2).await;
    b.stop.send(true).unwrap();
    a.wait_for("b gone", |s| s.members.len() == 1).await;
}
