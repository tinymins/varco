//! Real TCP + TLS + server + engine; only the NIC is replaced by channels.
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use varco::core::engine::{self, Counters, Device, DeviceFactory, NetInfo, Phase, Status};
use varco::core::error::FailReason;
use varco::credential::{encode_secret, Credential, Pin, Secret};
use varco::proto::{
    read_frame, write_frame, Frame, Hello, RejectReason, MAX_SERVER_FRAME, VERSION,
};
use varco::server::config::NetworkConfig;
use varco::server::hub::{Hub, MemberView};
use varco::server::state::{parse_ip_target, unix_now, BanTarget, CodeKind, Store};
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
        ssh_pubkey: None,
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
    start_isolated_server_with(addr, identity, None)
}

fn start_isolated_server_with(
    addr: SocketAddr,
    identity: &Identity,
    store: Option<Arc<Store>>,
) -> tokio::runtime::Runtime {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let config = tls::server_config(identity).unwrap();
    let hub = match store {
        Some(store) => Hub::new(networks()).with_store(store),
        None => Hub::new(networks()),
    };
    let hub = Arc::new(hub);
    // Bound before returning, so a client started next cannot be refused. Retries
    // because a runtime shut down just now may still be closing its listener.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let listener = loop {
        match std::net::TcpListener::bind(addr) {
            Ok(listener) => break listener,
            Err(_) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("binding {addr}: {error}"),
        }
    };
    listener.set_nonblocking(true).unwrap();
    runtime.spawn(async move {
        let listener = TcpListener::from_std(listener).unwrap();
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

// ---- Limited Codes, kicks and bans ----

fn test_store(name: &str) -> (std::path::PathBuf, Arc<Store>) {
    let dir = std::env::temp_dir().join(format!("varco-relay-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("state.json");
    let store = Store::load(path.clone(), unix_now()).unwrap();
    (path, Arc::new(store))
}

struct Managed {
    addr: SocketAddr,
    identity: Identity,
    hub: Arc<Hub>,
    store: Arc<Store>,
    state_path: std::path::PathBuf,
}

async fn start_managed(name: &str) -> Managed {
    let (state_path, store) = test_store(name);
    let hub = Arc::new(Hub::new(networks()).with_store(store.clone()));
    let identity = tls::generate_identity().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = tls::server_config(&identity).unwrap();
    let serving = hub.clone();
    tokio::spawn(async move {
        let _ = varco::server::serve(listener, serving, config).await;
    });
    Managed {
        addr,
        identity,
        hub,
        store,
        state_path,
    }
}

impl Managed {
    fn once(&self) -> (String, Secret) {
        let (record, secret) = self
            .store
            .create_code("a", CodeKind::Once, "", unix_now())
            .unwrap();
        (record.id, secret)
    }
    fn timed(&self, seconds: u64) -> (String, Secret) {
        let kind = CodeKind::Timed {
            expires_at: unix_now() + seconds,
        };
        let (record, secret) = self.store.create_code("a", kind, "", unix_now()).unwrap();
        (record.id, secret)
    }
    fn peer(&self, secret: Secret, name: &str) -> Peer {
        spawn_peer(self.addr, self.identity.pin, secret, name)
    }
    fn member(&self, hostname: &str) -> MemberView {
        self.hub
            .members()
            .into_iter()
            .find(|member| member.hostname == hostname)
            .expect("member is online")
    }
    fn used(&self, id: &str) -> usize {
        let codes = self.store.codes();
        let code = codes.iter().find(|code| code.id == id).unwrap();
        code.used_by.len()
    }
    async fn raw(&self, secret: Secret, client_id: &str, device: Option<&str>) -> RawClient {
        raw_connect(self.addr, self.identity.pin, secret, client_id, device)
            .await
            .expect("TLS handshake")
    }
    async fn wait_used(&self, id: &str, count: usize) {
        for _ in 0..200 {
            if self.used(id) == count {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("Code {id} did not reach {count} uses");
    }
}

/// A client that does only what each test says, which the engine would not.
struct RawClient {
    stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    reply: Frame,
}

async fn raw_connect(
    addr: SocketAddr,
    pin: Pin,
    secret: Secret,
    client_id: &str,
    device: Option<&str>,
) -> std::io::Result<RawClient> {
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let config = tls::client_config(pin).unwrap();
    let name = rustls::pki_types::ServerName::try_from(tls::TLS_NAME).unwrap();
    let mut stream = tokio_rustls::TlsConnector::from(config)
        .connect(name, tcp)
        .await?;
    let hello = Hello {
        version: VERSION,
        secret: encode_secret(&secret),
        client_id: client_id.to_owned(),
        hostname: client_id.to_owned(),
        prev_ip: None,
        device_id: device.map(str::to_owned),
    };
    write_frame(&mut stream, &Frame::Hello(hello)).await?;
    let reply = read_frame(&mut stream, MAX_SERVER_FRAME).await?;
    Ok(RawClient { stream, reply })
}

impl RawClient {
    fn rejected(&self) -> Option<RejectReason> {
        match self.reply {
            Frame::Reject(reason) => Some(reason),
            _ => None,
        }
    }
    fn welcomed(&self) -> bool {
        matches!(self.reply, Frame::Welcome(_))
    }
    async fn send_first_frame(&mut self) {
        write_frame(&mut self.stream, &Frame::Ping(1))
            .await
            .unwrap();
    }
}

/// Fails the way a machine without administrator rights does: after the Welcome.
struct NoPrivilegeFactory;

impl DeviceFactory for NoPrivilegeFactory {
    type Device = FakeDevice;
    fn create(&self, _net: &NetInfo) -> Result<FakeDevice, FailReason> {
        Err(FailReason::NoPrivilege)
    }
}

#[tokio::test]
async fn a_once_code_goes_to_the_first_device_only() {
    let server = start_managed("once").await;
    let (id, secret) = server.once();
    let mut first = server.peer(secret, "first");
    first.connected().await;
    server.wait_used(&id, 1).await;
    let mut second = server.peer(secret, "second");
    assert_eq!(second.failure().await, FailReason::CodeUsed);
    assert_eq!(second.devices_created.load(Ordering::SeqCst), 0);
    assert_eq!(server.used(&id), 1);
}

#[tokio::test]
async fn failing_to_create_the_nic_does_not_cost_the_code() {
    let server = start_managed("nic").await;
    let (id, secret) = server.once();
    let credential = Credential {
        server: server.addr.to_string(),
        pin: server.identity.pin,
        secret,
        ssh_pubkey: None,
    };
    let (status_tx, mut status) = watch::channel(Status::default());
    let (_stop, stop_rx) = watch::channel(false);
    tokio::spawn(engine::run(
        credential,
        "unprivileged".to_owned(),
        NoPrivilegeFactory,
        status_tx,
        Arc::new(Counters::default()),
        stop_rx,
    ));
    let failed = tokio::time::timeout(
        WAIT,
        status.wait_for(|s| matches!(s.phase, Phase::Failed(_))),
    )
    .await
    .unwrap()
    .unwrap()
    .phase
    .clone();
    assert_eq!(failed, Phase::Failed(FailReason::NoPrivilege));
    assert_eq!(server.used(&id), 0);

    // Retried with rights, as a new run. The hold ends as the failed run's
    // connection is seen to close, which takes a moment.
    let mut retried = None;
    for _ in 0..200 {
        let attempt = server.raw(secret, "with-rights", None).await;
        if attempt.welcomed() {
            retried = Some(attempt);
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let mut retried = retried.expect("the Code is still usable");
    retried.send_first_frame().await;
    server.wait_used(&id, 1).await;
}

#[tokio::test]
async fn nothing_is_sent_until_the_first_frame() {
    let server = start_managed("gate").await;
    let (id, secret) = server.once();
    let mut other = server.peer(SECRET_A, "other");
    let other_net = other.connected().await;

    let mut client = server.raw(secret, "quiet", None).await;
    let Frame::Welcome(welcome) = client.reply.clone() else {
        panic!("expected Welcome");
    };
    assert_eq!(server.used(&id), 0);
    // Someone is trying to reach it, and there is a member list to send.
    other
        .wait_for("sees the newcomer", |s| s.members.len() == 2)
        .await;
    other
        .inject
        .send(packet(other_net.ip, welcome.ip, b"hello"))
        .unwrap();
    let early = tokio::time::timeout(
        Duration::from_millis(400),
        read_frame(&mut client.stream, MAX_SERVER_FRAME),
    )
    .await;
    assert!(early.is_err(), "sent before first use: {early:?}");

    // Another device is held off meanwhile.
    let refused = server.raw(secret, "rival", None).await;
    assert_eq!(refused.rejected(), Some(RejectReason::CodeUsed));

    client.send_first_frame().await;
    server.wait_used(&id, 1).await;
    let later = tokio::time::timeout(WAIT, read_frame(&mut client.stream, MAX_SERVER_FRAME))
        .await
        .unwrap()
        .unwrap();
    assert!(!matches!(later, Frame::Reject(_) | Frame::Welcome(_)));
}

#[tokio::test]
async fn leaving_before_the_first_frame_leaves_the_code_unused() {
    let server = start_managed("leave").await;
    let (id, secret) = server.once();
    let client = server.raw(secret, "gone", None).await;
    assert!(client.welcomed());
    drop(client);
    let mut next = None;
    for _ in 0..200 {
        let attempt = server.raw(secret, "next", None).await;
        if attempt.welcomed() {
            next = Some(attempt);
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(next.is_some(), "the Code stayed held");
    assert_eq!(server.used(&id), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_used_code_survives_a_server_restart_for_its_device_only() {
    let identity = tls::generate_identity().unwrap();
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    let (path, store) = test_store("restart");
    let (record, secret) = store
        .create_code("a", CodeKind::Once, "", unix_now())
        .unwrap();
    let server = start_isolated_server_with(addr, &identity, Some(store));
    let mut peer = spawn_peer(addr, identity.pin, secret, "first");
    let net = peer.connected().await;
    for _ in 0..200 {
        let codes = Store::load(path.clone(), unix_now()).unwrap().codes();
        if !codes[0].used_by.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(
        record.id,
        Store::load(path.clone(), unix_now()).unwrap().codes()[0].id
    );

    server.shutdown_background();
    peer.wait_for("reconnecting", |s| {
        matches!(s.phase, Phase::Reconnecting { .. })
    })
    .await;

    let reloaded = Arc::new(Store::load(path, unix_now()).unwrap());
    let restarted = start_isolated_server_with(addr, &identity, Some(reloaded));
    peer.wait_for("connected again", |s| s.phase == Phase::Connected)
        .await;
    assert_eq!(peer.status.borrow().net.as_ref().unwrap().ip, net.ip);
    let rival = raw_connect(addr, identity.pin, secret, "rival", None)
        .await
        .unwrap();
    assert_eq!(rival.rejected(), Some(RejectReason::CodeUsed));
    restarted.shutdown_background();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_timed_code_stops_admitting_but_never_drops_a_running_client() {
    let identity = tls::generate_identity().unwrap();
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    let (path, store) = test_store("timed");
    let kind = CodeKind::Timed {
        expires_at: unix_now() + 3,
    };
    let (_, secret) = store.create_code("a", kind, "", unix_now()).unwrap();
    let server = start_isolated_server_with(addr, &identity, Some(store.clone()));
    let mut first = spawn_peer(addr, identity.pin, secret, "first");
    let mut second = spawn_peer(addr, identity.pin, secret, "second");
    first.connected().await;
    second.connected().await;
    for _ in 0..200 {
        if store.codes()[0].used_by.len() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(store.codes()[0].used_by.len(), 2, "both devices may use it");

    tokio::time::sleep(Duration::from_secs(4)).await;
    assert_eq!(first.status.borrow().phase, Phase::Connected);

    // Past the deadline, and every connection is lost.
    server.shutdown_background();
    first
        .wait_for("reconnecting", |s| {
            matches!(s.phase, Phase::Reconnecting { .. })
        })
        .await;
    let reloaded = Arc::new(Store::load(path, unix_now()).unwrap());
    let restarted = start_isolated_server_with(addr, &identity, Some(reloaded));
    first
        .wait_for("connected again", |s| s.phase == Phase::Connected)
        .await;
    let mut late = spawn_peer(addr, identity.pin, secret, "late");
    assert_eq!(late.failure().await, FailReason::CodeExpired);
    restarted.shutdown_background();
}

#[tokio::test]
async fn kicking_stops_this_run_and_a_new_run_can_come_back() {
    let server = start_managed("kick").await;
    let (_, secret) = server.timed(3600);
    let mut peer = server.peer(secret, "kicked");
    peer.connected().await;
    let member = server.member("kicked");
    server.hub.kick_member(&member.id, unix_now()).unwrap();
    assert_eq!(peer.failure().await, FailReason::Removed);
    // Started again, it is a new run with a new client_id.
    let mut again = server.peer(secret, "again");
    again.connected().await;
}

#[tokio::test]
async fn kicking_applies_to_a_permanent_credential_too() {
    let server = start_managed("kick-permanent").await;
    let mut peer = server.peer(SECRET_A, "kicked");
    peer.connected().await;
    let id = server.member("kicked").id;
    server.hub.kick_member(&id, unix_now()).unwrap();
    assert_eq!(peer.failure().await, FailReason::Removed);
    let mut again = server.peer(SECRET_A, "again");
    again.connected().await;
}

#[tokio::test]
async fn a_banned_device_stays_out_whatever_code_it_brings_until_lifted() {
    let server = start_managed("device").await;
    let device = "a".repeat(64);
    let (_, secret) = server.timed(3600);
    let mut client = server.raw(secret, "banned", Some(&device)).await;
    assert!(client.welcomed());
    client.send_first_frame().await;
    assert_eq!(
        server.member("banned").device.as_deref(),
        Some(device.as_str())
    );

    let ban = server
        .hub
        .add_ban(BanTarget::Device(device.clone()), "", unix_now())
        .unwrap();
    let closed = tokio::time::timeout(WAIT, async {
        while read_frame(&mut client.stream, MAX_SERVER_FRAME)
            .await
            .is_ok()
        {}
    })
    .await;
    assert!(closed.is_ok(), "banned device stayed connected");

    let (_, other_code) = server.timed(3600);
    for code in [secret, other_code, SECRET_A] {
        let attempt = server.raw(code, "new-run", Some(&device)).await;
        assert_eq!(attempt.rejected(), Some(RejectReason::Removed));
    }
    server.store.remove_ban(&ban.id).unwrap();
    assert!(server
        .raw(other_code, "new-run", Some(&device))
        .await
        .welcomed());
}

#[tokio::test]
async fn an_invalid_device_id_cannot_be_banned_into_or_shown() {
    let server = start_managed("bad-device").await;
    let client = server
        .raw(SECRET_A, "odd", Some("<script>alert(1)</script>"))
        .await;
    assert!(client.welcomed());
    assert_eq!(server.member("odd").device, None);
}

#[tokio::test]
async fn a_banned_address_is_dropped_before_tls_until_lifted() {
    let server = start_managed("ip").await;
    let mut peer = server.peer(SECRET_A, "elsewhere");
    peer.connected().await;
    assert_eq!(
        server.member("elsewhere").peer,
        Some("127.0.0.1".parse().unwrap())
    );
    let target = BanTarget::Ip(parse_ip_target("127.0.0.1").unwrap());
    let ban = server.hub.add_ban(target, "", unix_now()).unwrap();
    peer.wait_for("disconnected", |s| {
        matches!(s.phase, Phase::Reconnecting { .. })
    })
    .await;
    let attempt = raw_connect(server.addr, server.identity.pin, SECRET_A, "x", None).await;
    assert!(attempt.is_err(), "a banned address got through TLS");

    server.store.remove_ban(&ban.id).unwrap();
    peer.wait_for("back", |s| s.phase == Phase::Connected).await;
}

#[tokio::test]
async fn revoking_a_code_removes_those_who_came_with_it_and_nobody_else() {
    let server = start_managed("revoke").await;
    let (id, secret) = server.timed(3600);
    let mut with_code = server.peer(secret, "with-code");
    let mut permanent = server.peer(SECRET_A, "permanent");
    with_code.connected().await;
    permanent.connected().await;
    assert_eq!(
        server.member("with-code").code.as_deref(),
        Some(id.as_str())
    );
    assert_eq!(server.member("permanent").code, None);

    server.hub.revoke_code(&id, unix_now()).unwrap();
    assert_eq!(with_code.failure().await, FailReason::CredentialRejected);
    let mut late = server.peer(secret, "late");
    assert_eq!(late.failure().await, FailReason::CredentialRejected);
    assert_eq!(permanent.status.borrow().phase, Phase::Connected);
}

#[tokio::test]
async fn a_code_for_a_network_no_longer_configured_is_refused() {
    let server = start_managed("gone-network").await;
    let (record, secret) = server
        .store
        .create_code("removed", CodeKind::Once, "", unix_now())
        .unwrap();
    let attempt = server.raw(secret, "x", None).await;
    assert_eq!(attempt.rejected(), Some(RejectReason::InvalidCredential));
    assert!(server.store.codes().iter().any(|c| c.id == record.id));
}

#[tokio::test]
async fn state_is_on_disk_as_soon_as_a_code_is_used() {
    let server = start_managed("disk").await;
    let (id, secret) = server.once();
    let mut peer = server.peer(secret, "first");
    peer.connected().await;
    server.wait_used(&id, 1).await;
    let reloaded = Store::load(server.state_path.clone(), unix_now()).unwrap();
    assert_eq!(reloaded.codes()[0].used_by[0].hostname, "first");
}
