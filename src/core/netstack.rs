//! A TCP stack inside this process, for machines that cannot have a virtual NIC.
//! It answers mesh packets itself and accepts nothing but the SSH port, so this
//! machine stays reachable without any change to its network configuration.
use super::engine::{Device, DeviceFactory, NetInfo};
use super::error::FailReason;
use super::ssh::{ListenSource, MAX_CONNECTIONS, PORT};
use bytes::Bytes;
use rand::RngCore;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration as StackDuration, Instant as StackInstant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::{mpsc, watch, Mutex, Notify};
use tokio::task::AbortHandle;

const QUEUE_PACKETS: usize = 256;
const SOCKET_BUFFER: usize = 256 * 1024;
const STREAM_BUFFER: usize = 64 * 1024;
const CHUNK: usize = 16 * 1024;
/// Keeps a slot from being held forever by a peer that vanished with data unacknowledged.
const UNACKED_TIMEOUT: StackDuration = StackDuration::from_secs(300);

/// Where the SSH server takes connections from once the stack is up.
#[derive(Clone)]
pub struct MeshEndpoint {
    pub ip: Ipv4Addr,
    pub listener: MeshListener,
}

#[derive(Clone)]
pub struct MeshListener {
    accepted: Arc<Mutex<mpsc::Receiver<(DuplexStream, SocketAddr)>>>,
}

impl MeshListener {
    pub async fn accept(&self) -> io::Result<(DuplexStream, SocketAddr)> {
        self.accepted
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "stack stopped"))
    }
}

pub struct NetstackFactory {
    endpoint: watch::Sender<Option<MeshEndpoint>>,
}

impl NetstackFactory {
    pub fn new() -> (Self, watch::Receiver<Option<MeshEndpoint>>) {
        let (endpoint, receiver) = watch::channel(None);
        (Self { endpoint }, receiver)
    }
}

impl DeviceFactory for NetstackFactory {
    type Device = NetstackDevice;

    fn create(&self, net: &NetInfo) -> Result<NetstackDevice, FailReason> {
        let (device, listener) = spawn_listening_stack(net);
        self.endpoint.send_replace(Some(MeshEndpoint {
            ip: net.ip,
            listener,
        }));
        Ok(device)
    }

    fn ssh_source(&self) -> ListenSource {
        ListenSource::Mesh(self.endpoint.subscribe())
    }
}

pub struct NetstackDevice {
    inbound: mpsc::Sender<Bytes>,
    outbound: Mutex<mpsc::Receiver<Bytes>>,
    wake: Arc<Notify>,
    task: AbortHandle,
}

impl Device for NetstackDevice {
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let packet = self.outbound.lock().await.recv().await;
        let packet = packet.ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
        // The stack holds back while this queue is full.
        self.wake.notify_one();
        let len = packet.len().min(buf.len());
        buf[..len].copy_from_slice(&packet[..len]);
        Ok(len)
    }

    async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        match self.inbound.try_send(Bytes::copy_from_slice(buf)) {
            // As on a real NIC, TCP recovers whatever a full queue loses.
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(buf.len()),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            }
        }
    }
}

impl Drop for NetstackDevice {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Phy {
    inbound: VecDeque<Bytes>,
    outbound: mpsc::Sender<Bytes>,
    mtu: usize,
}

struct RxToken(Bytes);

impl phy::RxToken for RxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

struct TxToken<'a>(&'a mpsc::Sender<Bytes>);

impl phy::TxToken for TxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        let _ = self.0.try_send(packet.into());
        result
    }
}

impl phy::Device for Phy {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn receive(&mut self, _now: StackInstant) -> Option<(RxToken, TxToken<'_>)> {
        if self.outbound.capacity() == 0 {
            return None;
        }
        let packet = self.inbound.pop_front()?;
        Some((RxToken(packet), TxToken(&self.outbound)))
    }

    fn transmit(&mut self, _now: StackInstant) -> Option<TxToken<'_>> {
        (self.outbound.capacity() > 0).then_some(TxToken(&self.outbound))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities
    }
}

struct WakeStack(Arc<Notify>);

impl Wake for WakeStack {
    fn wake(self: Arc<Self>) {
        self.0.notify_one();
    }
}

/// Bytes read from one side and not yet taken by the other.
struct Chunk {
    data: Vec<u8>,
    start: usize,
    end: usize,
}

impl Chunk {
    fn new() -> Self {
        Self {
            data: vec![0; CHUNK],
            start: 0,
            end: 0,
        }
    }
    fn is_empty(&self) -> bool {
        self.start == self.end
    }
    fn ready(&self) -> &[u8] {
        &self.data[self.start..self.end]
    }
    /// Only meaningful while empty, which is the only time it is refilled.
    fn refill(&mut self) -> &mut [u8] {
        self.start = 0;
        self.end = 0;
        &mut self.data
    }
    fn filled(&mut self, len: usize) {
        self.end = len;
    }
    fn consume(&mut self, len: usize) {
        self.start += len;
    }
}

/// Joins an established TCP socket to the stream the application holds. Neither
/// side is read until the other has room, so backpressure crosses it intact.
struct Conn {
    stream: DuplexStream,
    to_app: Chunk,
    to_peer: Chunk,
    app_finished: bool,
    peer_finished: bool,
    closed: bool,
    app_gone: bool,
}

impl Conn {
    fn new(stream: DuplexStream) -> Self {
        Self {
            stream,
            to_app: Chunk::new(),
            to_peer: Chunk::new(),
            app_finished: false,
            peer_finished: false,
            closed: false,
            app_gone: false,
        }
    }

    /// True when anything moved, meaning the stack has new work.
    fn pump(&mut self, socket: &mut tcp::Socket<'_>, cx: &mut Context<'_>) -> bool {
        let mut moved = false;

        loop {
            if self.to_app.is_empty() && socket.can_recv() {
                match socket.recv_slice(self.to_app.refill()) {
                    Ok(len) => {
                        self.to_app.filled(len);
                        moved |= len > 0;
                    }
                    Err(_) => break,
                }
            }
            if self.to_app.is_empty() {
                break;
            }
            match Pin::new(&mut self.stream).poll_write(cx, self.to_app.ready()) {
                Poll::Ready(Ok(len)) => {
                    self.to_app.consume(len);
                    moved = true;
                }
                Poll::Ready(Err(_)) => {
                    self.app_gone = true;
                    socket.abort();
                    return true;
                }
                Poll::Pending => break,
            }
        }
        if self.to_app.is_empty()
            && !socket.may_recv()
            && !self.peer_finished
            && Pin::new(&mut self.stream).poll_shutdown(cx).is_ready()
        {
            self.peer_finished = true;
            moved = true;
        }

        loop {
            if self.to_peer.is_empty() && !self.app_finished && socket.can_send() {
                let mut read = ReadBuf::new(self.to_peer.refill());
                match Pin::new(&mut self.stream).poll_read(cx, &mut read) {
                    Poll::Ready(Ok(())) => {
                        let len = read.filled().len();
                        self.to_peer.filled(len);
                        self.app_finished = len == 0;
                        moved = true;
                    }
                    Poll::Ready(Err(_)) => {
                        self.app_gone = true;
                        socket.abort();
                        return true;
                    }
                    Poll::Pending => {}
                }
            }
            if self.to_peer.is_empty() {
                break;
            }
            match socket.send_slice(self.to_peer.ready()) {
                Ok(len) if len > 0 => {
                    self.to_peer.consume(len);
                    moved = true;
                }
                _ => break,
            }
        }
        if self.app_finished && self.to_peer.is_empty() && !self.closed {
            socket.close();
            self.closed = true;
            moved = true;
        }
        moved
    }

    /// A socket can finish closing while the application is still behind. What
    /// it received stays readable until now, and recycling it would discard that.
    fn delivered_everything(&self, socket: &tcp::Socket<'_>) -> bool {
        self.app_gone || (self.peer_finished && self.to_app.is_empty() && !socket.can_recv())
    }
}

struct Slot {
    handle: SocketHandle,
    conn: Option<Conn>,
}

fn new_socket() -> tcp::Socket<'static> {
    tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER]),
        tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER]),
    )
}

/// Keystrokes should not wait for an acknowledgement, a dead peer must not pin a
/// slot, and without congestion control a large `scp` overruns the relay's queues
/// and stalls on retransmission timeouts.
fn tune(socket: &mut tcp::Socket<'_>) {
    socket.set_nagle_enabled(false);
    socket.set_congestion_control(tcp::CongestionControl::Reno);
    socket.set_timeout(Some(UNACKED_TIMEOUT));
}

fn peer_address(socket: &tcp::Socket<'_>) -> Option<SocketAddr> {
    let remote = socket.remote_endpoint()?;
    let IpAddress::Ipv4(ip) = remote.addr;
    Some(SocketAddr::new(IpAddr::V4(ip), remote.port))
}

fn spawn_listening_stack(net: &NetInfo) -> (NetstackDevice, MeshListener) {
    let mut sockets = SocketSet::new(Vec::new());
    let mut slots: Vec<Slot> = (0..MAX_CONNECTIONS)
        .map(|_| Slot {
            handle: sockets.add(new_socket()),
            conn: None,
        })
        .collect();
    let (accept_tx, accept_rx) = mpsc::channel(MAX_CONNECTIONS);
    let service =
        move |sockets: &mut SocketSet<'static>, _iface: &mut Interface, cx: &mut Context<'_>| {
            let mut moved = false;
            for slot in &mut slots {
                let socket = sockets.get_mut::<tcp::Socket>(slot.handle);
                if let Some(conn) = &mut slot.conn {
                    moved |= conn.pump(socket, cx);
                    if !socket.is_open() && conn.delivered_everything(socket) {
                        slot.conn = None;
                    }
                }
                if !socket.is_open() && slot.conn.is_none() {
                    // Cannot fail: the port is constant and the socket is closed.
                    let _ = socket.listen(PORT);
                    continue;
                }
                if slot.conn.is_none() && socket.is_active() && socket.may_send() {
                    let (ours, theirs) = tokio::io::duplex(STREAM_BUFFER);
                    let accepted = peer_address(socket)
                        .is_some_and(|peer| accept_tx.try_send((theirs, peer)).is_ok());
                    if accepted {
                        tune(socket);
                        slot.conn = Some(Conn::new(ours));
                    } else {
                        socket.abort();
                    }
                    moved = true;
                }
            }
            moved
        };
    let device = spawn_stack(net, sockets, service);
    let listener = MeshListener {
        accepted: Arc::new(Mutex::new(accept_rx)),
    };
    (device, listener)
}

fn spawn_stack<S>(net: &NetInfo, sockets: SocketSet<'static>, service: S) -> NetstackDevice
where
    S: FnMut(&mut SocketSet<'static>, &mut Interface, &mut Context<'_>) -> bool + Send + 'static,
{
    let (inbound_tx, inbound_rx) = mpsc::channel(QUEUE_PACKETS);
    let (outbound_tx, outbound_rx) = mpsc::channel(QUEUE_PACKETS);
    let wake = Arc::new(Notify::new());
    let mut phy = Phy {
        inbound: VecDeque::new(),
        outbound: outbound_tx,
        mtu: usize::from(net.mtu),
    };
    let origin = Instant::now();
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = rand::rng().next_u64();
    let mut iface = Interface::new(config, &mut phy, stack_now(origin));
    let cidr = IpCidr::new(IpAddress::Ipv4(net.ip), net.prefix);
    iface.update_ip_addrs(|addrs| {
        addrs.push(cidr).expect("one address fits");
    });
    let task = tokio::spawn(run_stack(
        iface,
        phy,
        sockets,
        inbound_rx,
        wake.clone(),
        origin,
        service,
    ));
    NetstackDevice {
        inbound: inbound_tx,
        outbound: Mutex::new(outbound_rx),
        wake,
        task: task.abort_handle(),
    }
}

fn stack_now(origin: Instant) -> StackInstant {
    StackInstant::from_micros(origin.elapsed().as_micros() as i64)
}

async fn run_stack<S>(
    mut iface: Interface,
    mut phy: Phy,
    mut sockets: SocketSet<'static>,
    mut inbound: mpsc::Receiver<Bytes>,
    wake: Arc<Notify>,
    origin: Instant,
    mut service: S,
) where
    S: FnMut(&mut SocketSet<'static>, &mut Interface, &mut Context<'_>) -> bool,
{
    let waker = Waker::from(Arc::new(WakeStack(wake.clone())));
    loop {
        while let Ok(packet) = inbound.try_recv() {
            phy.inbound.push_back(packet);
        }
        // A block of its own: a `Context` must not be held across an await.
        {
            let mut cx = Context::from_waker(&waker);
            loop {
                iface.poll(stack_now(origin), &mut phy, &mut sockets);
                let moved = service(&mut sockets, &mut iface, &mut cx);
                let stalled = phy.inbound.is_empty() || phy.outbound.capacity() == 0;
                if !moved && stalled {
                    break;
                }
            }
        }
        let delay = iface.poll_delay(stack_now(origin), &sockets);
        tokio::select! {
            packet = inbound.recv() => match packet {
                Some(packet) => phy.inbound.push_back(packet),
                None => return,
            },
            _ = wake.notified() => {}
            _ = wait_for(delay) => {}
        }
        // The streams are polled by hand, so this is what returns their budget.
        tokio::task::yield_now().await;
    }
}

async fn wait_for(delay: Option<StackDuration>) {
    match delay {
        Some(delay) => tokio::time::sleep(Duration::from_micros(delay.total_micros())).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ssh::{self, SshState};
    use crate::credential::generate_secret;
    use russh::client;
    use russh::keys::ssh_key::private::Ed25519Keypair;
    use russh::keys::PrivateKey;
    use smoltcp::wire::IpEndpoint;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::oneshot;

    const WAIT: Duration = Duration::from_secs(60);
    const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 77, 1, 2);
    const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 77, 1, 3);

    fn net(ip: Ipv4Addr) -> NetInfo {
        NetInfo {
            network: "test".to_owned(),
            ip,
            prefix: 24,
            mtu: 1280,
        }
    }

    type Connected = oneshot::Sender<Result<DuplexStream, ()>>;

    struct Dialing {
        handle: SocketHandle,
        port: u16,
        started: bool,
        connected: Option<Connected>,
        conn: Option<Conn>,
    }

    /// The far side of the mesh: the same stack, dialling out over the same glue.
    struct Client {
        requests: mpsc::UnboundedSender<(u16, Connected)>,
        wake: Arc<Notify>,
        _wire: tokio::task::JoinHandle<()>,
    }

    impl Client {
        async fn dial(&self, port: u16) -> Result<DuplexStream, ()> {
            let (done, result) = oneshot::channel();
            self.requests.send((port, done)).unwrap();
            self.wake.notify_one();
            tokio::time::timeout(WAIT, result).await.unwrap().unwrap()
        }
    }

    fn spawn_client(server: NetstackDevice, drop_every: Option<u64>) -> Client {
        let (requests, mut pending) = mpsc::unbounded_channel::<(u16, Connected)>();
        let mut dialing: Vec<Dialing> = Vec::new();
        let mut next_local_port = 49152u16;
        let service =
            move |sockets: &mut SocketSet<'static>, iface: &mut Interface, cx: &mut Context<'_>| {
                let mut moved = false;
                while let Ok((port, connected)) = pending.try_recv() {
                    dialing.push(Dialing {
                        handle: sockets.add(new_socket()),
                        port,
                        started: false,
                        connected: Some(connected),
                        conn: None,
                    });
                    moved = true;
                }
                for dial in &mut dialing {
                    let socket = sockets.get_mut::<tcp::Socket>(dial.handle);
                    if !dial.started {
                        let target = IpEndpoint::new(IpAddress::Ipv4(SERVER_IP), dial.port);
                        socket
                            .connect(iface.context(), target, next_local_port)
                            .unwrap();
                        next_local_port += 1;
                        dial.started = true;
                        moved = true;
                        continue;
                    }
                    if dial.conn.is_none() && socket.may_send() {
                        let (ours, theirs) = tokio::io::duplex(STREAM_BUFFER);
                        tune(socket);
                        dial.conn = Some(Conn::new(ours));
                        if let Some(connected) = dial.connected.take() {
                            let _ = connected.send(Ok(theirs));
                        }
                        moved = true;
                    } else if dial.conn.is_none() && !socket.is_open() {
                        if let Some(connected) = dial.connected.take() {
                            let _ = connected.send(Err(()));
                        }
                    }
                    if let Some(conn) = &mut dial.conn {
                        moved |= conn.pump(socket, cx);
                    }
                }
                moved
            };
        let client = spawn_stack(&net(CLIENT_IP), SocketSet::new(Vec::new()), service);
        let wake = client.wake.clone();
        let wire = tokio::spawn(run_wire(client, server, drop_every));
        Client {
            requests,
            wake,
            _wire: wire,
        }
    }

    async fn run_wire(client: NetstackDevice, server: NetstackDevice, drop_every: Option<u64>) {
        let (client, server) = (Arc::new(client), Arc::new(server));
        let forward = |from: Arc<NetstackDevice>, to: Arc<NetstackDevice>| async move {
            let mut buf = vec![0; 2048];
            let mut seen = 0u64;
            while let Ok(len) = from.recv(&mut buf).await {
                seen += 1;
                if drop_every.is_some_and(|every| seen.is_multiple_of(every)) {
                    continue;
                }
                if to.send(&buf[..len]).await.is_err() {
                    break;
                }
            }
        };
        tokio::join!(
            forward(client.clone(), server.clone()),
            forward(server, client)
        );
    }

    fn start_pair(drop_every: Option<u64>) -> (MeshListener, Client) {
        let (server, listener) = spawn_listening_stack(&net(SERVER_IP));
        (listener, spawn_client(server, drop_every))
    }

    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31) ^ seed)
            .collect()
    }

    async fn accept(listener: &MeshListener) -> (DuplexStream, SocketAddr) {
        tokio::time::timeout(WAIT, listener.accept())
            .await
            .expect("accept timed out")
            .unwrap()
    }

    async fn exchange(a: DuplexStream, b: DuplexStream, len: usize) {
        let (from_a, from_b) = (pattern(len, 0x11), pattern(len, 0x77));
        let (expect_at_a, expect_at_b) = (from_b.clone(), from_a.clone());
        let side = |mut stream: DuplexStream, send: Vec<u8>, expect: Vec<u8>| async move {
            let (mut reader, mut writer) = tokio::io::split(&mut stream);
            let write = async {
                writer.write_all(&send).await.unwrap();
                writer.shutdown().await.unwrap();
            };
            let read = async {
                let mut got = Vec::with_capacity(expect.len());
                reader.read_to_end(&mut got).await.unwrap();
                assert!(
                    got == expect,
                    "received {} of {} bytes intact",
                    got.len(),
                    expect.len()
                );
            };
            tokio::join!(write, read);
        };
        tokio::time::timeout(WAIT, async {
            tokio::join!(side(a, from_a, expect_at_a), side(b, from_b, expect_at_b));
        })
        .await
        .expect("transfer timed out");
    }

    #[tokio::test]
    async fn peer_address_comes_from_the_packet() {
        let (listener, client) = start_pair(None);
        let _stream = client.dial(PORT).await.unwrap();
        let (_accepted, peer) = accept(&listener).await;
        assert_eq!(peer.ip(), IpAddr::V4(CLIENT_IP));
    }

    #[tokio::test]
    async fn large_transfer_keeps_its_bytes_and_backpressure() {
        let (listener, client) = start_pair(None);
        let stream = client.dial(PORT).await.unwrap();
        let (accepted, _) = accept(&listener).await;
        // Far larger than every buffer between the two ends put together.
        exchange(stream, accepted, 8 * 1024 * 1024).await;
    }

    #[tokio::test]
    async fn transfer_survives_lost_packets() {
        let (listener, client) = start_pair(Some(50));
        let stream = client.dial(PORT).await.unwrap();
        let (accepted, _) = accept(&listener).await;
        exchange(stream, accepted, 256 * 1024).await;
    }

    #[tokio::test]
    async fn data_outlives_the_connection_closing() {
        let (listener, client) = start_pair(None);
        let mut stream = client.dial(PORT).await.unwrap();
        let (mut accepted, _) = accept(&listener).await;
        // The server finishes both ways while the client has read nothing, so
        // every buffer is full when the sockets reach their final states.
        let sent = pattern(512 * 1024, 0x42);
        let writer = {
            let sent = sent.clone();
            tokio::spawn(async move {
                accepted.write_all(&sent).await.unwrap();
            })
        };
        tokio::time::sleep(Duration::from_millis(500)).await;
        stream.shutdown().await.unwrap();
        let mut got = Vec::new();
        tokio::time::timeout(WAIT, stream.read_to_end(&mut got))
            .await
            .unwrap()
            .unwrap();
        writer.await.unwrap();
        assert!(
            got == sent,
            "received {} of {} bytes",
            got.len(),
            sent.len()
        );
    }

    #[tokio::test]
    async fn other_ports_are_refused() {
        let (_listener, client) = start_pair(None);
        for port in [22, 80, 445, PORT + 1] {
            assert!(client.dial(port).await.is_err(), "port {port}");
        }
    }

    #[tokio::test]
    async fn closed_connections_free_their_slots() {
        let (listener, client) = start_pair(None);
        for round in 0..MAX_CONNECTIONS * 3 {
            let mut stream = client.dial(PORT).await.unwrap();
            let (mut accepted, _) = accept(&listener).await;
            stream.write_all(&[round as u8]).await.unwrap();
            let mut byte = [0];
            accepted.read_exact(&mut byte).await.unwrap();
            assert_eq!(byte[0], round as u8);
            // The peer closes first, as an SSH client does, then the server follows.
            stream.shutdown().await.unwrap();
            assert_eq!(accepted.read(&mut byte).await.unwrap(), 0);
            drop(accepted);
            let mut rest = Vec::new();
            stream.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty());
        }
    }

    #[tokio::test]
    async fn connections_past_the_limit_are_refused() {
        let (listener, client) = start_pair(None);
        let mut held = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            let stream = client.dial(PORT).await.unwrap();
            let (accepted, _) = accept(&listener).await;
            held.push((stream, accepted));
        }
        assert!(client.dial(PORT).await.is_err());

        let (mut stream, accepted) = held.pop().unwrap();
        stream.shutdown().await.unwrap();
        drop(accepted);
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.unwrap();
        let mut reopened = Err(());
        for _ in 0..100 {
            reopened = client.dial(PORT).await;
            if reopened.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(reopened.is_ok(), "the freed slot must be usable again");
    }

    #[tokio::test]
    async fn dropping_the_device_ends_the_stack() {
        let (server, listener) = spawn_listening_stack(&net(SERVER_IP));
        drop(server);
        let result = tokio::time::timeout(WAIT, listener.accept()).await.unwrap();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn factory_publishes_the_address_it_serves() {
        let (factory, endpoint) = NetstackFactory::new();
        assert!(endpoint.borrow().is_none());
        let _device = factory.create(&net(SERVER_IP)).unwrap();
        assert_eq!(endpoint.borrow().as_ref().map(|e| e.ip), Some(SERVER_IP));
    }

    struct AcceptingClient;

    impl client::Handler for AcceptingClient {
        type Error = russh::Error;
        async fn check_server_key(
            &mut self,
            _key: &russh::keys::PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    fn new_key() -> PrivateKey {
        PrivateKey::from(Ed25519Keypair::from_seed(&generate_secret()))
    }

    async fn try_login(
        stream: DuplexStream,
        key: &PrivateKey,
    ) -> (client::Handle<AcceptingClient>, bool) {
        let config = Arc::new(client::Config::default());
        let mut session = client::connect_stream(config, stream, AcceptingClient)
            .await
            .unwrap();
        let with_hash = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key.clone()), None);
        let result = session.authenticate_publickey("anyone", with_hash).await;
        (session, matches!(result, Ok(client::AuthResult::Success)))
    }

    #[tokio::test]
    async fn ssh_server_runs_over_the_stack() {
        let (listener, client) = start_pair(None);
        let user_key = new_key();
        let (state_tx, mut state) = watch::channel(SshState::Starting);
        let (stop, stop_rx) = watch::channel(false);
        let serving = tokio::spawn(ssh::serve(
            listener,
            "10.77.1.0/24".parse().unwrap(),
            Arc::new(user_key.public_key().clone()),
            Arc::new(ssh::server_config(new_key())),
            state_tx,
            SERVER_IP,
            stop_rx,
        ));

        let stream = client.dial(PORT).await.unwrap();
        let (refused, logged_in) = try_login(stream, &new_key()).await;
        assert!(!logged_in, "another key must be refused");
        drop(refused);

        let stream = client.dial(PORT).await.unwrap();
        let (session, logged_in) = try_login(stream, &user_key).await;
        assert!(logged_in, "the right key must work");
        tokio::time::timeout(
            WAIT,
            state.wait_for(|s| matches!(s, SshState::Listening { connections: 1, .. })),
        )
        .await
        .unwrap()
        .unwrap();

        #[cfg(unix)]
        {
            let mut channel = session.channel_open_session().await.unwrap();
            channel.exec(true, "echo over-the-stack").await.unwrap();
            let mut output = Vec::new();
            while let Some(message) = tokio::time::timeout(WAIT, channel.wait()).await.unwrap() {
                match message {
                    russh::ChannelMsg::Data { data } => output.extend_from_slice(&data),
                    russh::ChannelMsg::Close => break,
                    _ => {}
                }
            }
            assert_eq!(output, b"over-the-stack\n");
        }

        drop(session);
        stop.send(true).unwrap();
        tokio::time::timeout(WAIT, serving).await.unwrap().unwrap();
    }
}
