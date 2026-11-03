//! Membership, address allocation and the forwarding rule. Holds no socket I/O, so
//! the security-relevant logic can be tested directly.
use super::store::{client_key, Ban, BanTarget, ChangeError, Store, Workspace, WorkspaceId};
use crate::proto::{ipv4_endpoints, Member, RejectReason};
use bytes::Bytes;
use ipnet::Ipv4Net;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch, Notify};

pub const LEASE_HOLD: Duration = Duration::from_secs(3600);
pub const SESSION_QUEUE: usize = 256;
const MAX_HOSTNAME: usize = 64;

/// Bytes through one connection, or one network. "rx" is what the server received
/// from a member, "tx" is what it sent them.
#[derive(Debug, Default)]
pub struct Traffic {
    rx: AtomicU64,
    tx: AtomicU64,
}

impl Traffic {
    pub fn rx(&self) -> u64 {
        self.rx.load(Ordering::Relaxed)
    }
    pub fn tx(&self) -> u64 {
        self.tx.load(Ordering::Relaxed)
    }
    pub fn add_rx(&self, bytes: usize) {
        self.rx.fetch_add(bytes as u64, Ordering::Relaxed);
    }
    pub fn add_tx(&self, bytes: usize) {
        self.tx.fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

struct Live {
    session_id: u64,
    tx: mpsc::Sender<Bytes>,
    kick: Arc<Notify>,
    traffic: Arc<Traffic>,
}

struct Lease {
    ip: Ipv4Addr,
    hostname: String,
    live: Option<Live>,
    offline_since: Instant,
    details: Details,
}

/// What the console shows about a connection.
#[derive(Debug, Clone, Default)]
pub struct Details {
    pub peer: Option<IpAddr>,
    pub device: Option<String>,
    pub code: Option<String>,
    pub since: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MemberView {
    /// A [`client_key`], which is safe to show and is what a kick is addressed to.
    pub id: String,
    pub workspace_id: WorkspaceId,
    pub hostname: String,
    pub ip: Ipv4Addr,
    pub peer: Option<IpAddr>,
    pub device: Option<String>,
    pub code: Option<String>,
    pub since: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct NetworkStats {
    pub workspace_id: WorkspaceId,
    pub online: usize,
    pub capacity: usize,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Default)]
struct State {
    leases: HashMap<String, Lease>,
    by_ip: HashMap<Ipv4Addr, String>,
    next_session: u64,
}

pub struct Network {
    id: WorkspaceId,
    name: RwLock<String>,
    cidr: Ipv4Net,
    state: Mutex<State>,
    members: watch::Sender<Arc<Vec<Member>>>,
    traffic: Traffic,
}

pub struct Hub {
    networks: RwLock<HashMap<WorkspaceId, Arc<Network>>>,
    store: Option<Arc<Store>>,
}

pub struct Session {
    pub network: Arc<Network>,
    client_id: String,
    pub session_id: u64,
    pub network_name: String,
    pub ip: Ipv4Addr,
    pub prefix: u8,
    pub hostname: String,
    pub rx: mpsc::Receiver<Bytes>,
    pub kick: Arc<Notify>,
    pub members: watch::Receiver<Arc<Vec<Member>>>,
    pub traffic: Arc<Traffic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Forward {
    Sent,
    NotIpv4,
    SpoofedSource,
    NoRoute,
    QueueFull,
}

/// Hostnames come from clients and reach logs and other members' screens.
fn sanitize_hostname(raw: &str) -> String {
    let clean: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_HOSTNAME)
        .collect();
    if clean.trim().is_empty() {
        "unknown".to_owned()
    } else {
        clean
    }
}

impl Network {
    fn new(id: WorkspaceId, name: &str, cidr: Ipv4Net) -> Self {
        Self {
            id,
            name: RwLock::new(name.to_owned()),
            cidr,
            state: Mutex::default(),
            members: watch::Sender::new(Arc::new(Vec::new())),
            traffic: Traffic::default(),
        }
    }

    pub fn id(&self) -> WorkspaceId {
        self.id
    }

    pub fn traffic(&self) -> &Traffic {
        &self.traffic
    }

    fn name(&self) -> String {
        self.name.read().expect("name lock poisoned").clone()
    }

    /// The whole isolation guarantee: a packet can only ever be delivered to
    /// another online member of the sender's own network.
    pub fn forward(&self, sender_ip: Ipv4Addr, packet: Bytes) -> Forward {
        let Some((src, dst)) = ipv4_endpoints(&packet) else {
            return Forward::NotIpv4;
        };
        if src != sender_ip {
            return Forward::SpoofedSource;
        }
        if dst == sender_ip {
            return Forward::NoRoute;
        }
        let state = self.state.lock().expect("hub lock poisoned");
        let target = state
            .by_ip
            .get(&dst)
            .and_then(|id| state.leases.get(id))
            .and_then(|lease| lease.live.as_ref());
        match target {
            None => Forward::NoRoute,
            // Never wait: dropping is what inner TCP treats as a congestion signal,
            // and a stuck receiver must not hold up the sender or the lock.
            Some(live) => match live.tx.try_send(packet) {
                Ok(()) => Forward::Sent,
                Err(_) => Forward::QueueFull,
            },
        }
    }

    fn views(&self) -> Vec<MemberView> {
        let state = self.state.lock().expect("hub lock poisoned");
        state
            .leases
            .iter()
            .filter(|(_, lease)| lease.live.is_some())
            .map(|(client_id, lease)| self.member_view(client_id, lease))
            .collect()
    }

    fn member_view(&self, client_id: &str, lease: &Lease) -> MemberView {
        let traffic = lease.live.as_ref().map(|live| &live.traffic);
        MemberView {
            id: client_key(client_id),
            workspace_id: self.id,
            hostname: lease.hostname.clone(),
            ip: lease.ip,
            peer: lease.details.peer,
            device: lease.details.device.clone(),
            code: lease.details.code.clone(),
            since: lease.details.since,
            rx_bytes: traffic.map_or(0, |t| t.rx()),
            tx_bytes: traffic.map_or(0, |t| t.tx()),
        }
    }

    /// Only ends connections. A client reconnects at once, so whatever should keep
    /// it out has to be recorded before calling this.
    fn disconnect_where(&self, matches: &dyn Fn(&MemberView) -> bool) -> usize {
        let state = self.state.lock().expect("hub lock poisoned");
        let mut count = 0;
        for (client_id, lease) in &state.leases {
            if let Some(live) = &lease.live {
                if matches(&self.member_view(client_id, lease)) {
                    live.kick.notify_one();
                    count += 1;
                }
            }
        }
        count
    }
}

impl Hub {
    pub fn new(workspaces: &[Workspace]) -> Self {
        let hub = Self {
            networks: RwLock::default(),
            store: None,
        };
        for workspace in workspaces {
            hub.add_network(workspace);
        }
        hub
    }

    pub fn with_store(mut self, store: Arc<Store>) -> Self {
        self.store = Some(store);
        self
    }

    pub fn store(&self) -> Option<&Arc<Store>> {
        self.store.as_ref()
    }

    /// Replaces nothing that is running: a workspace's range is checked on creation.
    pub fn add_network(&self, workspace: &Workspace) {
        let Some(cidr) = workspace.net() else {
            tracing::error!(workspace = workspace.id, cidr = %workspace.cidr, "stored range is invalid, network not started");
            return;
        };
        let network = Arc::new(Network::new(workspace.id, &workspace.name, cidr));
        self.networks
            .write()
            .expect("networks lock poisoned")
            .insert(workspace.id, network);
    }

    /// Its members are disconnected. By then their Codes are gone, so they stop
    /// instead of reconnecting.
    pub fn remove_network(&self, id: WorkspaceId) {
        let removed = self
            .networks
            .write()
            .expect("networks lock poisoned")
            .remove(&id);
        if let Some(network) = removed {
            network.disconnect_where(&|_| true);
        }
    }

    /// New range, new network: members are disconnected, reconnect, and get an
    /// address in it. The client recreates its NIC when its address changes.
    pub fn replace_network(&self, workspace: &Workspace) {
        let old = self
            .networks
            .read()
            .expect("networks lock poisoned")
            .get(&workspace.id)
            .cloned();
        self.add_network(workspace);
        if let Some(old) = old {
            old.disconnect_where(&|_| true);
        }
    }

    pub fn rename_network(&self, id: WorkspaceId, name: &str) {
        if let Some(network) = self.network(id) {
            *network.name.write().expect("name lock poisoned") = name.to_owned();
        }
    }

    pub fn network(&self, id: WorkspaceId) -> Option<Arc<Network>> {
        self.networks
            .read()
            .expect("networks lock poisoned")
            .get(&id)
            .cloned()
    }

    fn all_networks(&self) -> Vec<Arc<Network>> {
        self.networks
            .read()
            .expect("networks lock poisoned")
            .values()
            .cloned()
            .collect()
    }

    pub fn join(
        &self,
        network: WorkspaceId,
        client_id: &str,
        hostname: &str,
        prev_ip: Option<Ipv4Addr>,
        now: Instant,
    ) -> Result<Session, RejectReason> {
        let net = self
            .network(network)
            .ok_or(RejectReason::InvalidCredential)?;
        let hostname = sanitize_hostname(hostname);
        let (tx, rx) = mpsc::channel(SESSION_QUEUE);
        let kick = Arc::new(Notify::new());
        let traffic = Arc::new(Traffic::default());
        let mut guard = net.state.lock().expect("hub lock poisoned");
        let state = &mut *guard;
        expire(state, now);

        let ip = match state.leases.get(client_id) {
            Some(lease) => lease.ip,
            None => allocate(net.cidr, state, prev_ip).ok_or(RejectReason::NetworkFull)?,
        };
        state.next_session += 1;
        let session_id = state.next_session;
        let live = Live {
            session_id,
            tx,
            kick: kick.clone(),
            traffic: traffic.clone(),
        };
        match state.leases.get_mut(client_id) {
            Some(lease) => {
                // A reconnect can arrive before the old connection is seen to die.
                if let Some(old) = lease.live.replace(live) {
                    old.kick.notify_one();
                }
                lease.hostname = hostname.clone();
            }
            None => {
                state.by_ip.insert(ip, client_id.to_owned());
                state.leases.insert(
                    client_id.to_owned(),
                    Lease {
                        ip,
                        hostname: hostname.clone(),
                        live: Some(live),
                        offline_since: now,
                        details: Details::default(),
                    },
                );
            }
        }
        publish_members(&net, state);
        drop(guard);
        Ok(Session {
            network_name: net.name(),
            prefix: net.cidr.prefix_len(),
            members: net.members.subscribe(),
            network: net,
            client_id: client_id.to_owned(),
            session_id,
            ip,
            hostname,
            rx,
            kick,
            traffic,
        })
    }

    /// Ignored if the session was already replaced, so an old connection dying
    /// late cannot take a fresh one offline.
    pub fn leave(&self, session: &Session, now: Instant) {
        let net = &session.network;
        let mut guard = net.state.lock().expect("hub lock poisoned");
        let state = &mut *guard;
        let Some(lease) = state.leases.get_mut(&session.client_id) else {
            return;
        };
        if lease
            .live
            .as_ref()
            .is_some_and(|live| live.session_id == session.session_id)
        {
            lease.live = None;
            lease.offline_since = now;
            publish_members(net, state);
        }
    }

    pub fn describe(&self, session: &Session, details: Details) {
        let mut state = session.network.state.lock().expect("hub lock poisoned");
        if let Some(lease) = state.leases.get_mut(&session.client_id) {
            lease.details = details;
        }
    }

    pub fn members(&self, workspace: WorkspaceId) -> Vec<MemberView> {
        let mut members = self.network(workspace).map_or_else(Vec::new, |n| n.views());
        members.sort_by_key(|member| member.ip);
        members
    }

    pub fn stats(&self) -> Vec<NetworkStats> {
        self.all_networks()
            .iter()
            .map(|net| {
                let state = net.state.lock().expect("hub lock poisoned");
                NetworkStats {
                    workspace_id: net.id,
                    online: state.leases.values().filter(|l| l.live.is_some()).count(),
                    capacity: net.cidr.hosts().count(),
                    rx_bytes: net.traffic.rx(),
                    tx_bytes: net.traffic.tx(),
                }
            })
            .collect()
    }

    fn require_store(&self) -> Result<&Arc<Store>, ChangeError> {
        self.store.as_ref().ok_or(ChangeError::NotFound)
    }

    /// Ends this run of the client. Whether it can come back after being started
    /// again depends on its Code.
    pub fn kick_member(
        &self,
        workspace: WorkspaceId,
        id: &str,
        now: u64,
    ) -> Result<MemberView, ChangeError> {
        let member = self
            .members(workspace)
            .into_iter()
            .find(|member| member.id == id)
            .ok_or(ChangeError::NotFound)?;
        self.require_store()?
            .kick(workspace, id, &member.hostname, now)?;
        if let Some(network) = self.network(workspace) {
            network.disconnect_where(&|member| member.id == id);
        }
        Ok(member)
    }

    pub fn delete_code(&self, workspace: WorkspaceId, id: &str) -> Result<(), ChangeError> {
        self.require_store()?.delete_code(workspace, id)?;
        self.disconnect_code(workspace, id);
        Ok(())
    }

    fn disconnect_code(&self, workspace: WorkspaceId, id: &str) {
        if let Some(network) = self.network(workspace) {
            network.disconnect_where(&|member| member.code.as_deref() == Some(id));
        }
    }

    /// A workspace's ban touches only its own members; `None` reaches all of them.
    pub fn add_ban(
        &self,
        workspace: Option<WorkspaceId>,
        target: BanTarget,
        note: &str,
        expires_at: Option<u64>,
        now: u64,
    ) -> Result<Ban, ChangeError> {
        let ban = self
            .require_store()?
            .add_ban(workspace, target, note, expires_at, now)?;
        let networks = match workspace {
            Some(id) => self.network(id).into_iter().collect(),
            None => self.all_networks(),
        };
        for network in networks {
            network.disconnect_where(&|member| {
                member.peer.is_some_and(|peer| ban.target.covers_ip(peer))
                    || ban.target.covers_device(member.device.as_deref())
            });
        }
        Ok(ban)
    }
}

fn expire(state: &mut State, now: Instant) {
    let by_ip = &mut state.by_ip;
    state.leases.retain(|_, lease| {
        let keep =
            lease.live.is_some() || now.saturating_duration_since(lease.offline_since) < LEASE_HOLD;
        if !keep {
            by_ip.remove(&lease.ip);
        }
        keep
    });
}

fn allocate(cidr: Ipv4Net, state: &State, prev_ip: Option<Ipv4Addr>) -> Option<Ipv4Addr> {
    // `hosts()` leaves out the network and broadcast addresses.
    let usable = |ip: &Ipv4Addr| !state.by_ip.contains_key(ip);
    if let Some(ip) = prev_ip {
        if cidr.hosts().any(|host| host == ip) && usable(&ip) {
            return Some(ip);
        }
    }
    cidr.hosts().find(usable)
}

fn publish_members(net: &Network, state: &State) {
    let mut members: Vec<Member> = state
        .leases
        .values()
        .filter(|lease| lease.live.is_some())
        .map(|lease| Member {
            hostname: lease.hostname.clone(),
            ip: lease.ip,
        })
        .collect();
    members.sort_by_key(|member| member.ip);
    net.members.send_replace(Arc::new(members));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace(id: WorkspaceId, cidr: &str) -> Workspace {
        Workspace {
            id,
            name: format!("w{id}"),
            cidr: cidr.into(),
            created_at: 0,
        }
    }

    fn hub() -> Hub {
        Hub::new(&[workspace(0, "10.1.0.0/24"), workspace(1, "10.2.0.0/30")])
    }

    fn packet(src: Ipv4Addr, dst: Ipv4Addr) -> Bytes {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        p.into()
    }

    fn join(hub: &Hub, net: WorkspaceId, id: &str) -> Session {
        hub.join(net, id, id, None, Instant::now()).unwrap()
    }

    #[test]
    fn members_reach_each_other() {
        let hub = hub();
        let a = join(&hub, 0, "a");
        let mut b = join(&hub, 0, "b");
        assert_eq!(
            hub.network(0).unwrap().forward(a.ip, packet(a.ip, b.ip)),
            Forward::Sent
        );
        assert!(b.rx.try_recv().is_ok());
    }

    #[test]
    fn spoofed_source_is_dropped() {
        let hub = hub();
        let a = join(&hub, 0, "a");
        let mut b = join(&hub, 0, "b");
        let forged = packet(Ipv4Addr::new(10, 1, 0, 200), b.ip);
        assert_eq!(
            hub.network(0).unwrap().forward(a.ip, forged),
            Forward::SpoofedSource
        );
        assert!(b.rx.try_recv().is_err());
    }

    #[test]
    fn other_networks_are_unreachable() {
        let hub = hub();
        let a = join(&hub, 0, "a");
        let mut other = join(&hub, 1, "x");
        assert_eq!(
            hub.network(0)
                .unwrap()
                .forward(a.ip, packet(a.ip, other.ip)),
            Forward::NoRoute
        );
        assert!(other.rx.try_recv().is_err());
    }

    #[test]
    fn outside_broadcast_multicast_self_and_non_ipv4_go_nowhere() {
        let hub = hub();
        let a = join(&hub, 0, "a");
        let _b = join(&hub, 0, "b");
        for dst in [
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(10, 1, 0, 255),
            Ipv4Addr::new(255, 255, 255, 255),
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::LOCALHOST,
            a.ip,
        ] {
            assert_eq!(
                hub.network(0).unwrap().forward(a.ip, packet(a.ip, dst)),
                Forward::NoRoute,
                "{dst}"
            );
        }
        let mut v6 = packet(a.ip, a.ip).to_vec();
        v6[0] = 0x60;
        assert_eq!(
            hub.network(0).unwrap().forward(a.ip, v6.into()),
            Forward::NotIpv4
        );
    }

    #[test]
    fn full_queue_drops_instead_of_blocking() {
        let hub = hub();
        let a = join(&hub, 0, "a");
        let b = join(&hub, 0, "stuck");
        for _ in 0..SESSION_QUEUE {
            assert_eq!(
                hub.network(0).unwrap().forward(a.ip, packet(a.ip, b.ip)),
                Forward::Sent
            );
        }
        assert_eq!(
            hub.network(0).unwrap().forward(a.ip, packet(a.ip, b.ip)),
            Forward::QueueFull
        );
    }

    #[test]
    fn allocates_lowest_free_host_and_reports_full() {
        let hub = hub();
        let first = join(&hub, 1, "1");
        let second = join(&hub, 1, "2");
        assert_eq!(first.ip, Ipv4Addr::new(10, 2, 0, 1));
        assert_eq!(second.ip, Ipv4Addr::new(10, 2, 0, 2));
        let third = hub.join(1, "3", "3", None, Instant::now());
        assert_eq!(third.err(), Some(RejectReason::NetworkFull));
    }

    #[test]
    fn prev_ip_is_honoured_only_when_free_and_inside_the_network() {
        let hub = hub();
        let now = Instant::now();
        let wanted = Ipv4Addr::new(10, 1, 0, 50);
        assert_eq!(hub.join(0, "a", "a", Some(wanted), now).unwrap().ip, wanted);
        assert_ne!(hub.join(0, "b", "b", Some(wanted), now).unwrap().ip, wanted);
        for bad in [
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(10, 1, 0, 0),
            Ipv4Addr::new(10, 1, 0, 255),
        ] {
            let id = bad.to_string();
            assert_ne!(hub.join(0, &id, &id, Some(bad), now).unwrap().ip, bad);
        }
    }

    #[test]
    fn lease_survives_disconnect_then_expires() {
        let hub = hub();
        let start = Instant::now();
        let first = hub.join(0, "a", "a", None, start).unwrap();
        let ip = first.ip;
        hub.leave(&first, start);
        // Held for its owner against other clients.
        let other = hub.join(0, "b", "b", None, start).unwrap();
        assert_ne!(other.ip, ip);
        let back = hub
            .join(0, "a", "a", None, start + Duration::from_secs(60))
            .unwrap();
        assert_eq!(back.ip, ip);
        hub.leave(&back, start);
        // After the hold, the lowest free address is available again.
        let later = start + LEASE_HOLD + Duration::from_secs(1);
        assert_eq!(hub.join(0, "c", "c", None, later).unwrap().ip, ip);
    }

    #[test]
    fn online_lease_never_expires() {
        let hub = hub();
        let start = Instant::now();
        let a = hub.join(0, "a", "a", None, start).unwrap();
        let later = start + LEASE_HOLD * 10;
        assert_ne!(hub.join(0, "b", "b", None, later).unwrap().ip, a.ip);
    }

    #[test]
    fn reconnect_kicks_the_old_session_and_a_late_leave_is_ignored() {
        let hub = hub();
        let a = join(&hub, 0, "c");
        let old = join(&hub, 0, "a");
        let mut new = join(&hub, 0, "a");
        assert_eq!(old.ip, new.ip);
        // Old connection finishes dying after the replacement arrived.
        hub.leave(&old, Instant::now());
        assert_eq!(
            hub.network(0).unwrap().forward(a.ip, packet(a.ip, new.ip)),
            Forward::Sent
        );
        assert!(new.rx.try_recv().is_ok());
    }

    #[test]
    fn member_list_tracks_joins_and_leaves_within_one_network() {
        let hub = hub();
        let a = join(&hub, 0, "a");
        let _other = join(&hub, 1, "x");
        let b = join(&hub, 0, "b");
        assert_eq!(a.members.borrow().len(), 2);
        hub.leave(&b, Instant::now());
        let names: Vec<_> = a
            .members
            .borrow()
            .iter()
            .map(|m| m.hostname.clone())
            .collect();
        assert_eq!(names, ["a"]);
    }

    #[test]
    fn hostnames_are_sanitized() {
        assert_eq!(sanitize_hostname("ok\n\x1b[31mfake"), "ok[31mfake");
        assert_eq!(sanitize_hostname("  \n"), "unknown");
        assert_eq!(sanitize_hostname(&"x".repeat(500)).len(), MAX_HOSTNAME);
    }

    #[test]
    fn identical_ranges_in_two_workspaces_stay_apart() {
        let hub = Hub::new(&[workspace(0, "10.1.0.0/24"), workspace(1, "10.1.0.0/24")]);
        let a = join(&hub, 0, "a");
        let mut b = join(&hub, 1, "b");
        assert_eq!(a.ip, b.ip, "same range, same first address");
        let other = join(&hub, 0, "c");
        let net = hub.network(0).unwrap();
        assert_eq!(net.forward(a.ip, packet(a.ip, other.ip)), Forward::Sent);
        assert!(b.rx.try_recv().is_err());
        assert_eq!(hub.members(0).len(), 2);
        assert_eq!(hub.members(1).len(), 1);
    }

    #[test]
    fn removing_a_network_disconnects_and_forgets_it() {
        let hub = hub();
        let a = join(&hub, 0, "a");
        hub.remove_network(0);
        assert!(hub.network(0).is_none());
        assert_eq!(
            hub.join(0, "x", "x", None, Instant::now()).err(),
            Some(RejectReason::InvalidCredential)
        );
        let notified = a.kick.notified();
        tokio::pin!(notified);
        assert!(notified.as_mut().enable(), "the member was told to go");
    }

    #[test]
    fn a_new_range_disconnects_members_and_gives_addresses_inside_it() {
        let hub = hub();
        let a = join(&hub, 0, "a");
        hub.replace_network(&workspace(0, "10.9.0.0/24"));
        let notified = a.kick.notified();
        tokio::pin!(notified);
        assert!(notified.as_mut().enable());
        // The old address is not honoured: it is outside the new range.
        let back = hub.join(0, "a", "a", Some(a.ip), Instant::now()).unwrap();
        assert_eq!(back.ip, Ipv4Addr::new(10, 9, 0, 1));
        // A late goodbye from the old network does not disturb the new one.
        hub.leave(&a, Instant::now());
        assert_eq!(hub.members(0).len(), 1);
    }

    #[test]
    fn renaming_applies_without_disconnecting() {
        let hub = hub();
        let a = join(&hub, 0, "a");
        hub.rename_network(0, "renamed");
        assert_eq!(join(&hub, 0, "b").network_name, "renamed");
        assert_eq!(a.network_name, "w0");
    }

    #[test]
    fn stats_count_members_and_capacity() {
        let hub = hub();
        let _a = join(&hub, 0, "a");
        let stats = hub.stats();
        let first = stats.iter().find(|s| s.workspace_id == 0).unwrap();
        assert_eq!((first.online, first.capacity), (1, 254));
    }
}
