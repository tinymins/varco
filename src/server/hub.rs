//! Membership, address allocation and the forwarding rule. Holds no socket I/O, so
//! the security-relevant logic can be tested directly.
use super::config::NetworkConfig;
use super::state::{client_key, Ban, BanTarget, ChangeError, Store};
use crate::credential::{secret_eq, Secret};
use crate::proto::{ipv4_endpoints, Member, RejectReason};
use bytes::Bytes;
use ipnet::Ipv4Net;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch, Notify};

pub const LEASE_HOLD: Duration = Duration::from_secs(3600);
pub const SESSION_QUEUE: usize = 256;
const MAX_HOSTNAME: usize = 64;

struct Live {
    session_id: u64,
    tx: mpsc::Sender<Bytes>,
    kick: Arc<Notify>,
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
    pub network: String,
    pub hostname: String,
    pub ip: Ipv4Addr,
    pub peer: Option<IpAddr>,
    pub device: Option<String>,
    pub code: Option<String>,
    pub since: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct NetworkView {
    pub name: String,
    pub cidr: String,
    pub online: usize,
    pub capacity: usize,
}

/// A secret from the config file: the console can list it but not change it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CredentialView {
    pub network: String,
    pub fingerprint: String,
}

#[derive(Default)]
struct State {
    leases: HashMap<String, Lease>,
    by_ip: HashMap<Ipv4Addr, String>,
    next_session: u64,
}

struct Network {
    name: String,
    cidr: Ipv4Net,
    state: Mutex<State>,
    members: watch::Sender<Arc<Vec<Member>>>,
}

pub struct Hub {
    secrets: Vec<(Secret, usize)>,
    networks: Vec<Network>,
    store: Option<Arc<Store>>,
}

pub struct Session {
    network: usize,
    client_id: String,
    pub session_id: u64,
    pub network_name: String,
    pub ip: Ipv4Addr,
    pub prefix: u8,
    pub hostname: String,
    pub rx: mpsc::Receiver<Bytes>,
    pub kick: Arc<Notify>,
    pub members: watch::Receiver<Arc<Vec<Member>>>,
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

impl Hub {
    pub fn new(configs: Vec<NetworkConfig>) -> Self {
        let mut secrets = Vec::new();
        let mut networks = Vec::with_capacity(configs.len());
        for (index, config) in configs.into_iter().enumerate() {
            secrets.extend(config.secrets.iter().map(|s| (*s, index)));
            networks.push(Network {
                name: config.name,
                cidr: config.cidr,
                state: Mutex::default(),
                members: watch::Sender::new(Arc::new(Vec::new())),
            });
        }
        Self {
            secrets,
            networks,
            store: None,
        }
    }

    /// Without a store only secrets from the config file are accepted.
    pub fn with_store(mut self, store: Arc<Store>) -> Self {
        self.store = Some(store);
        self
    }

    pub fn store(&self) -> Option<&Arc<Store>> {
        self.store.as_ref()
    }

    pub fn network_index(&self, name: &str) -> Option<usize> {
        self.networks.iter().position(|net| net.name == name)
    }

    /// Compares against every secret, so timing does not reveal which matched.
    pub fn authenticate(&self, secret: &Secret) -> Option<usize> {
        let mut found = None;
        for (candidate, network) in &self.secrets {
            if secret_eq(candidate, secret) {
                found = Some(*network);
            }
        }
        found
    }

    pub fn join(
        &self,
        network: usize,
        client_id: &str,
        hostname: &str,
        prev_ip: Option<Ipv4Addr>,
        now: Instant,
    ) -> Result<Session, RejectReason> {
        let net = &self.networks[network];
        let hostname = sanitize_hostname(hostname);
        let (tx, rx) = mpsc::channel(SESSION_QUEUE);
        let kick = Arc::new(Notify::new());
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
        publish_members(net, state);
        drop(guard);
        Ok(Session {
            network,
            client_id: client_id.to_owned(),
            session_id,
            network_name: net.name.clone(),
            ip,
            prefix: net.cidr.prefix_len(),
            hostname,
            rx,
            kick,
            members: net.members.subscribe(),
        })
    }

    /// The whole isolation guarantee: a packet can only ever be delivered to
    /// another online member of the sender's own network.
    pub fn forward(&self, network: usize, sender_ip: Ipv4Addr, packet: Bytes) -> Forward {
        let Some((src, dst)) = ipv4_endpoints(&packet) else {
            return Forward::NotIpv4;
        };
        if src != sender_ip {
            return Forward::SpoofedSource;
        }
        if dst == sender_ip {
            return Forward::NoRoute;
        }
        let state = self.networks[network]
            .state
            .lock()
            .expect("hub lock poisoned");
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

    /// Ignored if the session was already replaced, so an old connection dying
    /// late cannot take a fresh one offline.
    pub fn leave(&self, session: &Session, now: Instant) {
        let net = &self.networks[session.network];
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

    pub fn network(&self, session: &Session) -> usize {
        session.network
    }

    pub fn describe(&self, session: &Session, details: Details) {
        let net = &self.networks[session.network];
        let mut state = net.state.lock().expect("hub lock poisoned");
        if let Some(lease) = state.leases.get_mut(&session.client_id) {
            lease.details = details;
        }
    }

    pub fn members(&self) -> Vec<MemberView> {
        let mut members = Vec::new();
        for net in &self.networks {
            let state = net.state.lock().expect("hub lock poisoned");
            for (client_id, lease) in &state.leases {
                if lease.live.is_some() {
                    members.push(member_view(net, client_id, lease));
                }
            }
        }
        members.sort_by(|a, b| (&a.network, a.ip).cmp(&(&b.network, b.ip)));
        members
    }

    pub fn network_views(&self) -> Vec<NetworkView> {
        self.networks
            .iter()
            .map(|net| {
                let state = net.state.lock().expect("hub lock poisoned");
                NetworkView {
                    name: net.name.clone(),
                    cidr: net.cidr.to_string(),
                    online: state.leases.values().filter(|l| l.live.is_some()).count(),
                    capacity: net.cidr.hosts().count(),
                }
            })
            .collect()
    }

    pub fn credential_views(&self) -> Vec<CredentialView> {
        self.secrets
            .iter()
            .map(|(secret, network)| CredentialView {
                network: self.networks[*network].name.clone(),
                // A hash of a 32-byte random secret reveals nothing about it.
                fingerprint: client_key(&crate::credential::encode_secret(secret))[..16].to_owned(),
            })
            .collect()
    }

    /// Only ends connections. The client reconnects at once, so whatever should
    /// keep it out has to be recorded before calling this.
    fn disconnect_where(&self, matches: impl Fn(&MemberView) -> bool) -> usize {
        let mut count = 0;
        for net in &self.networks {
            let state = net.state.lock().expect("hub lock poisoned");
            for (client_id, lease) in &state.leases {
                if let Some(live) = &lease.live {
                    if matches(&member_view(net, client_id, lease)) {
                        live.kick.notify_one();
                        count += 1;
                    }
                }
            }
        }
        count
    }

    /// Ends this run of the client. Whether it can come back after being started
    /// again depends on its Code.
    pub fn kick_member(&self, id: &str, now: u64) -> Result<(), ChangeError> {
        if !self.members().iter().any(|member| member.id == id) {
            return Err(ChangeError::NotFound);
        }
        self.require_store()?.kick(id, now)?;
        self.disconnect_where(|member| member.id == id);
        Ok(())
    }

    pub fn revoke_code(&self, id: &str, now: u64) -> Result<(), ChangeError> {
        self.require_store()?.revoke_code(id, now)?;
        self.disconnect_where(|member| member.code.as_deref() == Some(id));
        Ok(())
    }

    pub fn add_ban(&self, target: BanTarget, note: &str, now: u64) -> Result<Ban, ChangeError> {
        let ban = self.require_store()?.add_ban(target, note, now)?;
        self.disconnect_where(|member| {
            member.peer.is_some_and(|peer| ban.target.covers_ip(peer))
                || ban.target.covers_device(member.device.as_deref())
        });
        Ok(ban)
    }

    fn require_store(&self) -> Result<&Arc<Store>, ChangeError> {
        self.store.as_ref().ok_or(ChangeError::NotFound)
    }
}

fn member_view(net: &Network, client_id: &str, lease: &Lease) -> MemberView {
    MemberView {
        id: client_key(client_id),
        network: net.name.clone(),
        hostname: lease.hostname.clone(),
        ip: lease.ip,
        peer: lease.details.peer,
        device: lease.details.device.clone(),
        code: lease.details.code.clone(),
        since: lease.details.since,
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

    const A: Secret = [1; 32];
    const B: Secret = [2; 32];

    fn hub() -> Hub {
        Hub::new(vec![
            NetworkConfig {
                name: "a".into(),
                cidr: "10.1.0.0/24".parse().unwrap(),
                secrets: vec![A],
            },
            NetworkConfig {
                name: "b".into(),
                cidr: "10.2.0.0/30".parse().unwrap(),
                secrets: vec![B],
            },
        ])
    }

    fn packet(src: Ipv4Addr, dst: Ipv4Addr) -> Bytes {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        p.into()
    }

    fn join(hub: &Hub, net: usize, id: &str) -> Session {
        hub.join(net, id, id, None, Instant::now()).unwrap()
    }

    #[test]
    fn secrets_select_their_network_and_others_fail() {
        let hub = hub();
        assert_eq!(hub.authenticate(&A), Some(0));
        assert_eq!(hub.authenticate(&B), Some(1));
        assert_eq!(hub.authenticate(&[3; 32]), None);
    }

    #[test]
    fn members_reach_each_other() {
        let hub = hub();
        let a = join(&hub, 0, "a");
        let mut b = join(&hub, 0, "b");
        assert_eq!(hub.forward(0, a.ip, packet(a.ip, b.ip)), Forward::Sent);
        assert!(b.rx.try_recv().is_ok());
    }

    #[test]
    fn spoofed_source_is_dropped() {
        let hub = hub();
        let a = join(&hub, 0, "a");
        let mut b = join(&hub, 0, "b");
        let forged = packet(Ipv4Addr::new(10, 1, 0, 200), b.ip);
        assert_eq!(hub.forward(0, a.ip, forged), Forward::SpoofedSource);
        assert!(b.rx.try_recv().is_err());
    }

    #[test]
    fn other_networks_are_unreachable() {
        let hub = hub();
        let a = join(&hub, 0, "a");
        let mut other = join(&hub, 1, "x");
        assert_eq!(
            hub.forward(0, a.ip, packet(a.ip, other.ip)),
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
                hub.forward(0, a.ip, packet(a.ip, dst)),
                Forward::NoRoute,
                "{dst}"
            );
        }
        let mut v6 = packet(a.ip, a.ip).to_vec();
        v6[0] = 0x60;
        assert_eq!(hub.forward(0, a.ip, v6.into()), Forward::NotIpv4);
    }

    #[test]
    fn full_queue_drops_instead_of_blocking() {
        let hub = hub();
        let a = join(&hub, 0, "a");
        let b = join(&hub, 0, "stuck");
        for _ in 0..SESSION_QUEUE {
            assert_eq!(hub.forward(0, a.ip, packet(a.ip, b.ip)), Forward::Sent);
        }
        assert_eq!(hub.forward(0, a.ip, packet(a.ip, b.ip)), Forward::QueueFull);
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
        assert_eq!(hub.forward(0, a.ip, packet(a.ip, new.ip)), Forward::Sent);
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
}
