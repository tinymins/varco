//! What the admin console changes while the server runs: limited-use Codes and
//! bans. Kept apart from the hub so these rules can be tested without connections.
//! Time is always passed in, so expiry needs no waiting in tests.
use crate::credential::{generate_secret, Secret};
use crate::proto::RejectReason;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

/// Long enough for a kicked client to have retried and stopped.
pub const KICK_HOLD_SECS: u64 = 7 * 24 * 3600;
const STATE_FILE: &str = "varco-state.json";

pub fn state_path(config_path: &Path) -> PathBuf {
    config_path.with_file_name(STATE_FILE)
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn random_id() -> String {
    hex(&generate_secret()[..8])
}

fn secret_key(secret: &Secret) -> String {
    hex(&Sha256::digest(secret))
}

/// A client_id works as a credential together with its Code, so only this is
/// stored or shown.
pub fn client_key(client_id: &str) -> String {
    hex(&Sha256::digest(client_id.as_bytes()))
}

/// `30m`, `24h` or `7d`, in seconds.
pub fn parse_duration(text: &str) -> Option<u64> {
    let text = text.trim();
    let unit = match text.chars().last()? {
        'm' => 60,
        'h' => 3600,
        'd' => 86400,
        _ => return None,
    };
    let count: u64 = text[..text.len() - 1].parse().ok()?;
    count.checked_mul(unit).filter(|secs| *secs > 0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CodeKind {
    /// One device, no time limit.
    Once,
    /// Any number of devices until the deadline.
    Timed { expires_at: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeUse {
    pub client: String,
    pub device: Option<String>,
    pub hostname: String,
    pub peer: IpAddr,
    pub at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeRecord {
    pub id: String,
    /// The Code itself is shown once and never stored.
    pub secret_hash: String,
    pub network: String,
    #[serde(flatten)]
    pub kind: CodeKind,
    pub note: String,
    pub created_at: u64,
    pub revoked_at: Option<u64>,
    pub used_by: Vec<CodeUse>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeStatus {
    Active,
    Used,
    Expired,
    Revoked,
}

impl CodeRecord {
    pub fn status(&self, now: u64) -> CodeStatus {
        if self.revoked_at.is_some() {
            return CodeStatus::Revoked;
        }
        match self.kind {
            CodeKind::Once if !self.used_by.is_empty() => CodeStatus::Used,
            CodeKind::Timed { expires_at } if now >= expires_at => CodeStatus::Expired,
            _ => CodeStatus::Active,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum BanTarget {
    Device(String),
    Ip(IpNet),
}

/// A v4 client reaching a dual-stack socket appears as `::ffff:a.b.c.d`.
fn canonical(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

/// One address or a CIDR range.
pub fn parse_ip_target(text: &str) -> Option<IpNet> {
    let text = text.trim();
    if let Ok(ip) = text.parse::<IpAddr>() {
        return Some(IpNet::from(canonical(ip)));
    }
    let net = text.parse::<IpNet>().ok()?;
    // Checked before truncating, which would turn a mapped address into another range.
    match canonical(net.addr()) {
        IpAddr::V4(addr) if net.addr().is_ipv6() => {
            let prefix = net.prefix_len().checked_sub(96)?;
            IpNet::new(IpAddr::V4(addr), prefix)
                .ok()
                .map(|net| net.trunc())
        }
        _ => Some(net.trunc()),
    }
}

impl BanTarget {
    pub fn covers_ip(&self, ip: IpAddr) -> bool {
        matches!(self, Self::Ip(net) if net.contains(&canonical(ip)))
    }

    pub fn covers_device(&self, device: Option<&str>) -> bool {
        matches!(self, Self::Device(banned) if Some(banned.as_str()) == device)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ban {
    pub id: String,
    #[serde(flatten)]
    pub target: BanTarget,
    pub note: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Kicked {
    client: String,
    at: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Disk {
    #[serde(default)]
    codes: Vec<CodeRecord>,
    #[serde(default)]
    bans: Vec<Ban>,
    #[serde(default)]
    kicked: Vec<Kicked>,
}

#[derive(Default)]
struct Inner {
    disk: Disk,
    /// (code id, client key) of connections that have not yet sent their first
    /// frame, with the sequence number of the reservation that holds each one.
    pending: HashMap<(String, String), u64>,
    next_seq: u64,
}

pub struct Store {
    path: PathBuf,
    inner: Mutex<Inner>,
}

#[derive(Debug, thiserror::Error)]
pub enum ChangeError {
    #[error("not found")]
    NotFound,
    #[error("already exists")]
    Conflict,
    #[error("cannot save state: {0}")]
    Io(#[from] io::Error),
}

/// A Code that passed its checks.
pub struct AdmittedCode {
    pub network: String,
    pub code_id: String,
    /// Present until this client has used the Code for real.
    pub reservation: Option<Reservation>,
}

pub struct UseDetails<'a> {
    pub device: Option<&'a str>,
    pub hostname: &'a str,
    pub peer: IpAddr,
}

/// Holds a Code for a connection that has not proved it is up and running.
/// Dropping it without [`Reservation::commit`] leaves the Code unused, so a NIC
/// that could not be created does not cost the person their Code.
pub struct Reservation {
    store: Arc<Store>,
    code_id: String,
    client: String,
    seq: u64,
}

impl Reservation {
    pub fn commit(&self, details: &UseDetails<'_>, now: u64) -> Result<(), ChangeError> {
        let mut inner = self.store.lock();
        let code = inner
            .disk
            .codes
            .iter()
            .find(|code| code.id == self.code_id)
            .ok_or(ChangeError::NotFound)?;
        if code.revoked_at.is_some() {
            return Err(ChangeError::NotFound);
        }
        if code.used_by.iter().any(|used| used.client == self.client) {
            return Ok(());
        }
        let record = CodeUse {
            client: self.client.clone(),
            device: details.device.map(str::to_owned),
            hostname: details.hostname.to_owned(),
            peer: canonical(details.peer),
            at: now,
        };
        self.store.change(&mut inner, |disk| {
            if let Some(code) = disk.codes.iter_mut().find(|c| c.id == self.code_id) {
                code.used_by.push(record);
            }
        })?;
        Ok(())
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let mut inner = self.store.lock();
        let key = (self.code_id.clone(), self.client.clone());
        // A reconnect may have taken over; its reservation is not ours to end.
        if inner.pending.get(&key) == Some(&self.seq) {
            inner.pending.remove(&key);
        }
    }
}

impl Store {
    /// A damaged file stops the server: starting empty would make used Codes
    /// usable again and lift every ban.
    pub fn load(path: PathBuf, now: u64) -> anyhow::Result<Self> {
        use anyhow::Context;
        let mut disk: Disk = match std::fs::read(&path) {
            Ok(text) => serde_json::from_slice(&text)
                .with_context(|| format!("parsing {}", path.display()))?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Disk::default(),
            Err(error) => {
                return Err(error).with_context(|| format!("reading {}", path.display()));
            }
        };
        prune_kicked(&mut disk, now);
        Ok(Self {
            path,
            inner: Mutex::new(Inner {
                disk,
                ..Inner::default()
            }),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().expect("state lock poisoned")
    }

    /// Nothing changes unless the change also reached the disk.
    fn change<T>(&self, inner: &mut Inner, apply: impl FnOnce(&mut Disk) -> T) -> io::Result<T> {
        let backup = inner.disk.clone();
        let result = apply(&mut inner.disk);
        match write_atomic(&self.path, &inner.disk) {
            Ok(()) => Ok(result),
            Err(error) => {
                inner.disk = backup;
                Err(error)
            }
        }
    }

    pub fn ip_banned(&self, ip: IpAddr) -> bool {
        self.lock()
            .disk
            .bans
            .iter()
            .any(|ban| ban.target.covers_ip(ip))
    }

    /// Banned device or kicked run.
    pub fn removed(&self, client_id: &str, device: Option<&str>) -> bool {
        let inner = self.lock();
        let client = client_key(client_id);
        inner.disk.kicked.iter().any(|k| k.client == client)
            || inner
                .disk
                .bans
                .iter()
                .any(|ban| ban.target.covers_device(device))
    }

    /// `Ok(None)` means this secret is not one of ours.
    pub fn admit_code(
        self: &Arc<Self>,
        secret: &Secret,
        client_id: &str,
        now: u64,
    ) -> Result<Option<AdmittedCode>, RejectReason> {
        let hash = secret_key(secret);
        let client = client_key(client_id);
        let mut inner = self.lock();
        let inner = &mut *inner;
        let Some(code) = inner.disk.codes.iter().find(|c| c.secret_hash == hash) else {
            return Ok(None);
        };
        if code.revoked_at.is_some() {
            return Ok(None);
        }
        // Before any limit: a Code's limits only apply to starting to use it.
        if code.used_by.iter().any(|used| used.client == client) {
            return Ok(Some(AdmittedCode {
                network: code.network.clone(),
                code_id: code.id.clone(),
                reservation: None,
            }));
        }
        match code.kind {
            CodeKind::Timed { expires_at } if now >= expires_at => {
                return Err(RejectReason::CodeExpired);
            }
            CodeKind::Once => {
                let held_by_other = inner
                    .pending
                    .keys()
                    .any(|(id, holder)| *id == code.id && *holder != client);
                if !code.used_by.is_empty() || held_by_other {
                    return Err(RejectReason::CodeUsed);
                }
            }
            CodeKind::Timed { .. } => {}
        }
        inner.next_seq += 1;
        let seq = inner.next_seq;
        inner.pending.insert((code.id.clone(), client.clone()), seq);
        Ok(Some(AdmittedCode {
            network: code.network.clone(),
            code_id: code.id.clone(),
            reservation: Some(Reservation {
                store: self.clone(),
                code_id: code.id.clone(),
                client,
                seq,
            }),
        }))
    }

    /// Run once a member is registered, so that a ban arriving between the first
    /// check and the registration is not missed by both.
    pub fn still_allowed(
        &self,
        peer: IpAddr,
        client_id: &str,
        device: Option<&str>,
        code_id: Option<&str>,
    ) -> bool {
        if self.ip_banned(peer) || self.removed(client_id, device) {
            return false;
        }
        code_id.is_none_or(|id| {
            self.lock()
                .disk
                .codes
                .iter()
                .any(|code| code.id == id && code.revoked_at.is_none())
        })
    }

    /// Returns the record and the secret, which exists nowhere else afterwards.
    pub fn create_code(
        &self,
        network: &str,
        kind: CodeKind,
        note: &str,
        now: u64,
    ) -> Result<(CodeRecord, Secret), ChangeError> {
        let secret = generate_secret();
        let record = CodeRecord {
            id: random_id(),
            secret_hash: secret_key(&secret),
            network: network.to_owned(),
            kind,
            note: note.to_owned(),
            created_at: now,
            revoked_at: None,
            used_by: Vec::new(),
        };
        let mut inner = self.lock();
        let stored = record.clone();
        self.change(&mut inner, |disk| disk.codes.push(stored))?;
        Ok((record, secret))
    }

    pub fn codes(&self) -> Vec<CodeRecord> {
        self.lock().disk.codes.clone()
    }

    pub fn revoke_code(&self, id: &str, now: u64) -> Result<(), ChangeError> {
        let mut inner = self.lock();
        let code = inner
            .disk
            .codes
            .iter()
            .find(|code| code.id == id)
            .ok_or(ChangeError::NotFound)?;
        if code.revoked_at.is_some() {
            return Ok(());
        }
        self.change(&mut inner, |disk| {
            if let Some(code) = disk.codes.iter_mut().find(|code| code.id == id) {
                code.revoked_at = Some(now);
            }
        })?;
        Ok(())
    }

    pub fn bans(&self) -> Vec<Ban> {
        self.lock().disk.bans.clone()
    }

    pub fn add_ban(&self, target: BanTarget, note: &str, now: u64) -> Result<Ban, ChangeError> {
        let mut inner = self.lock();
        if inner.disk.bans.iter().any(|ban| ban.target == target) {
            return Err(ChangeError::Conflict);
        }
        let ban = Ban {
            id: random_id(),
            target,
            note: note.to_owned(),
            created_at: now,
        };
        let stored = ban.clone();
        self.change(&mut inner, |disk| disk.bans.push(stored))?;
        Ok(ban)
    }

    pub fn remove_ban(&self, id: &str) -> Result<(), ChangeError> {
        let mut inner = self.lock();
        if !inner.disk.bans.iter().any(|ban| ban.id == id) {
            return Err(ChangeError::NotFound);
        }
        self.change(&mut inner, |disk| disk.bans.retain(|ban| ban.id != id))?;
        Ok(())
    }

    /// `client` is a [`client_key`]: the console never sees the id itself.
    pub fn kick(&self, client: &str, now: u64) -> Result<(), ChangeError> {
        let mut inner = self.lock();
        self.change(&mut inner, |disk| {
            prune_kicked(disk, now);
            if !disk.kicked.iter().any(|k| k.client == client) {
                disk.kicked.push(Kicked {
                    client: client.to_owned(),
                    at: now,
                });
            }
        })?;
        Ok(())
    }
}

fn prune_kicked(disk: &mut Disk, now: u64) {
    disk.kicked
        .retain(|kicked| now.saturating_sub(kicked.at) < KICK_HOLD_SECS);
}

fn write_atomic(path: &Path, disk: &Disk) -> io::Result<()> {
    let text = serde_json::to_vec_pretty(disk)?;
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".tmp");
    let temporary = PathBuf::from(temporary);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(&text)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&temporary, path)?;
    // Best effort: the rename has happened, so reporting failure now would leave
    // memory rolled back while the file has the change. A bare file name has an
    // empty parent, which means the current directory.
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        if let Ok(directory) = std::fs::File::open(parent) {
            let _ = directory.sync_all();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000_000;
    const PEER: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7));

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("varco-state-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn store(name: &str) -> Arc<Store> {
        let path = state_path(&temp_dir(name).join("config.toml"));
        Arc::new(Store::load(path, NOW).unwrap())
    }

    fn details() -> UseDetails<'static> {
        UseDetails {
            device: Some("d1"),
            hostname: "host",
            peer: PEER,
        }
    }

    fn timed(store: &Store, seconds: u64) -> (CodeRecord, Secret) {
        let kind = CodeKind::Timed {
            expires_at: NOW + seconds,
        };
        store.create_code("a", kind, "", NOW).unwrap()
    }

    fn admit(store: &Arc<Store>, secret: &Secret, client: &str) -> AdmittedCode {
        store.admit_code(secret, client, NOW).unwrap().unwrap()
    }

    fn reject(store: &Arc<Store>, secret: &Secret, client: &str, now: u64) -> RejectReason {
        match store.admit_code(secret, client, now) {
            Err(reason) => reason,
            Ok(_) => panic!("expected a rejection"),
        }
    }

    #[test]
    fn once_code_goes_to_one_device_and_stays_with_it() {
        let store = store("once");
        let (_, secret) = store.create_code("a", CodeKind::Once, "", NOW).unwrap();
        let first = admit(&store, &secret, "c1");
        assert_eq!(first.network, "a");
        first
            .reservation
            .as_ref()
            .unwrap()
            .commit(&details(), NOW)
            .unwrap();
        drop(first);
        assert_eq!(reject(&store, &secret, "c2", NOW), RejectReason::CodeUsed);
        // The device it went to reconnects with no further checks or reservation.
        assert!(admit(&store, &secret, "c1").reservation.is_none());
    }

    #[test]
    fn unconfirmed_connection_holds_the_code_only_while_it_lasts() {
        let store = store("hold");
        let (record, secret) = store.create_code("a", CodeKind::Once, "", NOW).unwrap();
        let first = admit(&store, &secret, "c1");
        assert_eq!(reject(&store, &secret, "c2", NOW), RejectReason::CodeUsed);
        drop(first);
        assert_eq!(store.codes()[0].status(NOW), CodeStatus::Active);
        assert!(store.codes()[0].used_by.is_empty());
        assert_eq!(admit(&store, &secret, "c2").code_id, record.id);
    }

    #[test]
    fn a_dying_old_connection_does_not_release_its_replacement() {
        let store = store("replace");
        let (_, secret) = store.create_code("a", CodeKind::Once, "", NOW).unwrap();
        let old = admit(&store, &secret, "c1");
        let new = admit(&store, &secret, "c1");
        drop(old);
        assert_eq!(reject(&store, &secret, "c2", NOW), RejectReason::CodeUsed);
        drop(new);
        let _ = admit(&store, &secret, "c2");
    }

    #[test]
    fn only_one_of_many_racing_devices_gets_a_once_code() {
        let store = store("race");
        let (_, secret) = store.create_code("a", CodeKind::Once, "", NOW).unwrap();
        let handles: Vec<_> = (0..16)
            .map(|index| {
                let store = store.clone();
                std::thread::spawn(move || store.admit_code(&secret, &format!("c{index}"), NOW))
            })
            .collect();
        // Results are all kept until counted, so no winner's hold has ended yet.
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let granted = results.iter().filter(|r| matches!(r, Ok(Some(_)))).count();
        let refused = results
            .iter()
            .filter(|r| matches!(r, Err(RejectReason::CodeUsed)))
            .count();
        assert_eq!((granted, refused), (1, 15));
    }

    #[test]
    fn timed_code_admits_many_until_it_expires_but_never_expires_a_user() {
        let store = store("timed");
        let (_, secret) = timed(&store, 100);
        let first = admit(&store, &secret, "c1");
        let second = admit(&store, &secret, "c2");
        first
            .reservation
            .as_ref()
            .unwrap()
            .commit(&details(), NOW)
            .unwrap();
        drop(first);
        drop(second);
        let later = NOW + 100;
        assert_eq!(store.codes()[0].status(later), CodeStatus::Expired);
        assert_eq!(
            reject(&store, &secret, "c3", later),
            RejectReason::CodeExpired
        );
        // c2 never finished joining, so the deadline applies to it.
        assert_eq!(
            reject(&store, &secret, "c2", later),
            RejectReason::CodeExpired
        );
        let back = store.admit_code(&secret, "c1", later).unwrap().unwrap();
        assert!(back.reservation.is_none());
    }

    #[test]
    fn revoking_beats_having_used_the_code() {
        let store = store("revoke");
        let (record, secret) = timed(&store, 100);
        let first = admit(&store, &secret, "c1");
        first
            .reservation
            .as_ref()
            .unwrap()
            .commit(&details(), NOW)
            .unwrap();
        drop(first);
        store.revoke_code(&record.id, NOW).unwrap();
        assert!(store.admit_code(&secret, "c1", NOW).unwrap().is_none());
        assert_eq!(store.codes()[0].status(NOW), CodeStatus::Revoked);
    }

    #[test]
    fn commit_is_refused_once_the_code_is_revoked() {
        let store = store("revoke-pending");
        let (record, secret) = store.create_code("a", CodeKind::Once, "", NOW).unwrap();
        let held = admit(&store, &secret, "c1");
        store.revoke_code(&record.id, NOW).unwrap();
        assert!(held
            .reservation
            .as_ref()
            .unwrap()
            .commit(&details(), NOW)
            .is_err());
    }

    #[test]
    fn unknown_secret_is_not_ours() {
        let store = store("unknown");
        assert!(store.admit_code(&[7; 32], "c1", NOW).unwrap().is_none());
    }

    #[test]
    fn state_survives_a_restart_without_the_secret_or_client_id() {
        let dir = temp_dir("reload");
        let path = state_path(&dir.join("config.toml"));
        let store = Arc::new(Store::load(path.clone(), NOW).unwrap());
        let (_, secret) = store.create_code("a", CodeKind::Once, "", NOW).unwrap();
        let used = admit(&store, &secret, "plain-client-id");
        used.reservation
            .as_ref()
            .unwrap()
            .commit(&details(), NOW)
            .unwrap();
        drop(used);
        store
            .add_ban(BanTarget::Device("bad".into()), "", NOW)
            .unwrap();
        store
            .add_ban(
                BanTarget::Ip(parse_ip_target("198.51.100.0/24").unwrap()),
                "",
                NOW,
            )
            .unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("plain-client-id"));
        assert!(!text.contains(&crate::credential::encode_secret(&secret)));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        let reloaded = Arc::new(Store::load(path, NOW).unwrap());
        assert_eq!(
            reject(&reloaded, &secret, "c2", NOW),
            RejectReason::CodeUsed
        );
        let back = reloaded
            .admit_code(&secret, "plain-client-id", NOW)
            .unwrap()
            .unwrap();
        assert!(back.reservation.is_none());
        assert!(reloaded.removed("anyone", Some("bad")));
        assert!(reloaded.ip_banned("198.51.100.9".parse().unwrap()));
    }

    #[test]
    fn a_config_path_with_no_directory_can_save() {
        // What `-c config.toml` gives. Relative to the crate root during tests.
        let name = format!("varco-state-test-{}.json", std::process::id());
        let store = Store::load(PathBuf::from(&name), NOW).unwrap();
        let saved = store.create_code("a", CodeKind::Once, "", NOW);
        let reloaded = Store::load(PathBuf::from(&name), NOW).map(|s| s.codes().len());
        let _ = std::fs::remove_file(&name);
        assert!(saved.is_ok());
        assert_eq!(store.codes().len(), 1);
        assert_eq!(reloaded.unwrap(), 1);
    }

    #[test]
    fn a_damaged_file_stops_the_server() {
        let dir = temp_dir("damaged");
        let path = state_path(&dir.join("config.toml"));
        std::fs::write(&path, "{ not json").unwrap();
        assert!(Store::load(path, NOW).is_err());
    }

    #[test]
    fn nothing_changes_when_saving_fails() {
        let dir = temp_dir("readonly");
        let path = dir.join("gone").join(STATE_FILE);
        let store = Arc::new(Store::load(path.clone(), NOW).unwrap());
        assert!(store.create_code("a", CodeKind::Once, "", NOW).is_err());
        assert!(store.codes().is_empty());
        assert!(store
            .add_ban(BanTarget::Device("d".into()), "", NOW)
            .is_err());
        assert!(!store.removed("c", Some("d")));

        // A Code that cannot record its first use must not be used.
        std::fs::create_dir(path.parent().unwrap()).unwrap();
        let (_, secret) = store.create_code("a", CodeKind::Once, "", NOW).unwrap();
        let held = admit(&store, &secret, "c1");
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
        assert!(held
            .reservation
            .as_ref()
            .unwrap()
            .commit(&details(), NOW)
            .is_err());
        assert!(store.codes()[0].used_by.is_empty());
    }

    #[test]
    fn kicks_are_forgotten_after_the_hold() {
        let dir = temp_dir("kick");
        let path = state_path(&dir.join("config.toml"));
        let store = Store::load(path.clone(), NOW).unwrap();
        store.kick(&client_key("c1"), NOW).unwrap();
        assert!(store.removed("c1", None));
        assert!(!store.removed("c2", None));
        assert!(Store::load(path.clone(), NOW + KICK_HOLD_SECS - 1)
            .unwrap()
            .removed("c1", None));
        assert!(!Store::load(path, NOW + KICK_HOLD_SECS)
            .unwrap()
            .removed("c1", None));
    }

    #[test]
    fn ip_bans_match_addresses_ranges_and_mapped_v6() {
        let store = store("ip");
        for text in ["203.0.113.7", "198.51.100.0/24", "2001:db8::/32"] {
            let target = BanTarget::Ip(parse_ip_target(text).unwrap());
            store.add_ban(target, "", NOW).unwrap();
        }
        for (ip, banned) in [
            ("203.0.113.7", true),
            ("203.0.113.8", false),
            ("198.51.100.200", true),
            ("::ffff:203.0.113.7", true),
            ("::ffff:198.51.100.1", true),
            ("2001:db8::1", true),
            ("2001:db9::1", false),
        ] {
            assert_eq!(store.ip_banned(ip.parse().unwrap()), banned, "{ip}");
        }
    }

    #[test]
    fn ip_targets_are_normalized_and_bad_ones_refused() {
        let parsed = |text| parse_ip_target(text).map(|net| net.to_string());
        assert_eq!(parsed("10.0.0.1").unwrap(), "10.0.0.1/32");
        assert_eq!(parsed("10.0.0.9/24").unwrap(), "10.0.0.0/24");
        assert_eq!(parsed("::ffff:10.0.0.1").unwrap(), "10.0.0.1/32");
        assert_eq!(parsed("::ffff:10.0.0.0/120").unwrap(), "10.0.0.0/24");
        for bad in ["", "host", "10.0.0.1/33", "::ffff:10.0.0.0/64"] {
            assert!(parse_ip_target(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn duplicate_ban_is_a_conflict_and_a_removed_ban_stops_applying() {
        let store = store("dup");
        let target = BanTarget::Device("d".into());
        let ban = store.add_ban(target.clone(), "", NOW).unwrap();
        assert!(matches!(
            store.add_ban(target, "", NOW),
            Err(ChangeError::Conflict)
        ));
        assert!(store.removed("c", Some("d")));
        assert!(!store.removed("c", None));
        store.remove_ban(&ban.id).unwrap();
        assert!(!store.removed("c", Some("d")));
        assert!(matches!(
            store.remove_ban(&ban.id),
            Err(ChangeError::NotFound)
        ));
    }

    #[test]
    fn still_allowed_catches_what_changed_since_the_first_check() {
        let store = store("recheck");
        let (record, _) = store.create_code("a", CodeKind::Once, "", NOW).unwrap();
        assert!(store.still_allowed(PEER, "c", Some("d"), Some(&record.id)));
        assert!(store.still_allowed(PEER, "c", None, None));
        store.revoke_code(&record.id, NOW).unwrap();
        assert!(!store.still_allowed(PEER, "c", Some("d"), Some(&record.id)));
        assert!(store.still_allowed(PEER, "c", Some("d"), None));
        store
            .add_ban(BanTarget::Ip(IpNet::from(PEER)), "", NOW)
            .unwrap();
        assert!(!store.still_allowed(PEER, "c", Some("d"), None));
    }

    #[test]
    fn durations_parse() {
        assert_eq!(parse_duration("30m"), Some(1800));
        assert_eq!(parse_duration(" 24h "), Some(86400));
        assert_eq!(parse_duration("7d"), Some(604800));
        for bad in ["", "h", "0h", "-1h", "1w", "24", "99999999999999999999d"] {
            assert_eq!(parse_duration(bad), None, "{bad}");
        }
    }
}
