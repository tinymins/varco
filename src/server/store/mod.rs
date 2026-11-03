//! Everything the server remembers, in one SQLite file: settings, workspaces,
//! accounts, Codes, bans and history. Holds no sockets, and takes the time as a
//! parameter, so these rules can be tested without connections or waiting.
mod accounts;
mod codes;
mod records;
#[cfg(test)]
mod tests;

pub use accounts::{
    hash_password, verify_password, AdminView, ApiToken, Role, SessionView, SshKey, TokenInfo,
    User, UserOverview,
};
pub use codes::{
    AdmitError, AdmittedCode, CodeLimits, CodeRecord, CodeStatus, CodeUse, Reservation, UseDetails,
};
pub use records::{AuditEntry, Ban, BanTarget, ConnectionRecord, Kicked, NewConnection};

use crate::credential::generate_secret;
use anyhow::Context;
use ipnet::{IpNet, Ipv4Net};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

pub type WorkspaceId = i64;
pub type UserId = i64;

pub const ROOT_USERNAME: &str = "root";
pub const ROOT_DEFAULT_PASSWORD: &str = "admin";
/// Long enough for a kicked client to have retried and stopped.
pub const KICK_HOLD_SECS: u64 = 7 * 24 * 3600;
pub const DEFAULT_HISTORY_DAYS: u64 = 30;
/// Bounds the member list size and leaves room for at least two hosts.
pub const MIN_PREFIX: u8 = 20;
pub const MAX_PREFIX: u8 = 30;

pub const SETTING_PUBLIC_ADDR: &str = "public_addr";
pub const SETTING_RELAY_LISTEN: &str = "relay_listen";
pub const SETTING_HISTORY_DAYS: &str = "history_days";

const SCHEMA_VERSION: i64 = 2;
const SCHEMA: &str = "
CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE workspaces (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    cidr TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_super INTEGER NOT NULL DEFAULT 0,
    must_change_password INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
);
CREATE TABLE memberships (
    user_id INTEGER NOT NULL REFERENCES users ON DELETE CASCADE,
    workspace_id INTEGER NOT NULL REFERENCES workspaces ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin')),
    PRIMARY KEY (user_id, workspace_id)
);
CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    user_agent TEXT NOT NULL
);
CREATE TABLE api_tokens (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    token TEXT NOT NULL,
    workspace_id INTEGER REFERENCES workspaces ON DELETE CASCADE,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    last_used INTEGER
);
CREATE TABLE ssh_keys (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users ON DELETE CASCADE,
    name TEXT NOT NULL,
    public_key TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (user_id, fingerprint)
);
CREATE TABLE codes (
    id TEXT PRIMARY KEY,
    secret_hash TEXT NOT NULL UNIQUE,
    secret BLOB NOT NULL,
    workspace_id INTEGER NOT NULL REFERENCES workspaces ON DELETE CASCADE,
    max_uses INTEGER,
    expires_at INTEGER,
    note TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE code_uses (
    code_id TEXT NOT NULL REFERENCES codes ON DELETE CASCADE,
    client TEXT NOT NULL,
    device TEXT,
    hostname TEXT NOT NULL,
    peer TEXT NOT NULL,
    at INTEGER NOT NULL,
    PRIMARY KEY (code_id, client)
);
CREATE TABLE bans (
    id TEXT PRIMARY KEY,
    workspace_id INTEGER REFERENCES workspaces ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('device', 'ip')),
    value TEXT NOT NULL,
    note TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER
);
CREATE TABLE kicked (
    workspace_id INTEGER NOT NULL REFERENCES workspaces ON DELETE CASCADE,
    client TEXT NOT NULL,
    hostname TEXT NOT NULL,
    at INTEGER NOT NULL,
    PRIMARY KEY (workspace_id, client)
);
CREATE TABLE connections (
    id INTEGER PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspaces ON DELETE CASCADE,
    client TEXT NOT NULL,
    hostname TEXT NOT NULL,
    ip TEXT NOT NULL,
    peer TEXT NOT NULL,
    device TEXT,
    code_id TEXT,
    started_at INTEGER NOT NULL,
    ended_at INTEGER,
    rx_bytes INTEGER NOT NULL DEFAULT 0,
    tx_bytes INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX connections_by_workspace ON connections (workspace_id, started_at);
-- Outlives what it describes on purpose, so no foreign key.
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY,
    at INTEGER NOT NULL,
    actor TEXT NOT NULL,
    workspace_id INTEGER,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    source TEXT NOT NULL
);
CREATE INDEX audit_by_workspace ON audit_log (workspace_id, at);
";

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn random_id() -> String {
    hex(&generate_secret()[..8])
}

/// Hash of anything that acts as a credential. Only this is stored or shown.
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

/// A v4 client reaching a dual-stack socket appears as `::ffff:a.b.c.d`.
pub fn canonical(ip: IpAddr) -> IpAddr {
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

pub fn parse_cidr(text: &str) -> Result<Ipv4Net, ChangeError> {
    let net: Ipv4Net = text
        .trim()
        .parse()
        .map_err(|_| ChangeError::Invalid("网段格式不正确，例如 10.77.1.0/24".to_owned()))?;
    if !(MIN_PREFIX..=MAX_PREFIX).contains(&net.prefix_len()) {
        return Err(ChangeError::Invalid(format!(
            "网段掩码要在 /{MIN_PREFIX} 到 /{MAX_PREFIX} 之间"
        )));
    }
    Ok(net.trunc())
}

/// A bad value would only surface later, as issued Codes that cannot connect.
pub fn is_host_port(addr: &str) -> bool {
    addr.rsplit_once(':').is_some_and(|(host, port)| {
        !host.is_empty()
            && !host.contains(char::is_whitespace)
            && !host.contains("://")
            && port.parse::<u16>().is_ok_and(|port| port != 0)
    })
}

#[derive(Debug, thiserror::Error)]
pub enum ChangeError {
    #[error("not found")]
    NotFound,
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Invalid(String),
    #[error("cannot save: {0}")]
    Db(#[from] rusqlite::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Workspace {
    pub id: WorkspaceId,
    pub name: String,
    pub cidr: String,
    pub created_at: u64,
}

impl Workspace {
    pub fn net(&self) -> Option<Ipv4Net> {
        self.cidr.parse().ok()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PageRequest<'a> {
    pub query: &'a str,
    pub limit: u32,
    pub offset: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub total: u64,
}

pub(crate) fn like_pattern(query: &str) -> String {
    let escaped = query
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    format!("%{escaped}%")
}

pub(crate) struct Inner {
    pub(crate) db: Connection,
    /// (code id, client key) of connections that have not yet sent their first
    /// frame, with the sequence number of the reservation that holds each one.
    pub(crate) pending: HashMap<(String, String), u64>,
    pub(crate) next_seq: u64,
    /// Checked for every new connection before TLS, so it must not touch the disk.
    pub(crate) global_ip_bans: Vec<(IpNet, Option<u64>)>,
}

pub struct Store {
    pub(crate) inner: Mutex<Inner>,
}

impl Store {
    /// A damaged file stops the server: starting empty would make used Codes
    /// usable again and lift every ban.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let db = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        restrict_permissions(path);
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "foreign_keys", true)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        let version: i64 = db.pragma_query_value(None, "user_version", |row| row.get(0))?;
        match version {
            0 => {
                db.execute_batch(&format!(
                    "BEGIN; {SCHEMA} PRAGMA user_version = {SCHEMA_VERSION}; COMMIT;"
                ))
                .with_context(|| format!("creating tables in {}", path.display()))?;
            }
            SCHEMA_VERSION => {}
            other => anyhow::bail!(
                "{} has data version {other}, this program understands {SCHEMA_VERSION}",
                path.display()
            ),
        }
        let store = Self {
            inner: Mutex::new(Inner {
                db,
                pending: HashMap::new(),
                next_seq: 0,
                global_ip_bans: Vec::new(),
            }),
        };
        {
            let mut inner = store.lock();
            records::reload_global_ip_bans(&mut inner)?;
        }
        store.ensure_root()?;
        Ok(store)
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().expect("store lock poisoned")
    }

    // ---- Settings ----

    pub fn setting(&self, key: &str) -> rusqlite::Result<Option<String>> {
        self.lock()
            .db
            .query_row("SELECT value FROM settings WHERE key = ?1", [key], |row| {
                row.get(0)
            })
            .optional()
    }

    pub fn set_setting(&self, key: &str, value: &str) -> rusqlite::Result<()> {
        self.lock().db.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn history_days(&self) -> rusqlite::Result<u64> {
        Ok(self
            .setting(SETTING_HISTORY_DAYS)?
            .and_then(|text| text.parse().ok())
            .unwrap_or(DEFAULT_HISTORY_DAYS))
    }

    // ---- Workspaces ----

    pub fn create_workspace(
        &self,
        name: &str,
        cidr: Ipv4Net,
        now: u64,
    ) -> Result<Workspace, ChangeError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(ChangeError::Invalid("工作区名称不能为空".to_owned()));
        }
        let inner = self.lock();
        let inserted = inner.db.execute(
            "INSERT INTO workspaces (name, cidr, created_at) VALUES (?1, ?2, ?3)",
            params![name, cidr.to_string(), now as i64],
        );
        match inserted {
            Ok(_) => Ok(Workspace {
                id: inner.db.last_insert_rowid(),
                name: name.to_owned(),
                cidr: cidr.to_string(),
                created_at: now,
            }),
            Err(error) if is_unique_violation(&error) => {
                Err(ChangeError::Conflict("已有同名工作区".to_owned()))
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn workspaces(&self) -> rusqlite::Result<Vec<Workspace>> {
        let inner = self.lock();
        let mut statement = inner
            .db
            .prepare("SELECT id, name, cidr, created_at FROM workspaces ORDER BY name")?;
        let rows = statement.query_map([], workspace_from_row)?;
        rows.collect()
    }

    pub fn workspace(&self, id: WorkspaceId) -> rusqlite::Result<Option<Workspace>> {
        self.lock()
            .db
            .query_row(
                "SELECT id, name, cidr, created_at FROM workspaces WHERE id = ?1",
                [id],
                workspace_from_row,
            )
            .optional()
    }

    pub fn update_workspace(
        &self,
        id: WorkspaceId,
        name: Option<&str>,
        cidr: Option<Ipv4Net>,
    ) -> Result<Workspace, ChangeError> {
        if name.is_some_and(|name| name.trim().is_empty()) {
            return Err(ChangeError::Invalid("工作区名称不能为空".to_owned()));
        }
        {
            let inner = self.lock();
            let changed = inner.db.execute(
                "UPDATE workspaces SET name = COALESCE(?2, name), cidr = COALESCE(?3, cidr)
                 WHERE id = ?1",
                params![id, name.map(str::trim), cidr.map(|net| net.to_string())],
            );
            match changed {
                Ok(0) => return Err(ChangeError::NotFound),
                Ok(_) => {}
                Err(error) if is_unique_violation(&error) => {
                    return Err(ChangeError::Conflict("已有同名工作区".to_owned()));
                }
                Err(error) => return Err(error.into()),
            }
        }
        self.workspace(id)?.ok_or(ChangeError::NotFound)
    }

    /// Everything in it goes too. Accounts left with no workspace are removed,
    /// since nothing is left for them to log in to.
    pub fn delete_workspace(&self, id: WorkspaceId) -> Result<(), ChangeError> {
        let mut inner = self.lock();
        let transaction = inner.db.transaction()?;
        let affected = transaction.execute("DELETE FROM workspaces WHERE id = ?1", [id])?;
        if affected == 0 {
            return Err(ChangeError::NotFound);
        }
        accounts::delete_orphans(&transaction)?;
        transaction.commit()?;
        records::reload_global_ip_bans(&mut inner)?;
        Ok(())
    }

    /// The first free range, as a starting point. Ranges may overlap between
    /// workspaces because they never reach each other.
    pub fn suggest_cidr(&self) -> rusqlite::Result<String> {
        let taken: Vec<String> = self.workspaces()?.into_iter().map(|w| w.cidr).collect();
        let free = (1..=254u8)
            .map(|third| format!("10.77.{third}.0/24"))
            .find(|cidr| !taken.contains(cidr));
        Ok(free.unwrap_or_else(|| "10.78.1.0/24".to_owned()))
    }

    /// What ages out. Called on a timer.
    pub fn purge(&self, now: u64) -> rusqlite::Result<()> {
        let days = self.history_days()?;
        let cutoff = now.saturating_sub(days.saturating_mul(86400)) as i64;
        let mut inner = self.lock();
        inner.db.execute(
            "DELETE FROM connections WHERE ended_at IS NOT NULL AND ended_at < ?1",
            [cutoff],
        )?;
        inner
            .db
            .execute("DELETE FROM audit_log WHERE at < ?1", [cutoff])?;
        inner.db.execute(
            "DELETE FROM kicked WHERE at <= ?1",
            [now.saturating_sub(KICK_HOLD_SECS) as i64],
        )?;
        inner.db.execute(
            "DELETE FROM bans WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            [now as i64],
        )?;
        inner
            .db
            .execute("DELETE FROM sessions WHERE expires_at <= ?1", [now as i64])?;
        records::reload_global_ip_bans(&mut inner)
    }
}

fn workspace_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Workspace> {
    Ok(Workspace {
        id: row.get(0)?,
        name: row.get(1)?,
        cidr: row.get(2)?,
        created_at: row.get::<_, i64>(3)? as u64,
    })
}

pub(crate) fn is_unique_violation(error: &rusqlite::Error) -> bool {
    matches!(
        error.sqlite_error_code(),
        Some(rusqlite::ErrorCode::ConstraintViolation)
    )
}

/// Holds Codes and API tokens that work as they are. The WAL files take the same mode from it.
fn restrict_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}
