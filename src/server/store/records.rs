//! Bans, kicks, connection history and the audit log.
use super::{
    canonical, client_key, like_pattern, parse_ip_target, random_id, ChangeError, Inner, Page,
    PageRequest, Store, WorkspaceId,
};
use ipnet::IpNet;
use rusqlite::params;
use serde::Serialize;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum BanTarget {
    Device(String),
    Ip(IpNet),
}

impl BanTarget {
    pub fn covers_ip(&self, ip: IpAddr) -> bool {
        matches!(self, Self::Ip(net) if net.contains(&canonical(ip)))
    }

    pub fn covers_device(&self, device: Option<&str>) -> bool {
        matches!(self, Self::Device(banned) if Some(banned.as_str()) == device)
    }

    fn parts(&self) -> (&'static str, String) {
        match self {
            Self::Device(id) => ("device", id.clone()),
            Self::Ip(net) => ("ip", net.to_string()),
        }
    }

    fn from_parts(kind: &str, value: String) -> Option<Self> {
        match kind {
            "device" => Some(Self::Device(value)),
            "ip" => parse_ip_target(&value).map(Self::Ip),
            _ => None,
        }
    }
}

/// `workspace_id` of `None` applies to every workspace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Ban {
    pub id: String,
    pub workspace_id: Option<WorkspaceId>,
    #[serde(flatten)]
    pub target: BanTarget,
    pub note: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Kicked {
    pub client: String,
    pub hostname: String,
    pub at: u64,
}

pub struct NewConnection<'a> {
    pub workspace: WorkspaceId,
    pub client: &'a str,
    pub hostname: &'a str,
    pub ip: std::net::Ipv4Addr,
    pub peer: IpAddr,
    pub device: Option<&'a str>,
    pub code_id: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConnectionRecord {
    pub id: i64,
    pub hostname: String,
    pub ip: String,
    pub peer: String,
    pub device: Option<String>,
    pub code_id: Option<String>,
    pub started_at: u64,
    pub ended_at: Option<u64>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditEntry {
    pub id: i64,
    pub at: u64,
    pub actor: String,
    pub workspace_id: Option<WorkspaceId>,
    pub action: String,
    pub target: String,
    pub source: String,
}

pub(super) fn reload_global_ip_bans(inner: &mut Inner) -> rusqlite::Result<()> {
    let mut statement = inner
        .db
        .prepare("SELECT value, expires_at FROM bans WHERE workspace_id IS NULL AND kind = 'ip'")?;
    let bans = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<i64>>(1)?.map(|at| at as u64),
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    inner.global_ip_bans = bans
        .into_iter()
        .filter_map(|(value, expires)| parse_ip_target(&value).map(|net| (net, expires)))
        .collect();
    Ok(())
}

fn ban_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Option<Ban>> {
    let kind: String = row.get(2)?;
    let value: String = row.get(3)?;
    let Some(target) = BanTarget::from_parts(&kind, value) else {
        return Ok(None);
    };
    Ok(Some(Ban {
        id: row.get(0)?,
        workspace_id: row.get(1)?,
        target,
        note: row.get(4)?,
        created_at: row.get::<_, i64>(5)? as u64,
        expires_at: row.get::<_, Option<i64>>(6)?.map(|at| at as u64),
    }))
}

impl Store {
    /// Before TLS, so only global bans can apply: which workspace a connection
    /// belongs to is not known yet.
    pub fn globally_banned_ip(&self, ip: IpAddr, now: u64) -> bool {
        let ip = canonical(ip);
        self.lock()
            .global_ip_bans
            .iter()
            .any(|(net, expires)| net.contains(&ip) && expires.is_none_or(|at| at > now))
    }

    /// Whether this workspace, or a global ban, keeps this connection out.
    pub fn blocked(
        &self,
        workspace: WorkspaceId,
        client_id: &str,
        device: Option<&str>,
        peer: IpAddr,
        now: u64,
    ) -> rusqlite::Result<bool> {
        let inner = self.lock();
        let kicked: i64 = inner.db.query_row(
            "SELECT COUNT(*) FROM kicked WHERE workspace_id = ?1 AND client = ?2",
            params![workspace, client_key(client_id)],
            |row| row.get(0),
        )?;
        if kicked > 0 {
            return Ok(true);
        }
        let mut statement = inner.db.prepare(
            "SELECT kind, value FROM bans
             WHERE (workspace_id IS NULL OR workspace_id = ?1)
               AND (expires_at IS NULL OR expires_at > ?2)",
        )?;
        let targets = statement.query_map(params![workspace, now as i64], |row| {
            Ok(BanTarget::from_parts(
                &row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
            ))
        })?;
        for target in targets {
            if target?.is_some_and(|t| t.covers_ip(peer) || t.covers_device(device)) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn add_ban(
        &self,
        workspace: Option<WorkspaceId>,
        target: BanTarget,
        note: &str,
        expires_at: Option<u64>,
        now: u64,
    ) -> Result<Ban, ChangeError> {
        let (kind, value) = target.parts();
        let mut inner = self.lock();
        let existing: i64 = inner.db.query_row(
            "SELECT COUNT(*) FROM bans
             WHERE workspace_id IS ?1 AND kind = ?2 AND value = ?3
               AND (expires_at IS NULL OR expires_at > ?4)",
            params![workspace, kind, value, now as i64],
            |row| row.get(0),
        )?;
        if existing > 0 {
            return Err(ChangeError::Conflict("已经在黑名单里".to_owned()));
        }
        let id = random_id();
        inner.db.execute(
            "INSERT INTO bans (id, workspace_id, kind, value, note, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                id,
                workspace,
                kind,
                value,
                note,
                now as i64,
                expires_at.map(|at| at as i64)
            ],
        )?;
        reload_global_ip_bans(&mut inner)?;
        Ok(Ban {
            id,
            workspace_id: workspace,
            target,
            note: note.to_owned(),
            created_at: now,
            expires_at,
        })
    }

    pub fn bans(
        &self,
        workspace: Option<WorkspaceId>,
        page: PageRequest<'_>,
        now: u64,
    ) -> rusqlite::Result<Page<Ban>> {
        let inner = self.lock();
        let pattern = like_pattern(page.query);
        let filter = "workspace_id IS ?1 AND (expires_at IS NULL OR expires_at > ?2)
                      AND (value LIKE ?3 ESCAPE '\\' OR note LIKE ?3 ESCAPE '\\')";
        let total: i64 = inner.db.query_row(
            &format!("SELECT COUNT(*) FROM bans WHERE {filter}"),
            params![workspace, now as i64, pattern],
            |row| row.get(0),
        )?;
        let mut statement = inner.db.prepare(&format!(
            "SELECT id, workspace_id, kind, value, note, created_at, expires_at FROM bans
             WHERE {filter} ORDER BY created_at DESC, id LIMIT ?4 OFFSET ?5"
        ))?;
        let items = statement
            .query_map(
                params![workspace, now as i64, pattern, page.limit, page.offset],
                ban_from_row,
            )?
            .filter_map(|row| row.transpose())
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Page {
            items,
            total: total as u64,
        })
    }

    /// Scoped, so a workspace cannot lift another's ban or a global one.
    pub fn remove_ban(&self, workspace: Option<WorkspaceId>, id: &str) -> Result<(), ChangeError> {
        let mut inner = self.lock();
        let affected = inner.db.execute(
            "DELETE FROM bans WHERE workspace_id IS ?1 AND id = ?2",
            params![workspace, id],
        )?;
        if affected == 0 {
            return Err(ChangeError::NotFound);
        }
        reload_global_ip_bans(&mut inner)?;
        Ok(())
    }

    /// `client` is a [`client_key`]: the console never sees the id itself.
    pub fn kick(
        &self,
        workspace: WorkspaceId,
        client: &str,
        hostname: &str,
        now: u64,
    ) -> Result<(), ChangeError> {
        self.lock().db.execute(
            "INSERT OR REPLACE INTO kicked (workspace_id, client, hostname, at)
             VALUES (?1, ?2, ?3, ?4)",
            params![workspace, client, hostname, now as i64],
        )?;
        Ok(())
    }

    pub fn kicked(&self, workspace: WorkspaceId) -> rusqlite::Result<Vec<Kicked>> {
        let inner = self.lock();
        let mut statement = inner.db.prepare(
            "SELECT client, hostname, at FROM kicked WHERE workspace_id = ?1 ORDER BY at DESC",
        )?;
        let rows = statement.query_map([workspace], |row| {
            Ok(Kicked {
                client: row.get(0)?,
                hostname: row.get(1)?,
                at: row.get::<_, i64>(2)? as u64,
            })
        })?;
        rows.collect()
    }

    pub fn unkick(&self, workspace: WorkspaceId, client: &str) -> Result<(), ChangeError> {
        let affected = self.lock().db.execute(
            "DELETE FROM kicked WHERE workspace_id = ?1 AND client = ?2",
            params![workspace, client],
        )?;
        if affected == 0 {
            return Err(ChangeError::NotFound);
        }
        Ok(())
    }

    pub fn open_connection(
        &self,
        connection: &NewConnection<'_>,
        now: u64,
    ) -> rusqlite::Result<i64> {
        let inner = self.lock();
        inner.db.execute(
            "INSERT INTO connections
                (workspace_id, client, hostname, ip, peer, device, code_id, started_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                connection.workspace,
                client_key(connection.client),
                connection.hostname,
                connection.ip.to_string(),
                canonical(connection.peer).to_string(),
                connection.device,
                connection.code_id,
                now as i64
            ],
        )?;
        Ok(inner.db.last_insert_rowid())
    }

    pub fn close_connection(
        &self,
        id: i64,
        rx_bytes: u64,
        tx_bytes: u64,
        now: u64,
    ) -> rusqlite::Result<()> {
        self.lock().db.execute(
            "UPDATE connections SET ended_at = ?2, rx_bytes = ?3, tx_bytes = ?4 WHERE id = ?1",
            params![id, now as i64, rx_bytes as i64, tx_bytes as i64],
        )?;
        Ok(())
    }

    /// Connections the last run of the server never saw end.
    pub fn close_stale_connections(&self, now: u64) -> rusqlite::Result<()> {
        self.lock().db.execute(
            "UPDATE connections SET ended_at = ?1 WHERE ended_at IS NULL",
            [now as i64],
        )?;
        Ok(())
    }

    pub fn connections(
        &self,
        workspace: WorkspaceId,
        page: PageRequest<'_>,
    ) -> rusqlite::Result<Page<ConnectionRecord>> {
        let inner = self.lock();
        let pattern = like_pattern(page.query);
        let filter = "workspace_id = ?1 AND (hostname LIKE ?2 ESCAPE '\\' OR ip LIKE ?2 ESCAPE '\\'
                      OR peer LIKE ?2 ESCAPE '\\' OR COALESCE(device, '') LIKE ?2 ESCAPE '\\')";
        let total: i64 = inner.db.query_row(
            &format!("SELECT COUNT(*) FROM connections WHERE {filter}"),
            params![workspace, pattern],
            |row| row.get(0),
        )?;
        let mut statement = inner.db.prepare(&format!(
            "SELECT id, hostname, ip, peer, device, code_id, started_at, ended_at, rx_bytes, tx_bytes
             FROM connections WHERE {filter} ORDER BY started_at DESC, id DESC LIMIT ?3 OFFSET ?4"
        ))?;
        let items = statement
            .query_map(
                params![workspace, pattern, page.limit, page.offset],
                |row| {
                    Ok(ConnectionRecord {
                        id: row.get(0)?,
                        hostname: row.get(1)?,
                        ip: row.get(2)?,
                        peer: row.get(3)?,
                        device: row.get(4)?,
                        code_id: row.get(5)?,
                        started_at: row.get::<_, i64>(6)? as u64,
                        ended_at: row.get::<_, Option<i64>>(7)?.map(|at| at as u64),
                        rx_bytes: row.get::<_, i64>(8)? as u64,
                        tx_bytes: row.get::<_, i64>(9)? as u64,
                    })
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Page {
            items,
            total: total as u64,
        })
    }

    pub fn audit(
        &self,
        actor: &str,
        workspace: Option<WorkspaceId>,
        action: &str,
        target: &str,
        source: &str,
        now: u64,
    ) -> rusqlite::Result<()> {
        self.lock().db.execute(
            "INSERT INTO audit_log (at, actor, workspace_id, action, target, source)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![now as i64, actor, workspace, action, target, source],
        )?;
        Ok(())
    }

    /// `workspace` of `None` is everything, for the super administrator.
    pub fn audit_entries(
        &self,
        workspace: Option<WorkspaceId>,
        page: PageRequest<'_>,
    ) -> rusqlite::Result<Page<AuditEntry>> {
        let inner = self.lock();
        let pattern = like_pattern(page.query);
        let filter = "(?1 IS NULL OR workspace_id = ?1) AND (actor LIKE ?2 ESCAPE '\\'
                      OR action LIKE ?2 ESCAPE '\\' OR target LIKE ?2 ESCAPE '\\')";
        let total: i64 = inner.db.query_row(
            &format!("SELECT COUNT(*) FROM audit_log WHERE {filter}"),
            params![workspace, pattern],
            |row| row.get(0),
        )?;
        let mut statement = inner.db.prepare(&format!(
            "SELECT id, at, actor, workspace_id, action, target, source FROM audit_log
             WHERE {filter} ORDER BY id DESC LIMIT ?3 OFFSET ?4"
        ))?;
        let items = statement
            .query_map(
                params![workspace, pattern, page.limit, page.offset],
                |row| {
                    Ok(AuditEntry {
                        id: row.get(0)?,
                        at: row.get::<_, i64>(1)? as u64,
                        actor: row.get(2)?,
                        workspace_id: row.get(3)?,
                        action: row.get(4)?,
                        target: row.get(5)?,
                        source: row.get(6)?,
                    })
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Page {
            items,
            total: total as u64,
        })
    }
}
