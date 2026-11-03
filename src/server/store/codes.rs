//! Codes, and the rule that their limits only apply to starting to use them.
use super::{
    canonical, client_key, hex, random_id, ChangeError, Page, PageRequest, Store, WorkspaceId,
};
use crate::credential::{generate_secret, Secret};
use crate::proto::RejectReason;
use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::sync::Arc;

fn secret_key(secret: &Secret) -> String {
    hex(&Sha256::digest(secret))
}

/// Neither limit makes a permanent Code.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct CodeLimits {
    /// Runs of the client, not machines: starting the program again is a new use.
    pub max_uses: Option<u32>,
    pub expires_at: Option<u64>,
}

impl CodeLimits {
    fn is_permanent(self) -> bool {
        self.max_uses.is_none() && self.expires_at.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeUse {
    pub client: String,
    pub device: Option<String>,
    pub hostname: String,
    pub peer: String,
    pub at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeStatus {
    Active,
    Used,
    Expired,
}

/// Leaves out the secret, which is only handed over by [`Store::code_secret`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeRecord {
    pub id: String,
    pub workspace_id: WorkspaceId,
    #[serde(flatten)]
    pub limits: CodeLimits,
    pub note: String,
    pub created_at: u64,
    pub status: CodeStatus,
    pub used_by: Vec<CodeUse>,
}

fn status_of(limits: CodeLimits, uses: usize, now: u64) -> CodeStatus {
    if limits.expires_at.is_some_and(|at| now >= at) {
        CodeStatus::Expired
    } else if limits.max_uses.is_some_and(|max| uses >= max as usize) {
        CodeStatus::Used
    } else {
        CodeStatus::Active
    }
}

/// A Code that passed its checks.
pub struct AdmittedCode {
    pub workspace: WorkspaceId,
    pub code_id: String,
    /// Present until this client has used the Code for real.
    pub reservation: Option<Reservation>,
}

#[derive(Debug)]
pub enum AdmitError {
    Reject(RejectReason),
    /// Says nothing about the Code, so the client must not be told it is bad.
    Db(rusqlite::Error),
}

impl From<rusqlite::Error> for AdmitError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Db(error)
    }
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
        let inner = self.store.lock();
        let exists: i64 = inner.db.query_row(
            "SELECT COUNT(*) FROM codes WHERE id = ?1",
            [&self.code_id],
            |row| row.get(0),
        )?;
        if exists == 0 {
            return Err(ChangeError::NotFound);
        }
        inner.db.execute(
            "INSERT OR IGNORE INTO code_uses (code_id, client, device, hostname, peer, at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                self.code_id,
                self.client,
                details.device,
                details.hostname,
                canonical(details.peer).to_string(),
                now as i64
            ],
        )?;
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
    /// `Ok(None)` means this secret opens nothing.
    pub fn admit_code(
        self: &Arc<Self>,
        secret: &Secret,
        client_id: &str,
        now: u64,
    ) -> Result<Option<AdmittedCode>, AdmitError> {
        let hash = secret_key(secret);
        let client = client_key(client_id);
        let mut guard = self.lock();
        let inner = &mut *guard;
        let row = inner
            .db
            .query_row(
                "SELECT id, workspace_id, max_uses, expires_at FROM codes
                 WHERE secret_hash = ?1",
                [&hash],
                |row| {
                    let id: String = row.get(0)?;
                    let workspace: WorkspaceId = row.get(1)?;
                    let limits = CodeLimits {
                        max_uses: row.get(2)?,
                        expires_at: row.get::<_, Option<i64>>(3)?.map(|at| at as u64),
                    };
                    Ok((id, workspace, limits))
                },
            )
            .optional()?;
        let Some((id, workspace, limits)) = row else {
            return Ok(None);
        };
        let admitted = |reservation| {
            Ok(Some(AdmittedCode {
                workspace,
                code_id: id.clone(),
                reservation,
            }))
        };
        // No limit to protect, so nothing to record for every run of every machine.
        if limits.is_permanent() {
            return admitted(None);
        }
        // Before any limit: a Code's limits only apply to starting to use it.
        let used: i64 = inner.db.query_row(
            "SELECT COUNT(*) FROM code_uses WHERE code_id = ?1",
            [&id],
            |row| row.get(0),
        )?;
        let already: i64 = inner.db.query_row(
            "SELECT COUNT(*) FROM code_uses WHERE code_id = ?1 AND client = ?2",
            params![id, client],
            |row| row.get(0),
        )?;
        if already > 0 {
            return admitted(None);
        }
        if limits.expires_at.is_some_and(|at| now >= at) {
            return Err(AdmitError::Reject(RejectReason::CodeExpired));
        }
        if let Some(max) = limits.max_uses {
            let held = inner
                .pending
                .keys()
                .filter(|(code, holder)| *code == id && *holder != client)
                .count() as i64;
            if used + held >= i64::from(max) {
                return Err(AdmitError::Reject(RejectReason::CodeUsed));
            }
        }
        inner.next_seq += 1;
        let seq = inner.next_seq;
        inner.pending.insert((id.clone(), client.clone()), seq);
        admitted(Some(Reservation {
            store: self.clone(),
            code_id: id.clone(),
            client,
            seq,
        }))
    }

    pub fn create_code(
        &self,
        workspace: WorkspaceId,
        limits: CodeLimits,
        note: &str,
        now: u64,
    ) -> Result<(CodeRecord, Secret), ChangeError> {
        let secret = generate_secret();
        let record = self.add_code(workspace, &secret, limits, note, now)?;
        Ok((record, secret))
    }

    pub fn add_code(
        &self,
        workspace: WorkspaceId,
        secret: &Secret,
        limits: CodeLimits,
        note: &str,
        now: u64,
    ) -> Result<CodeRecord, ChangeError> {
        if limits.max_uses == Some(0) {
            return Err(ChangeError::Invalid("使用次数至少为 1".to_owned()));
        }
        let id = random_id();
        self.lock().db.execute(
            "INSERT INTO codes (id, secret_hash, secret, workspace_id, max_uses, expires_at, note, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                id,
                secret_key(secret),
                secret,
                workspace,
                limits.max_uses,
                limits.expires_at.map(|at| at as i64),
                note,
                now as i64
            ],
        )?;
        Ok(CodeRecord {
            id,
            workspace_id: workspace,
            limits,
            note: note.to_owned(),
            created_at: now,
            status: status_of(limits, 0, now),
            used_by: Vec::new(),
        })
    }

    /// For copying a Code again.
    pub fn code_secret(&self, workspace: WorkspaceId, id: &str) -> Result<Secret, ChangeError> {
        self.lock()
            .db
            .query_row(
                "SELECT secret FROM codes WHERE workspace_id = ?1 AND id = ?2",
                params![workspace, id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(ChangeError::NotFound)
    }

    pub fn code(
        &self,
        workspace: WorkspaceId,
        id: &str,
        now: u64,
    ) -> rusqlite::Result<Option<CodeRecord>> {
        let inner = self.lock();
        let row = inner
            .db
            .query_row(
                "SELECT id, workspace_id, max_uses, expires_at, note, created_at
                 FROM codes WHERE workspace_id = ?1 AND id = ?2",
                params![workspace, id],
                code_row,
            )
            .optional()?;
        row.map(|row| finish_code(&inner.db, row, now)).transpose()
    }

    pub fn codes(
        &self,
        workspace: WorkspaceId,
        page: PageRequest<'_>,
        now: u64,
    ) -> rusqlite::Result<Page<CodeRecord>> {
        let inner = self.lock();
        let pattern = super::like_pattern(page.query);
        let filter = "workspace_id = ?1 AND (note LIKE ?2 ESCAPE '\\' OR id LIKE ?2 ESCAPE '\\')";
        let total: i64 = inner.db.query_row(
            &format!("SELECT COUNT(*) FROM codes WHERE {filter}"),
            params![workspace, pattern],
            |row| row.get(0),
        )?;
        let mut statement = inner.db.prepare(&format!(
            "SELECT id, workspace_id, max_uses, expires_at, note, created_at
             FROM codes WHERE {filter} ORDER BY created_at DESC, id LIMIT ?3 OFFSET ?4"
        ))?;
        let rows = statement
            .query_map(
                params![workspace, pattern, page.limit, page.offset],
                code_row,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let items = rows
            .into_iter()
            .map(|row| finish_code(&inner.db, row, now))
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Page {
            items,
            total: total as u64,
        })
    }

    /// `expiry` of `Some(None)` removes the deadline. Changing it never affects
    /// who is already using the Code.
    pub fn update_code(
        &self,
        workspace: WorkspaceId,
        id: &str,
        note: Option<&str>,
        expiry: Option<Option<u64>>,
    ) -> Result<(), ChangeError> {
        let inner = self.lock();
        let limits = inner
            .db
            .query_row(
                "SELECT max_uses, expires_at FROM codes WHERE workspace_id = ?1 AND id = ?2",
                params![workspace, id],
                |row| {
                    Ok(CodeLimits {
                        max_uses: row.get(0)?,
                        expires_at: row.get::<_, Option<i64>>(1)?.map(|at| at as u64),
                    })
                },
            )
            .optional()?
            .ok_or(ChangeError::NotFound)?;
        // Its users were never recorded, so a deadline would cut them off.
        if limits.is_permanent() && matches!(expiry, Some(Some(_))) {
            return Err(ChangeError::Conflict(
                "永久 Code 不能加期限，请删除后重新生成".to_owned(),
            ));
        }
        if let Some(note) = note {
            inner.db.execute(
                "UPDATE codes SET note = ?3 WHERE workspace_id = ?1 AND id = ?2",
                params![workspace, id, note],
            )?;
        }
        if let Some(expiry) = expiry {
            inner.db.execute(
                "UPDATE codes SET expires_at = ?3 WHERE workspace_id = ?1 AND id = ?2",
                params![workspace, id, expiry.map(|at| at as i64)],
            )?;
        }
        Ok(())
    }

    /// Scoped to the workspace, so an id from another one is simply not found.
    pub fn delete_code(&self, workspace: WorkspaceId, id: &str) -> Result<(), ChangeError> {
        let affected = self.lock().db.execute(
            "DELETE FROM codes WHERE workspace_id = ?1 AND id = ?2",
            params![workspace, id],
        )?;
        if affected == 0 {
            return Err(ChangeError::NotFound);
        }
        Ok(())
    }

    /// Whichever state the Code is in, as long as it exists.
    pub fn lookup_code_workspace(&self, secret: &Secret) -> rusqlite::Result<Option<WorkspaceId>> {
        self.lock()
            .db
            .query_row(
                "SELECT workspace_id FROM codes WHERE secret_hash = ?1",
                [secret_key(secret)],
                |row| row.get(0),
            )
            .optional()
    }

    pub fn code_is_live(&self, id: &str) -> rusqlite::Result<bool> {
        let count: i64 =
            self.lock()
                .db
                .query_row("SELECT COUNT(*) FROM codes WHERE id = ?1", [id], |row| {
                    row.get(0)
                })?;
        Ok(count > 0)
    }
}

struct CodeRow {
    id: String,
    workspace_id: WorkspaceId,
    limits: CodeLimits,
    note: String,
    created_at: u64,
}

fn code_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CodeRow> {
    Ok(CodeRow {
        id: row.get(0)?,
        workspace_id: row.get(1)?,
        limits: CodeLimits {
            max_uses: row.get(2)?,
            expires_at: row.get::<_, Option<i64>>(3)?.map(|at| at as u64),
        },
        note: row.get(4)?,
        created_at: row.get::<_, i64>(5)? as u64,
    })
}

fn finish_code(db: &rusqlite::Connection, row: CodeRow, now: u64) -> rusqlite::Result<CodeRecord> {
    let mut statement = db.prepare(
        "SELECT client, device, hostname, peer, at FROM code_uses
         WHERE code_id = ?1 ORDER BY at",
    )?;
    let used_by = statement
        .query_map([&row.id], |use_row| {
            Ok(CodeUse {
                client: use_row.get(0)?,
                device: use_row.get(1)?,
                hostname: use_row.get(2)?,
                peer: use_row.get(3)?,
                at: use_row.get::<_, i64>(4)? as u64,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(CodeRecord {
        status: status_of(row.limits, used_by.len(), now),
        id: row.id,
        workspace_id: row.workspace_id,
        limits: row.limits,
        note: row.note,
        created_at: row.created_at,
        used_by,
    })
}
