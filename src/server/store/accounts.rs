//! Accounts, workspace roles, login sessions and API tokens.
use super::{
    client_key, hex, is_unique_violation, random_id, ChangeError, Store, UserId, WorkspaceId,
    ROOT_DEFAULT_PASSWORD, ROOT_USERNAME,
};
use crate::credential::generate_secret;
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::Argon2;
use rusqlite::{params, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};

/// Slow on purpose, so call it from a thread that may block.
pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let hash = Argon2::default()
        .hash_password(password.as_bytes())
        .map_err(|error| anyhow::anyhow!("hashing password: {error}"))?;
    Ok(hash.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|parsed| {
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Owner,
    Admin,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
        }
    }

    fn parse(text: &str) -> Self {
        if text == "owner" {
            Self::Owner
        } else {
            Self::Admin
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: UserId,
    pub username: String,
    pub password_hash: String,
    pub is_super: bool,
    pub must_change_password: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdminView {
    pub user_id: UserId,
    pub username: String,
    pub role: Role,
    /// Other workspaces are not named: that is other teams' business.
    pub shared: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserOverview {
    pub id: UserId,
    pub username: String,
    pub is_super: bool,
    pub must_change_password: bool,
    pub created_at: u64,
    pub workspaces: Vec<(WorkspaceId, Role)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionView {
    pub id: String,
    pub created_at: u64,
    pub last_seen: u64,
    pub user_agent: String,
}

/// `workspace_id` of `None` acts as the super administrator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TokenInfo {
    pub id: String,
    pub workspace_id: Option<WorkspaceId>,
    pub name: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub last_used: Option<u64>,
}

/// A public key someone keeps on their account, for Codes that carry it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SshKey {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub fingerprint: String,
    pub created_at: u64,
}

pub struct ApiToken {
    pub info: TokenInfo,
    pub token: String,
}

/// Only rewritten this often, so reading the console does not mean writing the disk.
const TOUCH_INTERVAL_SECS: u64 = 60;
const USER_COLUMNS: &str = "id, username, password_hash, is_super, must_change_password";

fn user_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<User> {
    Ok(User {
        id: row.get(0)?,
        username: row.get(1)?,
        password_hash: row.get(2)?,
        is_super: row.get(3)?,
        must_change_password: row.get(4)?,
    })
}

pub(super) fn delete_orphans(transaction: &Transaction<'_>) -> rusqlite::Result<()> {
    transaction.execute(
        "DELETE FROM users WHERE is_super = 0
         AND id NOT IN (SELECT user_id FROM memberships)",
        [],
    )?;
    Ok(())
}

fn taken() -> ChangeError {
    ChangeError::Conflict("用户名已被占用".to_owned())
}

fn last_owner() -> ChangeError {
    ChangeError::Conflict("工作区至少要保留一个 owner".to_owned())
}

impl Store {
    pub(super) fn ensure_root(&self) -> anyhow::Result<()> {
        let exists: i64 = self.lock().db.query_row(
            "SELECT COUNT(*) FROM users WHERE is_super = 1",
            [],
            |row| row.get(0),
        )?;
        if exists == 0 {
            let hash = hash_password(ROOT_DEFAULT_PASSWORD)?;
            self.lock().db.execute(
                "INSERT INTO users
                    (username, password_hash, is_super, must_change_password, created_at)
                 VALUES (?1, ?2, 1, 1, ?3)",
                params![ROOT_USERNAME, hash, super::unix_now() as i64],
            )?;
        }
        Ok(())
    }

    /// For someone locked out, run on the server itself.
    pub fn reset_root_password(&self) -> anyhow::Result<()> {
        let hash = hash_password(ROOT_DEFAULT_PASSWORD)?;
        let inner = self.lock();
        inner.db.execute(
            "UPDATE users SET password_hash = ?1, must_change_password = 1 WHERE is_super = 1",
            [hash],
        )?;
        inner.db.execute(
            "DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE is_super = 1)",
            [],
        )?;
        Ok(())
    }

    pub fn user_by_name(&self, username: &str) -> rusqlite::Result<Option<User>> {
        self.lock()
            .db
            .query_row(
                &format!("SELECT {USER_COLUMNS} FROM users WHERE username = ?1"),
                [username],
                user_from_row,
            )
            .optional()
    }

    pub fn user(&self, id: UserId) -> rusqlite::Result<Option<User>> {
        self.lock()
            .db
            .query_row(
                &format!("SELECT {USER_COLUMNS} FROM users WHERE id = ?1"),
                [id],
                user_from_row,
            )
            .optional()
    }

    pub fn users(&self) -> rusqlite::Result<Vec<UserOverview>> {
        let inner = self.lock();
        let mut statement = inner.db.prepare(
            "SELECT id, username, is_super, must_change_password, created_at
             FROM users ORDER BY is_super DESC, username",
        )?;
        let users = statement
            .query_map([], |row| {
                Ok(UserOverview {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    is_super: row.get(2)?,
                    must_change_password: row.get(3)?,
                    created_at: row.get::<_, i64>(4)? as u64,
                    workspaces: Vec::new(),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut memberships = inner
            .db
            .prepare("SELECT workspace_id, role FROM memberships WHERE user_id = ?1")?;
        users
            .into_iter()
            .map(|mut user| {
                user.workspaces = memberships
                    .query_map([user.id], |row| {
                        Ok((row.get(0)?, Role::parse(&row.get::<_, String>(1)?)))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(user)
            })
            .collect()
    }

    /// Ends every other login of this user, in case the old password leaked.
    pub fn set_password(
        &self,
        user: UserId,
        hash: &str,
        must_change: bool,
        keep_session_hash: Option<&str>,
    ) -> Result<(), ChangeError> {
        let inner = self.lock();
        let changed = inner.db.execute(
            "UPDATE users SET password_hash = ?2, must_change_password = ?3 WHERE id = ?1",
            params![user, hash, must_change],
        )?;
        if changed == 0 {
            return Err(ChangeError::NotFound);
        }
        inner.db.execute(
            "DELETE FROM sessions WHERE user_id = ?1 AND token_hash IS NOT ?2",
            params![user, keep_session_hash],
        )?;
        Ok(())
    }

    /// New accounts must choose their own password at first login.
    pub fn add_admin(
        &self,
        workspace: WorkspaceId,
        username: &str,
        password_hash: &str,
        role: Role,
        now: u64,
    ) -> Result<UserId, ChangeError> {
        let username = username.trim();
        if username.is_empty() {
            return Err(ChangeError::Invalid("用户名不能为空".to_owned()));
        }
        let mut inner = self.lock();
        let transaction = inner.db.transaction()?;
        let inserted = transaction.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?1, ?2, ?3)",
            params![username, password_hash, now as i64],
        );
        match inserted {
            Ok(_) => {}
            Err(error) if is_unique_violation(&error) => return Err(taken()),
            Err(error) => return Err(error.into()),
        }
        let user = transaction.last_insert_rowid();
        transaction.execute(
            "INSERT INTO memberships (user_id, workspace_id, role) VALUES (?1, ?2, ?3)",
            params![user, workspace, role.as_str()],
        )?;
        transaction.commit()?;
        Ok(user)
    }

    /// Adds an existing account to one more workspace.
    pub fn attach_admin(
        &self,
        workspace: WorkspaceId,
        username: &str,
        role: Role,
    ) -> Result<UserId, ChangeError> {
        let user = self
            .user_by_name(username.trim())?
            .ok_or(ChangeError::NotFound)?;
        if user.is_super {
            return Err(ChangeError::Conflict("超管已经能管理所有工作区".to_owned()));
        }
        let inserted = self.lock().db.execute(
            "INSERT INTO memberships (user_id, workspace_id, role) VALUES (?1, ?2, ?3)",
            params![user.id, workspace, role.as_str()],
        );
        match inserted {
            Ok(_) => Ok(user.id),
            Err(error) if is_unique_violation(&error) => {
                Err(ChangeError::Conflict("已经是这个工作区的管理员".to_owned()))
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn role_of(&self, user: UserId, workspace: WorkspaceId) -> rusqlite::Result<Option<Role>> {
        self.lock()
            .db
            .query_row(
                "SELECT role FROM memberships WHERE user_id = ?1 AND workspace_id = ?2",
                params![user, workspace],
                |row| Ok(Role::parse(&row.get::<_, String>(0)?)),
            )
            .optional()
    }

    pub fn memberships(&self, user: UserId) -> rusqlite::Result<Vec<(WorkspaceId, Role)>> {
        let inner = self.lock();
        let mut statement = inner
            .db
            .prepare("SELECT workspace_id, role FROM memberships WHERE user_id = ?1")?;
        let rows = statement.query_map([user], |row| {
            Ok((row.get(0)?, Role::parse(&row.get::<_, String>(1)?)))
        })?;
        rows.collect()
    }

    pub fn admins(&self, workspace: WorkspaceId) -> rusqlite::Result<Vec<AdminView>> {
        let inner = self.lock();
        let mut statement = inner.db.prepare(
            "SELECT u.id, u.username, m.role,
                (SELECT COUNT(*) FROM memberships o WHERE o.user_id = u.id) > 1
             FROM memberships m JOIN users u ON u.id = m.user_id
             WHERE m.workspace_id = ?1
             ORDER BY m.role DESC, u.username",
        )?;
        let rows = statement.query_map([workspace], |row| {
            Ok(AdminView {
                user_id: row.get(0)?,
                username: row.get(1)?,
                role: Role::parse(&row.get::<_, String>(2)?),
                shared: row.get(3)?,
            })
        })?;
        rows.collect()
    }

    pub fn set_role(
        &self,
        workspace: WorkspaceId,
        user: UserId,
        role: Role,
    ) -> Result<(), ChangeError> {
        let mut inner = self.lock();
        let transaction = inner.db.transaction()?;
        let current = role_in(&transaction, user, workspace)?.ok_or(ChangeError::NotFound)?;
        if current == Role::Owner
            && role != Role::Owner
            && owner_count(&transaction, workspace)? <= 1
        {
            return Err(last_owner());
        }
        transaction.execute(
            "UPDATE memberships SET role = ?3 WHERE user_id = ?1 AND workspace_id = ?2",
            params![user, workspace, role.as_str()],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn remove_admin(&self, workspace: WorkspaceId, user: UserId) -> Result<(), ChangeError> {
        let mut inner = self.lock();
        let transaction = inner.db.transaction()?;
        let current = role_in(&transaction, user, workspace)?.ok_or(ChangeError::NotFound)?;
        if current == Role::Owner && owner_count(&transaction, workspace)? <= 1 {
            return Err(last_owner());
        }
        transaction.execute(
            "DELETE FROM memberships WHERE user_id = ?1 AND workspace_id = ?2",
            params![user, workspace],
        )?;
        delete_orphans(&transaction)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn delete_user(&self, user: UserId) -> Result<(), ChangeError> {
        let mut inner = self.lock();
        let transaction = inner.db.transaction()?;
        let is_super: bool = transaction
            .query_row("SELECT is_super FROM users WHERE id = ?1", [user], |row| {
                row.get(0)
            })
            .optional()?
            .ok_or(ChangeError::NotFound)?;
        if is_super {
            return Err(ChangeError::Conflict("不能删除超管".to_owned()));
        }
        let sole_owner: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM memberships m
             WHERE m.user_id = ?1 AND m.role = 'owner' AND (
                SELECT COUNT(*) FROM memberships o
                WHERE o.workspace_id = m.workspace_id AND o.role = 'owner') = 1",
            [user],
            |row| row.get(0),
        )?;
        if sole_owner > 0 {
            return Err(last_owner());
        }
        transaction.execute("DELETE FROM users WHERE id = ?1", [user])?;
        transaction.commit()?;
        Ok(())
    }

    // ---- Sessions ----

    /// Returns the token. Only its hash stays here, so the database cannot be
    /// replayed as a cookie.
    pub fn open_session(
        &self,
        user: UserId,
        user_agent: &str,
        lifetime_secs: u64,
        now: u64,
    ) -> rusqlite::Result<String> {
        let token = hex(&generate_secret());
        self.lock().db.execute(
            "INSERT INTO sessions (token_hash, user_id, created_at, expires_at, last_seen, user_agent)
             VALUES (?1, ?2, ?3, ?4, ?3, ?5)",
            params![
                client_key(&token),
                user,
                now as i64,
                now.saturating_add(lifetime_secs) as i64,
                user_agent.chars().take(200).collect::<String>()
            ],
        )?;
        Ok(token)
    }

    pub fn session_user(&self, token: &str, now: u64) -> rusqlite::Result<Option<User>> {
        let hash = client_key(token);
        let inner = self.lock();
        let found = inner
            .db
            .query_row(
                &format!(
                    "SELECT {columns}, s.last_seen FROM sessions s JOIN users u ON u.id = s.user_id
                     WHERE s.token_hash = ?1 AND s.expires_at > ?2",
                    columns =
                        "u.id, u.username, u.password_hash, u.is_super, u.must_change_password"
                ),
                params![hash, now as i64],
                |row| Ok((user_from_row(row)?, row.get::<_, i64>(5)? as u64)),
            )
            .optional()?;
        let Some((user, last_seen)) = found else {
            return Ok(None);
        };
        if now.saturating_sub(last_seen) >= TOUCH_INTERVAL_SECS {
            inner.db.execute(
                "UPDATE sessions SET last_seen = ?2 WHERE token_hash = ?1",
                params![hash, now as i64],
            )?;
        }
        Ok(Some(user))
    }

    pub fn close_session(&self, token: &str) -> rusqlite::Result<()> {
        self.lock().db.execute(
            "DELETE FROM sessions WHERE token_hash = ?1",
            [client_key(token)],
        )?;
        Ok(())
    }

    pub fn sessions(&self, user: UserId, now: u64) -> rusqlite::Result<Vec<SessionView>> {
        let inner = self.lock();
        let mut statement = inner.db.prepare(
            "SELECT substr(token_hash, 1, 16), created_at, last_seen, user_agent
             FROM sessions WHERE user_id = ?1 AND expires_at > ?2 ORDER BY last_seen DESC",
        )?;
        let rows = statement.query_map(params![user, now as i64], |row| {
            Ok(SessionView {
                id: row.get(0)?,
                created_at: row.get::<_, i64>(1)? as u64,
                last_seen: row.get::<_, i64>(2)? as u64,
                user_agent: row.get(3)?,
            })
        })?;
        rows.collect()
    }

    pub fn close_session_by_id(&self, user: UserId, id: &str) -> Result<(), ChangeError> {
        let affected = self.lock().db.execute(
            "DELETE FROM sessions WHERE user_id = ?1 AND substr(token_hash, 1, 16) = ?2",
            params![user, id],
        )?;
        if affected == 0 {
            return Err(ChangeError::NotFound);
        }
        Ok(())
    }

    // ---- SSH public keys ----

    pub fn ssh_keys(&self, user: UserId) -> rusqlite::Result<Vec<SshKey>> {
        let inner = self.lock();
        let mut statement = inner.db.prepare(
            "SELECT id, name, public_key, fingerprint, created_at
             FROM ssh_keys WHERE user_id = ?1 ORDER BY created_at, id",
        )?;
        let rows = statement.query_map([user], |row| {
            Ok(SshKey {
                id: row.get(0)?,
                name: row.get(1)?,
                public_key: row.get(2)?,
                fingerprint: row.get(3)?,
                created_at: row.get::<_, i64>(4)? as u64,
            })
        })?;
        rows.collect()
    }

    pub fn add_ssh_key(
        &self,
        user: UserId,
        name: &str,
        public_key: &str,
        fingerprint: &str,
        now: u64,
    ) -> Result<SshKey, ChangeError> {
        let id = random_id();
        let inserted = self.lock().db.execute(
            "INSERT INTO ssh_keys (id, user_id, name, public_key, fingerprint, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, user, name, public_key, fingerprint, now as i64],
        );
        match inserted {
            Ok(_) => Ok(SshKey {
                id,
                name: name.to_owned(),
                public_key: public_key.to_owned(),
                fingerprint: fingerprint.to_owned(),
                created_at: now,
            }),
            Err(error) if is_unique_violation(&error) => {
                Err(ChangeError::Conflict("已经添加过这个公钥".to_owned()))
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Scoped to the user, so someone else's key is simply not found.
    pub fn delete_ssh_key(&self, user: UserId, id: &str) -> Result<(), ChangeError> {
        let affected = self.lock().db.execute(
            "DELETE FROM ssh_keys WHERE user_id = ?1 AND id = ?2",
            params![user, id],
        )?;
        if affected == 0 {
            return Err(ChangeError::NotFound);
        }
        Ok(())
    }

    // ---- API tokens ----

    pub fn create_token(
        &self,
        workspace: Option<WorkspaceId>,
        name: &str,
        expires_at: Option<u64>,
        now: u64,
    ) -> Result<ApiToken, ChangeError> {
        let id = random_id();
        let token = format!("varco_{}", hex(&generate_secret()));
        self.lock().db.execute(
            "INSERT INTO api_tokens (id, token_hash, token, workspace_id, name, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                id,
                client_key(&token),
                token,
                workspace,
                name,
                now as i64,
                expires_at.map(|at| at as i64)
            ],
        )?;
        Ok(ApiToken {
            info: TokenInfo {
                id,
                workspace_id: workspace,
                name: name.to_owned(),
                created_at: now,
                expires_at,
                last_used: None,
            },
            token,
        })
    }

    pub fn tokens(&self, workspace: Option<WorkspaceId>) -> rusqlite::Result<Vec<TokenInfo>> {
        let inner = self.lock();
        let mut statement = inner.db.prepare(
            "SELECT id, workspace_id, name, created_at, expires_at, last_used
             FROM api_tokens WHERE workspace_id IS ?1 ORDER BY created_at DESC, id",
        )?;
        let rows = statement.query_map(params![workspace], |row| {
            Ok(TokenInfo {
                id: row.get(0)?,
                workspace_id: row.get(1)?,
                name: row.get(2)?,
                created_at: row.get::<_, i64>(3)? as u64,
                expires_at: row.get::<_, Option<i64>>(4)?.map(|at| at as u64),
                last_used: row.get::<_, Option<i64>>(5)?.map(|at| at as u64),
            })
        })?;
        rows.collect()
    }

    /// For copying a token again.
    pub fn token_secret(
        &self,
        workspace: Option<WorkspaceId>,
        id: &str,
    ) -> Result<String, ChangeError> {
        self.lock()
            .db
            .query_row(
                "SELECT token FROM api_tokens WHERE workspace_id IS ?1 AND id = ?2",
                params![workspace, id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(ChangeError::NotFound)
    }

    pub fn delete_token(
        &self,
        workspace: Option<WorkspaceId>,
        id: &str,
    ) -> Result<(), ChangeError> {
        let affected = self.lock().db.execute(
            "DELETE FROM api_tokens WHERE workspace_id IS ?1 AND id = ?2",
            params![workspace, id],
        )?;
        if affected == 0 {
            return Err(ChangeError::NotFound);
        }
        Ok(())
    }

    pub fn token_info(&self, token: &str, now: u64) -> rusqlite::Result<Option<TokenInfo>> {
        let hash = client_key(token);
        let inner = self.lock();
        let found = inner
            .db
            .query_row(
                "SELECT id, workspace_id, name, created_at, expires_at, last_used
                 FROM api_tokens
                 WHERE token_hash = ?1 AND (expires_at IS NULL OR expires_at > ?2)",
                params![hash, now as i64],
                |row| {
                    Ok(TokenInfo {
                        id: row.get(0)?,
                        workspace_id: row.get(1)?,
                        name: row.get(2)?,
                        created_at: row.get::<_, i64>(3)? as u64,
                        expires_at: row.get::<_, Option<i64>>(4)?.map(|at| at as u64),
                        last_used: row.get::<_, Option<i64>>(5)?.map(|at| at as u64),
                    })
                },
            )
            .optional()?;
        if let Some(info) = &found {
            if info
                .last_used
                .is_none_or(|at| now.saturating_sub(at) >= TOUCH_INTERVAL_SECS)
            {
                inner.db.execute(
                    "UPDATE api_tokens SET last_used = ?2 WHERE token_hash = ?1",
                    params![hash, now as i64],
                )?;
            }
        }
        Ok(found)
    }
}

fn role_in(
    transaction: &Transaction<'_>,
    user: UserId,
    workspace: WorkspaceId,
) -> rusqlite::Result<Option<Role>> {
    transaction
        .query_row(
            "SELECT role FROM memberships WHERE user_id = ?1 AND workspace_id = ?2",
            params![user, workspace],
            |row| Ok(Role::parse(&row.get::<_, String>(0)?)),
        )
        .optional()
}

fn owner_count(transaction: &Transaction<'_>, workspace: WorkspaceId) -> rusqlite::Result<i64> {
    transaction.query_row(
        "SELECT COUNT(*) FROM memberships WHERE workspace_id = ?1 AND role = 'owner'",
        [workspace],
        |row| row.get(0),
    )
}
