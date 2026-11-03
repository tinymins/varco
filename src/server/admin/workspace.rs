//! What can be done inside one workspace. Every handler takes a [`Scoped`], and
//! every store call is passed its workspace id.
use super::{ApiError, ApiResult, Console, OwnerScoped, PageParams, Scoped, Standing};
use crate::core::device;
use crate::core::ssh::store as ssh_store;
use crate::credential::Credential;
use crate::server::hub::{MemberView, NetworkStats};
use crate::server::store::{
    parse_duration, parse_ip_target, unix_now, AdminView, AuditEntry, Ban, BanTarget, CodeLimits,
    CodeRecord, ConnectionRecord, Kicked, Page, Role, TokenInfo, UserId, Workspace, WorkspaceId,
    SETTING_PUBLIC_ADDR,
};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Empty means none. `Err` carries the message to show.
pub(super) fn deadline(text: Option<&str>, now: u64) -> ApiResult<Option<u64>> {
    match text.map(str::trim) {
        None | Some("") => Ok(None),
        Some(text) => {
            let seconds = parse_duration(text)
                .ok_or_else(|| ApiError::bad_request("时长格式不正确，例如 30m、24h、7d"))?;
            now.checked_add(seconds)
                .map(Some)
                .ok_or_else(|| ApiError::bad_request("时长太长"))
        }
    }
}

#[derive(Serialize)]
pub struct Overview {
    workspace: Workspace,
    standing: Standing,
    stats: Option<NetworkStats>,
}

pub async fn overview(State(console): State<Arc<Console>>, scoped: Scoped) -> Json<Overview> {
    let id = scoped.workspace.id;
    Json(Overview {
        stats: console
            .hub
            .stats()
            .into_iter()
            .find(|stats| stats.workspace_id == id),
        workspace: scoped.workspace,
        standing: scoped.standing,
    })
}

pub async fn members(
    State(console): State<Arc<Console>>,
    scoped: Scoped,
    Query(params): Query<PageParams>,
) -> Json<Page<MemberView>> {
    let request = params.request();
    let query = request.query.to_lowercase();
    let matching: Vec<MemberView> = console
        .hub
        .members(scoped.workspace.id)
        .into_iter()
        .filter(|member| {
            query.is_empty()
                || member.hostname.to_lowercase().contains(&query)
                || member.ip.to_string().contains(&query)
                || member
                    .peer
                    .is_some_and(|peer| peer.to_string().contains(&query))
                || member.device.as_deref().is_some_and(|d| d.contains(&query))
        })
        .collect();
    let total = matching.len() as u64;
    Json(Page {
        items: matching
            .into_iter()
            .skip(request.offset as usize)
            .take(request.limit as usize)
            .collect(),
        total,
    })
}

#[derive(Deserialize)]
pub struct KickBody {
    id: String,
}

pub async fn kick(
    State(console): State<Arc<Console>>,
    scoped: Scoped,
    Json(body): Json<KickBody>,
) -> ApiResult<StatusCode> {
    let id = scoped.workspace.id;
    let member = console.hub.kick_member(id, &body.id, unix_now())?;
    console.audit(&scoped.actor, Some(id), "kick", &member.hostname);
    Ok(StatusCode::NO_CONTENT)
}

pub async fn kicked(
    State(console): State<Arc<Console>>,
    scoped: Scoped,
) -> ApiResult<Json<Vec<Kicked>>> {
    Ok(Json(console.store().kicked(scoped.workspace.id)?))
}

pub async fn unkick(
    State(console): State<Arc<Console>>,
    scoped: Scoped,
    Path((_, client)): Path<(WorkspaceId, String)>,
) -> ApiResult<StatusCode> {
    let id = scoped.workspace.id;
    console.store().unkick(id, &client)?;
    console.audit(&scoped.actor, Some(id), "unkick", &client);
    Ok(StatusCode::NO_CONTENT)
}

pub async fn connections(
    State(console): State<Arc<Console>>,
    scoped: Scoped,
    Query(params): Query<PageParams>,
) -> ApiResult<Json<Page<ConnectionRecord>>> {
    Ok(Json(
        console
            .store()
            .connections(scoped.workspace.id, params.request())?,
    ))
}

pub async fn codes(
    State(console): State<Arc<Console>>,
    scoped: Scoped,
    Query(params): Query<PageParams>,
) -> ApiResult<Json<Page<CodeRecord>>> {
    Ok(Json(console.store().codes(
        scoped.workspace.id,
        params.request(),
        unix_now(),
    )?))
}

#[derive(Deserialize)]
pub struct NewCode {
    max_uses: Option<u32>,
    /// `30m`, `24h` or `7d`. With neither this nor `max_uses`, the Code is permanent.
    duration: Option<String>,
    #[serde(default)]
    note: String,
    #[serde(default)]
    ssh_pubkey: String,
}

#[derive(Serialize)]
pub struct CreatedCode {
    code: String,
    #[serde(flatten)]
    record: CodeRecord,
    key_fingerprint: Option<String>,
}

pub async fn create_code(
    State(console): State<Arc<Console>>,
    scoped: Scoped,
    Json(body): Json<NewCode>,
) -> ApiResult<Json<CreatedCode>> {
    let now = unix_now();
    let store = console.store();
    let public_addr = store.setting(SETTING_PUBLIC_ADDR)?.ok_or_else(|| {
        ApiError::new(
            StatusCode::CONFLICT,
            "服务还没有设置对外地址，请超管先完成服务设置",
        )
    })?;
    let limits = CodeLimits {
        max_uses: body.max_uses,
        expires_at: deadline(body.duration.as_deref(), now)?,
    };
    let ssh_pubkey = match body.ssh_pubkey.trim() {
        "" => None,
        text => Some(
            ssh_store::parse_public_key(text)
                .map_err(|detail| ApiError::bad_request(detail.to_string()))?,
        ),
    };
    let key_fingerprint = ssh_pubkey.as_ref().map(ssh_store::fingerprint);
    let id = scoped.workspace.id;
    let (record, secret) = store.create_code(id, limits, &body.note, now)?;
    let credential = Credential {
        server: public_addr,
        pin: console.pin,
        secret,
        ssh_pubkey: None,
    };
    let credential = match ssh_pubkey {
        Some(key) => credential.with_ssh_pubkey(key),
        None => credential,
    };
    console.audit(&scoped.actor, Some(id), "create_code", &record.id);
    Ok(Json(CreatedCode {
        code: credential.encode(),
        record,
        key_fingerprint,
    }))
}

#[derive(Deserialize)]
pub struct CodeChange {
    note: Option<String>,
    /// Counted from now. Empty removes the deadline.
    duration: Option<String>,
}

pub async fn update_code(
    State(console): State<Arc<Console>>,
    scoped: Scoped,
    Path((_, code)): Path<(WorkspaceId, String)>,
    Json(body): Json<CodeChange>,
) -> ApiResult<StatusCode> {
    let id = scoped.workspace.id;
    let expiry = match body.duration.as_deref() {
        Some(text) => Some(deadline(Some(text), unix_now())?),
        None => None,
    };
    console
        .store()
        .update_code(id, &code, body.note.as_deref(), expiry)?;
    console.audit(&scoped.actor, Some(id), "update_code", &code);
    Ok(StatusCode::NO_CONTENT)
}

pub async fn revoke_code(
    State(console): State<Arc<Console>>,
    scoped: Scoped,
    Path((_, code)): Path<(WorkspaceId, String)>,
) -> ApiResult<StatusCode> {
    let id = scoped.workspace.id;
    console.hub.revoke_code(id, &code, unix_now())?;
    console.audit(&scoped.actor, Some(id), "revoke_code", &code);
    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_code(
    State(console): State<Arc<Console>>,
    scoped: Scoped,
    Path((_, code)): Path<(WorkspaceId, String)>,
) -> ApiResult<StatusCode> {
    let id = scoped.workspace.id;
    console.hub.delete_code(id, &code)?;
    console.audit(&scoped.actor, Some(id), "delete_code", &code);
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct NewBan {
    pub(super) kind: String,
    pub(super) value: String,
    #[serde(default)]
    pub(super) note: String,
    pub(super) duration: Option<String>,
}

pub(super) fn ban_target(body: &NewBan) -> ApiResult<BanTarget> {
    match body.kind.as_str() {
        "device" => {
            let value = body.value.trim();
            if !device::is_valid(value) {
                return Err(ApiError::bad_request("设备 ID 格式不正确"));
            }
            Ok(BanTarget::Device(value.to_owned()))
        }
        "ip" => parse_ip_target(&body.value)
            .map(BanTarget::Ip)
            .ok_or_else(|| ApiError::bad_request("IP 或网段格式不正确")),
        _ => Err(ApiError::bad_request("类型只能是 device 或 ip")),
    }
}

pub async fn bans(
    State(console): State<Arc<Console>>,
    scoped: Scoped,
    Query(params): Query<PageParams>,
) -> ApiResult<Json<Page<Ban>>> {
    Ok(Json(console.store().bans(
        Some(scoped.workspace.id),
        params.request(),
        unix_now(),
    )?))
}

pub async fn add_ban(
    State(console): State<Arc<Console>>,
    scoped: Scoped,
    Json(body): Json<NewBan>,
) -> ApiResult<Json<Ban>> {
    let now = unix_now();
    let id = scoped.workspace.id;
    let target = ban_target(&body)?;
    let expires = deadline(body.duration.as_deref(), now)?;
    let ban = console
        .hub
        .add_ban(Some(id), target, &body.note, expires, now)?;
    console.audit(&scoped.actor, Some(id), "add_ban", &body.value);
    Ok(Json(ban))
}

pub async fn remove_ban(
    State(console): State<Arc<Console>>,
    scoped: Scoped,
    Path((_, ban)): Path<(WorkspaceId, String)>,
) -> ApiResult<StatusCode> {
    let id = scoped.workspace.id;
    console.store().remove_ban(Some(id), &ban)?;
    console.audit(&scoped.actor, Some(id), "remove_ban", &ban);
    Ok(StatusCode::NO_CONTENT)
}

pub async fn audit(
    State(console): State<Arc<Console>>,
    scoped: Scoped,
    Query(params): Query<PageParams>,
) -> ApiResult<Json<Page<AuditEntry>>> {
    Ok(Json(console.store().audit_entries(
        Some(scoped.workspace.id),
        params.request(),
    )?))
}

pub async fn tokens(
    State(console): State<Arc<Console>>,
    scoped: Scoped,
) -> ApiResult<Json<Vec<TokenInfo>>> {
    Ok(Json(console.store().tokens(Some(scoped.workspace.id))?))
}

#[derive(Deserialize)]
pub struct NewToken {
    pub(super) name: String,
    pub(super) duration: Option<String>,
}

/// The token is in this response and nowhere else.
#[derive(Serialize)]
pub struct CreatedToken {
    pub(super) token: String,
    #[serde(flatten)]
    pub(super) info: TokenInfo,
}

pub async fn create_token(
    State(console): State<Arc<Console>>,
    scoped: Scoped,
    Json(body): Json<NewToken>,
) -> ApiResult<Json<CreatedToken>> {
    let now = unix_now();
    let id = scoped.workspace.id;
    let expires = deadline(body.duration.as_deref(), now)?;
    let created = console
        .store()
        .create_token(Some(id), &body.name, expires, now)?;
    console.audit(&scoped.actor, Some(id), "create_token", &created.info.id);
    Ok(Json(CreatedToken {
        token: created.token,
        info: created.info,
    }))
}

pub async fn delete_token(
    State(console): State<Arc<Console>>,
    scoped: Scoped,
    Path((_, token)): Path<(WorkspaceId, String)>,
) -> ApiResult<StatusCode> {
    let id = scoped.workspace.id;
    console.store().delete_token(Some(id), &token)?;
    console.audit(&scoped.actor, Some(id), "delete_token", &token);
    Ok(StatusCode::NO_CONTENT)
}

pub async fn admins(
    State(console): State<Arc<Console>>,
    OwnerScoped(scoped): OwnerScoped,
) -> ApiResult<Json<Vec<AdminView>>> {
    Ok(Json(console.store().admins(scoped.workspace.id)?))
}

#[derive(Deserialize)]
pub struct NewAdmin {
    username: String,
    /// Omitted by the super administrator to add an existing account.
    password: Option<String>,
    role: Role,
}

pub async fn add_admin(
    State(console): State<Arc<Console>>,
    OwnerScoped(scoped): OwnerScoped,
    Json(body): Json<NewAdmin>,
) -> ApiResult<StatusCode> {
    let id = scoped.workspace.id;
    let store = console.store();
    match body.password {
        Some(password) => {
            let hash = console.hash(password).await?;
            store.add_admin(id, &body.username, &hash, body.role, unix_now())?;
        }
        // Only someone who can already see every account may share one, so an owner
        // cannot use this to find out who else has an account here.
        None if scoped.standing == Standing::Super => {
            store.attach_admin(id, &body.username, body.role)?;
        }
        None => return Err(ApiError::bad_request("需要初始密码")),
    }
    console.audit(&scoped.actor, Some(id), "add_admin", &body.username);
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct RoleChange {
    role: Role,
}

pub async fn set_role(
    State(console): State<Arc<Console>>,
    OwnerScoped(scoped): OwnerScoped,
    Path((_, user)): Path<(WorkspaceId, UserId)>,
    Json(body): Json<RoleChange>,
) -> ApiResult<StatusCode> {
    let id = scoped.workspace.id;
    console.store().set_role(id, user, body.role)?;
    console.audit(&scoped.actor, Some(id), "set_role", &user.to_string());
    Ok(StatusCode::NO_CONTENT)
}

pub async fn remove_admin(
    State(console): State<Arc<Console>>,
    OwnerScoped(scoped): OwnerScoped,
    Path((_, user)): Path<(WorkspaceId, UserId)>,
) -> ApiResult<StatusCode> {
    let id = scoped.workspace.id;
    console.store().remove_admin(id, user)?;
    console.audit(&scoped.actor, Some(id), "remove_admin", &user.to_string());
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct PasswordReset {
    password: String,
}

/// An owner's reach stops at accounts only their workspace uses: taking over a
/// shared account would reach into another team.
pub async fn reset_admin_password(
    State(console): State<Arc<Console>>,
    OwnerScoped(scoped): OwnerScoped,
    Path((_, user)): Path<(WorkspaceId, UserId)>,
    Json(body): Json<PasswordReset>,
) -> ApiResult<StatusCode> {
    let id = scoped.workspace.id;
    let store = console.store();
    let target = store
        .admins(id)?
        .into_iter()
        .find(|admin| admin.user_id == user)
        .ok_or_else(ApiError::not_found)?;
    if target.shared && scoped.standing != Standing::Super {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "这个账号还属于其他工作区，请联系超管重置",
        ));
    }
    let hash = console.hash(body.password).await?;
    store.set_password(user, &hash, true, None)?;
    console.audit(&scoped.actor, Some(id), "reset_password", &target.username);
    Ok(StatusCode::NO_CONTENT)
}
