//! What only the super administrator can do, plus health and metrics.
use super::workspace::{ban_target, deadline, CreatedToken, NewBan, NewToken, TokenSecret};
use super::{ApiError, ApiResult, Console, PageParams, SuperOnly};
use crate::server::hub::NetworkStats;
use crate::server::store::{
    is_host_port, parse_cidr, unix_now, AuditEntry, Ban, ChangeError, Page, Role, TokenInfo,
    UserId, UserOverview, Workspace, WorkspaceId, SETTING_HISTORY_DAYS, SETTING_PUBLIC_ADDR,
    SETTING_PUBLIC_IP, SETTING_RELAY_LISTEN,
};
use axum::extract::{Path, Query, State};
use axum::http::header::{CONTENT_TYPE, HOST};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::fmt::Write;
use std::sync::Arc;

const DEFAULT_RELAY_LISTEN: &str = "0.0.0.0:8443";
const DEFAULT_RELAY_PORT: u16 = 8443;

#[derive(Serialize)]
pub struct Health {
    relay_listening: bool,
}

/// Open to anything that can reach the port, so it says nothing but this.
pub async fn healthz(State(console): State<Arc<Console>>) -> Json<Health> {
    Json(Health {
        relay_listening: console.relay.listening_on().await.is_some(),
    })
}

#[derive(Serialize)]
pub struct Settings {
    public_addr: Option<String>,
    /// Empty means the address is looked up each time a Code is copied.
    public_ip: Option<String>,
    relay_listen: Option<String>,
    relay_listening_on: Option<String>,
    history_days: u64,
    /// Starting points for a new installation.
    suggested_public_addr: String,
    suggested_relay_listen: &'static str,
}

/// The name this console was reached by is the best guess at where the relay is.
fn suggest_public_addr(headers: &HeaderMap) -> String {
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(HOST))
        .and_then(|value| value.to_str().ok())
        .unwrap_or("vpn.example.com");
    let name = match host.rsplit_once(':') {
        Some((name, port)) if port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => host,
    };
    format!("{name}:{DEFAULT_RELAY_PORT}")
}

pub async fn settings(
    State(console): State<Arc<Console>>,
    SuperOnly(_): SuperOnly,
    headers: HeaderMap,
) -> ApiResult<Json<Settings>> {
    let store = console.store();
    Ok(Json(Settings {
        public_addr: store.setting(SETTING_PUBLIC_ADDR)?,
        public_ip: store.setting(SETTING_PUBLIC_IP)?,
        relay_listen: store.setting(SETTING_RELAY_LISTEN)?,
        relay_listening_on: console.relay.listening_on().await,
        history_days: store.history_days()?,
        suggested_public_addr: suggest_public_addr(&headers),
        suggested_relay_listen: DEFAULT_RELAY_LISTEN,
    }))
}

#[derive(Deserialize)]
pub struct SettingsChange {
    public_addr: Option<String>,
    public_ip: Option<String>,
    relay_listen: Option<String>,
    history_days: Option<u64>,
}

pub async fn update_settings(
    State(console): State<Arc<Console>>,
    SuperOnly(actor): SuperOnly,
    Json(body): Json<SettingsChange>,
) -> ApiResult<StatusCode> {
    let store = console.store();
    let public_addr = body.public_addr.as_deref().map(str::trim);
    if public_addr.is_some_and(|addr| !is_host_port(addr)) {
        return Err(ApiError::bad_request(
            "对外地址要写成 host:port 或 ip:port，例如 vpn.example.com:8443",
        ));
    }
    let public_ip = body.public_ip.as_deref().map(str::trim);
    if public_ip.is_some_and(|ip| !ip.is_empty() && ip.parse::<std::net::IpAddr>().is_err()) {
        return Err(ApiError::bad_request(
            "对外 IP 只写 IP，不带端口，例如 203.0.113.7；留空表示自动解析",
        ));
    }
    if body.history_days == Some(0) {
        return Err(ApiError::bad_request("历史保留天数至少为 1"));
    }
    if let Some(listen) = body.relay_listen.as_deref().map(str::trim) {
        // First, because it is the one step that can fail for outside reasons.
        console
            .relay
            .listen(listen)
            .await
            .map_err(|detail| ApiError::bad_request(format!("无法监听 {listen}：{detail:#}")))?;
        store.set_setting(SETTING_RELAY_LISTEN, listen)?;
    }
    if let Some(addr) = public_addr {
        store.set_setting(SETTING_PUBLIC_ADDR, addr)?;
    }
    if let Some(ip) = public_ip {
        store.set_setting(SETTING_PUBLIC_IP, ip)?;
    }
    if let Some(days) = body.history_days {
        store.set_setting(SETTING_HISTORY_DAYS, &days.to_string())?;
    }
    console.audit(&actor, None, "update_settings", "");
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
pub struct WorkspaceRow {
    #[serde(flatten)]
    workspace: Workspace,
    stats: Option<NetworkStats>,
}

#[derive(Serialize)]
pub struct WorkspaceList {
    items: Vec<WorkspaceRow>,
    suggested_cidr: String,
}

pub async fn workspaces(
    State(console): State<Arc<Console>>,
    SuperOnly(_): SuperOnly,
) -> ApiResult<Json<WorkspaceList>> {
    let store = console.store();
    let stats = console.hub.stats();
    Ok(Json(WorkspaceList {
        items: store
            .workspaces()?
            .into_iter()
            .map(|workspace| WorkspaceRow {
                stats: stats
                    .iter()
                    .find(|s| s.workspace_id == workspace.id)
                    .cloned(),
                workspace,
            })
            .collect(),
        suggested_cidr: store.suggest_cidr()?,
    }))
}

#[derive(Deserialize)]
pub struct NewWorkspace {
    name: String,
    cidr: String,
    /// Optionally give it its owner straight away.
    owner_username: Option<String>,
    owner_password: Option<String>,
}

pub async fn create_workspace(
    State(console): State<Arc<Console>>,
    SuperOnly(actor): SuperOnly,
    Json(body): Json<NewWorkspace>,
) -> ApiResult<Json<Workspace>> {
    let store = console.store();
    let now = unix_now();
    let cidr = parse_cidr(&body.cidr)?;
    let owner = body
        .owner_username
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty());
    // Hashed before anything is created, as it is the slow part.
    let owner_hash = match (owner, body.owner_password) {
        (Some(_), Some(password)) => Some(console.hash(password).await?),
        _ => None,
    };
    let workspace = store.create_workspace(&body.name, cidr, now)?;
    let added = match (owner, &owner_hash) {
        (Some(name), Some(hash)) => store
            .add_admin(workspace.id, name, hash, Role::Owner, now)
            .map(drop),
        (Some(name), None) => store
            .attach_admin(workspace.id, name, Role::Owner)
            .map(drop),
        _ => Ok(()),
    };
    if let Err(problem) = added {
        // No half-made workspace left behind for a name that was taken.
        store.delete_workspace(workspace.id)?;
        return Err(match problem {
            ChangeError::NotFound => ApiError::bad_request("没有这个账号，请同时填写初始密码"),
            other => other.into(),
        });
    }
    console.hub.add_network(&workspace);
    console.audit(
        &actor,
        Some(workspace.id),
        "create_workspace",
        &workspace.name,
    );
    Ok(Json(workspace))
}

#[derive(Deserialize)]
pub struct WorkspaceChange {
    name: Option<String>,
    cidr: Option<String>,
}

pub async fn update_workspace(
    State(console): State<Arc<Console>>,
    SuperOnly(actor): SuperOnly,
    Path(id): Path<WorkspaceId>,
    Json(body): Json<WorkspaceChange>,
) -> ApiResult<Json<Workspace>> {
    let store = console.store();
    let before = store.workspace(id)?.ok_or_else(ApiError::not_found)?;
    let cidr = body.cidr.as_deref().map(parse_cidr).transpose()?;
    let updated = store.update_workspace(id, body.name.as_deref(), cidr)?;
    if updated.cidr != before.cidr {
        console.hub.replace_network(&updated);
    } else if updated.name != before.name {
        console.hub.rename_network(id, &updated.name);
    }
    console.audit(&actor, Some(id), "update_workspace", &updated.name);
    Ok(Json(updated))
}

pub async fn delete_workspace(
    State(console): State<Arc<Console>>,
    SuperOnly(actor): SuperOnly,
    Path(id): Path<WorkspaceId>,
) -> ApiResult<StatusCode> {
    let store = console.store();
    let workspace = store.workspace(id)?.ok_or_else(ApiError::not_found)?;
    // In this order: when members are disconnected their Codes are already gone,
    // so they stop instead of reconnecting.
    store.delete_workspace(id)?;
    console.hub.remove_network(id);
    console.audit(&actor, Some(id), "delete_workspace", &workspace.name);
    Ok(StatusCode::NO_CONTENT)
}

pub async fn users(
    State(console): State<Arc<Console>>,
    SuperOnly(_): SuperOnly,
) -> ApiResult<Json<Vec<UserOverview>>> {
    Ok(Json(console.store().users()?))
}

pub async fn delete_user(
    State(console): State<Arc<Console>>,
    SuperOnly(actor): SuperOnly,
    Path(user): Path<UserId>,
) -> ApiResult<StatusCode> {
    console.store().delete_user(user)?;
    console.audit(&actor, None, "delete_user", &user.to_string());
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct PasswordReset {
    password: String,
}

/// They must choose their own at next login.
pub async fn reset_user_password(
    State(console): State<Arc<Console>>,
    SuperOnly(actor): SuperOnly,
    Path(user): Path<UserId>,
    Json(body): Json<PasswordReset>,
) -> ApiResult<StatusCode> {
    let hash = console.hash(body.password).await?;
    console.store().set_password(user, &hash, true, None)?;
    console.audit(&actor, None, "reset_password", &user.to_string());
    Ok(StatusCode::NO_CONTENT)
}

pub async fn global_bans(
    State(console): State<Arc<Console>>,
    SuperOnly(_): SuperOnly,
    Query(params): Query<PageParams>,
) -> ApiResult<Json<Page<Ban>>> {
    Ok(Json(console.store().bans(
        None,
        params.request(),
        unix_now(),
    )?))
}

pub async fn add_global_ban(
    State(console): State<Arc<Console>>,
    SuperOnly(actor): SuperOnly,
    Json(body): Json<NewBan>,
) -> ApiResult<Json<Ban>> {
    let now = unix_now();
    let target = ban_target(&body)?;
    let expires = deadline(body.duration.as_deref(), now)?;
    let ban = console
        .hub
        .add_ban(None, target, &body.note, expires, now)?;
    console.audit(&actor, None, "add_ban", &body.value);
    Ok(Json(ban))
}

pub async fn remove_global_ban(
    State(console): State<Arc<Console>>,
    SuperOnly(actor): SuperOnly,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    console.store().remove_ban(None, &id)?;
    console.audit(&actor, None, "remove_ban", &id);
    Ok(StatusCode::NO_CONTENT)
}

pub async fn global_audit(
    State(console): State<Arc<Console>>,
    SuperOnly(_): SuperOnly,
    Query(params): Query<PageParams>,
) -> ApiResult<Json<Page<AuditEntry>>> {
    Ok(Json(console.store().audit_entries(None, params.request())?))
}

pub async fn global_tokens(
    State(console): State<Arc<Console>>,
    SuperOnly(_): SuperOnly,
) -> ApiResult<Json<Vec<TokenInfo>>> {
    Ok(Json(console.store().tokens(None)?))
}

pub async fn create_global_token(
    State(console): State<Arc<Console>>,
    SuperOnly(actor): SuperOnly,
    Json(body): Json<NewToken>,
) -> ApiResult<Json<CreatedToken>> {
    let now = unix_now();
    let expires = deadline(body.duration.as_deref(), now)?;
    let created = console
        .store()
        .create_token(None, &body.name, expires, now)?;
    console.audit(&actor, None, "create_token", &created.info.id);
    Ok(Json(CreatedToken {
        token: created.token,
        info: created.info,
    }))
}

pub async fn global_token_secret(
    State(console): State<Arc<Console>>,
    SuperOnly(actor): SuperOnly,
    Path(id): Path<String>,
) -> ApiResult<Json<TokenSecret>> {
    let token = console.store().token_secret(None, &id)?;
    console.audit(&actor, None, "copy_token", &id);
    Ok(Json(TokenSecret { token }))
}

pub async fn delete_global_token(
    State(console): State<Arc<Console>>,
    SuperOnly(actor): SuperOnly,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    console.store().delete_token(None, &id)?;
    console.audit(&actor, None, "delete_token", &id);
    Ok(StatusCode::NO_CONTENT)
}

/// Workspace names are free text, and the format gives these three characters meaning.
fn label_value(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

pub async fn metrics(
    State(console): State<Arc<Console>>,
    SuperOnly(_): SuperOnly,
) -> ApiResult<impl IntoResponse> {
    let workspaces = console.store().workspaces()?;
    let stats = console.hub.stats();
    let relay_up = u8::from(console.relay.listening_on().await.is_some());
    let mut out = String::new();
    let mut family =
        |name: &str, kind: &str, help: &str, value: &dyn Fn(&NetworkStats) -> String| {
            let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
            for stat in &stats {
                let label = workspaces
                    .iter()
                    .find(|w| w.id == stat.workspace_id)
                    .map_or_else(String::new, |w| label_value(&w.name));
                let _ = writeln!(out, "{name}{{workspace=\"{label}\"}} {}", value(stat));
            }
        };
    family(
        "varco_members_online",
        "gauge",
        "Members connected now.",
        &|s| s.online.to_string(),
    );
    family(
        "varco_addresses_total",
        "gauge",
        "Addresses the workspace's range holds.",
        &|s| s.capacity.to_string(),
    );
    family(
        "varco_received_bytes_total",
        "counter",
        "Packet bytes received from members since the server started.",
        &|s| s.rx_bytes.to_string(),
    );
    family(
        "varco_sent_bytes_total",
        "counter",
        "Packet bytes sent to members since the server started.",
        &|s| s.tx_bytes.to_string(),
    );
    let _ = writeln!(
        out,
        "# HELP varco_relay_up Whether the relay is listening.\n# TYPE varco_relay_up gauge\nvarco_relay_up {relay_up}"
    );
    Ok((
        [(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        out,
    ))
}
