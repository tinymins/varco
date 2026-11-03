//! The admin console: JSON over plain HTTP, meant to sit behind a reverse proxy that
//! provides TLS. Who may do what is decided in one place, the extractors below, so
//! a handler that takes a [`Scoped`] cannot reach another workspace.
mod account;
mod system;
#[cfg(test)]
mod tests;
mod workspace;

use super::hub::Hub;
use super::store::{
    client_key, hash_password, unix_now, ChangeError, PageRequest, Role, Store, UserId, Workspace,
    WorkspaceId,
};
use super::Relay;
use crate::credential::Pin;
use anyhow::Context;
use axum::extract::{FromRequestParts, Path, Request};
use axum::http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, COOKIE, REFERRER_POLICY,
    X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{from_fn, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

const COOKIE_NAME: &str = "varco_admin";
const SESSION_LIFETIME_SECS: u64 = 12 * 3600;
const MAX_FAILURES: u32 = 5;
const LOCKOUT: Duration = Duration::from_secs(60);
/// Forgotten once this quiet, so guessed usernames cannot fill memory.
const LIMITER_MEMORY: Duration = Duration::from_secs(3600);
const LIMITER_PRUNE_ABOVE: usize = 1024;
/// Each password check takes tens of megabytes for a moment.
const CONCURRENT_PASSWORD_CHECKS: usize = 4;
const DEFAULT_PAGE: u32 = 100;
const MAX_PAGE: u32 = 500;
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; \
                   base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// Per username: with several teams on one server, a shared count would let
/// anyone lock every team out.
#[derive(Default)]
struct Limiter {
    accounts: HashMap<String, Attempts>,
}

struct Attempts {
    failures: u32,
    locked_until: Option<Instant>,
    last_failure: Instant,
}

impl Limiter {
    fn locked(&mut self, username: &str, now: Instant) -> bool {
        let Some(attempts) = self.accounts.get_mut(username) else {
            return false;
        };
        match attempts.locked_until {
            Some(until) if now < until => true,
            Some(_) => {
                self.accounts.remove(username);
                false
            }
            None => false,
        }
    }

    fn failed(&mut self, username: &str, now: Instant) {
        if self.accounts.len() > LIMITER_PRUNE_ABOVE {
            self.accounts
                .retain(|_, a| now.saturating_duration_since(a.last_failure) < LIMITER_MEMORY);
        }
        let attempts = self
            .accounts
            .entry(username.to_owned())
            .or_insert(Attempts {
                failures: 0,
                locked_until: None,
                last_failure: now,
            });
        attempts.failures += 1;
        attempts.last_failure = now;
        if attempts.failures >= MAX_FAILURES {
            attempts.locked_until = Some(now + LOCKOUT);
        }
    }

    fn succeeded(&mut self, username: &str) {
        self.accounts.remove(username);
    }
}

pub struct Console {
    hub: Arc<Hub>,
    relay: Arc<Relay>,
    pin: Pin,
    limiter: Mutex<Limiter>,
    password_checks: Semaphore,
    /// Checked when the username does not exist, so a miss takes as long as a hit.
    decoy_hash: String,
}

impl Console {
    pub fn new(hub: Arc<Hub>, relay: Arc<Relay>, pin: Pin) -> Arc<Self> {
        Arc::new(Self {
            hub,
            relay,
            pin,
            limiter: Mutex::default(),
            password_checks: Semaphore::new(CONCURRENT_PASSWORD_CHECKS),
            decoy_hash: hash_password("decoy").expect("hashing a constant"),
        })
    }

    fn store(&self) -> &Arc<Store> {
        self.hub.store().expect("the server always has a store")
    }

    /// Failing to record is reported to the log, not to whoever made the change,
    /// which has already happened.
    fn audit(&self, actor: &Actor, workspace: Option<WorkspaceId>, action: &str, target: &str) {
        info!(actor = %actor.name, ?workspace, action, target, "admin console");
        if let Err(detail) = self.store().audit(
            &actor.name,
            workspace,
            action,
            target,
            &actor.source,
            unix_now(),
        ) {
            warn!(%detail, "audit entry not recorded");
        }
    }

    async fn hash(&self, password: String) -> ApiResult<String> {
        let _permit = self.password_checks.acquire().await.map_err(internal)?;
        tokio::task::spawn_blocking(move || hash_password(&password))
            .await
            .map_err(internal)?
            .map_err(internal)
    }
}

fn internal(detail: impl std::fmt::Display) -> ApiError {
    error!(%detail, "admin console request failed");
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "服务端出错，操作没有完成",
    )
}

pub struct ApiError(StatusCode, String);

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self(status, message.into())
    }
    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }
    fn forbidden() -> Self {
        Self::new(StatusCode::FORBIDDEN, "没有权限")
    }
    fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "对象不存在，可能已被处理")
    }
}

impl From<ChangeError> for ApiError {
    fn from(change: ChangeError) -> Self {
        match change {
            ChangeError::NotFound => Self::not_found(),
            ChangeError::Conflict(message) => Self::new(StatusCode::CONFLICT, message),
            ChangeError::Invalid(message) => Self::bad_request(message),
            ChangeError::Db(detail) => internal(detail),
        }
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(detail: rusqlite::Error) -> Self {
        internal(detail)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        #[derive(Serialize)]
        struct Body {
            error: String,
        }
        (self.0, Json(Body { error: self.1 })).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

// ---- Who is asking ----

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Super,
    User(UserId),
    /// A token acts as an ordinary administrator of its workspace.
    Token(WorkspaceId),
}

#[derive(Debug, Clone)]
pub struct Actor {
    pub name: String,
    pub access: Access,
    pub user: Option<UserId>,
    pub session: Option<String>,
    /// What the proxy reports. Anyone can send this header, so it is a note, not proof.
    pub source: String,
    pub must_change_password: bool,
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
}

fn cookie_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|pair| pair.trim().strip_prefix(COOKIE_NAME)?.strip_prefix('='))
}

fn source_of(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(|value| value.trim().chars().take(64).collect())
        .unwrap_or_default()
}

fn identify(console: &Console, headers: &HeaderMap) -> ApiResult<Option<Actor>> {
    let now = unix_now();
    let store = console.store();
    let source = source_of(headers);
    if let Some(token) = bearer_token(headers) {
        let Some(info) = store.token_info(token, now)? else {
            return Ok(None);
        };
        return Ok(Some(Actor {
            name: format!("token:{}", info.name),
            access: info.workspace_id.map_or(Access::Super, Access::Token),
            user: None,
            session: None,
            source,
            must_change_password: false,
        }));
    }
    let Some(token) = cookie_token(headers) else {
        return Ok(None);
    };
    let Some(user) = store.session_user(token, now)? else {
        return Ok(None);
    };
    Ok(Some(Actor {
        access: if user.is_super {
            Access::Super
        } else {
            Access::User(user.id)
        },
        name: user.username,
        user: Some(user.id),
        session: Some(client_key(token)),
        source,
        must_change_password: user.must_change_password,
    }))
}

/// Logged in, even if the password still has to be changed.
pub struct Signed(pub Actor);

impl FromRequestParts<Arc<Console>> for Signed {
    type Rejection = ApiError;
    async fn from_request_parts(
        parts: &mut Parts,
        console: &Arc<Console>,
    ) -> Result<Self, ApiError> {
        identify(console, &parts.headers)?
            .map(Self)
            .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "请先登录"))
    }
}

/// A person rather than a token, even if their password still has to be changed.
pub struct Person(pub Actor, pub UserId);

impl FromRequestParts<Arc<Console>> for Person {
    type Rejection = ApiError;
    async fn from_request_parts(
        parts: &mut Parts,
        console: &Arc<Console>,
    ) -> Result<Self, ApiError> {
        let Signed(actor) = Signed::from_request_parts(parts, console).await?;
        let user = actor.user.ok_or_else(ApiError::forbidden)?;
        Ok(Self(actor, user))
    }
}

/// Logged in with a password of their own.
pub struct Authed(pub Actor);

impl FromRequestParts<Arc<Console>> for Authed {
    type Rejection = ApiError;
    async fn from_request_parts(
        parts: &mut Parts,
        console: &Arc<Console>,
    ) -> Result<Self, ApiError> {
        let Signed(actor) = Signed::from_request_parts(parts, console).await?;
        if actor.must_change_password {
            return Err(ApiError::new(StatusCode::FORBIDDEN, "请先修改密码"));
        }
        Ok(Self(actor))
    }
}

pub struct SuperOnly(pub Actor);

impl FromRequestParts<Arc<Console>> for SuperOnly {
    type Rejection = ApiError;
    async fn from_request_parts(
        parts: &mut Parts,
        console: &Arc<Console>,
    ) -> Result<Self, ApiError> {
        let Authed(actor) = Authed::from_request_parts(parts, console).await?;
        if actor.access != Access::Super {
            return Err(ApiError::forbidden());
        }
        Ok(Self(actor))
    }
}

/// Someone's rights inside one workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Standing {
    Super,
    Owner,
    Admin,
}

/// A workspace the caller may act in. Any other answers "not found", so ids reveal
/// nothing about other teams.
pub struct Scoped {
    pub actor: Actor,
    pub workspace: Workspace,
    pub standing: Standing,
}

impl FromRequestParts<Arc<Console>> for Scoped {
    type Rejection = ApiError;
    async fn from_request_parts(
        parts: &mut Parts,
        console: &Arc<Console>,
    ) -> Result<Self, ApiError> {
        let Authed(actor) = Authed::from_request_parts(parts, console).await?;
        let Path(params) = Path::<HashMap<String, String>>::from_request_parts(parts, console)
            .await
            .map_err(|_| ApiError::not_found())?;
        let id: WorkspaceId = params
            .get("ws")
            .and_then(|text| text.parse().ok())
            .ok_or_else(ApiError::not_found)?;
        let standing = match actor.access {
            Access::Super => Some(Standing::Super),
            Access::Token(workspace) => (workspace == id).then_some(Standing::Admin),
            Access::User(user) => console.store().role_of(user, id)?.map(|role| match role {
                Role::Owner => Standing::Owner,
                Role::Admin => Standing::Admin,
            }),
        };
        let standing = standing.ok_or_else(ApiError::not_found)?;
        let workspace = console
            .store()
            .workspace(id)?
            .ok_or_else(ApiError::not_found)?;
        Ok(Self {
            actor,
            workspace,
            standing,
        })
    }
}

/// May change who administers a workspace.
pub struct OwnerScoped(pub Scoped);

impl FromRequestParts<Arc<Console>> for OwnerScoped {
    type Rejection = ApiError;
    async fn from_request_parts(
        parts: &mut Parts,
        console: &Arc<Console>,
    ) -> Result<Self, ApiError> {
        let scoped = Scoped::from_request_parts(parts, console).await?;
        if scoped.standing == Standing::Admin {
            return Err(ApiError::forbidden());
        }
        Ok(Self(scoped))
    }
}

// ---- Listing ----

#[derive(Debug, Deserialize)]
pub struct PageParams {
    #[serde(default)]
    q: String,
    limit: Option<u32>,
    #[serde(default)]
    offset: u32,
}

impl PageParams {
    fn request(&self) -> PageRequest<'_> {
        PageRequest {
            query: &self.q,
            limit: self.limit.unwrap_or(DEFAULT_PAGE).min(MAX_PAGE),
            offset: self.offset,
        }
    }
}

// ---- Middleware ----

/// A cross-site form cannot send this content type without a CORS preflight, which
/// this server never approves. Together with SameSite=Strict this stops CSRF. A
/// bearer token is never sent by a browser on its own, so it needs no such check.
async fn require_json_for_writes(request: Request, next: Next) -> Response {
    let is_read = matches!(*request.method(), Method::GET | Method::HEAD);
    let is_json = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json"));
    if !is_read && !is_json && bearer_token(request.headers()).is_none() {
        return ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "需要 Content-Type: application/json",
        )
        .into_response();
    }
    next.run(request).await
}

async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    let mut set = |name, value: &'static str| {
        headers.insert(name, HeaderValue::from_static(value));
    };
    // Responses can carry a Code that is shown only once.
    set(CACHE_CONTROL, "no-store");
    set(CONTENT_SECURITY_POLICY, CSP);
    set(REFERRER_POLICY, "no-referrer");
    set(X_CONTENT_TYPE_OPTIONS, "nosniff");
    set(X_FRAME_OPTIONS, "DENY");
    response
}

async fn script() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("ui/app.js"),
    )
}

async fn components() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("ui/components.js"),
    )
}

async fn stylesheet() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("ui/style.css"),
    )
}

pub fn router(console: Arc<Console>) -> Router {
    use account as a;
    use system as s;
    use workspace as w;
    Router::new()
        .route("/", get(|| async { Html(include_str!("ui/index.html")) }))
        .route("/app.js", get(script))
        .route("/components.js", get(components))
        .route("/style.css", get(stylesheet))
        .route("/healthz", get(s::healthz))
        .route("/metrics", get(s::metrics))
        .route("/api/login", post(a::login))
        .route("/api/logout", post(a::logout))
        .route("/api/me", get(a::me))
        .route("/api/me/password", post(a::change_password))
        .route("/api/me/sessions", get(a::sessions))
        .route(
            "/api/me/sessions/{id}",
            axum::routing::delete(a::end_session),
        )
        .route("/api/settings", get(s::settings).put(s::update_settings))
        .route(
            "/api/workspaces",
            get(s::workspaces).post(s::create_workspace),
        )
        .route(
            "/api/workspaces/{ws}",
            patch(s::update_workspace).delete(s::delete_workspace),
        )
        .route("/api/users", get(s::users))
        .route("/api/users/{user}", axum::routing::delete(s::delete_user))
        .route("/api/users/{user}/password", post(s::reset_user_password))
        .route("/api/bans", get(s::global_bans).post(s::add_global_ban))
        .route(
            "/api/bans/{id}",
            axum::routing::delete(s::remove_global_ban),
        )
        .route("/api/audit", get(s::global_audit))
        .route(
            "/api/tokens",
            get(s::global_tokens).post(s::create_global_token),
        )
        .route(
            "/api/tokens/{id}",
            axum::routing::delete(s::delete_global_token),
        )
        .route("/api/w/{ws}", get(w::overview))
        .route("/api/w/{ws}/members", get(w::members))
        .route("/api/w/{ws}/members/kick", post(w::kick))
        .route("/api/w/{ws}/kicked", get(w::kicked))
        .route(
            "/api/w/{ws}/kicked/{client}",
            axum::routing::delete(w::unkick),
        )
        .route("/api/w/{ws}/connections", get(w::connections))
        .route("/api/w/{ws}/codes", get(w::codes).post(w::create_code))
        .route(
            "/api/w/{ws}/codes/{id}",
            patch(w::update_code).delete(w::delete_code),
        )
        .route("/api/w/{ws}/codes/{id}/revoke", post(w::revoke_code))
        .route("/api/w/{ws}/bans", get(w::bans).post(w::add_ban))
        .route(
            "/api/w/{ws}/bans/{id}",
            axum::routing::delete(w::remove_ban),
        )
        .route("/api/w/{ws}/audit", get(w::audit))
        .route("/api/w/{ws}/tokens", get(w::tokens).post(w::create_token))
        .route(
            "/api/w/{ws}/tokens/{id}",
            axum::routing::delete(w::delete_token),
        )
        .route("/api/w/{ws}/admins", get(w::admins).post(w::add_admin))
        .route(
            "/api/w/{ws}/admins/{user}",
            patch(w::set_role).delete(w::remove_admin),
        )
        .route(
            "/api/w/{ws}/admins/{user}/password",
            post(w::reset_admin_password),
        )
        .layer(from_fn(require_json_for_writes))
        .layer(from_fn(security_headers))
        .with_state(console)
}

/// Binds now, so a port in use stops the server at startup instead of leaving it
/// running with no console.
pub async fn spawn(listen: &str, console: Arc<Console>) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding admin console {listen}"))?;
    let address = listener.local_addr()?;
    if !address.ip().is_loopback() {
        warn!(%address, "admin console is plain HTTP on a non-loopback address; passwords and Codes can be read on the network, and until the default password is changed anyone reaching this port can take over");
    }
    info!(%address, "admin console started");
    tokio::spawn(async move {
        if let Err(detail) = axum::serve(listener, router(console)).await {
            error!(%detail, "admin console stopped");
        }
    });
    Ok(())
}
