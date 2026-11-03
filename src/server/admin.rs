//! The admin console: JSON over plain HTTP, meant to sit behind a reverse proxy that
//! provides TLS. Every change goes through [`Hub`] or [`Store`], which save it
//! before it takes effect.
use super::config::AdminConfig;
use super::hub::{CredentialView, Hub, MemberView, NetworkView};
use super::state::{
    self, parse_duration, parse_ip_target, unix_now, Ban, BanTarget, ChangeError, CodeKind,
    CodeRecord, CodeStatus, CodeUse, Store,
};
use crate::core::device;
use crate::core::ssh::store as ssh_store;
use crate::credential::{Credential, Pin};
use anyhow::Context;
use axum::extract::{Path, Request, State};
use axum::http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, COOKIE, REFERRER_POLICY, SET_COOKIE,
    X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{from_fn, from_fn_with_state, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tracing::{error, info, warn};

const PAGE: &str = include_str!("admin.html");
const COOKIE_NAME: &str = "varco_admin";
const SESSION_LIFETIME: Duration = Duration::from_secs(12 * 3600);
const MAX_FAILURES: u32 = 5;
const LOCKOUT: Duration = Duration::from_secs(60);
// Scripts and styles are inline in the one page. Client-supplied text only ever
// reaches it through textContent.
const CSP: &str = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; \
                   connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// Counted for everyone together: behind a proxy there is no trustworthy client
/// address to count by.
#[derive(Default)]
struct Limiter {
    failures: u32,
    locked_until: Option<Instant>,
}

impl Limiter {
    fn locked(&mut self, now: Instant) -> bool {
        match self.locked_until {
            Some(until) if now < until => true,
            Some(_) => {
                self.locked_until = None;
                self.failures = 0;
                false
            }
            None => false,
        }
    }

    fn failed(&mut self, now: Instant) {
        self.failures += 1;
        if self.failures >= MAX_FAILURES {
            self.locked_until = Some(now + LOCKOUT);
        }
    }

    fn succeeded(&mut self) {
        self.failures = 0;
    }
}

pub struct Console {
    settings: AdminConfig,
    hub: Arc<Hub>,
    public_addr: String,
    pin: Pin,
    /// Hashes of session tokens, so nothing in memory can be replayed as a cookie.
    sessions: Mutex<HashMap<String, Instant>>,
    limiter: Mutex<Limiter>,
}

impl Console {
    pub fn new(settings: AdminConfig, hub: Arc<Hub>, public_addr: String, pin: Pin) -> Arc<Self> {
        Arc::new(Self {
            settings,
            hub,
            public_addr,
            pin,
            sessions: Mutex::default(),
            limiter: Mutex::default(),
        })
    }

    fn store(&self) -> Result<&Arc<Store>, ApiError> {
        self.hub
            .store()
            .ok_or_else(|| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "服务端没有状态存储"))
    }

    fn open_session(&self, now: Instant) -> String {
        let token = hex_token();
        let mut sessions = self.sessions.lock().expect("sessions lock poisoned");
        sessions.retain(|_, expires| *expires > now);
        sessions.insert(token_key(&token), now + SESSION_LIFETIME);
        token
    }

    fn session_valid(&self, token: &str, now: Instant) -> bool {
        self.sessions
            .lock()
            .expect("sessions lock poisoned")
            .get(&token_key(token))
            .is_some_and(|expires| *expires > now)
    }

    fn close_session(&self, token: &str) {
        self.sessions
            .lock()
            .expect("sessions lock poisoned")
            .remove(&token_key(token));
    }
}

fn hex_token() -> String {
    crate::credential::generate_secret()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn token_key(token: &str) -> String {
    state::client_key(token)
}

/// Compares hashes, so neither content nor length shows in the timing.
fn same_text(a: &str, b: &str) -> bool {
    let a = Sha256::digest(a.as_bytes());
    let b = Sha256::digest(b.as_bytes());
    a.ct_eq(&b).into()
}

struct ApiError(StatusCode, String);

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self(status, message.into())
    }
    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }
}

impl From<ChangeError> for ApiError {
    fn from(change: ChangeError) -> Self {
        match change {
            ChangeError::NotFound => Self::new(StatusCode::NOT_FOUND, "对象不存在，可能已被处理"),
            ChangeError::Conflict => Self::new(StatusCode::CONFLICT, "已经存在"),
            ChangeError::Io(detail) => {
                error!(%detail, "console change not saved");
                Self::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "无法写入状态文件，操作没有生效",
                )
            }
        }
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

type ApiResult<T> = Result<T, ApiError>;

fn cookie_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|pair| pair.trim().strip_prefix(COOKIE_NAME)?.strip_prefix('='))
}

async fn require_session(
    State(console): State<Arc<Console>>,
    request: Request,
    next: Next,
) -> Response {
    let valid = cookie_token(request.headers())
        .is_some_and(|token| console.session_valid(token, Instant::now()));
    if !valid {
        return ApiError::new(StatusCode::UNAUTHORIZED, "请先登录").into_response();
    }
    next.run(request).await
}

/// A cross-site form cannot send this content type without a CORS preflight, which
/// this server never approves. Together with SameSite=Strict this stops CSRF.
async fn require_json_for_writes(request: Request, next: Next) -> Response {
    let is_read = matches!(*request.method(), Method::GET | Method::HEAD);
    let is_json = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json"));
    if !is_read && !is_json {
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

pub fn router(console: Arc<Console>) -> Router {
    let protected = Router::new()
        .route("/api/overview", get(overview))
        .route("/api/members", get(members))
        .route("/api/members/kick", post(kick_member))
        .route("/api/codes", get(list_codes).post(create_code))
        .route("/api/codes/{id}/revoke", post(revoke_code))
        .route("/api/bans", get(list_bans).post(add_ban))
        .route("/api/bans/{id}", delete(remove_ban))
        .route("/api/logout", post(logout))
        .route_layer(from_fn_with_state(console.clone(), require_session));
    Router::new()
        .route("/", get(|| async { Html(PAGE) }))
        .route("/api/login", post(login))
        .merge(protected)
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
        warn!(%address, "admin console is plain HTTP on a non-loopback address; passwords and Codes can be read on the network unless it is only reachable through a TLS proxy");
    }
    info!(%address, "admin console started");
    tokio::spawn(async move {
        if let Err(detail) = axum::serve(listener, router(console)).await {
            error!(%detail, "admin console stopped");
        }
    });
    Ok(())
}

#[derive(Deserialize)]
struct LoginBody {
    username: String,
    password: String,
}

fn session_cookie(value: &str, max_age: u64, secure: bool) -> ApiResult<HeaderValue> {
    let secure = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{COOKIE_NAME}={value}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}{secure}"
    ))
    .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法设置登录状态"))
}

/// Only a proxy can have terminated TLS, as this listener has none.
fn behind_https(headers: &HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("https"))
}

async fn login(
    State(console): State<Arc<Console>>,
    headers: HeaderMap,
    Json(body): Json<LoginBody>,
) -> ApiResult<Response> {
    let now = Instant::now();
    let mut limiter = console.limiter.lock().expect("limiter lock poisoned");
    if limiter.locked(now) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "失败次数过多，请一分钟后再试",
        ));
    }
    let settings = &console.settings;
    // Both are always compared, so which one was wrong does not show in the timing.
    let matches = same_text(&body.username, &settings.username)
        & same_text(&body.password, &settings.password);
    if !matches {
        limiter.failed(now);
        warn!("admin console: failed login");
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "用户名或密码不正确",
        ));
    }
    limiter.succeeded();
    drop(limiter);
    let token = console.open_session(now);
    info!("admin console: logged in");
    let cookie = session_cookie(&token, SESSION_LIFETIME.as_secs(), behind_https(&headers))?;
    Ok((StatusCode::NO_CONTENT, [(SET_COOKIE, cookie)]).into_response())
}

async fn logout(State(console): State<Arc<Console>>, headers: HeaderMap) -> ApiResult<Response> {
    if let Some(token) = cookie_token(&headers) {
        console.close_session(token);
    }
    info!("admin console: logged out");
    let cookie = session_cookie("", 0, behind_https(&headers))?;
    Ok((StatusCode::NO_CONTENT, [(SET_COOKIE, cookie)]).into_response())
}

#[derive(Serialize)]
struct Overview {
    public_addr: String,
    networks: Vec<NetworkView>,
    credentials: Vec<CredentialView>,
}

async fn overview(State(console): State<Arc<Console>>) -> Json<Overview> {
    Json(Overview {
        public_addr: console.public_addr.clone(),
        networks: console.hub.network_views(),
        credentials: console.hub.credential_views(),
    })
}

async fn members(State(console): State<Arc<Console>>) -> Json<Vec<MemberView>> {
    Json(console.hub.members())
}

#[derive(Deserialize)]
struct KickBody {
    id: String,
}

async fn kick_member(
    State(console): State<Arc<Console>>,
    Json(body): Json<KickBody>,
) -> ApiResult<StatusCode> {
    console.hub.kick_member(&body.id, unix_now())?;
    info!(member = %body.id, "admin console: kicked");
    Ok(StatusCode::NO_CONTENT)
}

/// A record minus the secret's hash, which has no use outside the server.
#[derive(Serialize)]
struct CodeView {
    id: String,
    network: String,
    #[serde(flatten)]
    kind: CodeKind,
    note: String,
    created_at: u64,
    revoked_at: Option<u64>,
    status: CodeStatus,
    used_by: Vec<CodeUse>,
}

impl CodeView {
    fn new(record: CodeRecord, now: u64) -> Self {
        Self {
            status: record.status(now),
            id: record.id,
            network: record.network,
            kind: record.kind,
            note: record.note,
            created_at: record.created_at,
            revoked_at: record.revoked_at,
            used_by: record.used_by,
        }
    }
}

async fn list_codes(State(console): State<Arc<Console>>) -> ApiResult<Json<Vec<CodeView>>> {
    let now = unix_now();
    let mut codes: Vec<_> = console
        .store()?
        .codes()
        .into_iter()
        .map(|record| CodeView::new(record, now))
        .collect();
    codes.sort_by_key(|code| std::cmp::Reverse(code.created_at));
    Ok(Json(codes))
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum NewCodeKind {
    Once,
    Timed,
}

#[derive(Deserialize)]
struct NewCode {
    network: String,
    kind: NewCodeKind,
    /// For a timed Code: `30m`, `24h` or `7d`.
    #[serde(default)]
    duration: String,
    #[serde(default)]
    note: String,
    #[serde(default)]
    ssh_pubkey: String,
}

#[derive(Serialize)]
struct CreatedCode {
    code: String,
    #[serde(flatten)]
    record: CodeView,
    key_fingerprint: Option<String>,
}

async fn create_code(
    State(console): State<Arc<Console>>,
    Json(body): Json<NewCode>,
) -> ApiResult<Json<CreatedCode>> {
    let now = unix_now();
    if console.hub.network_index(&body.network).is_none() {
        return Err(ApiError::bad_request("没有这个网络"));
    }
    let kind = match body.kind {
        NewCodeKind::Once => CodeKind::Once,
        NewCodeKind::Timed => {
            let seconds = parse_duration(&body.duration)
                .ok_or_else(|| ApiError::bad_request("时长格式不正确，例如 30m、24h、7d"))?;
            CodeKind::Timed {
                expires_at: now
                    .checked_add(seconds)
                    .ok_or_else(|| ApiError::bad_request("时长太长"))?,
            }
        }
    };
    let ssh_pubkey = match body.ssh_pubkey.trim() {
        "" => None,
        text => Some(
            ssh_store::parse_public_key(text)
                .map_err(|detail| ApiError::bad_request(detail.to_string()))?,
        ),
    };
    let key_fingerprint = ssh_pubkey.as_ref().map(ssh_store::fingerprint);
    let (record, secret) = console
        .store()?
        .create_code(&body.network, kind, &body.note, now)?;
    let credential = Credential {
        server: console.public_addr.clone(),
        pin: console.pin,
        secret,
        ssh_pubkey: None,
    };
    let credential = match ssh_pubkey {
        Some(key) => credential.with_ssh_pubkey(key),
        None => credential,
    };
    info!(code = %record.id, network = %record.network, "admin console: Code created");
    Ok(Json(CreatedCode {
        code: credential.encode(),
        record: CodeView::new(record, now),
        key_fingerprint,
    }))
}

async fn revoke_code(
    State(console): State<Arc<Console>>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    console.hub.revoke_code(&id, unix_now())?;
    info!(code = %id, "admin console: Code revoked");
    Ok(StatusCode::NO_CONTENT)
}

async fn list_bans(State(console): State<Arc<Console>>) -> ApiResult<Json<Vec<Ban>>> {
    Ok(Json(console.store()?.bans()))
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum NewBanKind {
    Device,
    Ip,
}

#[derive(Deserialize)]
struct NewBan {
    kind: NewBanKind,
    value: String,
    #[serde(default)]
    note: String,
}

async fn add_ban(
    State(console): State<Arc<Console>>,
    Json(body): Json<NewBan>,
) -> ApiResult<Json<Ban>> {
    let target = match body.kind {
        NewBanKind::Device => {
            let value = body.value.trim();
            if !device::is_valid(value) {
                return Err(ApiError::bad_request("设备 ID 格式不正确"));
            }
            BanTarget::Device(value.to_owned())
        }
        NewBanKind::Ip => BanTarget::Ip(
            parse_ip_target(&body.value)
                .ok_or_else(|| ApiError::bad_request("IP 或网段格式不正确"))?,
        ),
    };
    let ban = console.hub.add_ban(target, &body.note, unix_now())?;
    info!(ban = %ban.id, target = ?ban.target, "admin console: banned");
    Ok(Json(ban))
}

async fn remove_ban(
    State(console): State<Arc<Console>>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    console.store()?.remove_ban(&id)?;
    info!(ban = %id, "admin console: ban removed");
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::config::NetworkConfig;
    use axum::body::{to_bytes, Body};
    use serde_json::{json, Value};
    use tower::ServiceExt;

    const PASSWORD: &str = "x";
    const NOW: u64 = 1_000_000;

    fn console(name: &str) -> Arc<Console> {
        let dir = std::env::temp_dir().join(format!("varco-admin-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::load(state::state_path(&dir.join("config.toml")), NOW).unwrap();
        let hub = Hub::new(vec![NetworkConfig {
            name: "a".into(),
            cidr: "10.1.0.0/24".parse().unwrap(),
            secrets: vec![[1; 32]],
        }])
        .with_store(Arc::new(store));
        let settings = AdminConfig {
            listen: "127.0.0.1:0".into(),
            username: "admin".into(),
            password: PASSWORD.into(),
        };
        Console::new(settings, Arc::new(hub), "203.0.113.7:8443".into(), [7; 32])
    }

    async fn send(
        console: &Arc<Console>,
        method: Method,
        uri: &str,
        cookie: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, HeaderMap, Value) {
        let mut request = Request::builder().method(method).uri(uri);
        if let Some(cookie) = cookie {
            request = request.header(COOKIE, cookie);
        }
        let body = match body {
            Some(body) => {
                request = request.header(CONTENT_TYPE, "application/json");
                Body::from(body.to_string())
            }
            None => Body::empty(),
        };
        let response = router(console.clone())
            .oneshot(request.body(body).unwrap())
            .await
            .unwrap();
        let (parts, body) = response.into_parts();
        let bytes = to_bytes(body, usize::MAX).await.unwrap();
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (parts.status, parts.headers, value)
    }

    async fn sign_in(console: &Arc<Console>) -> String {
        let body = json!({"username": "admin", "password": PASSWORD});
        let (status, headers, _) =
            send(console, Method::POST, "/api/login", None, Some(body)).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let cookie = headers[SET_COOKIE].to_str().unwrap();
        cookie.split(';').next().unwrap().to_owned()
    }

    #[tokio::test]
    async fn every_api_route_requires_a_session() {
        let console = console("auth");
        for (method, uri) in [
            (Method::GET, "/api/overview"),
            (Method::GET, "/api/members"),
            (Method::POST, "/api/members/kick"),
            (Method::GET, "/api/codes"),
            (Method::POST, "/api/codes"),
            (Method::POST, "/api/codes/x/revoke"),
            (Method::GET, "/api/bans"),
            (Method::POST, "/api/bans"),
            (Method::DELETE, "/api/bans/x"),
            (Method::POST, "/api/logout"),
        ] {
            let body = (method != Method::GET).then(|| json!({}));
            let (status, _, _) = send(&console, method, uri, None, body).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}");
        }
    }

    #[tokio::test]
    async fn forged_cookie_is_refused_and_logout_ends_the_session() {
        let console = console("logout");
        let (status, _, _) = send(
            &console,
            Method::GET,
            "/api/members",
            Some("varco_admin=forged"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let cookie = sign_in(&console).await;
        let (status, _, _) = send(&console, Method::GET, "/api/members", Some(&cookie), None).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, _) = send(
            &console,
            Method::POST,
            "/api/logout",
            Some(&cookie),
            Some(json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _, _) = send(&console, Method::GET, "/api/members", Some(&cookie), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn any_configured_password_works_and_repeated_failures_lock_everyone_out() {
        let console = console("limit");
        let wrong = || json!({"username": "admin", "password": "wrong"});
        for _ in 0..MAX_FAILURES {
            let (status, _, _) =
                send(&console, Method::POST, "/api/login", None, Some(wrong())).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        let right = json!({"username": "admin", "password": PASSWORD});
        let (status, _, _) = send(&console, Method::POST, "/api/login", None, Some(right)).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn the_lockout_ends_and_success_clears_the_count() {
        let start = Instant::now();
        let mut limiter = Limiter::default();
        for _ in 0..MAX_FAILURES - 1 {
            limiter.failed(start);
        }
        limiter.succeeded();
        limiter.failed(start);
        assert!(!limiter.locked(start));
        for _ in 0..MAX_FAILURES {
            limiter.failed(start);
        }
        assert!(limiter.locked(start));
        assert!(limiter.locked(start + LOCKOUT - Duration::from_secs(1)));
        assert!(!limiter.locked(start + LOCKOUT));
        limiter.failed(start + LOCKOUT);
        assert!(!limiter.locked(start + LOCKOUT));
    }

    #[test]
    fn sessions_expire() {
        let console = console("expiry");
        let start = Instant::now();
        let token = console.open_session(start);
        assert!(console.session_valid(&token, start + SESSION_LIFETIME - Duration::from_secs(1)));
        assert!(!console.session_valid(&token, start + SESSION_LIFETIME));
    }

    #[tokio::test]
    async fn writes_need_the_json_content_type() {
        let console = console("csrf");
        let cookie = sign_in(&console).await;
        let (status, _, _) = send(&console, Method::POST, "/api/logout", Some(&cookie), None).await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let (status, _, _) = send(&console, Method::GET, "/api/members", Some(&cookie), None).await;
        assert_eq!(status, StatusCode::OK, "that logout must not have happened");
    }

    #[tokio::test]
    async fn cookie_flags_follow_the_proxy() {
        let console = console("cookie");
        let login = |proto: Option<&'static str>| {
            let mut request = Request::builder()
                .method(Method::POST)
                .uri("/api/login")
                .header(CONTENT_TYPE, "application/json");
            if let Some(proto) = proto {
                request = request.header("x-forwarded-proto", proto);
            }
            request
                .body(Body::from(
                    json!({"username": "admin", "password": PASSWORD}).to_string(),
                ))
                .unwrap()
        };
        let plain = router(console.clone()).oneshot(login(None)).await.unwrap();
        let cookie = plain.headers()[SET_COOKIE].to_str().unwrap();
        assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"));
        assert!(!cookie.contains("Secure"));
        let proxied = router(console).oneshot(login(Some("https"))).await.unwrap();
        assert!(proxied.headers()[SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Secure"));
    }

    #[tokio::test]
    async fn page_is_served_with_protective_headers() {
        let console = console("page");
        let (status, headers, _) = send(&console, Method::GET, "/", None, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[X_FRAME_OPTIONS], "DENY");
        assert_eq!(headers[CACHE_CONTROL], "no-store");
        assert!(headers.contains_key(CONTENT_SECURITY_POLICY));
    }

    #[tokio::test]
    async fn created_code_parses_and_appears_without_its_secret() {
        let console = console("create");
        let cookie = sign_in(&console).await;
        let body = json!({"network": "a", "kind": "timed", "duration": "24h", "note": "n"});
        let (status, _, created) = send(
            &console,
            Method::POST,
            "/api/codes",
            Some(&cookie),
            Some(body),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let code = created["code"].as_str().unwrap();
        let parsed = Credential::parse(code).unwrap();
        assert_eq!(parsed.server, "203.0.113.7:8443");
        assert_eq!(parsed.pin, [7; 32]);
        assert_eq!(created["kind"], "timed");
        assert_eq!(created["status"], "active");

        let (_, _, list) = send(&console, Method::GET, "/api/codes", Some(&cookie), None).await;
        assert_eq!(list[0]["note"], "n");
        let text = list.to_string();
        assert!(!text.contains("secret_hash"));
        assert!(!text.contains(code));
    }

    #[tokio::test]
    async fn bad_code_requests_are_explained() {
        let console = console("badcode");
        let cookie = sign_in(&console).await;
        for body in [
            json!({"network": "nope", "kind": "once"}),
            json!({"network": "a", "kind": "timed", "duration": "soon"}),
            json!({"network": "a", "kind": "timed"}),
            json!({"network": "a", "kind": "once", "ssh_pubkey": "ssh-ed25519 nonsense"}),
        ] {
            let (status, _, reply) = send(
                &console,
                Method::POST,
                "/api/codes",
                Some(&cookie),
                Some(body.clone()),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert!(reply["error"].is_string());
        }
        let (_, _, list) = send(&console, Method::GET, "/api/codes", Some(&cookie), None).await;
        assert_eq!(list.as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn bans_can_be_added_listed_and_lifted() {
        let console = console("bans");
        let cookie = sign_in(&console).await;
        for (body, expected) in [
            (
                json!({"kind": "ip", "value": "nope"}),
                StatusCode::BAD_REQUEST,
            ),
            (
                json!({"kind": "device", "value": "short"}),
                StatusCode::BAD_REQUEST,
            ),
            (
                json!({"kind": "ip", "value": "198.51.100.0/24"}),
                StatusCode::OK,
            ),
            (
                json!({"kind": "ip", "value": "198.51.100.0/24"}),
                StatusCode::CONFLICT,
            ),
        ] {
            let (status, _, _) = send(
                &console,
                Method::POST,
                "/api/bans",
                Some(&cookie),
                Some(body),
            )
            .await;
            assert_eq!(status, expected);
        }
        let store = console.hub.store().unwrap();
        assert!(store.ip_banned("198.51.100.9".parse().unwrap()));
        let (_, _, list) = send(&console, Method::GET, "/api/bans", Some(&cookie), None).await;
        assert_eq!(list[0]["kind"], "ip");
        assert_eq!(list[0]["value"], "198.51.100.0/24");
        let uri = format!("/api/bans/{}", list[0]["id"].as_str().unwrap());
        let (status, _, _) = send(
            &console,
            Method::DELETE,
            &uri,
            Some(&cookie),
            Some(json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(!store.ip_banned("198.51.100.9".parse().unwrap()));
    }

    #[tokio::test]
    async fn kicking_someone_absent_is_not_found() {
        let console = console("kick");
        let cookie = sign_in(&console).await;
        let (status, _, _) = send(
            &console,
            Method::POST,
            "/api/members/kick",
            Some(&cookie),
            Some(json!({"id": "nobody"})),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn overview_lists_networks_and_credentials_without_secrets() {
        let console = console("overview");
        let cookie = sign_in(&console).await;
        let (_, _, overview) =
            send(&console, Method::GET, "/api/overview", Some(&cookie), None).await;
        assert_eq!(overview["networks"][0]["capacity"], 254);
        assert_eq!(overview["credentials"][0]["network"], "a");
        let secret = crate::credential::encode_secret(&[1; 32]);
        assert!(!overview.to_string().contains(&secret));
    }
}
