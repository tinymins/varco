//! Logging in, and what a logged-in person can do for themselves.
use super::{
    bearer_token, cookie_token, internal, source_of, Access, Actor, ApiError, ApiResult, Authed,
    Console, Person, Signed, Standing, COOKIE_NAME, SESSION_LIFETIME_SECS,
};
use crate::core::ssh::store as ssh_store;
use crate::server::store::{
    unix_now, verify_password, Role, SessionView, SshKey, WorkspaceId, SETTING_PUBLIC_ADDR,
};
use axum::extract::{Path, State};
use axum::http::header::{SET_COOKIE, USER_AGENT};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;
use tracing::warn;

#[derive(Deserialize)]
pub struct LoginBody {
    username: String,
    password: String,
}

fn session_cookie(value: &str, max_age: u64, secure: bool) -> ApiResult<HeaderValue> {
    let secure = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{COOKIE_NAME}={value}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}{secure}"
    ))
    .map_err(internal)
}

/// Only a proxy can have terminated TLS, as this listener has none.
fn behind_https(headers: &HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("https"))
}

pub async fn login(
    State(console): State<Arc<Console>>,
    headers: HeaderMap,
    Json(body): Json<LoginBody>,
) -> ApiResult<Response> {
    let too_many = || {
        ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "这个账号失败次数过多，请一分钟后再试",
        )
    };
    let locked = |console: &Console, username: &str| {
        console
            .limiter
            .lock()
            .expect("limiter lock poisoned")
            .locked(username, Instant::now())
    };
    if locked(&console, &body.username) {
        return Err(too_many());
    }
    // Checked again once it is this request's turn, so a burst of guesses cannot
    // all start before the first few have failed.
    let _permit = console.password_checks.acquire().await.map_err(internal)?;
    if locked(&console, &body.username) {
        return Err(too_many());
    }
    let user = console.store().user_by_name(&body.username)?;
    let hash = user.as_ref().map_or_else(
        || console.decoy_hash.clone(),
        |user| user.password_hash.clone(),
    );
    let password = body.password;
    let matches = tokio::task::spawn_blocking(move || verify_password(&password, &hash))
        .await
        .map_err(internal)?;
    let Some(user) = user.filter(|_| matches) else {
        console
            .limiter
            .lock()
            .expect("limiter lock poisoned")
            .failed(&body.username, Instant::now());
        warn!("admin console: failed login");
        let shown: String = body.username.chars().take(64).collect();
        if let Err(detail) = console.store().audit(
            &shown,
            None,
            "login_failed",
            "",
            &source_of(&headers),
            unix_now(),
        ) {
            warn!(%detail, "audit entry not recorded");
        }
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "用户名或密码不正确",
        ));
    };
    console
        .limiter
        .lock()
        .expect("limiter lock poisoned")
        .succeeded(&body.username);
    let agent = headers
        .get(USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let token = console
        .store()
        .open_session(user.id, agent, SESSION_LIFETIME_SECS, unix_now())?;
    let actor = Actor {
        name: user.username.clone(),
        access: Access::User(user.id),
        user: Some(user.id),
        session: None,
        source: source_of(&headers),
        must_change_password: user.must_change_password,
    };
    console.audit(&actor, None, "login", "");
    let cookie = session_cookie(&token, SESSION_LIFETIME_SECS, behind_https(&headers))?;
    Ok((StatusCode::NO_CONTENT, [(SET_COOKIE, cookie)]).into_response())
}

pub async fn logout(
    State(console): State<Arc<Console>>,
    Signed(actor): Signed,
    headers: HeaderMap,
) -> ApiResult<Response> {
    if bearer_token(&headers).is_none() {
        if let Some(token) = cookie_token(&headers) {
            console.store().close_session(token)?;
        }
    }
    console.audit(&actor, None, "logout", "");
    let cookie = session_cookie("", 0, behind_https(&headers))?;
    Ok((StatusCode::NO_CONTENT, [(SET_COOKIE, cookie)]).into_response())
}

#[derive(Serialize)]
pub struct MyWorkspace {
    id: WorkspaceId,
    name: String,
    cidr: String,
    standing: Standing,
}

#[derive(Serialize)]
pub struct Me {
    username: String,
    is_super: bool,
    must_change_password: bool,
    /// The server has no address yet, and only this person can give it one.
    setup_needed: bool,
    workspaces: Vec<MyWorkspace>,
}

pub async fn me(State(console): State<Arc<Console>>, Signed(actor): Signed) -> ApiResult<Json<Me>> {
    let store = console.store();
    let all = store.workspaces()?;
    let standing_in: Box<dyn Fn(WorkspaceId) -> Option<Standing>> = match actor.access {
        Access::Super => Box::new(|_| Some(Standing::Super)),
        Access::Token(own) => Box::new(move |id| (id == own).then_some(Standing::Admin)),
        Access::User(user) => {
            let memberships = store.memberships(user)?;
            Box::new(move |id| {
                memberships
                    .iter()
                    .find(|(workspace, _)| *workspace == id)
                    .map(|(_, role)| match role {
                        Role::Owner => Standing::Owner,
                        Role::Admin => Standing::Admin,
                    })
            })
        }
    };
    let is_super = actor.access == Access::Super;
    Ok(Json(Me {
        setup_needed: is_super && store.setting(SETTING_PUBLIC_ADDR)?.is_none(),
        is_super,
        must_change_password: actor.must_change_password,
        workspaces: all
            .into_iter()
            .filter_map(|workspace| {
                standing_in(workspace.id).map(|standing| MyWorkspace {
                    id: workspace.id,
                    name: workspace.name,
                    cidr: workspace.cidr,
                    standing,
                })
            })
            .collect(),
        username: actor.name,
    }))
}

#[derive(Deserialize)]
pub struct NewPassword {
    password: String,
}

/// Takes whatever it is given, even the password already in use. That is the
/// owner's call to make.
pub async fn change_password(
    State(console): State<Arc<Console>>,
    Person(actor, user): Person,
    Json(body): Json<NewPassword>,
) -> ApiResult<StatusCode> {
    let hash = console.hash(body.password).await?;
    console
        .store()
        .set_password(user, &hash, false, actor.session.as_deref())?;
    console.audit(&actor, None, "change_password", "");
    Ok(StatusCode::NO_CONTENT)
}

pub async fn sessions(
    State(console): State<Arc<Console>>,
    Authed(actor): Authed,
) -> ApiResult<Json<Vec<SessionView>>> {
    let user = actor.user.ok_or_else(ApiError::forbidden)?;
    Ok(Json(console.store().sessions(user, unix_now())?))
}

pub async fn end_session(
    State(console): State<Arc<Console>>,
    Authed(actor): Authed,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let user = actor.user.ok_or_else(ApiError::forbidden)?;
    console.store().close_session_by_id(user, &id)?;
    console.audit(&actor, None, "end_session", &id);
    Ok(StatusCode::NO_CONTENT)
}

pub async fn ssh_keys(
    State(console): State<Arc<Console>>,
    Authed(actor): Authed,
) -> ApiResult<Json<Vec<SshKey>>> {
    let user = actor.user.ok_or_else(ApiError::forbidden)?;
    Ok(Json(console.store().ssh_keys(user)?))
}

#[derive(Deserialize)]
pub struct NewSshKey {
    #[serde(default)]
    name: String,
    #[serde(default)]
    public_key: String,
}

/// Without a name, the key's own comment is what its owner will recognise it by.
pub async fn add_ssh_key(
    State(console): State<Arc<Console>>,
    Authed(actor): Authed,
    Json(body): Json<NewSshKey>,
) -> ApiResult<Json<SshKey>> {
    let user = actor.user.ok_or_else(ApiError::forbidden)?;
    let key = ssh_store::parse_public_key(&body.public_key)
        .map_err(|detail| ApiError::bad_request(detail.to_string()))?;
    let fingerprint = ssh_store::fingerprint(&key);
    let name = match body.name.trim() {
        "" if key.comment().is_empty() => fingerprint.clone(),
        "" => key.comment().to_string(),
        name => name.to_owned(),
    };
    let added = console.store().add_ssh_key(
        user,
        &name,
        body.public_key.trim(),
        &fingerprint,
        unix_now(),
    )?;
    console.audit(&actor, None, "add_ssh_key", &fingerprint);
    Ok(Json(added))
}

pub async fn delete_ssh_key(
    State(console): State<Arc<Console>>,
    Authed(actor): Authed,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let user = actor.user.ok_or_else(ApiError::forbidden)?;
    console.store().delete_ssh_key(user, &id)?;
    console.audit(&actor, None, "delete_ssh_key", &id);
    Ok(StatusCode::NO_CONTENT)
}
