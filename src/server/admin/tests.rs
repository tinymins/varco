use super::*;
use crate::credential::Credential;
use crate::server::store::{
    client_key, CodeLimits, ROOT_DEFAULT_PASSWORD, ROOT_USERNAME, SETTING_PUBLIC_ADDR,
};
use axum::body::{to_bytes, Body};
use axum::http::header::{SET_COOKIE, USER_AGENT};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use tower::ServiceExt;

const NOW_LIFETIME: u64 = 3600;

struct Harness {
    console: Arc<Console>,
    a: WorkspaceId,
    b: WorkspaceId,
}

fn harness(name: &str) -> Harness {
    let dir = std::env::temp_dir().join(format!("varco-console-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let store = Arc::new(Store::open(&dir.join("varco.db")).unwrap());
    let cidr = "10.1.0.0/24".parse().unwrap();
    let a = store.create_workspace("team-a", cidr, unix_now()).unwrap();
    let b = store.create_workspace("team-b", cidr, unix_now()).unwrap();
    let hub = Arc::new(Hub::new(&[a.clone(), b.clone()]).with_store(store));
    let identity = crate::tls::generate_identity().unwrap();
    let tls_config = crate::tls::server_config(&identity).unwrap();
    let relay = Arc::new(Relay::new(hub.clone(), tls_config));
    Harness {
        console: Console::new(hub, relay, [7; 32]),
        a: a.id,
        b: b.id,
    }
}

impl Harness {
    fn store(&self) -> &Arc<Store> {
        self.console.store()
    }

    /// Without the slow hash, which most tests do not need.
    fn user(&self, workspace: WorkspaceId, name: &str, role: Role) -> UserId {
        let id = self
            .store()
            .add_admin(workspace, name, "not-a-real-hash", role, unix_now())
            .unwrap();
        self.store()
            .set_password(id, "not-a-real-hash", false, None)
            .unwrap();
        id
    }

    fn session(&self, user: UserId) -> String {
        let token = self
            .store()
            .open_session(user, "test", NOW_LIFETIME, unix_now())
            .unwrap();
        format!("{COOKIE_NAME}={token}")
    }

    fn root(&self) -> UserId {
        let root = self.store().user_by_name(ROOT_USERNAME).unwrap().unwrap();
        self.store()
            .set_password(root.id, &root.password_hash, false, None)
            .unwrap();
        root.id
    }

    fn root_session(&self) -> String {
        self.session(self.root())
    }

    fn token(&self, workspace: Option<WorkspaceId>) -> String {
        self.store()
            .create_token(workspace, "t", None, unix_now())
            .unwrap()
            .token
    }

    async fn send(
        &self,
        method: Method,
        uri: &str,
        credential: &Credential_,
        body: Option<Value>,
    ) -> (StatusCode, HeaderMap, Value) {
        let mut request = Request::builder().method(method).uri(uri);
        match credential {
            Credential_::None => {}
            Credential_::Cookie(cookie) => request = request.header(COOKIE, cookie),
            Credential_::Bearer(token) => {
                request = request.header(AUTHORIZATION, format!("Bearer {token}"));
            }
        }
        let body = match body {
            Some(body) => {
                request = request.header(CONTENT_TYPE, "application/json");
                Body::from(body.to_string())
            }
            None => Body::empty(),
        };
        let response = router(self.console.clone())
            .oneshot(request.body(body).unwrap())
            .await
            .unwrap();
        let (parts, body) = response.into_parts();
        let bytes = to_bytes(body, usize::MAX).await.unwrap();
        let value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        (parts.status, parts.headers, value)
    }

    async fn as_root(&self, method: Method, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
        let cookie = Credential_::Cookie(self.root_session());
        let (status, _, value) = self.send(method, uri, &cookie, body).await;
        (status, value)
    }
}

#[derive(Clone)]
#[allow(non_camel_case_types)]
enum Credential_ {
    None,
    Cookie(String),
    Bearer(String),
}

// ---- The permission matrix ----

#[derive(Clone, Copy, Debug, PartialEq)]
enum Needs {
    Nothing,
    /// Logged in, even before changing the password. Tokens count.
    Signed,
    /// A person logged in, even before changing the password.
    Person,
    /// A person with their own password.
    PersonReady,
    Member,
    Owner,
    Super,
}

/// `{ws}` is workspace A. Other ids do not exist, so a request that gets through
/// changes nothing; bodies are empty for the same reason.
const ROUTES: &[(&str, &str, Needs)] = &[
    ("GET", "/", Needs::Nothing),
    ("GET", "/app.js", Needs::Nothing),
    ("GET", "/components.js", Needs::Nothing),
    ("GET", "/style.css", Needs::Nothing),
    ("GET", "/healthz", Needs::Nothing),
    ("GET", "/metrics", Needs::Super),
    ("POST", "/api/login", Needs::Nothing),
    ("POST", "/api/logout", Needs::Signed),
    ("GET", "/api/me", Needs::Signed),
    ("POST", "/api/me/password", Needs::Person),
    ("GET", "/api/me/sessions", Needs::PersonReady),
    ("DELETE", "/api/me/sessions/{id}", Needs::PersonReady),
    ("GET", "/api/me/ssh-keys", Needs::PersonReady),
    ("POST", "/api/me/ssh-keys", Needs::PersonReady),
    ("DELETE", "/api/me/ssh-keys/{id}", Needs::PersonReady),
    ("GET", "/api/settings", Needs::Super),
    ("PUT", "/api/settings", Needs::Super),
    ("GET", "/api/workspaces", Needs::Super),
    ("POST", "/api/workspaces", Needs::Super),
    ("PATCH", "/api/workspaces/{ws}", Needs::Super),
    ("DELETE", "/api/workspaces/{ws}", Needs::Super),
    ("GET", "/api/users", Needs::Super),
    ("DELETE", "/api/users/{user}", Needs::Super),
    ("POST", "/api/users/{user}/password", Needs::Super),
    ("GET", "/api/bans", Needs::Super),
    ("POST", "/api/bans", Needs::Super),
    ("DELETE", "/api/bans/{id}", Needs::Super),
    ("GET", "/api/audit", Needs::Super),
    ("GET", "/api/tokens", Needs::Super),
    ("POST", "/api/tokens", Needs::Super),
    ("DELETE", "/api/tokens/{id}", Needs::Super),
    ("GET", "/api/tokens/{id}/secret", Needs::Super),
    ("GET", "/api/w/{ws}", Needs::Member),
    ("GET", "/api/w/{ws}/members", Needs::Member),
    ("POST", "/api/w/{ws}/members/kick", Needs::Member),
    ("GET", "/api/w/{ws}/kicked", Needs::Member),
    ("DELETE", "/api/w/{ws}/kicked/{client}", Needs::Member),
    ("GET", "/api/w/{ws}/connections", Needs::Member),
    ("GET", "/api/w/{ws}/codes", Needs::Member),
    ("POST", "/api/w/{ws}/codes", Needs::Member),
    ("PATCH", "/api/w/{ws}/codes/{id}", Needs::Member),
    ("DELETE", "/api/w/{ws}/codes/{id}", Needs::Member),
    ("GET", "/api/w/{ws}/codes/{id}/copies", Needs::Member),
    ("POST", "/api/w/{ws}/codes/{id}/revoke", Needs::Member),
    ("GET", "/api/w/{ws}/bans", Needs::Member),
    ("POST", "/api/w/{ws}/bans", Needs::Member),
    ("DELETE", "/api/w/{ws}/bans/{id}", Needs::Member),
    ("GET", "/api/w/{ws}/audit", Needs::Member),
    ("GET", "/api/w/{ws}/tokens", Needs::Member),
    ("POST", "/api/w/{ws}/tokens", Needs::Member),
    ("DELETE", "/api/w/{ws}/tokens/{id}", Needs::Member),
    ("GET", "/api/w/{ws}/tokens/{id}/secret", Needs::Member),
    ("GET", "/api/w/{ws}/admins", Needs::Owner),
    ("POST", "/api/w/{ws}/admins", Needs::Owner),
    ("PATCH", "/api/w/{ws}/admins/{user}", Needs::Owner),
    ("DELETE", "/api/w/{ws}/admins/{user}", Needs::Owner),
    ("POST", "/api/w/{ws}/admins/{user}/password", Needs::Owner),
];

#[test]
fn every_route_is_in_the_permission_matrix() {
    let source = include_str!("mod.rs");
    let in_router: BTreeSet<&str> = source
        .split(".route(")
        .skip(1)
        .map(|rest| {
            rest.trim_start()
                .trim_start_matches('"')
                .split('"')
                .next()
                .unwrap()
        })
        .collect();
    let in_table: BTreeSet<&str> = ROUTES.iter().map(|(_, path, _)| *path).collect();
    assert_eq!(in_router, in_table, "add new routes to ROUTES");
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Who {
    Anonymous,
    /// Member of workspace A who has not chosen a password yet.
    NewPerson,
    OtherAdmin,
    OtherToken,
    Admin,
    WorkspaceToken,
    Owner,
    Root,
    RootToken,
}

const EVERYONE: [Who; 9] = [
    Who::Anonymous,
    Who::NewPerson,
    Who::OtherAdmin,
    Who::OtherToken,
    Who::Admin,
    Who::WorkspaceToken,
    Who::Owner,
    Who::Root,
    Who::RootToken,
];

/// `None` means allowed through. The handler may still dislike the empty body or
/// the id that does not exist, but it was reached.
fn expected(needs: Needs, who: Who) -> Option<StatusCode> {
    use Who::*;
    let (unauthorized, forbidden, not_found) = (
        Some(StatusCode::UNAUTHORIZED),
        Some(StatusCode::FORBIDDEN),
        Some(StatusCode::NOT_FOUND),
    );
    match (needs, who) {
        (Needs::Nothing, _) => None,
        (_, Anonymous) => unauthorized,
        (Needs::Signed, _) => None,
        (Needs::Person, OtherToken | WorkspaceToken | RootToken) => forbidden,
        (Needs::Person, _) => None,
        (_, NewPerson) => forbidden,
        (Needs::PersonReady, OtherToken | WorkspaceToken | RootToken) => forbidden,
        (Needs::PersonReady, _) => None,
        (Needs::Member | Needs::Owner, OtherAdmin | OtherToken) => not_found,
        (Needs::Member, _) => None,
        (Needs::Owner, Admin | WorkspaceToken) => forbidden,
        (Needs::Owner, _) => None,
        (Needs::Super, Root | RootToken) => None,
        (Needs::Super, _) => forbidden,
    }
}

#[tokio::test]
async fn the_permission_matrix_holds() {
    let h = harness("matrix");
    let root = h.root();
    let new_person = h
        .store()
        .add_admin(h.a, "new", "hash", Role::Admin, unix_now())
        .unwrap();
    let other_admin = h.user(h.b, "other", Role::Owner);
    let admin = h.user(h.a, "admin", Role::Admin);
    let owner = h.user(h.a, "owner", Role::Owner);
    let (other_token, ws_token, root_token) =
        (h.token(Some(h.b)), h.token(Some(h.a)), h.token(None));

    for (method, path, needs) in ROUTES {
        for who in EVERYONE {
            // A fresh session each time: one route being tried is logging out.
            let credential = match who {
                Who::Anonymous => Credential_::None,
                Who::NewPerson => Credential_::Cookie(h.session(new_person)),
                Who::OtherAdmin => Credential_::Cookie(h.session(other_admin)),
                Who::Admin => Credential_::Cookie(h.session(admin)),
                Who::Owner => Credential_::Cookie(h.session(owner)),
                Who::Root => Credential_::Cookie(h.session(root)),
                Who::OtherToken => Credential_::Bearer(other_token.clone()),
                Who::WorkspaceToken => Credential_::Bearer(ws_token.clone()),
                Who::RootToken => Credential_::Bearer(root_token.clone()),
            };
            let uri = path
                .replace("/api/workspaces/{ws}", "/api/workspaces/999999")
                .replace("{ws}", &h.a.to_string())
                .replace("{id}", "no-such-id")
                .replace("{client}", "no-such-client")
                .replace("{user}", "999999");
            let method = Method::from_bytes(method.as_bytes()).unwrap();
            let body = (method != Method::GET).then(|| json!({}));
            let (status, _, reply) = h.send(method.clone(), &uri, &credential, body).await;
            match expected(*needs, who) {
                Some(denied) => assert_eq!(status, denied, "{method} {uri} as {who:?}: {reply}"),
                None => assert!(
                    !matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN),
                    "{method} {uri} as {who:?} was refused with {status}: {reply}"
                ),
            }
        }
    }
    // Reaching a collection in its own workspace is not a 404, unlike the denials.
    for who in [Who::Admin, Who::WorkspaceToken, Who::Owner, Who::Root] {
        let credential = match who {
            Who::Admin => Credential_::Cookie(h.session(admin)),
            Who::Owner => Credential_::Cookie(h.session(owner)),
            Who::Root => Credential_::Cookie(h.session(root)),
            _ => Credential_::Bearer(ws_token.clone()),
        };
        let uri = format!("/api/w/{}/members", h.a);
        let (status, _, _) = h.send(Method::GET, &uri, &credential, None).await;
        assert_eq!(status, StatusCode::OK, "{who:?}");
    }
}

#[tokio::test]
async fn nothing_of_another_workspace_can_be_touched_by_its_id() {
    let h = harness("cross");
    let now = unix_now();
    let store = h.store();
    let (code, _) = store
        .create_code(h.b, CodeLimits::default(), "theirs", now)
        .unwrap();
    let ban = store
        .add_ban(
            Some(h.b),
            crate::server::store::BanTarget::Device("d".into()),
            "",
            None,
            now,
        )
        .unwrap();
    let token = store.create_token(Some(h.b), "theirs", None, now).unwrap();
    let their_admin = h.user(h.b, "theirs", Role::Admin);
    store.kick(h.b, "client", "h", now).unwrap();
    let mine = Credential_::Cookie({
        let owner = h.user(h.a, "mine", Role::Owner);
        h.session(owner)
    });
    let a = h.a;
    let attempts = [
        (
            Method::POST,
            format!("/api/w/{a}/codes/{}/revoke", code.id),
            json!({}),
        ),
        (
            Method::PATCH,
            format!("/api/w/{a}/codes/{}", code.id),
            json!({"note": "x"}),
        ),
        (
            Method::DELETE,
            format!("/api/w/{a}/codes/{}", code.id),
            json!({}),
        ),
        (
            Method::DELETE,
            format!("/api/w/{a}/bans/{}", ban.id),
            json!({}),
        ),
        (
            Method::DELETE,
            format!("/api/w/{a}/tokens/{}", token.info.id),
            json!({}),
        ),
        (
            Method::DELETE,
            format!("/api/w/{a}/kicked/client"),
            json!({}),
        ),
        (
            Method::DELETE,
            format!("/api/w/{a}/admins/{their_admin}"),
            json!({}),
        ),
        (
            Method::PATCH,
            format!("/api/w/{a}/admins/{their_admin}"),
            json!({"role": "owner"}),
        ),
        (
            Method::POST,
            format!("/api/w/{a}/admins/{their_admin}/password"),
            json!({"password": "x"}),
        ),
    ];
    for (method, uri, body) in attempts {
        let (status, _, _) = h.send(method.clone(), &uri, &mine, Some(body)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {uri}");
    }
    let unchanged = store.code(h.b, &code.id, now).unwrap().unwrap();
    assert_eq!(unchanged.note, "theirs");
    assert_eq!(unchanged.revoked_at, None);
    assert_eq!(store.role_of(their_admin, h.b).unwrap(), Some(Role::Admin));
    assert!(store.user(their_admin).unwrap().is_some());
    assert_eq!(store.tokens(Some(h.b)).unwrap().len(), 1);
    assert_eq!(store.kicked(h.b).unwrap().len(), 1);
}

#[tokio::test]
async fn what_a_workspace_lists_is_only_its_own() {
    let h = harness("lists");
    let now = unix_now();
    h.store()
        .create_code(h.b, CodeLimits::default(), "secret-plans", now)
        .unwrap();
    h.store()
        .audit("x", Some(h.b), "secret-action", "", "", now)
        .unwrap();
    let mine = Credential_::Cookie({
        let owner = h.user(h.a, "mine", Role::Owner);
        h.session(owner)
    });
    for path in [
        "codes",
        "audit",
        "bans",
        "tokens",
        "admins",
        "members",
        "kicked",
        "connections",
    ] {
        let uri = format!("/api/w/{}/{path}", h.a);
        let (status, _, reply) = h.send(Method::GET, &uri, &mine, None).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        let text = reply.to_string();
        assert!(!text.contains("secret-"), "{path}: {text}");
    }
    let (_, _, me) = h.send(Method::GET, "/api/me", &mine, None).await;
    assert_eq!(me["workspaces"].as_array().unwrap().len(), 1);
    assert_eq!(me["workspaces"][0]["name"], "team-a");
    assert_eq!(me["workspaces"][0]["standing"], "owner");
}

// ---- Login and first run ----

async fn login(h: &Harness, username: &str, password: &str) -> (StatusCode, HeaderMap) {
    let body = json!({"username": username, "password": password});
    let (status, headers, _) = h
        .send(Method::POST, "/api/login", &Credential_::None, Some(body))
        .await;
    (status, headers)
}

fn cookie_from(headers: &HeaderMap) -> Credential_ {
    let cookie = headers[SET_COOKIE].to_str().unwrap();
    Credential_::Cookie(cookie.split(';').next().unwrap().to_owned())
}

#[tokio::test]
async fn first_run_goes_from_default_login_to_a_listening_relay() {
    let h = harness("first-run");
    let (status, headers) = login(&h, ROOT_USERNAME, ROOT_DEFAULT_PASSWORD).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let cookie = cookie_from(&headers);

    let (_, _, me) = h.send(Method::GET, "/api/me", &cookie, None).await;
    assert_eq!(me["must_change_password"], true);
    assert_eq!(me["setup_needed"], true);
    // Nothing else opens until the password is changed.
    let (status, _, _) = h.send(Method::GET, "/api/workspaces", &cookie, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Any password will do, the same one included.
    let (status, _, _) = h
        .send(
            Method::POST,
            "/api/me/password",
            &cookie,
            Some(json!({"password": ROOT_DEFAULT_PASSWORD})),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, _, me) = h.send(Method::GET, "/api/me", &cookie, None).await;
    assert_eq!(me["must_change_password"], false);

    let (_, _, health) = h
        .send(Method::GET, "/healthz", &Credential_::None, None)
        .await;
    assert_eq!(health["relay_listening"], false);
    let (status, _, reply) = h
        .send(
            Method::POST,
            &format!("/api/w/{}/codes", h.a),
            &cookie,
            Some(json!({"max_uses": 1})),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{reply}");

    let (_, _, settings) = h.send(Method::GET, "/api/settings", &cookie, None).await;
    assert_eq!(settings["public_addr"], Value::Null);
    let (status, _, reply) = h
        .send(
            Method::PUT,
            "/api/settings",
            &cookie,
            Some(json!({"public_addr": "vpn.example.com:8443", "relay_listen": "127.0.0.1:0"})),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{reply}");
    let (_, _, health) = h
        .send(Method::GET, "/healthz", &Credential_::None, None)
        .await;
    assert_eq!(health["relay_listening"], true);
    let (_, _, me) = h.send(Method::GET, "/api/me", &cookie, None).await;
    assert_eq!(me["setup_needed"], false);
}

#[tokio::test]
async fn bad_settings_are_refused_and_change_nothing() {
    let h = harness("settings");
    for body in [
        json!({"public_addr": "no-port"}),
        json!({"history_days": 0}),
        json!({"relay_listen": "not an address", "public_addr": "ok.example.com:1"}),
    ] {
        let (status, reply) = h
            .as_root(Method::PUT, "/api/settings", Some(body.clone()))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {reply}");
    }
    assert_eq!(h.store().setting(SETTING_PUBLIC_ADDR).unwrap(), None);
    assert!(h.console.relay.listening_on().await.is_none());
}

#[tokio::test]
async fn a_failed_move_of_the_relay_keeps_the_old_address() {
    let h = harness("relay-move");
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let taken_addr = taken.local_addr().unwrap().to_string();
    let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let free_addr = free.local_addr().unwrap().to_string();
    drop(free);
    let (status, _) = h
        .as_root(
            Method::PUT,
            "/api/settings",
            Some(json!({"relay_listen": free_addr})),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = h
        .as_root(
            Method::PUT,
            "/api/settings",
            Some(json!({"relay_listen": taken_addr})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        h.console.relay.listening_on().await.as_deref(),
        Some(free_addr.as_str())
    );
    assert_eq!(
        h.store()
            .setting(crate::server::store::SETTING_RELAY_LISTEN)
            .unwrap()
            .as_deref(),
        Some(free_addr.as_str())
    );
}

#[tokio::test]
async fn lockout_is_per_username_and_also_covers_names_that_do_not_exist() {
    let h = harness("limit");
    for _ in 0..MAX_FAILURES {
        let (status, _) = login(&h, ROOT_USERNAME, "wrong").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, _) = login(&h, ROOT_USERNAME, ROOT_DEFAULT_PASSWORD).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    for _ in 0..MAX_FAILURES {
        let (status, _) = login(&h, "nobody", "wrong").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, _) = login(&h, "nobody", "wrong").await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "same as a real account"
    );

    // Other teams are unaffected.
    let hash = hash_password("theirs").unwrap();
    h.store()
        .add_admin(h.b, "someone", &hash, Role::Owner, unix_now())
        .unwrap();
    let (status, _) = login(&h, "someone", "theirs").await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[test]
fn the_lockout_ends_and_success_clears_the_count() {
    let start = Instant::now();
    let mut limiter = Limiter::default();
    for _ in 0..MAX_FAILURES - 1 {
        limiter.failed("u", start);
    }
    limiter.succeeded("u");
    limiter.failed("u", start);
    assert!(!limiter.locked("u", start));
    for _ in 0..MAX_FAILURES {
        limiter.failed("u", start);
    }
    assert!(limiter.locked("u", start));
    assert!(!limiter.locked("other", start));
    assert!(limiter.locked("u", start + LOCKOUT - Duration::from_secs(1)));
    assert!(!limiter.locked("u", start + LOCKOUT));
    limiter.failed("u", start + LOCKOUT);
    assert!(!limiter.locked("u", start + LOCKOUT));
}

#[test]
fn guessed_usernames_do_not_pile_up_forever() {
    let start = Instant::now();
    let mut limiter = Limiter::default();
    for index in 0..=LIMITER_PRUNE_ABOVE {
        limiter.failed(&format!("u{index}"), start);
    }
    limiter.failed("late", start + LIMITER_MEMORY);
    assert_eq!(limiter.accounts.len(), 1);
}

#[tokio::test]
async fn changing_a_password_ends_other_sessions_and_keeps_this_one() {
    let h = harness("password");
    let user = h.user(h.a, "u", Role::Admin);
    let (this, other) = (
        Credential_::Cookie(h.session(user)),
        Credential_::Cookie(h.session(user)),
    );
    let (status, _, _) = h
        .send(
            Method::POST,
            "/api/me/password",
            &this,
            Some(json!({"password": ""})),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "even an empty one is theirs to choose"
    );
    let (status, _, _) = h.send(Method::GET, "/api/me", &this, None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) = h.send(Method::GET, "/api/me", &other, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = login(&h, "u", "").await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn sessions_can_be_listed_and_ended() {
    let h = harness("my-sessions");
    let user = h.user(h.a, "u", Role::Admin);
    let this = Credential_::Cookie(h.session(user));
    let other_token = h
        .store()
        .open_session(user, "other device", NOW_LIFETIME, unix_now())
        .unwrap();
    let other = Credential_::Cookie(format!("{COOKIE_NAME}={other_token}"));
    let (_, _, list) = h.send(Method::GET, "/api/me/sessions", &this, None).await;
    assert_eq!(list.as_array().unwrap().len(), 2);
    let id = &client_key(&other_token)[..16];
    let uri = format!("/api/me/sessions/{id}");
    let (status, _, _) = h.send(Method::DELETE, &uri, &this, Some(json!({}))).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, _) = h.send(Method::GET, "/api/me", &other, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn writes_need_the_json_content_type_unless_using_a_token() {
    let h = harness("csrf");
    let cookie = Credential_::Cookie(h.root_session());
    let (status, _, _) = h.send(Method::POST, "/api/logout", &cookie, None).await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let (status, _, _) = h.send(Method::GET, "/api/me", &cookie, None).await;
    assert_eq!(status, StatusCode::OK, "that logout must not have happened");
    let token = Credential_::Bearer(h.token(None));
    let (status, _, _) = h.send(Method::POST, "/api/logout", &token, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn cookie_flags_follow_the_proxy() {
    let h = harness("cookie");
    let request = |proto: Option<&'static str>| {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri("/api/login")
            .header(CONTENT_TYPE, "application/json")
            .header(USER_AGENT, "test-browser");
        if let Some(proto) = proto {
            request = request.header("x-forwarded-proto", proto);
        }
        request
            .body(Body::from(
                json!({"username": ROOT_USERNAME, "password": ROOT_DEFAULT_PASSWORD}).to_string(),
            ))
            .unwrap()
    };
    let plain = router(h.console.clone())
        .oneshot(request(None))
        .await
        .unwrap();
    let cookie = plain.headers()[SET_COOKIE].to_str().unwrap();
    assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"));
    assert!(!cookie.contains("Secure"));
    let proxied = router(h.console.clone())
        .oneshot(request(Some("https")))
        .await
        .unwrap();
    assert!(proxied.headers()[SET_COOKIE]
        .to_str()
        .unwrap()
        .contains("Secure"));
}

#[tokio::test]
async fn pages_have_protective_headers_and_no_inline_allowance() {
    let h = harness("page");
    for path in ["/", "/app.js", "/components.js", "/style.css"] {
        let (status, headers, _) = h.send(Method::GET, path, &Credential_::None, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[X_FRAME_OPTIONS], "DENY");
        assert_eq!(headers[CACHE_CONTROL], "no-store");
        let policy = headers[CONTENT_SECURITY_POLICY].to_str().unwrap();
        assert!(!policy.contains("unsafe-inline"));
    }
    let page = include_str!("ui/index.html");
    assert!(!page.contains("<script>") && !page.contains("<style>") && !page.contains(" style="));
}

// ---- Workspaces and administrators ----

#[tokio::test]
async fn workspaces_are_created_with_their_owner_and_can_be_removed() {
    let h = harness("workspaces");
    let body = json!({
        "name": "team-c", "cidr": "10.3.0.0/24",
        "owner_username": "carol", "owner_password": "first"
    });
    let (status, created) = h.as_root(Method::POST, "/api/workspaces", Some(body)).await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let id = created["id"].as_i64().unwrap();
    assert!(h.console.hub.network(id).is_some(), "running straight away");

    let (status, headers) = login(&h, "carol", "first").await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let carol = cookie_from(&headers);
    let (_, _, me) = h.send(Method::GET, "/api/me", &carol, None).await;
    assert_eq!(me["must_change_password"], true);
    assert_eq!(me["workspaces"][0]["standing"], "owner");

    let (status, _) = h
        .as_root(
            Method::DELETE,
            &format!("/api/workspaces/{id}"),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(h.console.hub.network(id).is_none());
    let (status, _, _) = h.send(Method::GET, "/api/me", &carol, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "the account went with it");
}

#[tokio::test]
async fn a_workspace_is_not_left_behind_when_its_owner_cannot_be_made() {
    let h = harness("rollback");
    h.user(h.a, "taken", Role::Admin);
    let body = json!({
        "name": "team-c", "cidr": "10.3.0.0/24",
        "owner_username": "taken", "owner_password": "x"
    });
    let (status, _) = h.as_root(Method::POST, "/api/workspaces", Some(body)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let body = json!({"name": "team-d", "cidr": "10.3.0.0/24", "owner_username": "nobody"});
    let (status, _) = h.as_root(Method::POST, "/api/workspaces", Some(body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(h.store().workspaces().unwrap().len(), 2);
}

#[tokio::test]
async fn bad_workspaces_are_refused() {
    let h = harness("bad-workspaces");
    for (body, expected) in [
        (
            json!({"name": "x", "cidr": "10.0.0.0/8"}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"name": "x", "cidr": "nope"}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"name": " ", "cidr": "10.3.0.0/24"}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"name": "team-a", "cidr": "10.3.0.0/24"}),
            StatusCode::CONFLICT,
        ),
    ] {
        let (status, _) = h
            .as_root(Method::POST, "/api/workspaces", Some(body.clone()))
            .await;
        assert_eq!(status, expected, "{body}");
    }
}

#[tokio::test]
async fn a_workspace_can_be_renamed_and_given_a_new_range() {
    let h = harness("edit-workspace");
    let session = h
        .console
        .hub
        .join(h.a, "c", "c", None, Instant::now())
        .unwrap();
    let uri = format!("/api/workspaces/{}", h.a);
    let (status, _) = h
        .as_root(Method::PATCH, &uri, Some(json!({"name": "renamed"})))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        h.console.hub.members(h.a).len(),
        1,
        "a rename disturbs nobody"
    );
    let (status, updated) = h
        .as_root(Method::PATCH, &uri, Some(json!({"cidr": "10.9.0.0/24"})))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(updated["cidr"], "10.9.0.0/24");
    let notified = session.kick.notified();
    tokio::pin!(notified);
    assert!(notified.as_mut().enable(), "members were disconnected");
    let back = h
        .console
        .hub
        .join(h.a, "c", "c", None, Instant::now())
        .unwrap();
    assert_eq!(back.ip.to_string(), "10.9.0.1");
    assert_eq!(back.network_name, "renamed");
}

#[tokio::test]
async fn owners_manage_administrators_and_admins_do_not() {
    let h = harness("admins");
    let owner = Credential_::Cookie({
        let id = h.user(h.a, "owner", Role::Owner);
        h.session(id)
    });
    let admins = format!("/api/w/{}/admins", h.a);
    let (status, _, reply) = h
        .send(
            Method::POST,
            &admins,
            &owner,
            Some(json!({"username": "bob", "password": "first", "role": "admin"})),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{reply}");
    // An owner has no way to learn about or borrow other accounts.
    h.user(h.b, "theirs", Role::Admin);
    let (status, _, _) = h
        .send(
            Method::POST,
            &admins,
            &owner,
            Some(json!({"username": "theirs", "role": "admin"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let bob = h.store().user_by_name("bob").unwrap().unwrap();
    assert!(bob.must_change_password, "chooses their own at first login");
    let (status, headers) = login(&h, "bob", "first").await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let bob_cookie = cookie_from(&headers);
    h.store()
        .set_password(bob.id, &bob.password_hash, false, None)
        .unwrap();
    let bob_cookie = match bob_cookie {
        Credential_::Cookie(_) => Credential_::Cookie(h.session(bob.id)),
        other => other,
    };
    let (status, _, _) = h
        .send(
            Method::POST,
            &admins,
            &bob_cookie,
            Some(json!({"username": "eve", "password": "x", "role": "owner"})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let bob_uri = format!("{admins}/{}", bob.id);
    let (status, _, _) = h
        .send(
            Method::PATCH,
            &bob_uri,
            &owner,
            Some(json!({"role": "owner"})),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, _) = h.send(Method::GET, &admins, &bob_cookie, None).await;
    assert_eq!(status, StatusCode::OK, "now an owner");
    let (status, _, _) = h
        .send(Method::DELETE, &bob_uri, &owner, Some(json!({})))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(h.store().user(bob.id).unwrap().is_none());
    let (status, _, _) = h.send(Method::GET, "/api/me", &bob_cookie, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_last_owner_stays_and_shared_accounts_are_for_the_super_administrator() {
    let h = harness("shared");
    let owner_id = h.user(h.a, "owner", Role::Owner);
    let owner = Credential_::Cookie(h.session(owner_id));
    let admins = format!("/api/w/{}/admins", h.a);
    let (status, _, _) = h
        .send(
            Method::DELETE,
            &format!("{admins}/{owner_id}"),
            &owner,
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _, _) = h
        .send(
            Method::PATCH,
            &format!("{admins}/{owner_id}"),
            &owner,
            Some(json!({"role": "admin"})),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Root can put one account in two workspaces.
    let shared = h.user(h.a, "shared", Role::Admin);
    let (status, _) = h
        .as_root(
            Method::POST,
            &format!("/api/w/{}/admins", h.b),
            Some(json!({"username": "shared", "role": "owner"})),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(h.store().memberships(shared).unwrap().len(), 2);

    // Its password is then out of one team's reach, but not root's.
    let reset = format!("{admins}/{shared}/password");
    let body = json!({"password": "reset"});
    let (status, _, _) = h
        .send(Method::POST, &reset, &owner, Some(body.clone()))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = h.as_root(Method::POST, &reset, Some(body)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        h.store()
            .user(shared)
            .unwrap()
            .unwrap()
            .must_change_password
    );

    // An account only here is the owner's to reset.
    let only = h.user(h.a, "only", Role::Admin);
    let only_session = Credential_::Cookie(h.session(only));
    let (status, _, _) = h
        .send(
            Method::POST,
            &format!("{admins}/{only}/password"),
            &owner,
            Some(json!({"password": "x"})),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, _) = h.send(Method::GET, "/api/me", &only_session, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "logged out by the reset");
}

// ---- Codes, bans, tokens ----

fn set_public_addr(h: &Harness) {
    h.store()
        .set_setting(SETTING_PUBLIC_ADDR, "203.0.113.7:8443")
        .unwrap();
}

#[tokio::test]
async fn codes_of_every_kind_parse_and_appear_without_their_secret() {
    let h = harness("codes");
    set_public_addr(&h);
    let uri = format!("/api/w/{}/codes", h.a);
    for (body, max, has_deadline) in [
        (json!({"max_uses": 1}), Some(1), false),
        (json!({"duration": "24h"}), None, true),
        (json!({"max_uses": 3, "duration": "7d"}), Some(3), true),
        (json!({"note": "permanent"}), None, false),
    ] {
        let (status, created) = h.as_root(Method::POST, &uri, Some(body.clone())).await;
        assert_eq!(status, StatusCode::OK, "{body}: {created}");
        let code = created["code"].as_str().unwrap();
        let parsed = Credential::parse(code).unwrap();
        assert_eq!(parsed.server, "203.0.113.7:8443");
        assert_eq!(parsed.pin, [7; 32]);
        assert_eq!(created["max_uses"].as_u64(), max);
        assert_eq!(created["expires_at"].is_u64(), has_deadline);
        assert_eq!(created["status"], "active");
        let (_, list) = h.as_root(Method::GET, &uri, None).await;
        assert!(!list.to_string().contains(code));
        assert!(!list.to_string().contains("secret_hash"));
    }
    let (_, list) = h
        .as_root(Method::GET, &format!("{uri}?q=permanent"), None)
        .await;
    assert_eq!(list["total"], 1);
    let (_, list) = h
        .as_root(Method::GET, &format!("{uri}?limit=2&offset=1"), None)
        .await;
    assert_eq!(
        (
            list["total"].as_u64(),
            list["items"].as_array().unwrap().len()
        ),
        (Some(4), 2)
    );
}

#[tokio::test]
async fn bad_code_requests_are_explained() {
    let h = harness("bad-codes");
    set_public_addr(&h);
    let uri = format!("/api/w/{}/codes", h.a);
    for body in [
        json!({"max_uses": 0}),
        json!({"duration": "soon"}),
        json!({"ssh_pubkey": "ssh-ed25519 nonsense"}),
    ] {
        let (status, reply) = h.as_root(Method::POST, &uri, Some(body.clone())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(reply["error"].is_string());
    }
    let (_, list) = h.as_root(Method::GET, &uri, None).await;
    assert_eq!(list["total"], 0);
}

#[tokio::test]
async fn codes_can_be_edited_and_deleted() {
    let h = harness("edit-codes");
    set_public_addr(&h);
    let uri = format!("/api/w/{}/codes", h.a);
    let (_, created) = h
        .as_root(Method::POST, &uri, Some(json!({"duration": "1h"})))
        .await;
    let item = format!("{uri}/{}", created["id"].as_str().unwrap());
    let before = created["expires_at"].as_u64().unwrap();
    let (status, _) = h
        .as_root(
            Method::PATCH,
            &item,
            Some(json!({"note": "n", "duration": "7d"})),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, list) = h.as_root(Method::GET, &uri, None).await;
    assert_eq!(list["items"][0]["note"], "n");
    assert!(list["items"][0]["expires_at"].as_u64().unwrap() > before);
    let (status, _) = h
        .as_root(Method::PATCH, &item, Some(json!({"duration": ""})))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, list) = h.as_root(Method::GET, &uri, None).await;
    assert_eq!(list["items"][0]["expires_at"], Value::Null);
    let (status, _) = h
        .as_root(Method::PATCH, &item, Some(json!({"duration": "1h"})))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "now permanent");
    let (status, _) = h.as_root(Method::DELETE, &item, Some(json!({}))).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, list) = h.as_root(Method::GET, &uri, None).await;
    assert_eq!(list["total"], 0);
}

#[tokio::test]
async fn bans_can_be_added_listed_lifted_and_given_an_end() {
    let h = harness("bans");
    let uri = format!("/api/w/{}/bans", h.a);
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
            json!({"kind": "other", "value": "x"}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"kind": "ip", "value": "198.51.100.0/24", "duration": "1h"}),
            StatusCode::OK,
        ),
        (
            json!({"kind": "ip", "value": "198.51.100.0/24"}),
            StatusCode::CONFLICT,
        ),
    ] {
        let (status, _) = h.as_root(Method::POST, &uri, Some(body.clone())).await;
        assert_eq!(status, expected, "{body}");
    }
    let (_, list) = h.as_root(Method::GET, &uri, None).await;
    assert_eq!(list["items"][0]["kind"], "ip");
    assert_eq!(list["items"][0]["value"], "198.51.100.0/24");
    assert!(list["items"][0]["expires_at"].is_u64());
    // A workspace's ban does not stop connections before TLS, or anywhere else.
    assert!(!h
        .store()
        .globally_banned_ip("198.51.100.1".parse().unwrap(), unix_now()));
    let item = format!("{uri}/{}", list["items"][0]["id"].as_str().unwrap());
    let (status, _) = h.as_root(Method::DELETE, &item, Some(json!({}))).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let body = json!({"kind": "ip", "value": "198.51.100.0/24"});
    let (status, _) = h.as_root(Method::POST, "/api/bans", Some(body)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(h
        .store()
        .globally_banned_ip("198.51.100.1".parse().unwrap(), unix_now()));
}

#[tokio::test]
async fn tokens_are_shown_once_and_work_until_deleted() {
    let h = harness("tokens");
    let uri = format!("/api/w/{}/tokens", h.a);
    let (status, created) = h
        .as_root(Method::POST, &uri, Some(json!({"name": "ci"})))
        .await;
    assert_eq!(status, StatusCode::OK);
    let token = created["token"].as_str().unwrap().to_owned();
    let (_, list) = h.as_root(Method::GET, &uri, None).await;
    assert!(!list.to_string().contains(&token));
    assert_eq!(list[0]["name"], "ci");

    let bearer = Credential_::Bearer(token);
    let members = format!("/api/w/{}/members", h.a);
    let (status, _, _) = h.send(Method::GET, &members, &bearer, None).await;
    assert_eq!(status, StatusCode::OK);
    let (_, _, me) = h.send(Method::GET, "/api/me", &bearer, None).await;
    assert_eq!(me["workspaces"][0]["standing"], "admin");
    assert_eq!(me["username"], "token:ci");

    let item = format!("{uri}/{}", created["id"].as_str().unwrap());
    let (status, _) = h.as_root(Method::DELETE, &item, Some(json!({}))).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, _) = h.send(Method::GET, &members, &bearer, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn changes_leave_an_audit_trail_with_who_and_where() {
    let h = harness("audit");
    let owner_id = h.user(h.a, "owner", Role::Owner);
    let cookie = h.session(owner_id);
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/w/{}/bans", h.a))
        .header(COOKIE, cookie)
        .header(CONTENT_TYPE, "application/json")
        .header("x-forwarded-for", "198.51.100.5, 10.0.0.1")
        .body(Body::from(
            json!({"kind": "ip", "value": "203.0.113.1"}).to_string(),
        ))
        .unwrap();
    let response = router(h.console.clone()).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let (_, entries) = h
        .as_root(Method::GET, &format!("/api/w/{}/audit", h.a), None)
        .await;
    assert_eq!(entries["items"][0]["actor"], "owner");
    assert_eq!(entries["items"][0]["action"], "add_ban");
    assert_eq!(entries["items"][0]["source"], "198.51.100.5");

    let _ = login(&h, "owner", "wrong").await;
    let (_, entries) = h
        .as_root(Method::GET, "/api/audit?q=login_failed", None)
        .await;
    assert_eq!(entries["total"], 1);
}

#[tokio::test]
async fn metrics_report_every_workspace_and_escape_its_name() {
    let h = harness("metrics");
    let body = json!({"name": "a\"b", "cidr": "10.3.0.0/30"});
    let (status, _) = h.as_root(Method::POST, "/api/workspaces", Some(body)).await;
    assert_eq!(status, StatusCode::OK);
    let _session = h
        .console
        .hub
        .join(h.a, "c", "c", None, Instant::now())
        .unwrap();
    let token = Credential_::Bearer(h.token(None));
    let (status, headers, text) = h.send(Method::GET, "/metrics", &token, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers[CONTENT_TYPE]
        .to_str()
        .unwrap()
        .starts_with("text/plain"));
    let text = text.as_str().unwrap();
    assert!(
        text.contains("varco_members_online{workspace=\"team-a\"} 1"),
        "{text}"
    );
    assert!(
        text.contains("varco_members_online{workspace=\"team-b\"} 0"),
        "{text}"
    );
    assert!(
        text.contains("varco_addresses_total{workspace=\"a\\\"b\"} 2"),
        "{text}"
    );
    assert!(text.contains("varco_relay_up 0"), "{text}");
}

#[tokio::test]
async fn health_says_nothing_but_whether_the_relay_listens() {
    let h = harness("health");
    let (status, _, reply) = h
        .send(Method::GET, "/healthz", &Credential_::None, None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reply, json!({"relay_listening": false}));
}

const SSH_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl me@host";

#[tokio::test]
async fn a_code_can_be_copied_again_with_each_of_my_keys() {
    let h = harness("copy-code");
    set_public_addr(&h);
    let codes = format!("/api/w/{}/codes", h.a);
    let (_, created) = h.as_root(Method::POST, &codes, Some(json!({}))).await;
    let id = created["id"].as_str().unwrap();
    let copies_uri = format!("{codes}/{id}/copies");

    let (status, copies) = h.as_root(Method::GET, &copies_uri, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(copies["code"], created["code"]);
    assert_eq!(copies["keyed"], json!([]));

    let (status, key) = h
        .as_root(
            Method::POST,
            "/api/me/ssh-keys",
            Some(json!({"public_key": SSH_KEY})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{key}");
    assert_eq!(key["name"], "me@host");

    let (_, copies) = h.as_root(Method::GET, &copies_uri, None).await;
    let plain = Credential::parse(copies["code"].as_str().unwrap()).unwrap();
    assert!(plain.ssh_pubkey.is_none());
    let keyed = &copies["keyed"][0];
    assert_eq!(keyed["name"], "me@host");
    assert_eq!(keyed["fingerprint"], key["fingerprint"]);
    let joint = Credential::parse(keyed["code"].as_str().unwrap()).unwrap();
    assert_eq!(joint.secret, plain.secret);
    assert!(joint.ssh_pubkey.is_some());

    // A copy follows the server's address, and a token has no keys of its own.
    h.store()
        .set_setting(SETTING_PUBLIC_ADDR, "198.51.100.9:443")
        .unwrap();
    let token = Credential_::Bearer(h.token(Some(h.a)));
    let (_, _, copies) = h.send(Method::GET, &copies_uri, &token, None).await;
    let moved = Credential::parse(copies["code"].as_str().unwrap()).unwrap();
    assert_eq!(moved.server, "198.51.100.9:443");
    assert_eq!(moved.secret, plain.secret);
    assert_eq!(copies["keyed"], json!([]));

    let other = format!("/api/w/{}/codes/{id}/copies", h.b);
    let (status, _) = h.as_root(Method::GET, &other, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (_, audit) = h
        .as_root(
            Method::GET,
            &format!("/api/w/{}/audit?q=copy_code", h.a),
            None,
        )
        .await;
    assert!(audit["total"].as_u64().unwrap() >= 3, "{audit}");

    let (status, _) = h
        .as_root(
            Method::POST,
            &format!("{codes}/{id}/revoke"),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = h.as_root(Method::GET, &copies_uri, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_token_can_be_copied_again_and_still_works() {
    let h = harness("copy-token");
    let tokens = format!("/api/w/{}/tokens", h.a);
    let (_, created) = h
        .as_root(Method::POST, &tokens, Some(json!({"name": "ci"})))
        .await;
    let (id, token) = (
        created["id"].as_str().unwrap(),
        created["token"].as_str().unwrap(),
    );

    let (status, copy) = h
        .as_root(Method::GET, &format!("{tokens}/{id}/secret"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(copy["token"], token);

    let (_, list) = h.as_root(Method::GET, &tokens, None).await;
    assert!(!list.to_string().contains(token));

    let bearer = Credential_::Bearer(copy["token"].as_str().unwrap().to_owned());
    let (status, _, _) = h
        .send(Method::GET, &format!("/api/w/{}", h.a), &bearer, None)
        .await;
    assert_eq!(status, StatusCode::OK);

    let elsewhere = format!("/api/w/{}/tokens/{id}/secret", h.b);
    let (status, _) = h.as_root(Method::GET, &elsewhere, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let global = format!("/api/tokens/{id}/secret");
    let (status, _) = h.as_root(Method::GET, &global, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn ssh_keys_belong_to_one_person() {
    let h = harness("ssh-keys");
    let alice = Credential_::Cookie({
        let user = h.user(h.a, "alice", Role::Admin);
        h.session(user)
    });
    let bob = Credential_::Cookie({
        let user = h.user(h.a, "bob", Role::Admin);
        h.session(user)
    });
    let uri = "/api/me/ssh-keys";
    let add = |name: &str, key: &str| Some(json!({"name": name, "public_key": key}));

    for bad in [
        "ssh-ed25519 nonsense",
        "",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
    ] {
        let (status, _, _) = h.send(Method::POST, uri, &alice, add("", bad)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }
    let (status, _, key) = h
        .send(Method::POST, uri, &alice, add("laptop", SSH_KEY))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(key["name"], "laptop");
    // The same key under another comment is still the same key.
    let renamed = SSH_KEY.replace("me@host", "other@host");
    let (status, _, _) = h
        .send(Method::POST, uri, &alice, add("again", &renamed))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _, _) = h.send(Method::POST, uri, &bob, add("", SSH_KEY)).await;
    assert_eq!(status, StatusCode::OK);

    let one = format!("{uri}/{}", key["id"].as_str().unwrap());
    let (status, _, _) = h.send(Method::DELETE, &one, &bob, Some(json!({}))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, _, mine) = h.send(Method::GET, uri, &alice, None).await;
    assert_eq!(mine.as_array().unwrap().len(), 1);
    let (status, _, _) = h.send(Method::DELETE, &one, &alice, Some(json!({}))).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, _, mine) = h.send(Method::GET, uri, &alice, None).await;
    assert_eq!(mine, json!([]));
}
