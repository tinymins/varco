use super::*;
use crate::proto::RejectReason;
use std::path::PathBuf;
use std::sync::Arc;

const NOW: u64 = 1_000_000;
const PEER: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7));

fn db_path(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("varco-store-db-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("varco.db")
}

fn store(name: &str) -> Arc<Store> {
    Arc::new(Store::open(&db_path(name)).unwrap())
}

fn workspace(store: &Store, name: &str) -> WorkspaceId {
    store
        .create_workspace(name, "10.1.0.0/24".parse().unwrap(), NOW)
        .unwrap()
        .id
}

fn once() -> CodeLimits {
    CodeLimits {
        max_uses: Some(1),
        expires_at: None,
    }
}

fn until(seconds: u64) -> CodeLimits {
    CodeLimits {
        max_uses: None,
        expires_at: Some(NOW + seconds),
    }
}

fn details() -> UseDetails<'static> {
    UseDetails {
        device: Some("d1"),
        hostname: "host",
        peer: PEER,
    }
}

fn admit(store: &Arc<Store>, secret: &[u8; 32], client: &str) -> AdmittedCode {
    match store.admit_code(secret, client, NOW) {
        Ok(Some(admitted)) => admitted,
        _ => panic!("expected to be admitted"),
    }
}

fn reject(store: &Arc<Store>, secret: &[u8; 32], client: &str, now: u64) -> RejectReason {
    match store.admit_code(secret, client, now) {
        Err(AdmitError::Reject(reason)) => reason,
        _ => panic!("expected a rejection"),
    }
}

fn commit(admitted: &AdmittedCode) {
    admitted
        .reservation
        .as_ref()
        .unwrap()
        .commit(&details(), NOW)
        .unwrap();
}

const ALL: PageRequest<'static> = PageRequest {
    query: "",
    limit: 100,
    offset: 0,
};

#[test]
fn once_code_goes_to_one_run_and_stays_with_it() {
    let store = store("once");
    let ws = workspace(&store, "a");
    let (record, secret) = store.create_code(ws, once(), "", NOW).unwrap();
    let first = admit(&store, &secret, "c1");
    assert_eq!(first.workspace, ws);
    commit(&first);
    drop(first);
    assert_eq!(reject(&store, &secret, "c2", NOW), RejectReason::CodeUsed);
    assert!(admit(&store, &secret, "c1").reservation.is_none());
    let listed = store.code(ws, &record.id, NOW).unwrap().unwrap();
    assert_eq!(listed.status, CodeStatus::Used);
    assert_eq!(listed.used_by[0].hostname, "host");
}

#[test]
fn unconfirmed_connection_holds_the_code_only_while_it_lasts() {
    let store = store("hold");
    let ws = workspace(&store, "a");
    let (record, secret) = store.create_code(ws, once(), "", NOW).unwrap();
    let first = admit(&store, &secret, "c1");
    assert_eq!(reject(&store, &secret, "c2", NOW), RejectReason::CodeUsed);
    drop(first);
    let listed = store.code(ws, &record.id, NOW).unwrap().unwrap();
    assert_eq!(listed.status, CodeStatus::Active);
    let _ = admit(&store, &secret, "c2");
}

#[test]
fn a_dying_old_connection_does_not_release_its_replacement() {
    let store = store("replace");
    let ws = workspace(&store, "a");
    let (_, secret) = store.create_code(ws, once(), "", NOW).unwrap();
    let old = admit(&store, &secret, "c1");
    let new = admit(&store, &secret, "c1");
    drop(old);
    assert_eq!(reject(&store, &secret, "c2", NOW), RejectReason::CodeUsed);
    drop(new);
    let _ = admit(&store, &secret, "c2");
}

#[test]
fn only_one_of_many_racing_runs_gets_a_once_code() {
    let store = store("race");
    let ws = workspace(&store, "a");
    let (_, secret) = store.create_code(ws, once(), "", NOW).unwrap();
    let handles: Vec<_> = (0..16)
        .map(|index| {
            let store = store.clone();
            std::thread::spawn(move || store.admit_code(&secret, &format!("c{index}"), NOW))
        })
        .collect();
    // Results are all kept until counted, so no winner's hold has ended yet.
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let granted = results.iter().filter(|r| matches!(r, Ok(Some(_)))).count();
    let refused = results
        .iter()
        .filter(|r| matches!(r, Err(AdmitError::Reject(RejectReason::CodeUsed))))
        .count();
    assert_eq!((granted, refused), (1, 15));
}

#[test]
fn timed_code_admits_many_until_it_expires_but_never_expires_a_user() {
    let store = store("timed");
    let ws = workspace(&store, "a");
    let (record, secret) = store.create_code(ws, until(100), "", NOW).unwrap();
    let first = admit(&store, &secret, "c1");
    let second = admit(&store, &secret, "c2");
    commit(&first);
    drop(first);
    drop(second);
    let later = NOW + 100;
    let listed = store.code(ws, &record.id, later).unwrap().unwrap();
    assert_eq!(listed.status, CodeStatus::Expired);
    assert_eq!(
        reject(&store, &secret, "c3", later),
        RejectReason::CodeExpired
    );
    // c2 never finished joining, so the deadline applies to it.
    assert_eq!(
        reject(&store, &secret, "c2", later),
        RejectReason::CodeExpired
    );
    let back = store.admit_code(&secret, "c1", later).unwrap().unwrap();
    assert!(back.reservation.is_none());
}

#[test]
fn both_limits_combine() {
    let store = store("combined");
    let ws = workspace(&store, "a");
    let limits = CodeLimits {
        max_uses: Some(2),
        expires_at: Some(NOW + 100),
    };
    let (_, secret) = store.create_code(ws, limits, "", NOW).unwrap();
    for client in ["c1", "c2"] {
        let admitted = admit(&store, &secret, client);
        commit(&admitted);
    }
    assert_eq!(reject(&store, &secret, "c3", NOW), RejectReason::CodeUsed);
    assert_eq!(
        reject(&store, &secret, "c3", NOW + 100),
        RejectReason::CodeExpired
    );
    assert!(store
        .admit_code(&secret, "c2", NOW + 100)
        .unwrap()
        .is_some());
}

#[test]
fn permanent_code_records_nothing() {
    let store = store("permanent");
    let ws = workspace(&store, "a");
    let (record, secret) = store
        .create_code(ws, CodeLimits::default(), "", NOW)
        .unwrap();
    for client in ["c1", "c2", "c3"] {
        assert!(admit(&store, &secret, client).reservation.is_none());
    }
    let listed = store
        .code(ws, &record.id, NOW + 1_000_000)
        .unwrap()
        .unwrap();
    assert_eq!(listed.status, CodeStatus::Active);
    assert!(listed.used_by.is_empty());
}

#[test]
fn a_permanent_code_cannot_gain_a_deadline() {
    let store = store("no-deadline");
    let ws = workspace(&store, "a");
    let (record, _) = store
        .create_code(ws, CodeLimits::default(), "", NOW)
        .unwrap();
    assert!(matches!(
        store.update_code(ws, &record.id, None, Some(Some(NOW + 1))),
        Err(ChangeError::Conflict(_))
    ));
    store.update_code(ws, &record.id, Some("n"), None).unwrap();
    assert_eq!(store.code(ws, &record.id, NOW).unwrap().unwrap().note, "n");
}

#[test]
fn deadlines_can_move_without_affecting_users() {
    let store = store("extend");
    let ws = workspace(&store, "a");
    let (record, secret) = store.create_code(ws, until(100), "", NOW).unwrap();
    let first = admit(&store, &secret, "c1");
    commit(&first);
    drop(first);
    store
        .update_code(ws, &record.id, None, Some(Some(NOW + 1)))
        .unwrap();
    assert_eq!(
        reject(&store, &secret, "c2", NOW + 1),
        RejectReason::CodeExpired
    );
    assert!(store.admit_code(&secret, "c1", NOW + 1).unwrap().is_some());
    store
        .update_code(ws, &record.id, None, Some(Some(NOW + 500)))
        .unwrap();
    assert!(store.admit_code(&secret, "c2", NOW + 1).unwrap().is_some());
}

#[test]
fn deleting_beats_having_used_the_code() {
    let store = store("delete");
    let ws = workspace(&store, "a");
    let (record, secret) = store.create_code(ws, until(100), "", NOW).unwrap();
    let first = admit(&store, &secret, "c1");
    commit(&first);
    drop(first);
    store.delete_code(ws, &record.id).unwrap();
    assert!(store.admit_code(&secret, "c1", NOW).unwrap().is_none());
    assert!(store.code(ws, &record.id, NOW).unwrap().is_none());
}

#[test]
fn commit_is_refused_once_the_code_is_deleted() {
    let store = store("delete-pending");
    let ws = workspace(&store, "a");
    let (record, secret) = store.create_code(ws, once(), "", NOW).unwrap();
    let held = admit(&store, &secret, "c1");
    store.delete_code(ws, &record.id).unwrap();
    assert!(held
        .reservation
        .as_ref()
        .unwrap()
        .commit(&details(), NOW)
        .is_err());
}

#[test]
fn a_first_use_that_cannot_be_saved_is_refused() {
    let store = store("readonly");
    let ws = workspace(&store, "a");
    let (record, secret) = store.create_code(ws, once(), "", NOW).unwrap();
    let held = admit(&store, &secret, "c1");
    store
        .lock()
        .db
        .pragma_update(None, "query_only", true)
        .unwrap();
    assert!(held
        .reservation
        .as_ref()
        .unwrap()
        .commit(&details(), NOW)
        .is_err());
    store
        .lock()
        .db
        .pragma_update(None, "query_only", false)
        .unwrap();
    assert!(store
        .code(ws, &record.id, NOW)
        .unwrap()
        .unwrap()
        .used_by
        .is_empty());
}

#[test]
fn ids_from_another_workspace_are_not_found() {
    let store = store("scope");
    let a = workspace(&store, "a");
    let b = workspace(&store, "b");
    let (code, _) = store.create_code(a, once(), "", NOW).unwrap();
    let ban = store
        .add_ban(Some(a), BanTarget::Device("d".into()), "", None, NOW)
        .unwrap();
    let token = store.create_token(Some(a), "t", None, NOW).unwrap();
    store.kick(a, "client", "h", NOW).unwrap();
    assert!(store.code(b, &code.id, NOW).unwrap().is_none());
    for result in [
        store.update_code(b, &code.id, Some("x"), None),
        store.delete_code(b, &code.id),
        store.remove_ban(Some(b), &ban.id),
        store.remove_ban(None, &ban.id),
        store.delete_token(Some(b), &token.info.id),
        store.delete_token(None, &token.info.id),
        store.unkick(b, "client"),
    ] {
        assert!(matches!(result, Err(ChangeError::NotFound)));
    }
    assert_eq!(store.codes(b, ALL, NOW).unwrap().total, 0);
    assert_eq!(store.bans(Some(b), ALL, NOW).unwrap().total, 0);
    assert!(store.kicked(b).unwrap().is_empty());
}

#[test]
fn bans_and_kicks_apply_to_their_own_workspace_and_globals_to_all() {
    let store = store("ban-scope");
    let a = workspace(&store, "a");
    let b = workspace(&store, "b");
    store
        .add_ban(Some(a), BanTarget::Device("d1".into()), "", None, NOW)
        .unwrap();
    store
        .add_ban(
            Some(a),
            BanTarget::Ip(parse_ip_target("203.0.113.7").unwrap()),
            "",
            None,
            NOW,
        )
        .unwrap();
    store.kick(a, &client_key("c1"), "h", NOW).unwrap();
    let other: IpAddr = "198.51.100.1".parse().unwrap();
    assert!(store.blocked(a, "x", Some("d1"), other, NOW).unwrap());
    assert!(store.blocked(a, "x", None, PEER, NOW).unwrap());
    assert!(store.blocked(a, "c1", None, other, NOW).unwrap());
    assert!(!store.blocked(b, "x", Some("d1"), other, NOW).unwrap());
    assert!(!store.blocked(b, "x", None, PEER, NOW).unwrap());
    assert!(!store.blocked(b, "c1", None, other, NOW).unwrap());
    assert!(!store.globally_banned_ip(PEER, NOW));

    store
        .add_ban(None, BanTarget::Device("d2".into()), "", None, NOW)
        .unwrap();
    store
        .add_ban(
            None,
            BanTarget::Ip(parse_ip_target("198.51.100.0/24").unwrap()),
            "",
            None,
            NOW,
        )
        .unwrap();
    assert!(store.blocked(b, "x", Some("d2"), PEER, NOW).unwrap());
    assert!(store.globally_banned_ip(other, NOW));
    assert!(store.globally_banned_ip("::ffff:198.51.100.9".parse().unwrap(), NOW));
}

#[test]
fn bans_can_expire_and_be_set_again() {
    let store = store("ban-expiry");
    let target = BanTarget::Ip(parse_ip_target("203.0.113.7").unwrap());
    let ws = workspace(&store, "a");
    store
        .add_ban(None, target.clone(), "", Some(NOW + 10), NOW)
        .unwrap();
    assert!(store.globally_banned_ip(PEER, NOW + 9));
    assert!(!store.globally_banned_ip(PEER, NOW + 10));
    assert!(store.blocked(ws, "c", None, PEER, NOW + 9).unwrap());
    assert!(!store.blocked(ws, "c", None, PEER, NOW + 10).unwrap());
    assert!(matches!(
        store.add_ban(None, target.clone(), "", None, NOW),
        Err(ChangeError::Conflict(_))
    ));
    assert_eq!(store.bans(None, ALL, NOW + 10).unwrap().total, 0);
    store.add_ban(None, target, "", None, NOW + 10).unwrap();
    store.purge(NOW + 11).unwrap();
    assert!(store.globally_banned_ip(PEER, NOW + 11));
}

#[test]
fn state_survives_a_restart_and_keeps_only_codes_and_tokens_readable() {
    let path = db_path("reload");
    let store = Arc::new(Store::open(&path).unwrap());
    let ws = workspace(&store, "a");
    let (record, secret) = store.create_code(ws, once(), "", NOW).unwrap();
    let used = admit(&store, &secret, "plain-client-id");
    commit(&used);
    drop(used);
    store
        .add_ban(
            None,
            BanTarget::Ip(parse_ip_target("198.51.100.0/24").unwrap()),
            "",
            None,
            NOW,
        )
        .unwrap();
    let token = store.create_token(None, "t", None, NOW).unwrap();
    let session = store
        .open_session(
            store.user_by_name(ROOT_USERNAME).unwrap().unwrap().id,
            "ua",
            100,
            NOW,
        )
        .unwrap();
    drop(store);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let bytes = std::fs::read(&path).unwrap();
    let contains = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
    assert!(!contains(b"plain-client-id"));
    assert!(!contains(session.as_bytes()));

    let reloaded = Arc::new(Store::open(&path).unwrap());
    assert_eq!(
        reject(&reloaded, &secret, "c2", NOW),
        RejectReason::CodeUsed
    );
    assert!(reloaded
        .admit_code(&secret, "plain-client-id", NOW)
        .unwrap()
        .unwrap()
        .reservation
        .is_none());
    assert!(reloaded.globally_banned_ip("198.51.100.9".parse().unwrap(), NOW));
    assert!(reloaded.session_user(&session, NOW).unwrap().is_some());
    assert!(reloaded.token_info(&token.token, NOW).unwrap().is_some());
    // Kept so they can be copied again.
    assert_eq!(reloaded.code_secret(ws, &record.id).unwrap(), secret);
    assert_eq!(
        reloaded.token_secret(None, &token.info.id).unwrap(),
        token.token
    );
}

#[test]
fn a_damaged_or_newer_file_stops_the_server() {
    let path = db_path("damaged");
    std::fs::write(
        &path,
        b"this is not a database, and it is long enough to tell",
    )
    .unwrap();
    assert!(Store::open(&path).is_err());

    let path = db_path("newer");
    drop(Store::open(&path).unwrap());
    let db = rusqlite::Connection::open(&path).unwrap();
    db.pragma_update(None, "user_version", 99).unwrap();
    drop(db);
    assert!(Store::open(&path).is_err());
}

#[test]
fn root_starts_with_the_default_password_and_can_be_reset() {
    let store = store("root");
    let root = store.user_by_name(ROOT_USERNAME).unwrap().unwrap();
    assert!(root.is_super && root.must_change_password);
    assert!(verify_password(ROOT_DEFAULT_PASSWORD, &root.password_hash));

    let session = store.open_session(root.id, "", 100, NOW).unwrap();
    // Any password is accepted, the same one included.
    store
        .set_password(root.id, &hash_password("admin").unwrap(), false, None)
        .unwrap();
    assert!(store.session_user(&session, NOW).unwrap().is_none());

    let session = store.open_session(root.id, "", 100, NOW).unwrap();
    store
        .set_password(root.id, &hash_password("").unwrap(), false, None)
        .unwrap();
    assert!(verify_password(
        "",
        &store.user(root.id).unwrap().unwrap().password_hash
    ));
    assert!(store.session_user(&session, NOW).unwrap().is_none());

    let session = store.open_session(root.id, "", 100, NOW).unwrap();
    store.reset_root_password().unwrap();
    let root = store.user(root.id).unwrap().unwrap();
    assert!(root.must_change_password);
    assert!(verify_password(ROOT_DEFAULT_PASSWORD, &root.password_hash));
    assert!(store.session_user(&session, NOW).unwrap().is_none());
}

#[test]
fn changing_a_password_keeps_only_the_session_asked_to_stay() {
    let store = store("sessions");
    let root = store.user_by_name(ROOT_USERNAME).unwrap().unwrap();
    let kept = store.open_session(root.id, "kept", 100, NOW).unwrap();
    let other = store.open_session(root.id, "other", 100, NOW).unwrap();
    store
        .set_password(root.id, "hash", false, Some(&client_key(&kept)))
        .unwrap();
    assert!(store.session_user(&kept, NOW).unwrap().is_some());
    assert!(store.session_user(&other, NOW).unwrap().is_none());
    assert_eq!(store.sessions(root.id, NOW).unwrap().len(), 1);
    assert!(store.session_user(&kept, NOW + 100).unwrap().is_none());
}

#[test]
fn sessions_can_be_listed_and_ended_by_their_owner_only() {
    let store = store("session-scope");
    let ws = workspace(&store, "a");
    let user = store.add_admin(ws, "u", "h", Role::Admin, NOW).unwrap();
    let root = store.user_by_name(ROOT_USERNAME).unwrap().unwrap();
    let token = store.open_session(user, "browser", 100, NOW).unwrap();
    let id = store.sessions(user, NOW).unwrap()[0].id.clone();
    assert!(matches!(
        store.close_session_by_id(root.id, &id),
        Err(ChangeError::NotFound)
    ));
    assert!(store.session_user(&token, NOW).unwrap().is_some());
    store.close_session_by_id(user, &id).unwrap();
    assert!(store.session_user(&token, NOW).unwrap().is_none());
}

#[test]
fn a_workspace_keeps_at_least_one_owner() {
    let store = store("owners");
    let ws = workspace(&store, "a");
    let owner = store.add_admin(ws, "o", "h", Role::Owner, NOW).unwrap();
    let admin = store.add_admin(ws, "a", "h", Role::Admin, NOW).unwrap();
    assert!(matches!(
        store.remove_admin(ws, owner),
        Err(ChangeError::Conflict(_))
    ));
    assert!(matches!(
        store.set_role(ws, owner, Role::Admin),
        Err(ChangeError::Conflict(_))
    ));
    assert!(matches!(
        store.delete_user(owner),
        Err(ChangeError::Conflict(_))
    ));
    store.set_role(ws, admin, Role::Owner).unwrap();
    store.remove_admin(ws, owner).unwrap();
    assert!(
        store.user(owner).unwrap().is_none(),
        "orphan account removed"
    );
}

#[test]
fn usernames_are_unique_and_only_attaching_shares_an_account() {
    let store = store("shared");
    let a = workspace(&store, "a");
    let b = workspace(&store, "b");
    let user = store.add_admin(a, "u", "h", Role::Owner, NOW).unwrap();
    assert!(matches!(
        store.add_admin(b, "u", "h", Role::Admin, NOW),
        Err(ChangeError::Conflict(_))
    ));
    assert!(matches!(
        store.add_admin(b, " ", "h", Role::Admin, NOW),
        Err(ChangeError::Invalid(_))
    ));
    assert_eq!(store.attach_admin(b, "u", Role::Admin).unwrap(), user);
    assert!(store.admins(a).unwrap()[0].shared);
    assert_eq!(store.memberships(user).unwrap().len(), 2);
    assert_eq!(store.role_of(user, b).unwrap(), Some(Role::Admin));
    assert!(matches!(
        store.attach_admin(b, "u", Role::Admin),
        Err(ChangeError::Conflict(_))
    ));
    assert!(matches!(
        store.attach_admin(b, ROOT_USERNAME, Role::Admin),
        Err(ChangeError::Conflict(_))
    ));
    store.remove_admin(b, user).unwrap();
    assert!(
        store.user(user).unwrap().is_some(),
        "still in the other one"
    );
}

#[test]
fn deleting_a_workspace_takes_everything_in_it_and_its_only_accounts() {
    let store = store("delete");
    let a = workspace(&store, "a");
    let b = workspace(&store, "b");
    let (_, secret) = store.create_code(a, once(), "", NOW).unwrap();
    let only_a = store.add_admin(a, "only", "h", Role::Owner, NOW).unwrap();
    let both = store.add_admin(a, "both", "h", Role::Owner, NOW).unwrap();
    store.attach_admin(b, "both", Role::Owner).unwrap();
    let token = store.create_token(Some(a), "t", None, NOW).unwrap();
    store
        .add_ban(Some(a), BanTarget::Device("d".into()), "", None, NOW)
        .unwrap();
    store.delete_workspace(a).unwrap();
    assert!(store.admit_code(&secret, "c", NOW).unwrap().is_none());
    assert!(store.user(only_a).unwrap().is_none());
    assert!(store.user(both).unwrap().is_some());
    assert!(store.token_info(&token.token, NOW).unwrap().is_none());
    assert!(matches!(
        store.delete_workspace(a),
        Err(ChangeError::NotFound)
    ));
    assert!(store.user_by_name(ROOT_USERNAME).unwrap().is_some());
}

#[test]
fn workspace_names_are_unique_and_ranges_may_overlap() {
    let store = store("names");
    let cidr: Ipv4Net = "10.1.0.0/24".parse().unwrap();
    let a = store.create_workspace("a", cidr, NOW).unwrap();
    store.create_workspace("b", cidr, NOW).unwrap();
    assert!(matches!(
        store.create_workspace("a", cidr, NOW),
        Err(ChangeError::Conflict(_))
    ));
    assert!(matches!(
        store.create_workspace(" ", cidr, NOW),
        Err(ChangeError::Invalid(_))
    ));
    assert!(matches!(
        store.update_workspace(a.id, Some("b"), None),
        Err(ChangeError::Conflict(_))
    ));
    let renamed = store.update_workspace(a.id, Some("c"), None).unwrap();
    assert_eq!(
        (renamed.name.as_str(), renamed.cidr.as_str()),
        ("c", "10.1.0.0/24")
    );
    assert!(matches!(
        store.update_workspace(999, Some("x"), None),
        Err(ChangeError::NotFound)
    ));
}

#[test]
fn suggested_ranges_skip_those_in_use() {
    let store = store("suggest");
    assert_eq!(store.suggest_cidr().unwrap(), "10.77.1.0/24");
    store
        .create_workspace("a", "10.77.1.0/24".parse().unwrap(), NOW)
        .unwrap();
    assert_eq!(store.suggest_cidr().unwrap(), "10.77.2.0/24");
}

#[test]
fn cidrs_are_checked() {
    assert_eq!(
        parse_cidr("10.1.2.3/24").unwrap().to_string(),
        "10.1.2.0/24"
    );
    for bad in ["", "x", "10.0.0.0/8", "10.0.0.0/31", "::1/64"] {
        assert!(parse_cidr(bad).is_err(), "{bad}");
    }
}

#[test]
fn addresses_are_checked() {
    for good in ["203.0.113.7:8443", "vpn.example.com:8443", "[::1]:1"] {
        assert!(is_host_port(good), "{good}");
    }
    for bad in [
        "203.0.113.7",
        "vpn.example.com",
        ":8443",
        "h:0",
        "h:70000",
        "https://h:443",
        "a b:1",
    ] {
        assert!(!is_host_port(bad), "{bad}");
    }
}

#[test]
fn old_records_age_out_but_open_connections_and_bans_stay() {
    let store = store("purge");
    let ws = workspace(&store, "a");
    let connection = |client| NewConnection {
        workspace: ws,
        client,
        hostname: "h",
        ip: "10.1.0.1".parse().unwrap(),
        peer: PEER,
        device: None,
        code_id: None,
    };
    let finished = store.open_connection(&connection("c1"), NOW).unwrap();
    store.close_connection(finished, 5, 7, NOW).unwrap();
    store.open_connection(&connection("c2"), NOW).unwrap();
    store.audit("root", Some(ws), "x", "y", "", NOW).unwrap();
    store.kick(ws, "c", "h", NOW).unwrap();

    let month_later = NOW + 31 * 86400;
    store.purge(month_later).unwrap();
    let left = store.connections(ws, ALL).unwrap();
    assert_eq!(left.total, 1);
    assert_eq!(left.items[0].ended_at, None);
    assert_eq!(store.audit_entries(None, ALL).unwrap().total, 0);
    assert!(store.kicked(ws).unwrap().is_empty());

    store.close_stale_connections(month_later).unwrap();
    assert_eq!(
        store.connections(ws, ALL).unwrap().items[0].ended_at,
        Some(month_later)
    );
}

#[test]
fn history_keeps_the_days_asked_for() {
    let store = store("days");
    store.audit("root", None, "x", "y", "", NOW).unwrap();
    store.set_setting(SETTING_HISTORY_DAYS, "1").unwrap();
    store.purge(NOW + 2 * 86400).unwrap();
    assert_eq!(store.audit_entries(None, ALL).unwrap().total, 0);
}

#[test]
fn searches_filter_and_treat_wildcards_as_text() {
    let store = store("search");
    let ws = workspace(&store, "a");
    store.create_code(ws, once(), "alpha", NOW).unwrap();
    store.create_code(ws, once(), "100%", NOW).unwrap();
    let find = |query| {
        store
            .codes(
                ws,
                PageRequest {
                    query,
                    limit: 10,
                    offset: 0,
                },
                NOW,
            )
            .unwrap()
            .total
    };
    assert_eq!(find(""), 2);
    assert_eq!(find("alp"), 1);
    assert_eq!(find("%"), 1);
    assert_eq!(find("_"), 0);
    let page = store
        .codes(
            ws,
            PageRequest {
                query: "",
                limit: 1,
                offset: 1,
            },
            NOW,
        )
        .unwrap();
    assert_eq!((page.total, page.items.len()), (2, 1));
}

#[test]
fn audit_is_scoped_for_workspaces_and_outlives_them() {
    let store = store("audit");
    let a = workspace(&store, "a");
    let b = workspace(&store, "b");
    store.audit("o", Some(a), "kick", "h1", "", NOW).unwrap();
    store.audit("p", Some(b), "kick", "h2", "", NOW).unwrap();
    store.audit("root", None, "login", "", "", NOW).unwrap();
    assert_eq!(store.audit_entries(Some(a), ALL).unwrap().total, 1);
    assert_eq!(store.audit_entries(None, ALL).unwrap().total, 3);
    store.delete_workspace(a).unwrap();
    assert_eq!(store.audit_entries(None, ALL).unwrap().total, 3);
}

#[test]
fn tokens_expire_and_can_be_deleted() {
    let store = store("tokens");
    let ws = workspace(&store, "a");
    let token = store
        .create_token(Some(ws), "ci", Some(NOW + 10), NOW)
        .unwrap();
    assert!(token.token.starts_with("varco_"));
    assert_eq!(
        store
            .token_info(&token.token, NOW)
            .unwrap()
            .unwrap()
            .workspace_id,
        Some(ws)
    );
    assert_eq!(
        store.tokens(Some(ws)).unwrap()[0].last_used,
        Some(NOW),
        "use is recorded"
    );
    assert!(store.token_info(&token.token, NOW + 10).unwrap().is_none());
    store.delete_token(Some(ws), &token.info.id).unwrap();
    assert!(store.tokens(Some(ws)).unwrap().is_empty());
}

#[test]
fn ip_targets_are_normalized_and_bad_ones_refused() {
    let parsed = |text| parse_ip_target(text).map(|net| net.to_string());
    assert_eq!(parsed("10.0.0.1").unwrap(), "10.0.0.1/32");
    assert_eq!(parsed("10.0.0.9/24").unwrap(), "10.0.0.0/24");
    assert_eq!(parsed("::ffff:10.0.0.1").unwrap(), "10.0.0.1/32");
    assert_eq!(parsed("::ffff:10.0.0.0/120").unwrap(), "10.0.0.0/24");
    for bad in ["", "host", "10.0.0.1/33", "::ffff:10.0.0.0/64"] {
        assert!(parse_ip_target(bad).is_none(), "{bad}");
    }
}

#[test]
fn durations_parse() {
    assert_eq!(parse_duration("30m"), Some(1800));
    assert_eq!(parse_duration(" 24h "), Some(86400));
    assert_eq!(parse_duration("7d"), Some(604800));
    for bad in ["", "h", "0h", "-1h", "1w", "24", "99999999999999999999d"] {
        assert_eq!(parse_duration(bad), None, "{bad}");
    }
}
