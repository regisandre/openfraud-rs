//! The state file: API keys and the admin token as digests, and the two
//! secrets openfraud makes once and keeps (the pseudonym key, the webhook
//! secret).

use openfraud::keys::{KeySet, LiveAdmin, LiveKeys, Scope, State};

fn temp(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("openfraud-keys-{}-{name}.toml", std::process::id()))
}

#[test]
fn secrets_are_made_once_and_survive_a_restart() {
    let path = temp("secrets");
    let _ = std::fs::remove_file(&path);
    let mut state = State::load(&path).unwrap();
    assert!(state.ensure_secrets(), "a new state gets its secrets");
    assert!(!state.ensure_secrets(), "and only once");
    state.save(&path).unwrap();
    let again = State::load(&path).unwrap();
    assert_eq!(again.pseudonym_key(), state.pseudonym_key(), "the pseudonym key is kept");
    assert_eq!(again.pseudonym_key().unwrap().len(), 32, "32 random bytes");
    assert!(again.webhook_secret.as_deref().unwrap().starts_with("whsec_"));
    let text = std::fs::read_to_string(&path).unwrap();
    let key = state.add_key("ci").unwrap();
    assert!(!text.contains(&key), "a key never reaches the file");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn keys_and_tokens_are_checked_by_digest() {
    let mut state = State::default();
    let key = state.add_key("backend").unwrap();
    assert!(key.starts_with("of_") && key.len() == 51, "{key}");
    let front = state.add_key_with("front", Scope::Events).unwrap();
    let token = state.rotate_admin_token();
    assert!(token.starts_with("ofa_"));
    assert!(state.is_admin(&token));
    assert!(!state.is_admin(&key), "an API key is not the admin token");

    let mut keys = KeySet::from_lines(["external-key-0123456789abcdef"].into_iter()).unwrap();
    keys.extend_state(&state);
    // (case, presented, scope or None when refused)
    let cases = [
        ("a created key", key.as_str(), Some(Scope::Full)),
        ("an events key", front.as_str(), Some(Scope::Events)),
        ("an external key", "external-key-0123456789abcdef", Some(Scope::Full)),
        ("a wrong key", "of_000000000000000000000000000000000000000000000000", None),
        ("the admin token", token.as_str(), None),
        ("nothing", "", None),
    ];
    let mut failures = Vec::new();
    for (case, presented, want) in cases {
        if keys.scope_of(presented) != want || keys.matches(presented) != want.is_some() {
            failures.push(format!("{case}: want {want:?}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
    assert!(
        KeySet::from_lines(["short"].into_iter()).is_err(),
        "a short external key is refused"
    );
    let id = state.api_keys[0].id.clone();
    assert!(state.revoke(&id));
    assert!(!state.revoke(&id), "revoking twice says so");
}

#[test]
fn a_key_made_by_another_process_works_at_the_next_request() {
    let path = temp("live");
    let _ = std::fs::remove_file(&path);
    let mut live = LiveKeys::load(KeySet::default(), &path).unwrap();
    assert!(live.current().is_empty());
    let mut state = State::load(&path).unwrap();
    let key = state.add_key("cli").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(20));
    state.save(&path).unwrap();
    assert!(live.current().matches(&key), "the new key is read from the file");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_rotated_admin_token_applies_at_the_next_request() {
    let path = temp("admin");
    let _ = std::fs::remove_file(&path);
    let mut state = State::load(&path).unwrap();
    let old = state.rotate_admin_token();
    state.save(&path).unwrap();
    let mut live = LiveAdmin::load(&path);
    assert!(live.is_admin(&old));
    assert!(!live.is_admin("ofa_wrong"), "a wrong token is refused");
    std::thread::sleep(std::time::Duration::from_millis(20));
    let new = state.rotate_admin_token();
    state.save(&path).unwrap();
    assert!(!live.is_admin(&old), "the old token stops at once");
    assert!(live.is_admin(&new), "the new one works");
    let _ = std::fs::remove_file(&path);
}
