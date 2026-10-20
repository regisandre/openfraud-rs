//! The HTTP API: who may call it, what it answers, and the words it uses
//! when it refuses.
#![allow(clippy::type_complexity)]

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use openfraud::config::Config;
use openfraud::engine::Engine;
use openfraud::keys::{KeySet, LiveKeys, Scope};
use openfraud::server::{App, admin_router, api_router};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tower::ServiceExt;

const KEY: &str = "test-key-0123456789abcdefghij";

const CONFIG: &str = r#"
[server]
max_body_bytes = 2048

[safety]
require_replay = false

[compliance]
ground = "Terms, section 7"
redress = "Reply to the notice"
appeal_url = "https://app.example.com/appeal"

[workflows.signup]
events = ["account.created"]
review_at = 50
quarantine_at = 80

[[workflows.signup.rules]]
id = "signup_blocked_ip"
when = '"blocked_ips" in event.ip_lists'
decision = "quarantine"
reason = "A sign-up from a blocked address"

[[workflows.signup.rules]]
id = "signup_watch"
when = "true"
score = 1
mode = "shadow"
reason = "Watches every sign-up"
"#;

fn app_with(text: &str) -> (Arc<App>, PathBuf) {
    let dir = std::env::temp_dir().join(format!("openfraud-api-{}-{}", std::process::id(), openfraud::event::random_hex(4)));
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("openfraud.toml");
    std::fs::write(&config_path, text).unwrap();
    let config = Config::parse(text, &dir).unwrap();
    let state = dir.join("state.toml");
    let keys = LiveKeys::load(KeySet::from_lines([KEY].into_iter()).unwrap(), &state).unwrap();
    let engine = Engine::open(config, b"api-test-key-api-test-key-api-te".to_vec(), None).unwrap();
    (Arc::new(App::new(engine, keys, config_path, "whsec_AAAA".into())), dir)
}

fn app() -> (Arc<App>, PathBuf) {
    app_with(CONFIG)
}

async fn call_with(
    router: &Router,
    method: &str,
    path: &str,
    key: Option<&str>,
    content_type: Option<&str>,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> (u16, Value) {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(key) = key {
        req = req.header("authorization", format!("Bearer {key}"));
    }
    if let Some(ct) = content_type {
        req = req.header("content-type", ct);
    }
    for (name, value) in headers {
        req = req.header(*name, *value);
    }
    let response = router.clone().oneshot(req.body(Body::from(body)).unwrap()).await.unwrap();
    let status = response.status().as_u16();
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

async fn call(router: &Router, method: &str, path: &str, key: Option<&str>, content_type: Option<&str>, body: Vec<u8>) -> (u16, Value) {
    call_with(router, method, path, key, content_type, &[], body).await
}

#[tokio::test]
async fn a_refused_request_gets_the_error_envelope_and_a_true_reason() {
    let (app, _dir) = app();
    let api = api_router(app);
    let json_ct = Some("application/json");
    let ok_event = br#"{"type":"account.created"}"#.to_vec();
    // (case, method, path, key, content type, body, status, error type, in the message)
    let cases: Vec<(&str, &str, &str, bool, Option<&str>, Vec<u8>, u16, &str, &str)> = vec![
        (
            "no key",
            "POST",
            "/v1/decide",
            false,
            json_ct,
            ok_event.clone(),
            401,
            "unauthorized",
            "API key",
        ),
        (
            "no JSON content type",
            "POST",
            "/v1/events",
            true,
            None,
            ok_event.clone(),
            415,
            "unsupported_media",
            "application/json",
        ),
        (
            "not JSON",
            "POST",
            "/v1/events",
            true,
            json_ct,
            b"{".to_vec(),
            400,
            "bad_request",
            "JSON",
        ),
        (
            "an unknown field",
            "POST",
            "/v1/events",
            true,
            json_ct,
            br#"{"type":"account.created","colour":"red"}"#.to_vec(),
            400,
            "bad_request",
            "colour",
        ),
        (
            "a bad event type",
            "POST",
            "/v1/events",
            true,
            json_ct,
            br#"{"type":"Bad"}"#.to_vec(),
            400,
            "invalid_event",
            "type",
        ),
        (
            "a type outside the vocabulary",
            "POST",
            "/v1/decide",
            true,
            json_ct,
            br#"{"type":"trial.started"}"#.to_vec(),
            400,
            "invalid_event",
            "custom",
        ),
        (
            "a body too large",
            "POST",
            "/v1/events",
            true,
            json_ct,
            format!(r#"{{"type":"account.created","attrs":{{"x":"{}"}}}}"#, "a".repeat(3_000)).into_bytes(),
            413,
            "body_too_large",
            "2048",
        ),
        (
            "an unknown account",
            "GET",
            "/v1/actors/nobody",
            true,
            None,
            vec![],
            404,
            "not_found",
            "nobody",
        ),
        (
            "an unknown tenant",
            "GET",
            "/v1/tenants/nobody",
            true,
            None,
            vec![],
            404,
            "not_found",
            "nobody",
        ),
        (
            "an unknown case",
            "GET",
            "/v1/cases/999",
            true,
            None,
            vec![],
            404,
            "not_found",
            "999",
        ),
        (
            "an appeal on an unknown case",
            "POST",
            "/v1/cases/999/appeal",
            true,
            json_ct,
            br#"{"message":"hi"}"#.to_vec(),
            404,
            "not_found",
            "999",
        ),
        (
            "an unknown statement",
            "GET",
            "/v1/statements/st_nope",
            true,
            None,
            vec![],
            404,
            "not_found",
            "st_nope",
        ),
        (
            "a bad label",
            "POST",
            "/v1/actors/u1/label",
            true,
            json_ct,
            br#"{"label":"maybe"}"#.to_vec(),
            400,
            "bad_request",
            "maybe",
        ),
        (
            "an unknown list",
            "POST",
            "/v1/lists/nope/items",
            true,
            json_ct,
            br#"{"items":["1.2.3.4"]}"#.to_vec(),
            404,
            "not_found",
            "nope",
        ),
        (
            "a bad list item",
            "POST",
            "/v1/lists/blocked_ips/items",
            true,
            json_ct,
            br#"{"items":["999.1.1.1"]}"#.to_vec(),
            400,
            "bad_request",
            "999.1.1.1",
        ),
        (
            "too many events in a batch",
            "POST",
            "/v1/events/batch",
            true,
            json_ct,
            format!(r#"{{"events":[{}]}}"#, vec!["{}"; 101].join(",")).into_bytes(),
            400,
            "bad_request",
            "100",
        ),
        ("an unknown route", "GET", "/v1/nothing", true, None, vec![], 404, "not_found", ""),
    ];
    let mut failures = Vec::new();
    for (case, method, path, with_key, ct, body, status, kind, words) in cases {
        let (got, v) = call(&api, method, path, with_key.then_some(KEY), ct, body).await;
        let err_type = v["error"]["type"].as_str().unwrap_or_default();
        let message = v["error"]["message"].as_str().unwrap_or_default();
        if got != status || err_type != kind || !message.contains(words) {
            failures.push(format!("{case}: {got} {v}, want {status} {kind} with {words:?}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[tokio::test]
async fn decide_answers_with_reasons_actions_and_a_statement() {
    let (app, _dir) = app();
    let api = api_router(app.clone());
    let ct = Some("application/json");
    let ev = |actor: &str, ip: &str| {
        json!({"type": "account.created", "actor_id": actor, "ip": ip})
            .to_string()
            .into_bytes()
    };

    let (status, v) = call(&api, "POST", "/v1/decide", Some(KEY), ct, ev("u1", "192.0.2.1")).await;
    assert_eq!((status, v["decision"].as_str()), (200, Some("allow")), "{v}");
    assert!(v["took_us"].is_u64());
    assert_eq!(
        v["shadow"]["reasons"][0]["rule"], "signup_watch",
        "a shadow rule is reported apart: {v}"
    );
    assert_eq!(v["reasons"].as_array().map(Vec::len), Some(0));
    assert!(
        v["signals"].is_object() && v["scores"]["account_abuse"].is_number() && v["scores"]["bot"].is_number(),
        "the answer carries its signals and three scores: {v}"
    );

    let (status, v) = call(
        &api,
        "POST",
        "/v1/lists/blocked_ips/items",
        Some(KEY),
        ct,
        br#"{"items":["192.0.2.0/24"],"note":"abuse"}"#.to_vec(),
    )
    .await;
    assert_eq!((status, v["added"].as_u64()), (200, Some(1)), "{v}");

    let (_, dry) = call(&api, "POST", "/v1/decide?dry_run=true", Some(KEY), ct, ev("u2", "192.0.2.9")).await;
    assert_eq!(
        (dry["decision"].as_str(), dry["dry_run"].as_bool()),
        (Some("quarantine"), Some(true)),
        "a list item applies at once: {dry}"
    );
    let (status, _) = call(&api, "GET", "/v1/actors/u2", Some(KEY), None, vec![]).await;
    assert_eq!(status, 404, "a dry run stores no account");

    let key = [("idempotency-key", "signup-u2")];
    let (_, v) = call_with(&api, "POST", "/v1/decide", Some(KEY), ct, &key, ev("u2", "192.0.2.9")).await;
    assert_eq!(v["decision"], "quarantine");
    assert!(
        v["reasons"].as_array().unwrap().iter().any(|r| r["rule"] == "signup_blocked_ip"),
        "{v}"
    );
    assert_eq!(
        v["actions"][0],
        json!({"action": "quarantine", "target": "actor", "id": "u2"}),
        "{v}"
    );
    let case_id = v["case_id"].as_i64().expect("a case is opened");
    let (_, again) = call_with(&api, "POST", "/v1/decide", Some(KEY), ct, &key, ev("u2", "192.0.2.9")).await;
    assert_eq!(
        (again["duplicate"].as_bool(), again["case_id"].as_i64()),
        (Some(true), Some(case_id)),
        "a retry with the key gets the first answer"
    );

    let statement = v["statement_id"].as_str().expect("a statement of reasons");
    let (status, s) = call(&api, "GET", &format!("/v1/statements/{statement}"), Some(KEY), None, vec![]).await;
    assert_eq!(status, 200, "{s}");
    let s = &s["statement"];
    assert_eq!(s["restriction"]["decision"], "quarantine");
    assert_eq!(
        (s["ground"].as_str(), s["appeal_url"].as_str()),
        (Some("Terms, section 7"), Some("https://app.example.com/appeal"))
    );
    assert_eq!(s["automated_decision"], true);
    assert!(
        s["facts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f.as_str().is_some_and(|f| f.contains("blocked address"))),
        "{s}"
    );

    let (status, v) = call(&api, "GET", "/v1/actors/u2", Some(KEY), None, vec![]).await;
    assert_eq!(status, 200);
    assert_eq!(v["actor"]["status"], "quarantined");
    assert_eq!(v["recent"][0]["decision"], "quarantine");
    // Each recent event carries what the decision saw, for a person reviewing the account.
    assert!(v["recent"][0]["signals"].is_object(), "signals on a recent event: {v}");
    assert!(
        v["recent"][0]["scores"]["account_takeover"].is_number(),
        "scores on a recent event: {v}"
    );
    assert_eq!(v["open_case"], case_id);
    assert!(!v.to_string().contains("192.0.2.9"), "no raw IP address in an answer");

    let (status, v) = call(
        &api,
        "POST",
        &format!("/v1/cases/{case_id}/appeal"),
        Some(KEY),
        ct,
        br#"{"message":"I run a real venue"}"#.to_vec(),
    )
    .await;
    assert_eq!((status, v["case"]["status"].as_str()), (200, Some("appealed")), "{v}");

    let (status, v) = call(
        &api,
        "POST",
        &format!("/v1/cases/{case_id}/resolve"),
        Some(KEY),
        ct,
        br#"{"label":"false_positive","note":"a real venue"}"#.to_vec(),
    )
    .await;
    assert_eq!((status, v["subject"]["status"].as_str()), (200, Some("trusted")), "{v}");
    let (_, v) = call(&api, "GET", &format!("/v1/cases/{case_id}"), Some(KEY), None, vec![]).await;
    assert_eq!(v["case"]["label"], "false_positive");

    let batch = json!({"events": [{"type": "account.created", "actor_id": "b1"}, {"type": "Bad"}]})
        .to_string()
        .into_bytes();
    let (status, v) = call(&api, "POST", "/v1/events/batch", Some(KEY), ct, batch).await;
    assert_eq!(status, 200);
    assert_eq!(
        (v["results"][0]["accepted"].as_bool(), v["results"][1]["accepted"].as_bool()),
        (Some(true), Some(false)),
        "{v}"
    );

    let (status, v) = call(&api, "GET", "/health", None, None, vec![]).await;
    assert_eq!((status, v["status"].as_str()), (200, Some("ok")), "health needs no key");
}

#[tokio::test]
async fn an_account_can_be_exported_and_erased() {
    let (app, _dir) = app();
    let api = api_router(app.clone());
    let ct = Some("application/json");
    let ev = json!({"type": "account.created", "actor_id": "gone", "email": "someone@example.com", "ip": "203.0.113.4"})
        .to_string()
        .into_bytes();
    call(&api, "POST", "/v1/events", Some(KEY), ct, ev).await;
    let (status, v) = call(&api, "GET", "/v1/subjects/gone/export", Some(KEY), None, vec![]).await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["events"].as_array().map(Vec::len), Some(1));
    assert!(
        !v.to_string().contains("someone@example.com"),
        "the export holds pseudonyms, never a raw address"
    );
    let (status, v) = call(&api, "DELETE", "/v1/subjects/gone", Some(KEY), None, vec![]).await;
    assert_eq!(status, 200, "{v}");
    let (status, _) = call(&api, "GET", "/v1/actors/gone", Some(KEY), None, vec![]).await;
    assert_eq!(status, 404, "nothing is left");
}

#[tokio::test]
async fn an_events_key_sends_events_and_nothing_else() {
    let (app, dir) = app();
    let mut state = openfraud::keys::State::load(&dir.join("state.toml")).unwrap();
    let events_key = state.add_key_with("front", Scope::Events).unwrap();
    state.save(&dir.join("state.toml")).unwrap();
    let api = api_router(app);
    let json_ct = Some("application/json");
    let event = br#"{"type":"account.created","actor_id":"u1"}"#.to_vec();
    let status = br#"{"status":"trusted"}"#.to_vec();
    // (case, method, path, key, body, status)
    let cases: Vec<(&str, &str, &str, &str, Vec<u8>, u16)> = vec![
        ("decide", "POST", "/v1/decide", &events_key, event.clone(), 200),
        ("track", "POST", "/v1/events", &events_key, event.clone(), 200),
        ("trust an account", "POST", "/v1/actors/u1/status", &events_key, status.clone(), 403),
        (
            "label an account",
            "POST",
            "/v1/actors/u1/label",
            &events_key,
            br#"{"label":"legit"}"#.to_vec(),
            403,
        ),
        ("export an account", "GET", "/v1/subjects/u1/export", &events_key, vec![], 403),
        ("erase an account", "DELETE", "/v1/subjects/u1", &events_key, vec![], 403),
        ("read the lists", "GET", "/v1/lists", &events_key, vec![], 403),
        ("a full key acts", "POST", "/v1/actors/u1/status", KEY, status.clone(), 200),
    ];
    let mut failures = Vec::new();
    for (case, method, path, key, body, want) in cases {
        let ct = if body.is_empty() { None } else { json_ct };
        let (got, value) = call(&api, method, path, Some(key), ct, body).await;
        if got != want {
            failures.push(format!("{case}: got {got}, want {want}: {value}"));
        } else if want == 403 && value["error"]["type"] != "forbidden" {
            failures.push(format!("{case}: {value}"));
        }
    }
    // Which account an address belongs to is account data: an events key
    // never learns it from an answer, a full key does.
    let signup = br#"{"type":"account.created","actor_id":"owner_1","email":"owner@example.com"}"#.to_vec();
    call(&api, "POST", "/v1/events", Some(KEY), json_ct, signup).await;
    let attempt = |id: &str| format!(r#"{{"id":"{id}","type":"session.login_failed","email":"owner@example.com"}}"#).into_bytes();
    for (case, key, id, want) in [
        ("an events key", events_key.as_str(), "try_1", Value::Null),
        ("a full key", KEY, "try_2", json!("owner_1")),
    ] {
        let (_, value) = call(&api, "POST", "/v1/decide", Some(key), json_ct, attempt(id)).await;
        if value["matched_actor"] != want {
            failures.push(format!("{case}: matched_actor {}, want {want}", value["matched_actor"]));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[tokio::test]
async fn the_admin_interface_needs_the_admin_token() {
    let (app, dir) = app();
    let token = app.rotate_admin_token().unwrap();
    let admin = admin_router(app);
    let (status, _) = call(&admin, "GET", "/admin/api/overview", None, None, vec![]).await;
    assert_eq!(status, 401);
    let (status, _) = call(&admin, "GET", "/admin/api/overview", Some(KEY), None, vec![]).await;
    assert_eq!(status, 401, "an API key does not open the admin interface");
    let (status, v) = call(&admin, "GET", "/admin/api/overview", Some(&token), None, vec![]).await;
    assert_eq!(status, 200, "{v}");
    assert!(
        v["workflows"].as_array().is_some_and(|w| w.len() > 1),
        "the core workflows are listed too: {v}"
    );

    // A configuration with a mistake is refused and the file is untouched.
    let bad = json!({"text": "[workflows.x]\nevents = []\n"}).to_string().into_bytes();
    let (status, v) = call(&admin, "PUT", "/admin/api/config", Some(&token), Some("application/json"), bad).await;
    assert_eq!(status, 422, "{v}");
    assert!(v["error"]["problems"].as_array().is_some_and(|p| !p.is_empty()));
    assert_eq!(std::fs::read_to_string(Path::new(&dir).join("openfraud.toml")).unwrap(), CONFIG);

    // A good one is written and applied.
    let good_text = CONFIG.replace("quarantine_at = 80", "quarantine_at = 70");
    let good = json!({"text": good_text}).to_string().into_bytes();
    let (status, v) = call(&admin, "PUT", "/admin/api/config", Some(&token), Some("application/json"), good).await;
    assert_eq!(status, 200, "{v}");
    assert!(
        std::fs::read_to_string(Path::new(&dir).join("openfraud.toml"))
            .unwrap()
            .contains("quarantine_at = 70")
    );

    // The playground decides without storing.
    let test = json!({"event": {"type": "account.created", "actor_id": "t1"}})
        .to_string()
        .into_bytes();
    let (status, v) = call(&admin, "POST", "/admin/api/test", Some(&token), Some("application/json"), test).await;
    assert_eq!((status, v["dry_run"].as_bool()), (200, Some(true)), "{v}");

    let (status, v) = call(&admin, "GET", "/admin/api/rules", Some(&token), None, vec![]).await;
    assert_eq!(status, 200, "{v}");
    let watch = v["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "signup_watch")
        .cloned()
        .unwrap();
    assert_eq!(
        (watch["mode"].as_str(), watch["origin"].as_str()),
        (Some("shadow"), Some("config")),
        "{watch}"
    );
    // A screen can name the rule in its own words: the reason it gives when it fires.
    assert_eq!(watch["reason"].as_str(), Some("Watches every sign-up"), "{watch}");
}

#[tokio::test]
async fn a_rule_is_promoted_only_after_a_full_replay() {
    let text = CONFIG.replace("require_replay = false", "require_replay = true");
    let (app, dir) = app_with(&text);
    let token = app.rotate_admin_token().unwrap();
    let admin = admin_router(app.clone());
    let api = api_router(app.clone());
    let ct = Some("application/json");
    let (_, v) = call(
        &api,
        "POST",
        "/v1/decide",
        Some(KEY),
        ct,
        json!({"type": "account.created", "actor_id": "n1"}).to_string().into_bytes(),
    )
    .await;
    assert_eq!(v["shadow"]["reasons"][0]["rule"], "signup_watch");

    // The Rules page counts the stored shadow hit.
    let (status, v) = call(&admin, "GET", "/admin/api/rules", Some(&token), None, vec![]).await;
    assert_eq!(status, 200, "{v}");
    let watch = v["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "signup_watch")
        .cloned()
        .unwrap();
    assert_eq!(
        (watch["fired_30d"].as_u64(), watch["actors_30d"].as_u64()),
        (Some(1), Some(1)),
        "{watch}"
    );

    let (status, v) = call(&admin, "POST", "/admin/api/rules/signup_watch/promote", Some(&token), None, vec![]).await;
    assert_eq!(status, 400, "a few seconds of history is not a 30-day replay: {v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("30-day replay"), "{v}");
    assert!(
        !std::fs::read_to_string(dir.join("openfraud.toml"))
            .unwrap()
            .contains("[overrides.signup_watch]")
    );

    // History older than the window: the replay covers 30 days.
    let old = openfraud::event::now() - 31 * 86_400;
    call(
        &api,
        "POST",
        "/v1/events",
        Some(KEY),
        ct,
        json!({"type": "account.created", "actor_id": "n0", "at": old})
            .to_string()
            .into_bytes(),
    )
    .await;
    let (status, v) = call(&admin, "POST", "/admin/api/rules/signup_watch/promote", Some(&token), None, vec![]).await;
    assert_eq!(status, 200, "{v}");
    assert!(
        std::fs::read_to_string(dir.join("openfraud.toml"))
            .unwrap()
            .contains("[overrides.signup_watch]\nmode = \"act\"")
    );
    let (_, v) = call(
        &api,
        "POST",
        "/v1/decide",
        Some(KEY),
        ct,
        json!({"type": "account.created", "actor_id": "n2"}).to_string().into_bytes(),
    )
    .await;
    assert_eq!(v["reasons"][0]["rule"], "signup_watch", "the promoted rule acts: {v}");
}

#[tokio::test]
async fn a_rule_asked_to_act_by_hand_is_promoted_by_its_replay() {
    let text = format!(
        "{}\n[overrides.signup_watch]\nmode = \"act\"\n",
        CONFIG.replace("require_replay = false", "require_replay = true")
    );
    let (app, dir) = app_with(&text);
    let token = app.rotate_admin_token().unwrap();
    let admin = admin_router(app.clone());
    let api = api_router(app.clone());
    let ct = Some("application/json");
    let old = openfraud::event::now() - 31 * 86_400;
    call(
        &api,
        "POST",
        "/v1/events",
        Some(KEY),
        ct,
        json!({"type": "account.created", "actor_id": "h0", "at": old})
            .to_string()
            .into_bytes(),
    )
    .await;
    let (_, v) = call(
        &api,
        "POST",
        "/v1/decide",
        Some(KEY),
        ct,
        json!({"type": "account.created", "actor_id": "h1"}).to_string().into_bytes(),
    )
    .await;
    assert_eq!(
        v["shadow"]["reasons"][0]["pending_approval"], true,
        "asked to act, not yet approved: {v}"
    );
    let (status, v) = call(&admin, "POST", "/admin/api/rules/signup_watch/promote", Some(&token), None, vec![]).await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(
        std::fs::read_to_string(dir.join("openfraud.toml")).unwrap(),
        text,
        "the file already said so"
    );
    let (_, v) = call(
        &api,
        "POST",
        "/v1/decide",
        Some(KEY),
        ct,
        json!({"type": "account.created", "actor_id": "h2"}).to_string().into_bytes(),
    )
    .await;
    assert_eq!(v["reasons"][0]["rule"], "signup_watch", "{v}");
}

#[tokio::test]
async fn a_rule_is_snoozed_for_one_account_after_a_false_positive() {
    let (app, _dir) = app();
    let api = api_router(app.clone());
    let ct = Some("application/json");
    let body = |v: Value| v.to_string().into_bytes();
    let snooze = |rule: &str, period: &str| body(json!({"rule": rule, "for": period, "note": "a false positive"}));

    let (status, v) = call(&api, "POST", "/v1/actors/fp/snoozes", Some(KEY), ct, snooze("signup_watch", "30d")).await;
    assert_eq!((status, v["snoozes"][0]["rule"].as_str()), (200, Some("signup_watch")), "{v}");
    let (_, v) = call(
        &api,
        "POST",
        "/v1/decide",
        Some(KEY),
        ct,
        body(json!({"type": "account.created", "actor_id": "fp"})),
    )
    .await;
    assert_eq!(v["snoozed"], json!(["signup_watch"]), "the answer names the snoozed rule: {v}");
    let (_, v) = call(&api, "GET", "/v1/actors/fp", Some(KEY), None, vec![]).await;
    assert_eq!(v["snoozes"].as_array().map(Vec::len), Some(1), "the account shows its snoozes: {v}");

    // (case, path, body, status)
    let refused: [(&str, &str, Vec<u8>, u16); 5] = [
        ("an unknown rule", "/v1/actors/fp/snoozes", snooze("nope", "30d"), 404),
        ("a built-in rule", "/v1/actors/fp/snoozes", snooze("actor_quarantined", "30d"), 400),
        // An administrator's block is lifted in its list, never snoozed.
        ("a block", "/v1/actors/fp/snoozes", snooze("core_blocked_actor", "30d"), 400),
        (
            "a period that is not one",
            "/v1/actors/fp/snoozes",
            snooze("signup_watch", "soon"),
            400,
        ),
        ("a period over a year", "/v1/actors/fp/snoozes", snooze("signup_watch", "400d"), 400),
    ];
    let mut failures = Vec::new();
    for (case, path, b, want) in refused {
        let (status, v) = call(&api, "POST", path, Some(KEY), ct, b).await;
        if status != want {
            failures.push(format!("{case}: {status} {v}"));
        }
    }

    let (_, v) = call(&api, "DELETE", "/v1/actors/fp/snoozes/signup_watch", Some(KEY), None, vec![]).await;
    assert_eq!(v["lifted"], true, "{v}");
    let (_, v) = call(&api, "DELETE", "/v1/actors/fp/snoozes/signup_watch", Some(KEY), None, vec![]).await;
    assert_eq!(v["lifted"], false, "lifting twice says so: {v}");

    // Resolving a case as a false positive can snooze the rules that opened it.
    call(
        &api,
        "POST",
        "/v1/lists/blocked_ips/items",
        Some(KEY),
        ct,
        body(json!({"items": ["203.0.113.9"]})),
    )
    .await;
    let ev = |id: &str| body(json!({"id": id, "type": "account.created", "actor_id": "fp2", "ip": "203.0.113.9"}));
    let (_, v) = call(&api, "POST", "/v1/decide", Some(KEY), ct, ev("e1")).await;
    assert_eq!(v["decision"], "quarantine", "{v}");
    let case = v["case_id"].as_i64().expect("a case");
    let (status, v) = call(
        &api,
        "POST",
        &format!("/v1/cases/{case}/resolve"),
        Some(KEY),
        ct,
        body(json!({"label": "false_positive", "note": "a shared office address", "snooze": "30d"})),
    )
    .await;
    assert_eq!(status, 200, "{v}");
    let snoozed: Vec<&str> = v["snoozed"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
    if !snoozed.contains(&"signup_blocked_ip") {
        failures.push(format!("the case's rules are snoozed: {v}"));
    }
    if snoozed.iter().any(|rule| rule.starts_with("core_blocked_")) {
        failures.push(format!("a block among the case's rules stays: {v}"));
    }
    let (_, v) = call(&api, "POST", "/v1/decide", Some(KEY), ct, ev("e2")).await;
    if v["decision"] == "quarantine" {
        failures.push(format!("the same address no longer quarantines this account: {v}"));
    }
    let (status, _) = call(
        &api,
        "POST",
        &format!("/v1/cases/{case}/resolve"),
        Some(KEY),
        ct,
        body(json!({"label": "fraud", "snooze": "30d"})),
    )
    .await;
    if status != 400 {
        failures.push(format!("a fraud verdict snoozes nothing: {status}"));
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[tokio::test]
async fn a_pinned_admin_token_is_not_rotated_from_the_interface() {
    let (app, _dir) = app();
    let token = "ofa_given-by-the-host-0123456789abcdef";
    app.pin_admin_token(token).unwrap();
    let admin = admin_router(app);
    let (status, v) = call(&admin, "PUT", "/admin/api/rotate", Some(token), None, vec![]).await;
    assert_eq!(status, 409, "{v}");
    assert_eq!(v["error"]["type"], "conflict", "{v}");
    let (status, v) = call(&admin, "GET", "/admin/api/overview", Some(token), None, vec![]).await;
    assert_eq!(status, 200, "the pinned token still opens the interface: {v}");
}

#[tokio::test]
async fn a_rules_hits_are_read_for_review_newest_first_and_pseudonymized() {
    let (app, _dir) = app_with(CONFIG);
    let token = app.rotate_admin_token().unwrap();
    let admin = admin_router(app.clone());
    let api = api_router(app.clone());
    let ct = Some("application/json");
    for (actor, email) in [("h1", "first@example.com"), ("h2", "second@example.com")] {
        let event = json!({"type": "account.created", "actor_id": actor, "email": email, "ip": "203.0.113.9"});
        let (status, v) = call(&api, "POST", "/v1/decide", Some(KEY), ct, event.to_string().into_bytes()).await;
        assert_eq!(status, 200, "{v}");
    }

    // (case, path, status, the accounts in order)
    let cases: Vec<(&str, &str, u16, Vec<&str>)> = vec![
        (
            "every account the rule hit, newest first",
            "/admin/api/rules/signup_watch/hits",
            200,
            vec!["h2", "h1"],
        ),
        ("a limit", "/admin/api/rules/signup_watch/hits?limit=1", 200, vec!["h2"]),
        (
            "a window that ends before the hits holds nothing more than the window",
            "/admin/api/rules/signup_watch/hits?days=1",
            200,
            vec!["h2", "h1"],
        ),
        ("a rule that is not there", "/admin/api/rules/nope/hits", 404, vec![]),
        ("a limit over 20", "/admin/api/rules/signup_watch/hits?limit=21", 400, vec![]),
        ("a window over 366 days", "/admin/api/rules/signup_watch/hits?days=367", 400, vec![]),
    ];
    let mut failures = Vec::new();
    for (case, path, want_status, want_accounts) in cases {
        let (status, v) = call(&admin, "GET", path, Some(&token), None, vec![]).await;
        if status != want_status {
            failures.push(format!("{case}: {status} {v}"));
            continue;
        }
        if status != 200 {
            continue;
        }
        let accounts: Vec<&str> = v["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|a| a["actor"].as_str())
            .collect();
        if accounts != want_accounts {
            failures.push(format!("{case}: accounts {accounts:?}, want {want_accounts:?}"));
        }
        let first = &v["accounts"][0];
        if v["rule"] != "signup_watch" || v["reason"] != "Watches every sign-up" || first["events"][0]["type"] != "account.created" {
            failures.push(format!("{case}: the rule, its reason or the timeline: {v}"));
        }
        // A reviewer, a person or a model, reads the timeline as the AI assistant does: no raw email or address.
        let text = v.to_string();
        if text.contains("second@example.com") || text.contains("203.0.113.9") {
            failures.push(format!("{case}: a raw email or address: {text}"));
        }
    }
    let (_, v) = call(&admin, "GET", "/admin/api/rules", Some(&token), None, vec![]).await;
    let watch = v["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "signup_watch")
        .cloned()
        .unwrap();
    // What a rule decides when it fires, so a host can tell a rule that only reviews from one that blocks.
    if watch.get("decision").is_none() || watch["score"] != 1 {
        failures.push(format!("the rule list says what a rule decides: {watch}"));
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

#[tokio::test]
async fn list_items_are_added_archived_restored_and_exported_over_the_api() {
    let text = format!("{CONFIG}\n[lists.trusted_pairs]\nkind = \"value\"\nkey = \"actor\"\nsecond = \"device\"\nexpire = \"14d\"\n");
    let (app, _) = app_with(&text);
    let router = api_router(app.clone());
    let json_ct = Some("application/json");
    let body = |v: Value| v.to_string().into_bytes();
    let mut failures = Vec::new();

    let (status, lists) = call(&router, "GET", "/v1/lists", Some(KEY), None, vec![]).await;
    let pairs = lists["lists"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["name"] == "trusted_pairs")
        .cloned();
    if status != 200
        || pairs.as_ref().map(|l| (l["key"].clone(), l["second"].clone(), l["expire"].clone()))
            != Some((json!("actor"), json!("device"), json!("14d")))
    {
        failures.push(format!("a list says what its items are: {lists}"));
    }
    let (status, added) = call(
        &router,
        "POST",
        "/v1/lists/trusted_pairs/items",
        Some(KEY),
        json_ct,
        body(json!({"items": [{"value": "u1", "second": "device-1"}], "note": "verified by email"})),
    )
    .await;
    if (status, added["added"].clone()) != (200, json!(1)) {
        failures.push(format!("a pair is added: {status} {added}"));
    }
    let (status, plain) = call(
        &router,
        "POST",
        "/v1/lists/trusted_pairs/items",
        Some(KEY),
        json_ct,
        body(json!({"items": ["u2"]})),
    )
    .await;
    if status != 400 {
        failures.push(format!("a pair list refuses a single value: {status} {plain}"));
    }
    let (_, listed) = call(&router, "GET", "/v1/lists/trusted_pairs/items", Some(KEY), None, vec![]).await;
    let entry = listed["entries"][0].clone();
    if entry["value"] != "u1" || entry["second"].as_str().is_none_or(|d| d == "device-1") || entry["note"] != "verified by email" {
        failures.push(format!("the entries show the pair as stored: {listed}"));
    }
    let item = json!({"items": [{"value": "u1", "second": entry["second"]}]});
    let (status, archived) = call(
        &router,
        "POST",
        "/v1/lists/trusted_pairs/items/archive",
        Some(KEY),
        json_ct,
        body(item.clone()),
    )
    .await;
    if (status, archived["archived"].clone()) != (200, json!(1)) {
        failures.push(format!("an item is archived: {status} {archived}"));
    }
    let (_, active) = call(&router, "GET", "/v1/lists/trusted_pairs/items", Some(KEY), None, vec![]).await;
    let (_, all) = call(
        &router,
        "GET",
        "/v1/lists/trusted_pairs/items?archived=true",
        Some(KEY),
        None,
        vec![],
    )
    .await;
    if active["entries"].as_array().is_none_or(|e| !e.is_empty()) || all["entries"].as_array().is_none_or(|e| e.len() != 1) {
        failures.push(format!("archived items are listed only when asked: {active} {all}"));
    }
    let (status, back) = call(
        &router,
        "POST",
        "/v1/lists/trusted_pairs/items/unarchive",
        Some(KEY),
        json_ct,
        body(item),
    )
    .await;
    if (status, back["unarchived"].clone()) != (200, json!(1)) {
        failures.push(format!("an item is restored: {status} {back}"));
    }
    let request = axum::http::Request::builder()
        .method("GET")
        .uri("/v1/lists/trusted_pairs/export")
        .header("authorization", format!("Bearer {KEY}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let csv = String::from_utf8(to_bytes(response.into_body(), 1 << 20).await.unwrap().to_vec()).unwrap();
    if !content_type.starts_with("text/csv") || !csv.contains("\nu1,") {
        failures.push(format!("a list is exported as CSV: {content_type} {csv}"));
    }
    // A cell a spreadsheet would run as a formula is quoted and defused.
    for value in ["=HYPERLINK(\"http://x\")", "+1", "-1", "@SUM(A1)"] {
        call(
            &router,
            "POST",
            "/v1/lists/trusted_pairs/items",
            Some(KEY),
            json_ct,
            body(json!({"items": [{"value": value, "second": "d"}], "note": value})),
        )
        .await;
    }
    let request = axum::http::Request::builder()
        .method("GET")
        .uri("/v1/lists/trusted_pairs/export")
        .header("authorization", format!("Bearer {KEY}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let csv = String::from_utf8(to_bytes(response.into_body(), 1 << 20).await.unwrap().to_vec()).unwrap();
    for line in csv.lines().skip(1) {
        for cell in line.split(',') {
            let bare = cell.trim_start_matches('"');
            if bare.starts_with(['=', '+', '-', '@']) {
                failures.push(format!("a formula reaches the export: {line}"));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[tokio::test]
async fn an_address_is_looked_up_alone_or_in_a_batch() {
    let (app, _) = app();
    app.engine.add_list_item("tor_exits", "203.0.113.0/24", "admin", "").unwrap();
    let router = api_router(app.clone());
    let mut failures = Vec::new();
    let (status, one) = call(&router, "GET", "/v1/ips/203.0.113.5", Some(KEY), None, vec![]).await;
    if status != 200 || one["address"] != "203.0.113.5" || one["type"] != "ipv4" || one["lists"] != json!(["tor_exits"]) {
        failures.push(format!("one address: {status} {one}"));
    }
    let (status, bad) = call(&router, "GET", "/v1/ips/not-an-ip", Some(KEY), None, vec![]).await;
    if status != 400 {
        failures.push(format!("not an address: {status} {bad}"));
    }
    let body = json!({"ips": ["203.0.113.5", "2001:db8::1", "203.0.113.5", "nope"]})
        .to_string()
        .into_bytes();
    let (status, many) = call(&router, "POST", "/v1/ips/query", Some(KEY), Some("application/json"), body).await;
    if status != 200 || many["meta"] != json!({"total": 4, "valid": 2}) || many["results"].as_array().map(Vec::len) != Some(2) {
        failures.push(format!("a batch: {status} {many}"));
    }
    let too_many = json!({"ips": vec!["192.0.2.1"; 1_001]}).to_string().into_bytes();
    let (status, _) = call(&router, "POST", "/v1/ips/query", Some(KEY), Some("application/json"), too_many).await;
    if status != 400 && status != 413 {
        failures.push(format!("more than 1,000 addresses: {status}"));
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[tokio::test]
async fn stored_events_are_filtered_and_grouped_from_the_admin_interface() {
    let (app, _) = app();
    let token = app.rotate_admin_token().unwrap();
    let now = openfraud::event::now();
    let send = |v: Value| {
        let raw: openfraud::event::RawEvent = serde_json::from_value(v).unwrap();
        app.engine.process(raw, openfraud::engine::Options::default()).unwrap();
    };
    send(json!({"type": "account.created", "actor_id": "q1", "country": "BE", "at": now - 300, "attrs": {"plan": "trial", "amount": 10}}));
    send(json!({"type": "account.created", "actor_id": "q2", "country": "FR", "at": now - 200, "attrs": {"plan": "pro", "amount": 30}}));
    send(
        json!({"type": "account.created", "actor_id": "q3", "country": "FR", "at": now - 100, "user_agent": "curl/8.0", "attrs": {"plan": "trial", "amount": 50}}),
    );
    send(json!({"type": "session.login", "actor_id": "q1", "country": "BE", "at": now - 50}));
    let admin = admin_router(app.clone());
    let post = |path: &'static str, body: Value| {
        let admin = admin.clone();
        let token = token.clone();
        async move {
            call(
                &admin,
                "POST",
                path,
                Some(&token),
                Some("application/json"),
                body.to_string().into_bytes(),
            )
            .await
        }
    };
    let since = now - 3_600;
    // (case, query, how many events)
    let cases: Vec<(&str, Value, u64)> = vec![
        (
            "one type",
            json!({"from": since, "filters": [{"field": "type", "op": "eq", "value": "account.created"}]}),
            3,
        ),
        (
            "an attribute",
            json!({"from": since, "filters": [{"field": "attrs.plan", "op": "eq", "value": "trial"}]}),
            2,
        ),
        (
            "one of several values",
            json!({"from": since, "filters": [{"field": "country", "op": "in", "value": ["FR", "DE"]}]}),
            2,
        ),
        (
            "a range",
            json!({"from": since, "filters": [{"field": "attrs.amount", "op": "range", "value": {"gte": 20, "lte": 40}}]}),
            1,
        ),
        (
            "a signal",
            json!({"from": since, "filters": [{"field": "signals", "op": "contains", "value": "http_client_library"}]}),
            1,
        ),
        (
            "a fired rule",
            json!({"from": since, "filters": [{"field": "rules", "op": "contains", "value": "signup_watch"}]}),
            3,
        ),
        (
            "either of two groups",
            json!({"from": since, "any": [[{"field": "country", "op": "eq", "value": "BE"}], [{"field": "attrs.plan", "op": "eq", "value": "pro"}]]}),
            3,
        ),
        (
            "a field that exists",
            json!({"from": since, "filters": [{"field": "agent.os", "op": "exists"}]}),
            1,
        ),
        ("nothing before the window", json!({"from": now - 120}), 2),
    ];
    let mut failures = Vec::new();
    for (case, query, want) in cases {
        let (status, v) = post("/admin/api/events/query", query).await;
        if status != 200 || v["count"] != json!(want) {
            failures.push(format!("{case}: {status} {v}"));
        }
    }
    let (status, v) = post(
        "/admin/api/events/query",
        json!({"from": since, "filters": [{"field": "type", "op": "eq", "value": "account.created"}], "limit": 2}),
    )
    .await;
    if status != 200 || v["events"].as_array().map(Vec::len) != Some(2) || v["events"][0]["actor"] != "q3" {
        failures.push(format!("the newest records first, up to the limit: {v}"));
    }
    let (status, g) = post(
        "/admin/api/events/group",
        json!({"from": since, "group_by": ["type"], "columns": [{"op": "count"}, {"op": "count_distinct", "field": "actor"}, {"op": "sum", "field": "attrs.amount"}]}),
    )
    .await;
    let created = g["groups"]
        .as_array()
        .and_then(|rows| rows.iter().find(|r| r["keys"][0] == "account.created").cloned());
    if status != 200 || created.as_ref().map(|r| r["values"].clone()) != Some(json!([3, 3, 90])) {
        failures.push(format!("grouped by type: {status} {g}"));
    }
    // (case, query, words in the refusal)
    let refused: Vec<(&str, &'static str, Value, &str)> = vec![
        (
            "an unknown field",
            "/admin/api/events/query",
            json!({"from": since, "filters": [{"field": "secret';--", "op": "eq", "value": 1}]}),
            "field",
        ),
        (
            "an unknown operator",
            "/admin/api/events/query",
            json!({"from": since, "filters": [{"field": "type", "op": "like", "value": "%"}]}),
            "op",
        ),
        ("a window over a year", "/admin/api/events/query", json!({"from": 0}), "366"),
        (
            "four group keys",
            "/admin/api/events/group",
            json!({"from": since, "group_by": ["type", "actor", "country", "tenant"]}),
            "group_by",
        ),
    ];
    for (case, path, query, words) in refused {
        let (status, v) = post(path, query).await;
        if status != 400 || !v["error"]["message"].as_str().unwrap_or("").contains(words) {
            failures.push(format!("{case}: {status} {v}"));
        }
    }
    let (status, schema) = call(&admin, "GET", "/admin/api/events/schema", Some(&token), None, vec![]).await;
    if status != 200 || !schema["fields"].as_array().is_some_and(|f| f.iter().any(|x| x == "attrs.<name>")) {
        failures.push(format!("the schema lists the fields: {schema}"));
    }
    let (_, overview) = call(&admin, "GET", "/admin/api/overview", Some(&token), None, vec![]).await;
    let stats = &overview["stats"];
    if stats["signups_7d"] != json!(3) || stats["signups_prev_7d"] != json!(0) || stats["logins_7d"] != json!(1) {
        failures.push(format!("the overview counts sign-ups and logins against the week before: {stats}"));
    }
    if !stats["top_rules_7d"]
        .as_array()
        .is_some_and(|r| r.iter().any(|x| x["rule"] == "signup_watch" && x["count"] == 3))
    {
        failures.push(format!("the overview names the rules that fired most: {stats}"));
    }
    if !stats["top_signals_7d"]
        .as_array()
        .is_some_and(|r| r.iter().any(|x| x["signal"] == "http_client_library"))
    {
        failures.push(format!("the overview names the signals seen most: {stats}"));
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[tokio::test]
async fn an_account_page_shows_its_devices_and_the_lists_that_hold_it() {
    let text = format!("{CONFIG}\n[lists.vip]\nkind = \"value\"\nkey = \"actor\"\n");
    let (app, _) = app_with(&text);
    let send = |v: Value| {
        let raw: openfraud::event::RawEvent = serde_json::from_value(v).unwrap();
        app.engine.process(raw, openfraud::engine::Options::default()).unwrap();
    };
    send(json!({"type": "session.login", "actor_id": "d1", "device": "phone", "at": 1_000}));
    send(json!({"type": "session.login", "actor_id": "d1", "device": "laptop", "at": 2_000}));
    app.engine
        .add_list_entry("trusted_devices", "d1", Some("laptop"), None, "admin", "")
        .unwrap();
    app.engine.add_list_entry("vip", "d1", None, None, "admin", "").unwrap();
    let router = api_router(app.clone());
    let (status, v) = call(&router, "GET", "/v1/actors/d1", Some(KEY), None, vec![]).await;
    let mut failures = Vec::new();
    let devices = v["devices"].as_array().cloned().unwrap_or_default();
    if status != 200 || devices.len() != 2 || devices.iter().filter(|d| d["trusted"] == true).count() != 1 {
        failures.push(format!("two devices, one trusted: {v}"));
    }
    if devices.iter().any(|d| d["device"] == "phone" || d["device"] == "laptop") {
        failures.push("devices are shown as pseudonyms".into());
    }
    let lists = v["lists"].as_array().cloned().unwrap_or_default();
    if !lists.contains(&json!("vip")) || !lists.contains(&json!("trusted_devices")) {
        failures.push(format!("the lists that hold the account: {v}"));
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
