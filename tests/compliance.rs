//! Compliance: a statement of reasons for every automatic restriction,
//! export and erasure of an account, retention, and the audit log.

use openfraud::config::{Config, Decision};
use openfraud::engine::{Engine, Label, Options, Outcome};
use openfraud::store::SubjectKind;
use serde_json::{Value, json};
use std::path::Path;

const CONFIG: &str = r#"
[safety]
require_replay = false

[server]
retention_days = 30

[compliance]
ground = "Terms of service, section 7"
redress = "Reply to the notice"
appeal_url = "https://app.example.com/appeal"

[workflows.payouts]
events = ["payout.requested"]

[[workflows.payouts.rules]]
id = "new_seller"
when = "actor.age < 86400"
decision = "hold"
hold_for = "7d"
reason = "A first payout within a day of sign-up"

[[workflows.payouts.rules]]
id = "over_limit"
when = "has(event.attrs.over)"
decision = "block"
reason = "Over the payout limit"

[[workflows.payouts.rules]]
id = "flagged_destination"
when = "has(event.attrs.flagged)"
decision = "quarantine"
actions = ["suspend_feature:payouts"]
reason = "A payout to a destination used by a fraudulent account"
"#;

fn engine_with(text: &str) -> Engine {
    Engine::open(
        Config::parse(text, Path::new(".")).unwrap(),
        b"compliance-key-compliance-key-co".to_vec(),
        None,
    )
    .unwrap()
}

fn send(e: &Engine, v: Value) -> Outcome {
    e.process(serde_json::from_value(v).unwrap(), Options::default()).unwrap()
}

#[test]
fn an_automatic_restriction_comes_with_a_statement_of_reasons() {
    let e = engine_with(CONFIG);
    // (case, event, restriction decision, scope words, duration words)
    let cases: Vec<(&str, Value, &str, &str, &str)> = vec![
        (
            "a hold for a set time",
            json!({"type": "payout.requested", "actor_id": "s1", "at": 1_000}),
            "hold",
            "the action asked for",
            "until 1970-01-08",
        ),
        (
            "a quarantine with a feature suspended",
            json!({"type": "payout.requested", "actor_id": "s2", "at": 1_000, "attrs": {"flagged": true}}),
            "quarantine",
            "the feature `payouts`",
            "until a person reviews it",
        ),
    ];
    let mut failures = Vec::new();
    for (case, event, decision, scope, duration) in cases {
        let out = send(&e, event);
        let Some(id) = out.statement_id.clone() else {
            failures.push(format!("{case}: no statement"));
            continue;
        };
        let s = e.statement(&id).unwrap().unwrap();
        let r = &s["restriction"];
        let scope_ok = r["scope"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x.as_str().is_some_and(|x| x.contains(scope)));
        let facts_ok = s["facts"].as_array().is_some_and(|f| !f.is_empty());
        if r["decision"] != decision
            || !scope_ok
            || !r["duration"].as_str().unwrap().contains(duration)
            || !facts_ok
            || s["automated_decision"] != true
            || s["ground"] != "Terms of service, section 7"
            || s["redress"] != "Reply to the notice"
            || s["appeal_url"] != "https://app.example.com/appeal"
            || s["case_id"] != json!(out.case_id)
        {
            failures.push(format!("{case}: {s}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");

    // A plain block, with no action to take, is a restriction too.
    let blocked = send(
        &e,
        json!({"type": "payout.requested", "actor_id": "s4", "at": 1_000, "attrs": {"over": true}}),
    );
    assert_eq!(blocked.decision, Decision::Block);
    assert!(blocked.statement_id.is_some(), "a block comes with a statement");

    // A person's restriction has one too, marked as not automated.
    let st = e.with_store(|s| s.subject_statements(SubjectKind::Actor, "s3")).unwrap();
    assert!(st.is_empty());
    e.label("s3", Label::Fraud, "admin", "chargebacks").unwrap();
    let st = e.with_store(|s| s.subject_statements(SubjectKind::Actor, "s3")).unwrap();
    assert_eq!(st.len(), 1);
    assert_eq!(st[0]["automated_decision"], false);
}

#[test]
fn an_account_is_exported_then_erased_with_no_trace_left() {
    let e = engine_with(CONFIG);
    send(
        &e,
        json!({"type": "account.created", "actor_id": "x", "email": "Person@Example.com", "ip": "203.0.113.7", "attrs": {"card_fingerprint": "fp_x"}}),
    );
    send(
        &e,
        json!({"type": "account.created", "actor_id": "y", "attrs": {"card_fingerprint": "fp_x"}}),
    );
    send(&e, json!({"type": "payout.requested", "actor_id": "x", "at": 2_000}));
    let export = e.export("x").unwrap();
    assert_eq!(export["events"].as_array().unwrap().len(), 2);
    assert!(!export["statements"].as_array().unwrap().is_empty());
    let text = export.to_string();
    assert!(
        !text.to_lowercase().contains("person@example.com") && !text.contains("203.0.113.7"),
        "pseudonyms only: {text}"
    );

    e.set_status(
        SubjectKind::Actor,
        "x",
        openfraud::config::Status::Review,
        None,
        "admin",
        "x asked for a refund",
    )
    .unwrap();
    // Rows whose target merely shares the erased id: a rule, a list, a key,
    // a tenant. The erasure leaves them as they are.
    let unrelated = [
        ("rule_approved", "replay report"),
        ("list_add", "203.0.113.9"),
        ("key_created", ""),
        ("set_status", "tenant suspended trust 0 "),
    ];
    for (action, detail) in unrelated {
        e.with_store(|s| s.audit(1_500, "admin", action, "x", detail)).unwrap();
    }
    let removed = e.erase("x", "admin").unwrap();
    assert!(removed > 0);
    let after = e.export("x").unwrap();
    assert_eq!(
        (after["actor"].clone(), after["events"].as_array().unwrap().len()),
        (Value::Null, 0),
        "{after}"
    );
    assert!(after["identifiers"].as_array().unwrap().is_empty());
    assert_eq!(e.cluster("y").unwrap()["size"], 1, "the cluster no longer holds x");
    let audit = e.with_store(|s| s.audit_log(20)).unwrap();
    assert!(audit.iter().any(|a| a.action == "erase"), "the erasure is audited: {audit:?}");
    assert!(
        !audit
            .iter()
            .any(|a| a.target == "x" && a.detail.as_deref().unwrap_or("").contains("refund")),
        "the actor's own rows are under a marker: {audit:?}"
    );
    for (action, detail) in unrelated {
        assert!(
            audit
                .iter()
                .any(|a| a.action == action && a.target == "x" && a.detail.as_deref().unwrap_or("") == detail),
            "{action} about another kind of target is kept: {audit:?}"
        );
    }
}

#[test]
fn a_fraud_flag_survives_erasure_only_when_configured() {
    for keep in [false, true] {
        let text = CONFIG.replace("[compliance]", &format!("[compliance]\nkeep_fraud_flag_after_erasure = {keep}"));
        let e = engine_with(&text);
        send(
            &e,
            json!({"type": "payment.method_added", "actor_id": "bad", "attrs": {"card_fingerprint": "fp_bad"}}),
        );
        e.label("bad", Label::Fraud, "admin", "").unwrap();
        e.erase("bad", "admin").unwrap();
        let back = send(
            &e,
            json!({"type": "payment.method_added", "actor_id": "new", "attrs": {"card_fingerprint": "fp_bad"}}),
        );
        let flagged = back.rules.is_empty()
            && e.user_links("new")
                .unwrap()
                .iter()
                .any(|(k, _, f)| k == "card_fingerprint" && *f > 0);
        assert_eq!(flagged, keep, "keep_fraud_flag_after_erasure = {keep}");
    }
}

#[test]
fn events_past_retention_are_deleted() {
    let e = engine_with(CONFIG);
    send(&e, json!({"type": "account.created", "actor_id": "old", "at": 1_000}));
    send(&e, json!({"type": "account.created", "actor_id": "new", "at": 40 * 86_400}));
    e.maintain(41 * 86_400).unwrap();
    assert_eq!(e.with_store(|s| s.event_count()).unwrap(), 1, "only the event inside 30 days stays");
    assert_eq!(e.user_events("new", 10).unwrap().len(), 1);
    // (case, actor, kept)
    let cases = [
        ("an account inactive past retention is forgotten", "old", false),
        ("an active account stays", "new", true),
    ];
    for (case, actor, kept) in cases {
        let found = e.user(actor).unwrap().is_some();
        let linked = e.cluster(actor).unwrap()["root"].is_string();
        assert_eq!((found, linked), (kept, kept), "{case}");
    }
}

#[test]
fn a_restricted_or_labelled_account_outlives_retention() {
    let e = engine_with(CONFIG);
    // (actor, event, how it ends up)
    send(
        &e,
        json!({"type": "payout.requested", "actor_id": "held", "at": 1_000, "attrs": {"flagged": true}}),
    );
    send(&e, json!({"type": "account.created", "actor_id": "fraud", "at": 1_000}));
    e.label("fraud", Label::Fraud, "admin", "").unwrap();
    send(&e, json!({"type": "account.created", "actor_id": "plain", "at": 1_000}));
    e.maintain(100 * 86_400).unwrap();
    let kept: Vec<bool> = ["held", "fraud", "plain"].iter().map(|a| e.user(a).unwrap().is_some()).collect();
    assert_eq!(
        kept,
        vec![true, true, false],
        "quarantined and labelled accounts are kept to recognize a return"
    );
}
