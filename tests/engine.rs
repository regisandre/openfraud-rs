//! The engine end to end on a small configuration: events in, decisions
//! out, and what it remembers between events (counters, statuses, trust,
//! cases). Tenants, the link graph, account takeover, the safety brake and
//! compliance have their own files.
#![allow(clippy::type_complexity)]

use openfraud::config::{Config, Decision, Mode, Status};
use openfraud::engine::{Engine, Label, Options, Outcome};
use openfraud::event::RawEvent;
use serde_json::{Value, json};
use std::path::Path;

const CONFIG: &str = r#"
[safety]
require_replay = false

[privacy]
id_attrs = ["card_fingerprint"]

[lists.blocked_ips]
kind = "ip"
items = ["198.51.100.0/24"]

[counters.accounts_per_ip_1h]
events = ["account.created"]
by = "ip"
distinct = "actor"
window = "1h"

[workflows.signup]
events = ["account.created"]
step_up_at = 30
review_at = 50
quarantine_at = 80

[[workflows.signup.rules]]
id = "ip_burst"
when = "counters.accounts_per_ip_1h > 2"
score = 60
reason = "Many accounts from one IP"

[[workflows.signup.rules]]
id = "broken_rule"
when = "event.attrs.missing == 1"
score = 10
reason = "Reads a missing attribute"

[[workflows.signup.rules]]
id = "farm"
when = "has(event.attrs.farm) && event.attrs.farm"
score = 100
reason = "A sign-up farm"

[workflows.cards]
events = ["payment.method_added"]
review_at = 50
hold_at = 70
block_at = 80

[[workflows.cards.rules]]
id = "card_shared"
when = "links.card_fingerprint.users > 0"
score = 50
reason = "A card on another account"

[[workflows.cards.rules]]
id = "card_flagged"
when = "links.card_fingerprint.flagged > 0"
decision = "block"
reason = "A card on a quarantined account"

[[workflows.cards.rules]]
id = "card_shadow"
when = "true"
score = 100
mode = "shadow"
reason = "A shadow rule that would block every card"

[workflows.payouts]
events = ["payout.requested"]
max_decision = "hold"

[[workflows.payouts.rules]]
id = "payout_new"
when = "actor.age < 86400"
decision = "hold"
hold_for = "7d"
reason = "A payout on the first day"

[[workflows.payouts.rules]]
id = "payout_flagged"
when = "has(event.attrs.flagged)"
decision = "quarantine"
reason = "A payout to a flagged destination"
"#;

fn engine_with(text: &str) -> Engine {
    let config = Config::parse(text, Path::new(".")).unwrap();
    Engine::open(config, b"engine-test-key-engine-test-key!".to_vec(), None).unwrap()
}

fn engine() -> Engine {
    engine_with(CONFIG)
}

fn ev(value: Value) -> RawEvent {
    serde_json::from_value(value).unwrap()
}

fn send(engine: &Engine, value: Value) -> Outcome {
    engine.process(ev(value), Options::default()).unwrap()
}

fn asked(out: &Outcome) -> Vec<String> {
    out.actions.iter().map(|a| format!("{}:{}", a.target, a.action)).collect()
}

#[test]
fn counters_add_up_across_events_and_a_retry_counts_once() {
    let e = engine();
    let mut decisions = Vec::new();
    for (i, actor) in ["u1", "u2", "u2", "u3"].iter().enumerate() {
        let id = if i == 2 { "evt_1".to_owned() } else { format!("evt_{i}") };
        let out = send(
            &e,
            json!({"id": id, "type": "account.created", "actor_id": actor, "ip": "203.0.113.5", "at": 1_000 + i as u64}),
        );
        decisions.push((out.decision, out.duplicate));
    }
    assert_eq!(
        decisions,
        vec![
            (Decision::Allow, false),
            (Decision::Allow, false),
            (Decision::Allow, true),
            (Decision::Review, false)
        ],
        "the third account from one IP is reviewed; the retry of evt_1 is answered from the first decision"
    );
    let out = send(
        &e,
        json!({"type": "account.created", "actor_id": "u4", "ip": "203.0.113.6", "at": 1_010}),
    );
    assert_eq!(out.decision, Decision::Allow, "another IP has its own count");
}

#[test]
fn an_event_type_outside_the_vocabulary_is_refused() {
    let e = engine();
    let err = e
        .process(ev(json!({"type": "trial.started", "actor_id": "u1"})), Options::default())
        .unwrap_err();
    assert!(err.to_string().contains("not an event type"), "{err}");
    let custom = engine_with(&format!("{CONFIG}\n[events]\ncustom = [\"x.game_won\"]\n"));
    assert!(
        custom
            .process(ev(json!({"type": "x.game_won", "actor_id": "u1"})), Options::default())
            .is_ok(),
        "a declared custom type is accepted"
    );
}

#[test]
fn a_rule_that_cannot_be_decided_is_reported_not_fired() {
    let e = engine();
    let out = send(&e, json!({"type": "account.created", "actor_id": "u1", "ip": "203.0.113.5"}));
    assert_eq!(out.decision, Decision::Allow);
    assert_eq!(out.errors.len(), 1, "{:?}", out.errors);
    assert_eq!(out.errors[0].rule, "broken_rule");
    assert!(out.rules.iter().all(|r| r.id != "broken_rule"));
}

#[test]
fn every_decision_band_asks_its_action() {
    // (case, config changes, event, decision, actions)
    let e = engine();
    let cases: Vec<(&str, Value, Decision, Vec<&str>)> = vec![
        (
            "a blocked address is blocked by the core, with no action to keep",
            json!({"type": "account.created", "actor_id": "b1", "ip": "198.51.100.7"}),
            Decision::Block,
            vec![],
        ),
        (
            "a score past quarantine_at quarantines the actor",
            json!({"type": "account.created", "actor_id": "b2", "attrs": {"farm": true}}),
            Decision::Quarantine,
            vec!["actor:quarantine"],
        ),
        (
            "a hold rule holds",
            json!({"type": "payout.requested", "actor_id": "b3"}),
            Decision::Hold,
            vec!["actor:hold"],
        ),
        (
            "a capped workflow holds instead of quarantining",
            json!({"type": "payout.requested", "actor_id": "b4", "attrs": {"flagged": true}}),
            Decision::Hold,
            vec!["actor:hold"],
        ),
    ];
    let mut failures = Vec::new();
    for (case, event, want, actions) in cases {
        let out = send(&e, event);
        let got = asked(&out);
        if out.decision != want || actions.iter().any(|a| !got.contains(&a.to_string())) {
            failures.push(format!("{case}: {} {got:?}", out.decision.as_str()));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_hold_says_when_it_ends() {
    let e = engine();
    let out = send(&e, json!({"type": "payout.requested", "actor_id": "p1", "at": 10_000}));
    assert_eq!((out.decision, out.hold_until), (Decision::Hold, Some(10_000 + 7 * 86_400)));
}

#[test]
fn a_quarantined_account_stays_restricted_until_a_person_releases_it() {
    let e = engine();
    let out = send(&e, json!({"type": "account.created", "actor_id": "bad", "attrs": {"farm": true}}));
    assert_eq!(out.decision, Decision::Quarantine);
    assert_eq!(out.actor.as_ref().unwrap().status, Status::Quarantined);
    assert!(out.case_id.is_some(), "a quarantine opens a case");
    assert!(out.statement_id.is_some(), "and writes a statement of reasons");

    let later = send(&e, json!({"type": "subscription.invoice_paid", "actor_id": "bad"}));
    assert_eq!(
        later.decision,
        Decision::Block,
        "any later event of a quarantined account is blocked"
    );
    assert!(later.rules.iter().any(|r| r.id == "actor_quarantined"), "{:?}", later.rules);

    e.label("bad", Label::Legit, "admin", "checked by phone").unwrap();
    let actor = e.user("bad").unwrap().unwrap();
    assert_eq!(
        (actor.status, actor.trust),
        (Status::Trusted, 1),
        "a legit label trusts the account"
    );
    assert!(
        e.case(out.case_id.unwrap()).unwrap().unwrap().resolved_at.is_some(),
        "the label resolves the case"
    );
    let after = send(&e, json!({"type": "account.created", "actor_id": "bad", "attrs": {"farm": true}}));
    assert_eq!(
        after.decision,
        Decision::Hold,
        "a trusted account is held for a person, never quarantined automatically"
    );
    assert!(after.protected);
}

#[test]
fn shadow_rules_say_what_they_would_do() {
    let e = engine();
    let out = send(
        &e,
        json!({"type": "payment.method_added", "actor_id": "a", "attrs": {"card_fingerprint": "fp_1"}}),
    );
    assert_eq!(out.decision, Decision::Allow);
    assert_eq!(out.shadow_decision, Decision::Block, "the shadow rule would have blocked");
    assert!(out.rules.iter().any(|r| r.id == "card_shadow" && r.mode == Mode::Shadow));
}

#[test]
fn a_paid_invoice_earns_trust_from_the_core() {
    let e = engine();
    send(&e, json!({"type": "subscription.invoice_paid", "actor_id": "p"}));
    assert_eq!(e.user("p").unwrap().unwrap().trust, 1);
    send(
        &e,
        json!({"type": "payment.method_added", "actor_id": "q", "attrs": {"card_fingerprint": "fp_9"}}),
    );
    e.label("q", Label::Fraud, "admin", "").unwrap();
    let out = send(
        &e,
        json!({"type": "payment.method_added", "actor_id": "p", "attrs": {"card_fingerprint": "fp_9"}}),
    );
    assert_eq!(out.decision, Decision::Hold, "a paying account is held instead of blocked");
    assert!(out.protected);
    assert_ne!(e.user("p").unwrap().unwrap().status, Status::Quarantined);
}

#[test]
fn a_dry_run_decides_without_remembering() {
    let e = engine();
    for actor in ["u1", "u2"] {
        send(&e, json!({"type": "account.created", "actor_id": actor, "ip": "203.0.113.5"}));
    }
    let dry = e
        .process(
            ev(json!({"type": "account.created", "actor_id": "u3", "ip": "203.0.113.5"})),
            Options {
                dry_run: true,
                ..Options::default()
            },
        )
        .unwrap();
    assert_eq!(dry.decision, Decision::Review, "the dry run counts the event it decides");
    assert!(e.user("u3").unwrap().is_none(), "a dry run stores no account");
    let real = send(&e, json!({"type": "account.created", "actor_id": "u4", "ip": "203.0.113.5"}));
    assert_eq!(
        real.decision,
        Decision::Review,
        "and leaves the counters as they were: u4 is the third"
    );
}
