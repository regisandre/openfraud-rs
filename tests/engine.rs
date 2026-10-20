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

[counters.sends_per_actor_10m]
events = ["message.send_requested"]
by = "actor"
window = "10m"

[workflows.sending]
events = ["message.send_requested"]

[[workflows.sending.rules]]
id = "send_burst"
when = "counters.sends_per_actor_10m > 2"
actions = ["throttle:1h"]
reason = "More than 2 sends in 10 minutes"

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
fn a_throttle_refuses_the_same_action_until_it_expires() {
    let e = engine();
    let send_at = |id: &str, at: u64| send(&e, json!({"id": id, "type": "message.send_requested", "actor_id": "t1", "at": at}));
    // (case, outcome, decision, throttled rule fired, retry_after)
    let first = send_at("s1", 10_000);
    let second = send_at("s2", 10_010);
    let third = send_at("s3", 10_020);
    let fourth = send_at("s4", 10_080);
    let other = send(&e, json!({"type": "account.updated", "actor_id": "t1", "at": 10_090}));
    let after = send_at("s5", 10_020 + 3_601);
    let cases: Vec<(&str, &Outcome, Decision, bool, Option<u64>)> = vec![
        ("under the limit", &first, Decision::Allow, false, None),
        ("still under", &second, Decision::Allow, false, None),
        (
            "the burst itself goes through and sets the throttle",
            &third,
            Decision::Allow,
            false,
            None,
        ),
        ("the next send is refused", &fourth, Decision::Block, true, Some(3_600 - 60)),
        ("another action is not throttled", &other, Decision::Allow, false, None),
        ("after the throttle ends", &after, Decision::Allow, false, None),
    ];
    for (case, out, decision, throttled, retry) in cases {
        assert_eq!(out.decision, decision, "{case}: {:?}", out.rules);
        assert_eq!(
            out.rules.iter().any(|r| r.id == "actor_throttled"),
            throttled,
            "{case}: {:?}",
            out.rules
        );
        assert_eq!(out.retry_after, retry, "{case}");
    }
    assert!(asked(&third).contains(&"actor:throttle:1h".to_owned()), "{:?}", asked(&third));
    assert!(
        fourth.repeat,
        "a throttle repeats an earlier decision: no new statement, not counted by the brake"
    );
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

#[test]
fn a_long_attribute_becomes_a_short_counter_key() {
    let p = openfraud::event::Pseudonymizer::new(b"0123456789abcdef0123456789abcdef".to_vec());
    let privacy = openfraud::config::Privacy::default();
    let long = "a".repeat(60_000);
    let other = format!("{}b", "a".repeat(59_999));
    // (case, attribute, key length at most, same key as `long`)
    let cases: Vec<(&str, String, usize, bool)> = vec![
        ("a short value is kept as is", "promo10".into(), 7, false),
        ("a long value is hashed", long.clone(), 80, true),
        ("another long value hashes apart", other, 80, false),
    ];
    let key_of = |value: &str| {
        let raw: RawEvent = serde_json::from_value(json!({"type": "a.b", "attrs": {"code": value}})).unwrap();
        let event = raw.normalize(&p, &privacy, 0).unwrap();
        openfraud::engine::key_value(&event, &openfraud::config::Key::Attr("code".into()), None).unwrap()
    };
    let long_key = key_of(&long);
    let mut failures = Vec::new();
    for (case, value, max, same) in cases {
        let key = key_of(&value);
        if key.len() > max || (key == long_key) != same {
            failures.push(format!("{case}: {} bytes, {}", key.len(), &key[..key.len().min(40)]));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_new_system_browser_or_language_is_noticed_after_the_first() {
    let config = r#"
[workflows.seen]
events = ["session.login"]
mode = "act"
[[workflows.seen.rules]]
id = "new_os"
when = "session.new_os"
score = 1
reason = "os"
[[workflows.seen.rules]]
id = "new_browser"
when = "session.new_browser"
score = 1
reason = "browser"
[[workflows.seen.rules]]
id = "new_language"
when = "session.new_language"
score = 1
reason = "language"
"#;
    let e = engine_with(config);
    let chrome_win = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
    let firefox_win = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0";
    let safari_mac =
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15";
    // (case, user agent, language, rules that fire)
    let steps: [(&str, &str, &str, &[&str]); 5] = [
        ("the first login sets the baseline", chrome_win, "fr", &[]),
        ("the same again", chrome_win, "fr-BE", &[]),
        ("another browser on the same system", firefox_win, "fr", &["new_browser"]),
        ("another system and browser", safari_mac, "fr", &["new_browser", "new_os"]),
        ("another language", chrome_win, "nl", &["new_language"]),
    ];
    let mut failures = Vec::new();
    for (i, (case, ua, language, want)) in steps.iter().enumerate() {
        let out = send(
            &e,
            json!({"type": "session.login", "actor_id": "u", "at": 1_000 + i as u64, "user_agent": ua, "language": language}),
        );
        let mut fired: Vec<&str> = out.rules.iter().map(|r| r.id.as_str()).collect();
        fired.sort();
        if fired != *want {
            failures.push(format!("{case}: fired {fired:?}, want {want:?}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_snoozed_rule_stays_silent_for_one_account_until_it_wakes() {
    let e = engine();
    let farm = |actor: &str, at: u64| json!({"type": "account.created", "actor_id": actor, "at": at, "attrs": {"farm": true}});
    e.snooze("u_fp", "farm", 2_000, "admin", "a false positive").unwrap();
    assert_eq!(
        e.snoozes("u_fp")
            .unwrap()
            .iter()
            .map(|s| (s.rule.as_str(), s.until))
            .collect::<Vec<_>>(),
        [("farm", 2_000)]
    );
    // (case, actor, at, the rule fires, the answer lists it as snoozed)
    let steps = [
        ("snoozed for this account", "u_fp", 1_000, false, true),
        ("another account is still caught", "u_other", 1_001, true, false),
        ("the snooze ends", "u_fp", 2_001, true, false),
    ];
    let mut failures = Vec::new();
    for (case, actor, at, fires, listed) in steps {
        let out = send(&e, farm(actor, at));
        let fired = out.rules.iter().any(|r| r.id == "farm");
        let snoozed = out.snoozed.iter().any(|r| r == "farm");
        if (fired, snoozed) != (fires, listed) {
            failures.push(format!("{case}: fired {fired}, listed {snoozed}"));
        }
    }
    e.snooze("u_2", "farm", 10_000, "admin", "").unwrap();
    assert!(e.unsnooze("u_2", "farm", "admin").unwrap(), "a snooze is lifted");
    assert!(!e.unsnooze("u_2", "farm", "admin").unwrap(), "lifting it twice says so");
    if !send(&e, farm("u_2", 3_000)).rules.iter().any(|r| r.id == "farm") {
        failures.push("a lifted snooze lets the rule fire".into());
    }
    // (case, rule, words in the refusal)
    for (case, rule, words) in [
        ("an unknown rule", "nope", "no rule"),
        ("a built-in rule", "actor_quarantined", "built-in"),
        ("a rule about the workspace", "core_paid_invoice_tenant", "workspace"),
    ] {
        match e.snooze("u_3", rule, 10_000, "admin", "") {
            Ok(()) => failures.push(format!("{case}: accepted")),
            Err(err) if !format!("{err:#}").contains(words) => failures.push(format!("{case}: {err:#}")),
            Err(_) => {}
        }
    }
    let audit = e.with_store(|s| s.audit_log(20)).unwrap();
    if !audit.iter().any(|a| a.action == "snooze" && a.target == "u_fp") {
        failures.push(format!("the snooze is audited: {audit:?}"));
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn the_answer_names_its_signals_and_a_score_per_family() {
    let text = r#"
[safety]
require_replay = false

[core]
account_takeover = false

[workflows.logins]
events = ["session.login"]
family = "takeover"
step_up_at = 30

[[workflows.logins.rules]]
id = "new_device_login"
when = "session.new_device"
score = 40
reason = "A new device"

[[workflows.logins.rules]]
id = "scripted_login"
when = "has(event.agent) && event.agent.http_client"
score = 30
family = "bot"
mode = "shadow"
reason = "A script"

[[workflows.logins.rules]]
id = "partner_referral"
when = "has(event.attrs.partner)"
signal = "partner_referral"
reason = "Sent by a partner"

[workflows.signup]
events = ["account.created"]

[[workflows.signup.rules]]
id = "farm"
when = "has(event.attrs.farm)"
decision = "block"
reason = "A farm"
"#;
    let e = engine_with(text);
    e.add_list_item("tor_exits", "203.0.113.66", "admin", "").unwrap();
    let login = |actor: &str, device: &str, ip: &str, ua: &str, at: u64, attrs: Value| json!({"type": "session.login", "actor_id": actor, "device": device, "ip": ip, "user_agent": ua, "at": at, "attrs": attrs});
    let browser = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36";
    send(&e, login("a1", "d1", "198.51.100.1", browser, 1_000, json!({})));
    send(&e, login("a2", "d9", "198.51.100.2", browser, 1_001, json!({})));
    // (case, event, signals present, signals absent, (takeover, abuse, bot))
    let cases: Vec<(&str, Value, Vec<&str>, Vec<&str>, (f64, f64, f64))> = vec![
        (
            "a known device in a browser",
            login("a1", "d1", "198.51.100.1", browser, 1_100, json!({})),
            vec![],
            vec!["new_device", "http_client_library", "tor_ip"],
            (0.0, 0.0, 0.0),
        ),
        (
            "a new device, through Tor, by a script, used by another account",
            login("a1", "d9", "203.0.113.66", "curl/8.4.0", 1_200, json!({"partner": true})),
            vec![
                "new_device",
                "tor_ip",
                "http_client_library",
                "multiple_accounts_per_device",
                "partner_referral",
            ],
            vec!["web_crawler"],
            (0.4, 0.0, 0.3),
        ),
        (
            "a sign-up from a farm with an address that is no address",
            json!({"type": "account.created", "actor_id": "f1", "email": "not-an-address", "at": 1_300, "attrs": {"farm": true}}),
            vec!["invalid_email"],
            vec![],
            (0.0, 1.0, 0.0),
        ),
    ];
    let mut failures = Vec::new();
    for (case, event, present, absent, (takeover, abuse, bot)) in cases {
        let out = send(&e, event);
        for name in &present {
            if !out.signals.contains_key(*name) {
                failures.push(format!("{case}: {name} missing from {:?}", out.signals.keys().collect::<Vec<_>>()));
            }
        }
        for name in &absent {
            if out.signals.contains_key(*name) {
                failures.push(format!("{case}: {name} should not be there"));
            }
        }
        let got = (out.scores.account_takeover, out.scores.account_abuse, out.scores.bot);
        if got != (takeover, abuse, bot) {
            failures.push(format!("{case}: scores {got:?}, want {:?}", (takeover, abuse, bot)));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn an_attempt_before_sign_in_is_matched_to_the_account_its_email_belongs_to() {
    let text = r#"
[safety]
require_replay = false

[workflows.anonymous]
events = ["session.login_failed"]

[[workflows.anonymous.rules]]
id = "flagged_account_targeted"
when = 'matched.known && matched.status == "quarantined"'
score = 10
reason = "An attempt on an account already quarantined"
"#;
    let e = engine_with(text);
    send(
        &e,
        json!({"type": "account.created", "actor_id": "acc_1", "email": "Ann.Lee@gmail.com", "at": 1_000}),
    );
    send(
        &e,
        json!({"type": "account.created", "actor_id": "acc_2", "email": "bob@example.com", "at": 1_001}),
    );
    e.set_status(
        openfraud::store::SubjectKind::Actor,
        "acc_2",
        Status::Quarantined,
        None,
        "admin",
        "",
    )
    .unwrap();
    // (case, email, matched account, the rule fires)
    let cases = [
        (
            "the address as the provider reads it",
            "annlee+promo@googlemail.com",
            Some("acc_1"),
            false,
        ),
        ("an account already quarantined", "BOB@example.com", Some("acc_2"), true),
        ("an address no account has", "nobody@example.com", None, false),
    ];
    let mut failures = Vec::new();
    for (case, email, want, fires) in cases {
        let out = send(
            &e,
            json!({"type": "session.login_failed", "email": email, "ip": "198.51.100.4", "at": 2_000}),
        );
        if out.matched_actor.as_deref() != want {
            failures.push(format!("{case}: matched {:?}, want {want:?}", out.matched_actor));
        }
        if out.rules.iter().any(|r| r.id == "flagged_account_targeted") != fires {
            failures.push(format!("{case}: the rule should fire: {fires}"));
        }
        if out.actor.is_some() || out.case_id.is_some() {
            failures.push(format!("{case}: the attempt is not the account's own: no actor, no case"));
        }
    }
    let stored = e.user_events("acc_1", 10).unwrap();
    if stored.iter().any(|(ev, _)| ev.kind == "session.login_failed") {
        failures.push("an anonymous attempt is not filed under the account it matched".into());
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn metrics_aggregate_group_by_several_keys_and_learn_a_baseline() {
    let text = r#"
[safety]
require_replay = false

[counters.avg_amount_per_actor_1d]
events = ["payment.attempted"]
by = "actor"
agg = "avg"
of = "attrs.amount"
window = "1d"

[counters.payments_per_actor_and_card_1h]
events = ["payment.attempted"]
by = ["actor", "attrs.card"]
window = "1h"

[counters.failed_per_actor_1h]
events = ["payment.failed"]
by = "actor"
window = "1h"

[counters.events_per_actor_1h]
events = ["payment.attempted"]
by = "actor"
window = "1h"
baseline = "7d"

[workflows.pay]
events = ["payment.attempted"]

[[workflows.pay.rules]]
id = "big_vs_average"
when = "event.attrs.amount > 2 * counters.avg_amount_per_actor_1d"
score = 10
reason = "An amount twice the account's average, this one included"

[[workflows.pay.rules]]
id = "same_card_burst"
when = "counters.payments_per_actor_and_card_1h > 2"
score = 10
reason = "Three payments with one card on one account in an hour"

[[workflows.pay.rules]]
id = "failure_ratio"
when = "counters.failed_per_actor_1h * 2 >= max(counters.events_per_actor_1h, 1)"
score = 10
reason = "Half the attempts failed"

[[workflows.pay.rules]]
id = "burst_over_baseline"
when = "counters.events_per_actor_1h > 5 && counters.events_per_actor_1h > 3 * baselines.events_per_actor_1h"
score = 10
reason = "Far more payments than this account usually makes"
"#;
    let e = engine_with(text);
    let pay = |actor: &str, card: &str, amount: i64, at: u64| json!({"type": "payment.attempted", "actor_id": actor, "at": at, "attrs": {"amount": amount, "card": card}});
    let mut failures = Vec::new();
    let day = 86_400;
    // A steady account: two payments a day for six days.
    for d in 0..6 {
        for h in [8, 20] {
            send(&e, pay("steady", &format!("c{d}{h}"), 1_000, 1_000 + d * day + h * 3_600));
        }
    }
    let fired = |out: &Outcome, rule: &str| out.rules.iter().any(|r| r.id == rule);
    let t = 1_000 + 6 * day;
    let big = send(&e, pay("steady", "cx", 5_000, t));
    if !fired(&big, "big_vs_average") {
        failures.push(format!("5000 against an average near 1000: {:?}", big.rules));
    }
    let mut last = big;
    for i in 1..=6 {
        last = send(&e, pay("steady", "same", 900, t + i * 60));
    }
    if !fired(&last, "same_card_burst") {
        failures.push("the same card on the same account three times".into());
    }
    if send(&e, pay("other", "same", 900, t + 500))
        .rules
        .iter()
        .any(|r| r.id == "same_card_burst")
    {
        failures.push("another account with that card has its own count".into());
    }
    if !fired(&last, "burst_over_baseline") {
        failures.push(format!("seven payments in an hour against two a day: {:?}", last.rules));
    }
    send(&e, json!({"type": "payment.failed", "actor_id": "ratio", "at": t}));
    if !fired(&send(&e, pay("ratio", "c", 10, t + 1)), "failure_ratio") {
        failures.push("one failure for one attempt is half".into());
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_burst_far_above_the_usual_rate_is_a_high_activity_signal() {
    let on = engine_with("[safety]\nrequire_replay = false\n\n[core]\nactivity = true\n");
    let off = engine_with("[safety]\nrequire_replay = false\n");
    let ev =
        |actor: &str, at: u64| json!({"type": "resource.created", "actor_id": actor, "device": "dev_a", "ip": "198.51.100.77", "at": at});
    let mut failures = Vec::new();
    // A quiet week: one event a day.
    for d in 0..6u64 {
        send(&on, ev("quiet", 1_000 + d * 86_400));
    }
    let t = 1_000 + 6 * 86_400;
    let mut last = send(&on, ev("quiet", t));
    if last.signals.contains_key("high_activity_account") {
        failures.push("one more event on a quiet week is not a burst".into());
    }
    for i in 1..=25 {
        last = send(&on, ev("quiet", t + i * 30));
    }
    for name in ["high_activity_account", "high_activity_device", "high_activity_ip"] {
        if !last.signals.contains_key(name) {
            failures.push(format!("26 events in 15 minutes after a quiet week: {name} missing"));
        }
    }
    let mut quiet_off = send(&off, ev("quiet", t));
    for i in 1..=25 {
        quiet_off = send(&off, ev("quiet", t + i * 30));
    }
    if quiet_off.signals.keys().any(|k| k.starts_with("high_activity")) {
        failures.push("off by default: the counters cost memory".into());
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn an_address_is_checked_for_mail_and_against_the_domains_of_known_fraud() {
    let text = r#"
[safety]
require_replay = false

[email]
mx_check = true

[workflows.signup]
events = ["account.created"]

[[workflows.signup.rules]]
id = "registered_domain_seen"
when = 'has(event.email_registered_domain) && event.email_registered_domain == "fraudco.net"'
signal = "fraudco"
reason = "Reads the registered domain"
"#;
    let e = engine_with(text);
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = calls.clone();
    e.set_mail_check(Some(std::sync::Arc::new(move |domain: &str| {
        seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Some(domain != "nomail.example")
    })));
    let signup = |actor: &str, email: &str, at: u64| json!({"type": "account.created", "actor_id": actor, "email": email, "at": at});
    let mut failures = Vec::new();
    let out = send(&e, signup("m1", "ann@nomail.example", 1_000));
    if !out.signals.contains_key("unreachable_email") {
        failures.push("an address whose domain takes no mail".into());
    }
    send(&e, signup("m2", "bob@nomail.example", 1_001));
    if calls.load(std::sync::atomic::Ordering::SeqCst) != 1 {
        failures.push(format!(
            "a domain is asked once a day: {} calls",
            calls.load(std::sync::atomic::Ordering::SeqCst)
        ));
    }
    if send(&e, signup("m3", "carl@example.com", 1_002))
        .signals
        .contains_key("unreachable_email")
    {
        failures.push("a domain that takes mail".into());
    }
    // Two accounts labelled fraud on one registered domain list it; a free
    // mailbox provider is never listed.
    send(&e, signup("f1", "x1@a.fraudco.net", 2_000));
    send(&e, signup("f2", "x2@b.fraudco.net", 2_001));
    send(&e, signup("g1", "y1@gmail.com", 2_002));
    send(&e, signup("g2", "y2@gmail.com", 2_003));
    for actor in ["f1", "f2", "g1", "g2"] {
        e.label(actor, Label::Fraud, "admin", "").unwrap();
    }
    let next = send(&e, signup("n1", "z@c.fraudco.net", 3_000));
    if !next.signals.contains_key("fraudulent_email_domain") || !next.signals.contains_key("fraudco") {
        failures.push(format!(
            "a third address on the domain: {:?}",
            next.signals.keys().collect::<Vec<_>>()
        ));
    }
    if send(&e, signup("n2", "w@gmail.com", 3_001))
        .signals
        .contains_key("fraudulent_email_domain")
    {
        failures.push("gmail is never a fraud domain".into());
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn traits_stay_on_the_account_with_the_type_they_first_had() {
    let text = r#"
[safety]
require_replay = false

[workflows.w]
events = ["resource.created"]

[[workflows.w.rules]]
id = "enterprise_bulk"
when = 'has(actor.traits.plan) && actor.traits.plan == "enterprise" && actor.traits.seats > 10'
signal = "enterprise_bulk"
reason = "A large enterprise account"
"#;
    let e = engine_with(text);
    let ev = |traits: Value, at: u64| json!({"type": "resource.created", "actor_id": "t1", "at": at, "traits": traits});
    let mut failures = Vec::new();
    send(&e, ev(json!({"plan": "enterprise", "seats": 50}), 1_000));
    if !send(&e, ev(json!({}), 1_001)).signals.contains_key("enterprise_bulk") {
        failures.push("traits sent once stay on the account".into());
    }
    send(&e, ev(json!({"seats": "many"}), 1_002));
    let actor = e.user("t1").unwrap().unwrap();
    if actor.traits.get("seats") != Some(&json!(50)) {
        failures.push(format!("a trait keeps the type it first had: {:?}", actor.traits));
    }
    let mut many = serde_json::Map::new();
    for i in 0..60 {
        many.insert(format!("t{i}"), json!(i));
    }
    send(&e, ev(Value::Object(many), 1_003));
    if e.user("t1").unwrap().unwrap().traits.len() > 50 {
        failures.push("an account keeps at most 50 traits".into());
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
