//! The safety nets: a rule asked to act waits in shadow for an approved
//! replay, and the brake turns restrictions into reviews when they spike.

use openfraud::config::{Config, Decision, Mode};
use openfraud::engine::{Engine, Options, Outcome};
use serde_json::{Value, json};
use std::path::Path;

const RULES: &str = r#"
[workflows.payouts]
events = ["payout.requested"]

[[workflows.payouts.rules]]
id = "big_payout"
when = "has(event.attrs.amount) && event.attrs.amount > 1000"
decision = "block"
reason = "A big payout"
"#;

fn engine(text: &str) -> Engine {
    Engine::open(
        Config::parse(text, Path::new(".")).unwrap(),
        b"safety-test-key-safety-test-key!".to_vec(),
        None,
    )
    .unwrap()
}

fn send(e: &Engine, v: Value) -> Outcome {
    e.process(serde_json::from_value(v).unwrap(), Options::default()).unwrap()
}

fn payout(e: &Engine, actor: &str, at: u64) -> Outcome {
    send(
        e,
        json!({"type": "payout.requested", "actor_id": actor, "at": at, "attrs": {"amount": 5000}}),
    )
}

#[test]
fn a_rule_acts_only_once_its_replay_is_approved() {
    let e = engine(RULES);
    let out = payout(&e, "p1", 1_000);
    assert_eq!(
        (out.decision, out.shadow_decision),
        (Decision::Allow, Decision::Block),
        "unapproved: it only says what it would do"
    );
    let rule = out.rules.iter().find(|r| r.id == "big_payout").unwrap();
    assert!(rule.pending && rule.mode == Mode::Shadow, "{rule:?}");
    assert_eq!(e.approvals().get("core_blocked_ip"), Some(&true), "core rules need no replay");

    e.approve("big_payout", &json!({"days": 30}), "admin").unwrap();
    assert_eq!(payout(&e, "p2", 1_001).decision, Decision::Block, "approved: it acts");

    // Changing the rule's logic withdraws the approval.
    e.reload(Config::parse(&RULES.replace("> 1000", "> 500"), Path::new(".")).unwrap())
        .unwrap();
    assert_eq!(
        payout(&e, "p3", 1_002).decision,
        Decision::Allow,
        "an edited rule waits for a new replay"
    );
    // Its wording does not.
    e.reload(Config::parse(&RULES.replace("A big payout", "A large payout"), Path::new(".")).unwrap())
        .unwrap();
    assert_eq!(payout(&e, "p4", 1_003).decision, Decision::Block);
    // Its workflow's thresholds are part of its logic.
    e.reload(
        Config::parse(
            &RULES.replace("A big payout", "A large payout").replace(
                "events = [\"payout.requested\"]",
                "events = [\"payout.requested\"]
max_decision = \"hold\"",
            ),
            Path::new("."),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        payout(&e, "p5", 1_004).decision,
        Decision::Allow,
        "a changed cap waits for a new replay"
    );
}

#[test]
fn blocks_of_an_account_already_quarantined_do_not_feed_the_brake() {
    let text = format!(
        "[safety]
require_replay = false
max_auto_per_hour = 2
{RULES}"
    );
    let e = engine(&text);
    e.label("q1", openfraud::engine::Label::Fraud, "admin", "").unwrap();
    for i in 0..5 {
        let out = send(&e, json!({"type": "payout.requested", "actor_id": "q1", "at": 5_000 + i}));
        assert_eq!(
            (out.decision, out.brake),
            (Decision::Block, false),
            "the account is blocked, as already decided"
        );
    }
    assert!(!e.brake().engaged);
    assert_eq!(payout(&e, "fresh", 5_010).decision, Decision::Block, "a new restriction still acts");
}

#[test]
fn the_brake_turns_a_spike_of_restrictions_into_reviews_until_released() {
    let text = format!(
        "[safety]\nrequire_replay = false\nmax_auto_per_hour = 3\nmin_per_hour = 1000\n\n[webhooks]\nurl = \"https://hooks.example.com/x\"\n{RULES}"
    );
    let e = engine(&text);
    let decisions: Vec<Decision> = (0..3)
        .map(|i| payout(&e, &format!("a{i}"), 10_000 + i))
        .map(|o| o.decision)
        .collect();
    assert_eq!(decisions, vec![Decision::Block; 3], "under the threshold");
    let tripped = payout(&e, "a3", 10_010);
    assert_eq!(
        (tripped.decision, tripped.brake),
        (Decision::Review, true),
        "the fourth in an hour trips the brake"
    );
    assert!(e.brake().engaged);
    let later = payout(&e, "a4", 20_000);
    assert_eq!(
        (later.decision, later.brake),
        (Decision::Review, true),
        "it stays engaged after the hour: a person releases it"
    );
    let hooks: Vec<String> = e
        .with_store(|s| s.outbox_recent(100))
        .unwrap()
        .into_iter()
        .filter_map(|i| serde_json::from_str::<Value>(&i.payload).ok()?["type"].as_str().map(str::to_owned))
        .collect();
    assert!(hooks.contains(&"brake.engaged".to_owned()), "{hooks:?}");

    e.release_brake("admin").unwrap();
    assert_eq!(payout(&e, "a5", 20_001).decision, Decision::Block, "released: rules act again");
}

#[test]
fn the_brake_trips_on_a_multiple_of_the_weekly_average() {
    let text = format!("[safety]\nrequire_replay = false\nmax_auto_per_hour = 1000\nbaseline_multiple = 5.0\nmin_per_hour = 4\n{RULES}");
    let e = engine(&text);
    // A busy week: two restrictions an hour, so five times the average is ten.
    let start = 1_000_000;
    for i in 0..336 {
        payout(&e, &format!("w{i}"), start + i * 1_800);
    }
    let now = start + 336 * 1_800 + 3_600;
    let burst: Vec<bool> = (0..12).map(|i| payout(&e, &format!("b{i}"), now + i).brake).collect();
    let first = burst.iter().position(|b| *b);
    assert_eq!(
        first,
        Some(10),
        "the eleventh restriction in an hour is past 5x the hourly average: {burst:?}"
    );
}

#[test]
fn an_engaged_brake_survives_a_restart() {
    let text = format!(
        "[safety]
require_replay = false
max_auto_per_hour = 1
{RULES}"
    );
    let db = std::env::temp_dir().join(format!("openfraud-brake-{}.db", openfraud::event::random_hex(4)));
    let open = || {
        Engine::open(
            Config::parse(&text, Path::new(".")).unwrap(),
            b"safety-test-key-safety-test-key!".to_vec(),
            Some(&db),
        )
        .unwrap()
    };
    let e = open();
    payout(&e, "r1", 1_000);
    assert!(payout(&e, "r2", 1_001).brake);
    drop(e);
    let e = open();
    assert!(e.brake().engaged, "the brake is read back from the database");
    assert_eq!(payout(&e, "r3", 1_002).decision, Decision::Review);
}
