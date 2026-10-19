//! The link graph: accounts sharing a strong identifier form one cluster,
//! cluster counters add up across it, and a fraud label on one account puts
//! the rest up for review, never under an automatic restriction.

use openfraud::config::{Config, Decision, Status};
use openfraud::engine::{Engine, Label, Options, Outcome};
use openfraud::store::SubjectKind;
use serde_json::{Value, json};
use std::path::Path;

const CONFIG: &str = r#"
[safety]
require_replay = false

[graph]
max_shared = 3

[counters.trials_per_cluster]
events = ["subscription.trial_started"]
by = "cluster"
distinct = "actor"
window = "365d"

[workflows.trials]
events = ["subscription.trial_started"]
review_at = 50

[[workflows.trials.rules]]
id = "cluster_trials"
when = "counters.trials_per_cluster > 1"
score = 50
reason = "A linked account already had a trial"

[[workflows.trials.rules]]
id = "cluster_four_trials"
when = "counters.trials_per_cluster > 3"
score = 1
reason = "Four trials in one cluster"

[[workflows.trials.rules]]
id = "cluster_flagged"
when = "links.cluster.flagged > 0"
score = 50
reason = "A linked account is flagged"
"#;

fn engine() -> Engine {
    Engine::open(
        Config::parse(CONFIG, Path::new(".")).unwrap(),
        b"graph-test-key-graph-test-key-gr".to_vec(),
        None,
    )
    .unwrap()
}

fn send(e: &Engine, v: Value) -> Outcome {
    e.process(serde_json::from_value(v).unwrap(), Options::default()).unwrap()
}

#[test]
fn accounts_sharing_an_identifier_form_one_cluster() {
    let e = engine();
    // a and b share a card, b and c a device: a, b and c are one cluster.
    send(
        &e,
        json!({"type": "payment.method_added", "actor_id": "a", "attrs": {"card_fingerprint": "fp_1"}}),
    );
    send(
        &e,
        json!({"type": "payment.method_added", "actor_id": "b", "attrs": {"card_fingerprint": "fp_1"}}),
    );
    send(&e, json!({"type": "session.login", "actor_id": "b", "device": "dev_1"}));
    let out = send(&e, json!({"type": "session.login", "actor_id": "c", "device": "dev_1"}));
    assert_eq!(out.decision, Decision::Allow);
    let cluster = e.cluster("a").unwrap();
    assert_eq!(cluster["size"], 3, "{cluster}");
    let kinds: Vec<&str> = cluster["joined_by"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|k| k["kind"].as_str())
        .collect();
    assert_eq!(kinds, vec!["card_fingerprint", "device"], "{cluster}");
    assert_eq!(e.cluster("c").unwrap()["root"], cluster["root"]);

    // A country is not a strong identifier: d stays alone.
    send(&e, json!({"type": "session.login", "actor_id": "d", "country": "BE"}));
    assert_eq!(e.cluster("d").unwrap()["size"], 1);
}

#[test]
fn an_identifier_shared_by_too_many_accounts_links_nobody() {
    let e = engine();
    for actor in ["s1", "s2", "s3", "s4", "s5"] {
        send(
            &e,
            json!({"type": "session.login", "actor_id": actor, "device": "dev_shared_kiosk"}),
        );
    }
    let size = e.cluster("s5").unwrap()["size"].as_u64().unwrap();
    assert!(size <= 4, "past max_shared = 3, the kiosk device joins no one more: {size}");
}

#[test]
fn a_cluster_counter_counts_across_the_accounts_it_joins() {
    let e = engine();
    // Two trials on separate accounts, joined only later by a card.
    let first = send(&e, json!({"type": "subscription.trial_started", "actor_id": "t1"}));
    let second = send(&e, json!({"type": "subscription.trial_started", "actor_id": "t2"}));
    assert_eq!((first.decision, second.decision), (Decision::Allow, Decision::Allow));
    send(
        &e,
        json!({"type": "payment.method_added", "actor_id": "t1", "attrs": {"card_fingerprint": "fp_9"}}),
    );
    let third = send(
        &e,
        json!({"type": "subscription.trial_started", "actor_id": "t3", "attrs": {"card_fingerprint": "fp_9"}}),
    );
    assert!(
        third.rules.iter().any(|r| r.id == "cluster_trials"),
        "t3 joins t1's cluster, which had a trial: {:?}",
        third.rules
    );
    send(
        &e,
        json!({"type": "payment.method_added", "actor_id": "t2", "attrs": {"card_fingerprint": "fp_9"}}),
    );
    let merged = send(
        &e,
        json!({"type": "subscription.trial_started", "actor_id": "t4", "attrs": {"card_fingerprint": "fp_9"}}),
    );
    assert_eq!(merged.decision, Decision::Review);
    assert!(
        merged.rules.iter().any(|r| r.id == "cluster_four_trials"),
        "the two clusters' counts were added up when they joined: {:?}",
        merged.rules
    );
    assert_eq!(e.cluster("t2").unwrap()["size"], 4, "t2 joined later: one cluster of four");
}

#[test]
fn a_fraud_label_puts_the_cluster_up_for_review_not_under_a_ban() {
    let e = engine();
    send(
        &e,
        json!({"type": "payment.method_added", "actor_id": "f", "attrs": {"card_fingerprint": "fp_2"}}),
    );
    send(
        &e,
        json!({"type": "payment.method_added", "actor_id": "g", "attrs": {"card_fingerprint": "fp_2"}}),
    );
    send(&e, json!({"type": "subscription.invoice_paid", "actor_id": "paying"}));
    send(
        &e,
        json!({"type": "payment.method_added", "actor_id": "paying", "attrs": {"card_fingerprint": "fp_2"}}),
    );
    e.label("paying", Label::Legit, "admin", "").unwrap();

    e.label("f", Label::Fraud, "admin", "stolen card").unwrap();
    let g = e.subject(SubjectKind::Actor, "g").unwrap().unwrap();
    assert_eq!(g.status, Status::Normal, "a linked account is not restricted");
    let cases = e.with_store(|s| s.subject_cases(SubjectKind::Actor, "g")).unwrap();
    assert_eq!(cases.len(), 1, "it gets a case: {cases:?}");
    assert_eq!(cases[0].reasons, vec!["cluster_fraud".to_owned()]);
    assert!(
        e.with_store(|s| s.subject_cases(SubjectKind::Actor, "paying"))
            .unwrap()
            .iter()
            .all(|c| c.reasons != vec!["cluster_fraud".to_owned()]),
        "a trusted account is left alone"
    );

    let next = send(&e, json!({"type": "subscription.trial_started", "actor_id": "g"}));
    assert!(
        next.rules.iter().any(|r| r.id == "cluster_flagged"),
        "rules see the flagged cluster: {:?}",
        next.rules
    );
}

#[test]
fn a_cluster_stops_growing_at_its_cap() {
    let text = CONFIG.replace("max_shared = 3", "max_shared = 50\nmax_cluster = 4");
    let e = Engine::open(
        Config::parse(&text, Path::new(".")).unwrap(),
        b"graph-test-key-graph-test-key-gr".to_vec(),
        None,
    )
    .unwrap();
    // A chain: each account shares a device with the next one.
    for i in 0..8 {
        send(
            &e,
            json!({"type": "session.login", "actor_id": format!("c{i}"), "device": format!("dev_{i}")}),
        );
        send(
            &e,
            json!({"type": "session.login", "actor_id": format!("c{i}"), "device": format!("dev_{}", i + 1)}),
        );
    }
    let size = e.cluster("c0").unwrap()["size"].as_u64().unwrap();
    assert_eq!(size, 4, "a chain of shared devices cannot merge everyone");
    let out = send(&e, json!({"type": "session.login", "actor_id": "c7", "device": "dev_8"}));
    assert_eq!(out.decision, Decision::Allow);
}
