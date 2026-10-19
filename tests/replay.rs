//! Replay: the stored history run again through a candidate configuration,
//! to see what a rule change would have decided before it acts.

use openfraud::config::{Config, Decision};
use openfraud::engine::{Engine, Label, Options};
use openfraud::replay::replay;
use serde_json::json;
use std::path::Path;

const LIVE: &str = r#"
[workflows.cards]
events = ["payment.method_added"]
review_at = 50
block_at = 80

[[workflows.cards.rules]]
id = "prepaid"
when = 'has(event.attrs.card_funding) && event.attrs.card_funding == "prepaid"'
score = 30
reason = "A prepaid card"
"#;

#[test]
fn a_candidate_rule_is_measured_on_history_and_labels() {
    let live = Engine::open(
        Config::parse(LIVE, Path::new(".")).unwrap(),
        b"replay-test-key-replay-test-key!".to_vec(),
        None,
    )
    .unwrap();
    // Three prepaid cards from fresh accounts (two later confirmed fraud),
    // one prepaid card from a real customer, one credit card.
    let events = [
        ("f1", "prepaid", "MA"),
        ("f2", "prepaid", "NG"),
        ("ok1", "prepaid", "BE"),
        ("ok2", "credit", "BE"),
        ("x1", "prepaid", "MA"),
        ("fp1", "prepaid", "BR"),
    ];
    for (i, (user, funding, country)) in events.iter().enumerate() {
        let raw = serde_json::from_value(json!({
            "id": format!("e{i}"), "type": "payment.method_added", "actor_id": user, "at": 1_000 + i as u64,
            "country": "BE", "attrs": {"card_funding": funding, "card_country": country}
        }))
        .unwrap();
        let out = live
            .process(
                raw,
                Options {
                    dry_run: false,
                    now: Some(2_000),
                },
            )
            .unwrap();
        assert_eq!(out.decision, Decision::Allow, "nothing blocks live");
    }
    live.label("f1", Label::Fraud, "admin", "").unwrap();
    live.label("f2", Label::Fraud, "admin", "").unwrap();
    live.label("ok1", Label::Legit, "admin", "").unwrap();
    live.label("fp1", Label::FalsePositive, "admin", "").unwrap();
    live.label("missed", Label::Fraud, "admin", "").unwrap();

    let candidate = LIVE.replace(
        "[[workflows.cards.rules]]",
        r#"[[workflows.cards.rules]]
id = "foreign_prepaid"
when = 'has(event.attrs.card_country) && event.attrs.card_country != event.country && event.attrs.card_funding == "prepaid"'
score = 60
reason = "A foreign prepaid card"

[[workflows.cards.rules]]"#,
    );
    let report = replay(&live, Config::parse(&candidate, Path::new(".")).unwrap(), 0).unwrap();
    assert_eq!(report.events, 6);
    assert_eq!(
        report.changed.len(),
        4,
        "the four foreign prepaid cards change, though the rule is new and unapproved: {:?}",
        report.changed
    );
    assert!(
        report
            .changed
            .iter()
            .all(|c| c.before == Decision::Allow && c.after == Decision::Block)
    );
    let rule = report.rules.iter().find(|r| r.id == "foreign_prepaid").unwrap();
    assert_eq!(
        (rule.fired, rule.users, rule.fraud, rule.legit, rule.false_positive),
        (4, 4, 2, 0, 1),
        "{rule:?}"
    );
    // Precision: fraud among the labelled accounts it hit. Recall: the
    // accounts labelled fraud it hit, of all labelled fraud.
    assert_eq!((rule.precision, rule.recall), (Some(2.0 / 3.0), Some(2.0 / 3.0)), "{rule:?}");
    let prepaid = report.rules.iter().find(|r| r.id == "prepaid").unwrap();
    assert_eq!(
        (prepaid.fired, prepaid.fraud, prepaid.legit, prepaid.false_positive),
        (5, 2, 1, 1),
        "{prepaid:?}"
    );
    assert_eq!(report.before.get(&Decision::Allow), Some(&6));
    assert_eq!(report.after.get(&Decision::Block), Some(&4));
    assert_eq!(
        (report.from, report.to),
        (Some(1_000), Some(1_005)),
        "the span of history it covers"
    );
}
