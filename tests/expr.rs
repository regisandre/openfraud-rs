//! Rule conditions: CEL expressions, checked when the configuration loads
//! and evaluated against the facts of one event.
#![allow(clippy::type_complexity)]

use openfraud::event::Pseudonymizer;
use openfraud::expr::{Expr, Facts, Known, Scope};
use openfraud::lists::{List, ListKind};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, RwLock};

fn known() -> Known {
    Known {
        counters: BTreeSet::from(["signups_per_ip_1h".to_owned()]),
        lists: BTreeSet::from(["brands".to_owned(), "disposable".to_owned(), "tor_exits".to_owned()]),
    }
}

fn lists() -> Arc<RwLock<HashMap<String, List>>> {
    let mut disposable = List::new(ListKind::Domain);
    disposable.extend_from_text("mailinator.com");
    let mut tor = List::new(ListKind::Ip);
    tor.extend_from_text("185.220.101.0/24");
    let mut brands = List::new(ListKind::Value);
    brands.extend_from_text("openai\npaypal");
    Arc::new(RwLock::new(HashMap::from([
        ("brands".to_owned(), brands),
        ("disposable".to_owned(), disposable),
        ("tor_exits".to_owned(), tor),
    ])))
}

#[test]
fn a_condition_is_checked_when_it_loads() {
    // (case, source, words in the error, or "" when accepted)
    let cases: Vec<(&str, String, &str)> = vec![
        ("a valid condition", "counters.signups_per_ip_1h > 3".into(), ""),
        ("a valid list lookup", r#"in_list("disposable", event.email_domain)"#.into(), ""),
        ("a valid IP list test", r#""tor_exits" in event.ip_lists"#.into(), ""),
        ("a syntax error", "counters.x >".into(), "Syntax"),
        ("an unknown counter", "counters.signups_per_ip_24h > 3".into(), "signups_per_ip_24h"),
        (
            "an unknown list",
            r#"in_list("disposables", event.email_domain)"#.into(),
            "disposables",
        ),
        ("an unknown IP list", r#""tor" in event.ip_lists"#.into(), "tor"),
        ("an unknown list in mentions()", r#"mentions("brand", event.kind)"#.into(), "brand"),
        (
            "a list name that is not written out",
            "in_list(event.kind, event.email_domain)".into(),
            "literal",
        ),
        ("an unknown variable", "account.age > 3".into(), "account"),
        (
            "a condition too long",
            format!("true && {}", "true && ".repeat(400) + "true"),
            "characters",
        ),
        ("an empty condition", "  ".into(), "empty"),
    ];
    let mut failures = Vec::new();
    for (case, source, words) in cases {
        match (Expr::compile(&source, &known()), words) {
            (Ok(_), "") => {}
            (Ok(_), _) => failures.push(format!("{case}: accepted, want an error with {words:?}")),
            (Err(e), "") => failures.push(format!("{case}: refused: {e}")),
            (Err(e), words) if !e.contains(words) => failures.push(format!("{case}: {e:?} does not name {words:?}")),
            (Err(_), _) => {}
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_condition_is_true_false_or_an_error() {
    let p = Pseudonymizer::new(b"expr-test-key-expr-test-key-expr".to_vec());
    let recipients: Vec<String> = ["a1@gmail.com", "b2@yahoo.com", "c3@outlook.com", "d4@icloud.com"]
        .iter()
        .map(|r| p.email(r))
        .collect();
    let facts = Facts {
        event: json!({
            "type": "message.send_requested",
            "at": 10_000,
            "email": p.email("openai7623@gmail.com"),
            "email_domain": "mailinator.com",
            "ip_lists": ["tor_exits"],
            "attrs": { "recipients": recipients, "plan": "trial", "amount": 12.5, "username": "OpenAI7623" }
        }),
        actor: json!({ "id": "u1", "trust": 0, "status": "normal", "age": 900 }),
        tenant: json!({ "id": "", "age": 0 }),
        counters: json!({ "signups_per_ip_1h": 4 }),
        links: json!({ "card_fingerprint": { "users": 2, "flagged": 1 } }),
        session: json!({ "new_device": true, "travel_kmh": 950 }),
        related: json!({}),
        firsts: BTreeMap::from([
            ("account.created".to_owned(), 9_100),
            ("subscription.trial_started".to_owned(), 9_500),
        ]),
        lasts: BTreeMap::from([("session.password_reset".to_owned(), 9_800)]),
        at: 10_000,
    };
    let scope = Scope::new(&facts, lists());
    // (case, source, Some(result) or None for an error)
    let cases: Vec<(&str, &str, Option<bool>)> = vec![
        ("a counter", "counters.signups_per_ip_1h > 3", Some(true)),
        ("an actor field", "actor.age < 3600 && actor.trust == 0", Some(true)),
        ("user is the actor, for old rules", "user.age == 900", Some(true)),
        ("a session signal", "session.new_device && session.travel_kmh > 800", Some(true)),
        ("an attribute", r#"event.attrs.plan == "trial""#, Some(true)),
        ("a decimal attribute", "event.attrs.amount > 10", Some(true)),
        ("a domain list", r#"in_list("disposable", event.email_domain)"#, Some(true)),
        ("an IP list membership", r#""tor_exits" in event.ip_lists"#, Some(true)),
        (
            "a text that mentions a listed word, in any case",
            r#"mentions("brands", event.attrs.username)"#,
            Some(true),
        ),
        ("a text that mentions none", r#"mentions("brands", event.attrs.plan)"#, Some(false)),
        ("a link count", "links.card_fingerprint.flagged > 0", Some(true)),
        (
            "a missing attribute guarded by has()",
            "has(event.attrs.coupon) && event.attrs.coupon == \"X\"",
            Some(false),
        ),
        ("a missing attribute is an error", "event.attrs.coupon == \"X\"", None),
        ("a non-boolean result is an error", "actor.age", None),
        (
            "the inbox placement probe",
            "size(event.attrs.recipients) <= 10 && freemail_share(event.attrs.recipients) == 1.0 && providers(event.attrs.recipients) >= 3",
            Some(true),
        ),
        (
            "recipients like the sender",
            "alike(event.attrs.recipients, event.email) >= 1",
            Some(false),
        ),
        ("the provider of the sender", r#"provider(event.email) == "google""#, Some(true)),
        (
            "seconds since the first event of a type",
            r#"since("account.created") == 900"#,
            Some(true),
        ),
        (
            "a trial within an hour of sign-up",
            r#"since("account.created") - since("subscription.trial_started") < 3600"#,
            Some(true),
        ),
        (
            "since() of a type never seen is -1",
            r#"since("subscription.invoice_paid") == -1"#,
            Some(true),
        ),
        (
            "seconds since the last event of a type",
            r#"since_last("session.password_reset") == 200"#,
            Some(true),
        ),
    ];
    let mut failures = Vec::new();
    for (case, source, want) in cases {
        let expr = match Expr::compile(source, &known()) {
            Ok(expr) => expr,
            Err(e) => {
                failures.push(format!("{case}: does not compile: {e}"));
                continue;
            }
        };
        let got = expr.eval(&scope).ok();
        if got != want {
            failures.push(format!("{case}: got {:?}, want {want:?}", expr.eval(&scope)));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
