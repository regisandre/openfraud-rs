//! Lists: domains, IP ranges and plain values, read from text in the
//! formats public lists use, and looked up by rules.
#![allow(clippy::type_complexity)]

use openfraud::lists::{List, ListKind};

#[test]
fn a_list_matches_what_it_holds() {
    // (case, kind, text, probe, want)
    let cases: Vec<(&str, ListKind, &str, &str, bool)> = vec![
        ("a listed domain", ListKind::Domain, "mailinator.com\n", "mailinator.com", true),
        (
            "a subdomain of a listed domain",
            ListKind::Domain,
            "mailinator.com",
            "x.mailinator.com",
            true,
        ),
        (
            "a domain that only ends the same",
            ListKind::Domain,
            "mailinator.com",
            "notmailinator.com",
            false,
        ),
        (
            "an email address checks its domain",
            ListKind::Domain,
            "mailinator.com",
            "abc.def@mailinator.com",
            true,
        ),
        ("domains ignore case", ListKind::Domain, "Mailinator.COM", "mailinator.com", true),
        (
            "comments and blank lines are skipped",
            ListKind::Domain,
            "# header\n\n  yopmail.com  # inline\n",
            "yopmail.com",
            true,
        ),
        ("a single IPv4", ListKind::Ip, "185.220.101.1", "185.220.101.1", true),
        ("an IPv4 range", ListKind::Ip, "185.220.100.0/22", "185.220.103.255", true),
        (
            "just outside an IPv4 range",
            ListKind::Ip,
            "185.220.100.0/22",
            "185.220.104.0",
            false,
        ),
        ("an IPv6 range", ListKind::Ip, "2001:db8::/32", "2001:db8:ffff::1", true),
        ("IPv4 is not IPv6", ListKind::Ip, "::/0", "1.2.3.4", false),
        (
            "a FireHOL-style file with comments",
            ListKind::Ip,
            "# ipsum\n10.0.0.0/8\n192.168.1.1\n",
            "10.20.30.40",
            true,
        ),
        ("not an IP", ListKind::Ip, "10.0.0.0/8", "hello", false),
        ("a plain value", ListKind::Value, "openai\nchatgpt\n", "openai", true),
        ("values are exact", ListKind::Value, "openai", "openai7623", false),
    ];
    let mut failures = Vec::new();
    for (case, kind, text, probe, want) in cases {
        let mut list = List::new(kind);
        let problems = list.extend_from_text(text);
        if !problems.is_empty() {
            failures.push(format!("{case}: problems {problems:?}"));
        }
        if list.contains(probe) != want {
            failures.push(format!("{case}: {probe} should give {want}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_bad_line_is_reported_and_the_rest_is_kept() {
    let mut list = List::new(ListKind::Ip);
    let problems = list.extend_from_text("10.0.0.0/8\nnot-an-ip\n1.2.3.0/33\n8.8.8.8\n");
    assert_eq!(problems.len(), 2, "two bad lines: {problems:?}");
    assert!(problems[0].contains("line 2"), "{problems:?}");
    let secret = List::new(ListKind::Domain).extend_from_text("SMTP_PASSWORD=hunter2");
    assert!(
        secret.len() == 1 && !secret[0].contains("hunter2"),
        "a bad line is named by its number, never shown: a list file may be anything: {secret:?}"
    );
    assert!(list.contains("8.8.8.8"), "the good lines are kept");
    assert_eq!(list.len(), 2);
}

#[test]
fn removing_an_item_stops_matching_it() {
    let mut list = List::new(ListKind::Ip);
    list.extend_from_text("10.0.0.0/8\n1.2.3.4");
    assert!(list.remove("1.2.3.4"));
    assert!(!list.contains("1.2.3.4"));
    assert!(list.contains("10.1.1.1"));
    assert!(!list.remove("9.9.9.9"), "removing what is absent says so");
}

#[test]
fn an_item_added_for_a_while_matches_until_it_ends() {
    // (case, kind, item, until, probe, at, want)
    let cases: Vec<(&str, ListKind, &str, u64, &str, u64, bool)> = vec![
        ("a value before its end", ListKind::Value, "u_1", 1_000, "u_1", 999, true),
        ("a value at its end", ListKind::Value, "u_1", 1_000, "u_1", 1_000, false),
        (
            "an address inside its range before the end",
            ListKind::Ip,
            "203.0.113.0/24",
            1_000,
            "203.0.113.9",
            500,
            true,
        ),
        (
            "an address after the end",
            ListKind::Ip,
            "203.0.113.0/24",
            1_000,
            "203.0.113.9",
            2_000,
            false,
        ),
        (
            "a domain before its end",
            ListKind::Domain,
            "spam.example",
            1_000,
            "a@x.spam.example",
            10,
            true,
        ),
        (
            "a prefix after its end",
            ListKind::Prefix,
            "+3247",
            1_000,
            "+32470000000",
            1_001,
            false,
        ),
    ];
    let mut failures = Vec::new();
    for (case, kind, item, until, probe, at, want) in cases {
        let mut list = List::new(kind);
        list.insert_until(item, Some(until)).unwrap();
        if list.contains_at(probe, at) != want {
            failures.push(format!("{case}: {probe} at {at} should give {want}"));
        }
        if list.len() != 1 {
            failures.push(format!("{case}: the item is counted once, not {}", list.len()));
        }
    }
    let mut list = List::new(ListKind::Ip);
    list.insert("198.51.100.1").unwrap();
    list.insert_until("198.51.100.1", Some(10)).unwrap();
    if !list.contains_at("198.51.100.1", 50) {
        failures.push("an item kept for good stays when it is also added for a while".into());
    }
    let mut list = List::new(ListKind::Value);
    list.insert_until("u_2", Some(10)).unwrap();
    list.insert_until("u_2", Some(100)).unwrap();
    if !list.contains_at("u_2", 50) {
        failures.push("adding an item again moves its end".into());
    }
    list.remove("u_2");
    if list.contains_at("u_2", 5) {
        failures.push("a removed item ends at once".into());
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_text_mentions_an_item_in_any_case_and_follows_edits() {
    let mut list = List::new(ListKind::Value);
    list.extend_from_text("PayPal\nopenai");
    // (case, text, mentioned)
    let cases = [
        ("an item inside a word", "support-paypal-team", true),
        ("another case", "OpenAI billing", true),
        ("non-ASCII around it", "équipe PAYPAL ünited", true),
        ("nothing listed", "a plain username", false),
    ];
    let mut failures = Vec::new();
    for (case, text, want) in cases {
        if list.mentioned_in(text) != want {
            failures.push(format!("{case}: want {want}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
    list.insert("Stripe").unwrap();
    assert!(list.mentioned_in("stripe-help"), "an added item is found");
    list.remove("PayPal");
    assert!(!list.mentioned_in("paypal-help"), "a removed item is not");
}

// ------------------------------------------------- lists the engine fills

use openfraud::config::Config;
use openfraud::engine::{Engine, Options, Outcome};
use openfraud::event::RawEvent;
use serde_json::{Value, json};
use std::path::Path;

const LISTS: &str = r#"
[safety]
require_replay = false

[webhooks]
url = "https://hooks.example.com/openfraud"

[lists.trusted_pairs]
kind = "value"
key = "actor"
second = "device"
expire = "14d"
description = "A device trusted for one account"

[lists.hot_ips]
kind = "ip"
expire = "1h"

[lists.users_in_review]
kind = "value"
key = "actor"

[workflows.logins]
events = ["session.login"]
review_at = 50
block_at = 80
on_review = { actions = ["list.add:users_in_review"] }

[[workflows.logins.rules]]
id = "trusted_pair"
when = '"trusted_pairs" in event.lists'
decision = "allow"
reason = "A device this account proved it owns"

[[workflows.logins.rules]]
id = "verified_device"
when = "has(event.attrs.verified)"
actions = ["list.add:trusted_pairs"]
reason = "The account proved it owns this device"

[[workflows.logins.rules]]
id = "attack"
when = "has(event.attrs.attack)"
score = 60
actions = ["list.add:hot_ips"]
reason = "An attack"

[[workflows.logins.rules]]
id = "hot_ip"
when = '"hot_ips" in event.ip_lists'
decision = "block"
reason = "An address seen attacking within the hour"

[[workflows.logins.rules]]
id = "shadow_adder"
when = "has(event.attrs.shadow)"
mode = "shadow"
actions = ["list.add:users_in_review"]
reason = "Would put the account in review"
"#;

fn engine_with(text: &str) -> Engine {
    let config = Config::parse(text, Path::new(".")).unwrap();
    Engine::open(config, b"lists-test-key-lists-test-key-xx".to_vec(), None).unwrap()
}

fn send(e: &Engine, value: Value) -> Outcome {
    let raw: RawEvent = serde_json::from_value(value).unwrap();
    e.process(raw, Options::default()).unwrap()
}

fn login(actor: &str, device: &str, ip: &str, at: u64, attrs: Value) -> Value {
    json!({"type": "session.login", "actor_id": actor, "device": device, "ip": ip, "at": at, "attrs": attrs})
}

fn fired(out: &Outcome, rule: &str) -> bool {
    out.rules.iter().any(|r| r.id == rule)
}

fn webhooks(e: &Engine, kind: &str) -> Vec<Value> {
    e.with_store(|s| s.outbox_recent(500))
        .unwrap()
        .into_iter()
        .filter_map(|o| serde_json::from_str::<Value>(&o.payload).ok())
        .filter(|p| p["type"] == kind)
        .collect()
}

fn changes(out: &Outcome) -> Vec<(String, String)> {
    out.list_changes.iter().map(|c| (c.list.clone(), c.action.clone())).collect()
}

#[test]
fn a_rule_puts_what_it_saw_on_a_list_and_later_events_match_it() {
    let e = engine_with(LISTS);
    let day = 86_400;
    let proof = send(&e, login("u1", "d1", "192.0.2.1", 1_000, json!({"verified": true})));
    let mut failures = Vec::new();
    if changes(&proof) != [("trusted_pairs".to_string(), "add".to_string())] {
        failures.push(format!("the answer says which list changed: {:?}", proof.list_changes));
    }
    if proof.actions.iter().any(|a| a.action.starts_with("list.")) {
        failures.push(format!(
            "a list change is openfraud's own, not an action for the application: {:?}",
            proof.actions
        ));
    }
    // (case, event, the trusted pair matches)
    let steps = [
        (
            "the same account on the same device",
            login("u1", "d1", "192.0.2.1", 2_000, json!({})),
            true,
        ),
        (
            "the same account on another device",
            login("u1", "d2", "192.0.2.1", 2_001, json!({})),
            false,
        ),
        (
            "another account on the same device",
            login("u2", "d1", "192.0.2.1", 2_002, json!({})),
            false,
        ),
        (
            "the pair after its 14 days",
            login("u1", "d1", "192.0.2.1", 1_000 + 14 * day, json!({})),
            false,
        ),
    ];
    for (case, event, want) in steps {
        let out = send(&e, event);
        if fired(&out, "trusted_pair") != want {
            failures.push(format!("{case}: trusted_pair fired {}, want {want}", !want));
        }
    }

    let attack = send(&e, login("u3", "d3", "203.0.113.5", 5_000, json!({"attack": true})));
    let want = [
        ("hot_ips".to_string(), "add".to_string()),
        ("users_in_review".to_string(), "add".to_string()),
    ];
    if changes(&attack) != want {
        failures.push(format!(
            "a rule's list and the review band's list both get the event: {:?}",
            changes(&attack)
        ));
    }
    // (case, event, hot_ip fires)
    let steps = [
        (
            "another account from the address within the hour",
            login("u4", "d4", "203.0.113.5", 5_100, json!({})),
            true,
        ),
        (
            "the address after the hour",
            login("u5", "d5", "203.0.113.5", 5_000 + 3_601, json!({})),
            false,
        ),
    ];
    for (case, event, want) in steps {
        let out = send(&e, event);
        if fired(&out, "hot_ip") != want {
            failures.push(format!("{case}: hot_ip fired {}, want {want}", !want));
        }
    }
    send(&e, login("u6", "d6", "192.0.2.9", 6_000, json!({"shadow": true})));
    let review: Vec<String> = e
        .list_entries("users_in_review", false)
        .unwrap()
        .into_iter()
        .map(|i| i.value)
        .collect();
    if review != ["u3"] {
        failures.push(format!("a shadow rule changes no list: {review:?}"));
    }
    let entries = e.list_entries("hot_ips", false).unwrap();
    if entries.first().map(|i| i.by.as_str()) != Some("rule:attack") {
        failures.push(format!("an item says which rule put it there: {entries:?}"));
    }
    let created = webhooks(&e, "list_item.created");
    if created.len() != 3 || created.iter().any(|w| w["data"]["list"].is_null()) {
        failures.push(format!("each new item is announced: {created:?}"));
    }
    let dry: RawEvent = serde_json::from_value(login("u7", "d7", "192.0.2.7", 7_000, json!({"verified": true}))).unwrap();
    e.process(dry, Options { dry_run: true, now: None }).unwrap();
    if e.list_entries("trusted_pairs", true).unwrap().iter().any(|i| i.value == "u7") {
        failures.push("a dry run changes no list".into());
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_person_adds_archives_and_restores_list_items() {
    let e = engine_with(LISTS);
    let mut failures = Vec::new();
    // A pair given by a person names the raw device: it is stored as the
    // pseudonym events carry.
    e.add_list_entry("trusted_pairs", "u9", Some("raw-device-9"), None, "admin", "seen in person")
        .unwrap();
    if !fired(
        &send(&e, login("u9", "raw-device-9", "192.0.2.1", 1_000, json!({}))),
        "trusted_pair",
    ) {
        failures.push("a pair added by a person matches the account on that device".into());
    }
    let entries = e.list_entries("trusted_pairs", false).unwrap();
    let pair = &entries[0];
    if pair.second.as_deref() == Some("raw-device-9") || pair.second.is_none() {
        failures.push(format!("the device is kept as a pseudonym: {pair:?}"));
    }
    if (pair.by.as_str(), pair.note.as_str()) != ("admin", "seen in person") || pair.expires_at.is_none() {
        failures.push(format!("the item keeps its author, note and the list's lifetime: {pair:?}"));
    }
    e.add_list_entry("users_in_review", "u8", None, Some(50_000), "admin", "").unwrap();
    assert!(e.archive_list_item("users_in_review", "u8", None, "admin").unwrap());
    if !e.list_entries("users_in_review", false).unwrap().is_empty() {
        failures.push("an archived item leaves the active list".into());
    }
    let archived = e.list_entries("users_in_review", true).unwrap();
    if archived.len() != 1 || archived[0].archived_at.is_none() {
        failures.push(format!("an archived item is kept for the record: {archived:?}"));
    }
    assert!(e.unarchive_list_item("users_in_review", "u8", None, "admin").unwrap());
    if e.list_entries("users_in_review", false).unwrap().iter().all(|i| i.value != "u8") {
        failures.push("a restored item is active again".into());
    }
    for kind in ["list_item.archived", "list_item.unarchived"] {
        if webhooks(&e, kind).is_empty() {
            failures.push(format!("{kind} is announced"));
        }
    }
    // The 14 days of the pair end: maintenance archives it and says so.
    let ends = e.list_entries("trusted_pairs", false).unwrap()[0].expires_at.unwrap();
    e.maintain(ends + 1).unwrap();
    let after = e.list_entries("trusted_pairs", true).unwrap();
    if after.iter().any(|i| i.archived_at.is_none()) {
        failures.push(format!("an item past its end is archived: {after:?}"));
    }
    let csv = e.list_csv("trusted_pairs").unwrap();
    if !csv.starts_with("value,second,added_at,expires_at,archived_at,by,note\n") || !csv.contains("u9,") {
        failures.push(format!("a list exports as CSV: {csv}"));
    }
    if e.add_list_entry("users_in_review", "u1", Some("x"), None, "admin", "").is_ok() {
        failures.push("a second value on a list of one key is refused".into());
    }
    if e.add_list_entry("trusted_pairs", "u1", None, None, "admin", "").is_ok() {
        failures.push("a pair list needs its second value".into());
    }
    e.erase("u9", "admin").unwrap();
    if e.list_entries("trusted_pairs", true).unwrap().iter().any(|i| i.value == "u9") {
        failures.push("an erased account leaves no list item".into());
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn an_allow_rule_that_stops_ends_every_workflow_but_the_blocks() {
    let text = r#"
[safety]
require_replay = false

[lists.trusted_pairs]
kind = "value"
key = "actor"
second = "device"

[workflows.allowlist]
events = ["session.login"]

[[workflows.allowlist.rules]]
id = "known_pair"
when = '"trusted_pairs" in event.lists'
decision = "allow"
stop = true
reason = "A device this account proved it owns"

[workflows.risk]
events = ["session.login"]
step_up_at = 30

[[workflows.risk.rules]]
id = "always_risky"
when = "true"
score = 40
reason = "Always risky in this test"
"#;
    let e = engine_with(text);
    e.add_list_entry("trusted_pairs", "u1", Some("d1"), None, "admin", "").unwrap();
    e.add_list_item("blocked_actors", "u2", "admin", "").unwrap();
    e.add_list_entry("trusted_pairs", "u2", Some("d2"), None, "admin", "").unwrap();
    // (case, actor, device, decision, stopped by)
    let cases = [
        ("a trusted pair skips the other workflows", "u1", "d1", "allow", Some("known_pair")),
        ("an unknown pair is stepped up", "u1", "d9", "step_up", None),
        ("a block by an administrator still blocks", "u2", "d2", "block", Some("known_pair")),
    ];
    let mut failures = Vec::new();
    for (case, actor, device, decision, stopped) in cases {
        let out = send(&e, login(actor, device, "192.0.2.1", 1_000, json!({})));
        if out.decision.as_str() != decision || out.stopped_by.as_deref() != stopped {
            failures.push(format!("{case}: {} stopped by {:?}", out.decision.as_str(), out.stopped_by));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
