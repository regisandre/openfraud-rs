//! What an incoming event becomes before any rule sees it: times read,
//! names checked, and every email address and IP address replaced by a
//! keyed pseudonym.
#![allow(clippy::type_complexity)]

use openfraud::config::Privacy;
use openfraud::event::{Pseudonymizer, RawEvent, parse_time, valid_type};
use serde_json::json;

fn pseudo() -> Pseudonymizer {
    Pseudonymizer::new(b"0123456789abcdef0123456789abcdef".to_vec())
}

#[test]
fn a_time_is_unix_seconds_or_rfc3339() {
    // (input, unix seconds or None when refused)
    let cases: Vec<(serde_json::Value, Option<u64>)> = vec![
        (json!(1_792_420_320), Some(1_792_420_320)),
        (json!(1_792_420_320.9), Some(1_792_420_320)),
        (json!("2026-10-19T12:32:00Z"), Some(1_792_413_120)),
        (json!("2026-10-19T14:32:00+02:00"), Some(1_792_413_120)),
        (json!("2026-10-19T14:32:00.250+02:00"), Some(1_792_413_120)),
        (json!("1970-01-01T00:00:00Z"), Some(0)),
        (json!("2024-02-29T00:00:00Z"), Some(1_709_164_800)),
        (json!("2026-13-01T00:00:00Z"), None),
        (json!("2026-10-19 12:32:00"), None),
        (json!("yesterday"), None),
        (json!(-5), None),
        (json!(true), None),
    ];
    let mut failures = Vec::new();
    for (input, want) in cases {
        let got = parse_time(&input).ok();
        if got != want {
            failures.push(format!("{input}: got {got:?}, want {want:?}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn an_event_type_is_lowercase_dotted_words() {
    let cases = [
        ("account.created", true),
        ("message.send_requested", true),
        ("x.custom_thing2", true),
        ("signup", true),
        ("Account.Created", false),
        ("account..created", false),
        (".created", false),
        ("account.created.", false),
        ("account created", false),
        ("2fa.enabled", false),
        ("", false),
    ];
    let mut failures = Vec::new();
    for (name, want) in cases {
        if valid_type(name) != want {
            failures.push(format!("{name:?}: want {want}"));
        }
    }
    assert!(!valid_type(&"a".repeat(65)), "a 65-character type is refused");
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn email_addresses_become_pseudonyms_that_keep_the_domain() {
    let p = pseudo();
    // (case, a, b, same pseudonym, same stem)
    let cases: Vec<(&str, &str, &str, bool, bool)> = vec![
        ("case and spaces do not matter", " John@Gmail.com", "john@gmail.com", true, true),
        ("gmail ignores dots", "j.o.h.n@gmail.com", "john@gmail.com", true, true),
        ("gmail ignores a plus tag", "john+promo@gmail.com", "john@gmail.com", true, true),
        ("googlemail is gmail", "john@googlemail.com", "john@gmail.com", true, true),
        (
            "any provider ignores a plus tag",
            "ann+x@outlook.com",
            "ann@outlook.com",
            true,
            true,
        ),
        ("dots count outside gmail", "a.nn@outlook.com", "ann@outlook.com", false, true),
        (
            "digits make another address with the same stem",
            "openai7623@gmail.com",
            "openai@gmail.com",
            false,
            true,
        ),
        (
            "the same stem on two providers",
            "openai7623@yahoo.com",
            "openai@icloud.com",
            false,
            true,
        ),
        ("other people", "alice@gmail.com", "bob@gmail.com", false, false),
    ];
    let mut failures = Vec::new();
    for (case, a, b, same, same_stem) in cases {
        let (pa, pb) = (p.email(a), p.email(b));
        if (pa == pb) != same {
            failures.push(format!("{case}: {pa} vs {pb}, same pseudonym should be {same}"));
        }
        let stem = |s: &str| s.split('@').next().unwrap().split('.').nth(1).unwrap().to_owned();
        if (stem(&pa) == stem(&pb)) != same_stem {
            failures.push(format!("{case}: {pa} vs {pb}, same stem should be {same_stem}"));
        }
        if a.contains('@')
            && !pa.ends_with(
                &a.trim()
                    .to_lowercase()
                    .split('@')
                    .nth(1)
                    .unwrap()
                    .replace("googlemail.com", "gmail.com"),
            )
        {
            failures.push(format!("{case}: {pa} lost its domain"));
        }
        if pa.contains(&a.trim().to_lowercase().split('@').next().unwrap().to_owned()) {
            failures.push(format!("{case}: {pa} shows the local part"));
        }
    }
    let other = Pseudonymizer::new(b"another key, another pseudonym!!".to_vec());
    if other.email("john@gmail.com") == p.email("john@gmail.com") {
        failures.push("another key gives the same pseudonym".into());
    }
    assert_eq!(p.email("not an address"), p.email("not an address"));
    assert!(
        p.email("not an address").ends_with("@invalid"),
        "an invalid address gets the domain `invalid`"
    );
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn an_event_is_normalized_before_rules_see_it() {
    let p = pseudo();
    let raw: RawEvent = serde_json::from_value(json!({
        "id": "evt_1",
        "type": "message.send_requested",
        "at": "2026-10-19T12:47:00Z",
        "actor_id": "u_1",
        "tenant_id": "ws_9",
        "owner_id": "u_0",
        "email": "Owner@Gmail.com",
        "phone": "+32 470 12-34-56",
        "ip": "203.0.113.77",
        "device": "dev-1",
        "country": "be",
        "subject": { "type": "page", "id": "p_77" },
        "attrs": {
            "recipients": ["a@gmail.com", "b@yahoo.com"],
            "billing_email": "x@outlook.com",
            "numbers": ["+447700900101", "+447700900102", "+447700900103", "+33612345678"],
            "count": 4,
            "card_fingerprint": "fp_123"
        }
    }))
    .unwrap();
    let privacy = Privacy {
        contact_attrs: vec!["recipients".into(), "billing_email".into(), "numbers".into()],
        id_attrs: vec!["card_fingerprint".into()],
    };
    let ev = raw.normalize(&p, &privacy, 2_000_000_000).unwrap();
    let mut failures = Vec::new();
    let check = |failures: &mut Vec<String>, case: &str, ok: bool| {
        if !ok {
            failures.push(case.to_owned());
        }
    };
    check(&mut failures, "the id is kept", ev.id == "evt_1");
    check(&mut failures, "the time is read", ev.at == 1_792_414_020);
    check(
        &mut failures,
        "the actor, tenant and owner are kept",
        (ev.actor.as_deref(), ev.tenant.as_deref(), ev.owner.as_deref()) == (Some("u_1"), Some("ws_9"), Some("u_0")),
    );
    check(
        &mut failures,
        "the email is a pseudonym",
        ev.email.as_deref() == Some(p.email("owner@gmail.com").as_str()),
    );
    check(
        &mut failures,
        "the email domain is kept",
        ev.email_domain.as_deref() == Some("gmail.com"),
    );
    check(
        &mut failures,
        "the phone keeps its first digits only",
        ev.phone_prefix.as_deref() == Some("+324701"),
    );
    check(&mut failures, "the country is upper case", ev.country.as_deref() == Some("BE"));
    check(
        &mut failures,
        "the IP prefix is a /24",
        ev.ip_prefix.as_deref() == Some("203.0.113.0/24"),
    );
    check(
        &mut failures,
        "the IP is hashed",
        ev.ip_hash.as_deref().is_some_and(|h| h.len() == 16 && !h.contains("203")),
    );
    check(
        &mut failures,
        "the raw IP is kept in memory only",
        ev.ip.map(|ip| ip.to_string()) == Some("203.0.113.77".into()),
    );
    let stored = serde_json::to_string(&ev).unwrap();
    check(&mut failures, "the raw IP is never serialized", !stored.contains("203.0.113.77"));
    check(
        &mut failures,
        "no raw address is serialized",
        !stored.contains("a@gmail.com") && !stored.contains("x@outlook.com") && !stored.contains("Owner"),
    );
    check(
        &mut failures,
        "no full phone number is serialized",
        !stored.contains("447700900101") && !stored.contains("4701234"),
    );
    check(
        &mut failures,
        "a list of addresses keeps its length",
        ev.attrs["recipients"].as_array().map(|a| a.len()) == Some(2),
    );
    check(
        &mut failures,
        "a phone in a list keeps its prefix",
        ev.attrs["numbers"][0].as_str().is_some_and(|n| n.starts_with("+447700~")),
    );
    check(
        &mut failures,
        "a list of numbers gets its shape",
        ev.attrs["numbers_shape"] == json!({"count": 4, "roles": 0, "invalid": 0, "prefixes": 2, "longest_run": 3}),
    );
    check(
        &mut failures,
        "a list of addresses gets its shape too",
        ev.attrs["recipients_shape"] == json!({"count": 2, "roles": 0, "invalid": 0, "prefixes": 0, "longest_run": 0}),
    );
    check(
        &mut failures,
        "a single address gets no shape",
        ev.attrs.get("billing_email_shape").is_none(),
    );
    check(&mut failures, "other attributes are untouched", ev.attrs["count"] == json!(4));
    check(
        &mut failures,
        "an identifier attribute is hashed",
        ev.attrs["card_fingerprint"]
            .as_str()
            .is_some_and(|v| v != "fp_123" && v.len() == 16),
    );
    check(
        &mut failures,
        "the identifiers hold card, device, email, the IP, its network and the phone",
        {
            let kinds: Vec<&str> = ev.ids.keys().map(String::as_str).collect();
            kinds == ["card_fingerprint", "device", "email", "ip", "ip_prefix", "phone"]
        },
    );
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn an_event_type_is_known_or_declared() {
    let custom = vec!["x.game_won".to_owned()];
    // (type, accepted)
    let cases = [
        ("account.created", true),
        ("session.login", true),
        ("payment.method_added", true),
        ("subscription.trial_started", true),
        ("message.contacts_imported", true),
        ("payout.destination_changed", true),
        ("usage.recorded", true),
        ("content.moderated", true),
        ("x.game_won", true),
        ("account.exploded", false),
        ("x.unknown", false),
    ];
    let mut failures = Vec::new();
    for (kind, want) in cases {
        if openfraud::event::known_type(kind, &custom) != want {
            failures.push(format!("{kind}: want {want}"));
        }
    }
    assert!(openfraud::event::VOCABULARY.len() >= 40, "the vocabulary covers the nine families");
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_bad_event_is_refused_with_a_reason() {
    let p = pseudo();
    // (case, event, words in the error)
    let cases: Vec<(&str, serde_json::Value, &str)> = vec![
        ("no type", json!({"user": "u"}), "type"),
        ("a bad type", json!({"type": "Bad Type"}), "type"),
        ("a bad time", json!({"type": "a.b", "at": "soon"}), "at"),
        ("a bad ip", json!({"type": "a.b", "ip": "999.1.1.1"}), "ip"),
        (
            "a too long actor id",
            json!({"type": "a.b", "actor_id": "u".repeat(300)}),
            "actor_id",
        ),
        (
            "a phone without a country code",
            json!({"type": "a.b", "phone": "0470123456"}),
            "phone",
        ),
        ("attrs that are not an object", json!({"type": "a.b", "attrs": [1]}), "attrs"),
    ];
    let mut failures = Vec::new();
    for (case, value, words) in cases {
        let result = serde_json::from_value::<RawEvent>(value)
            .map_err(|e| e.to_string())
            .and_then(|raw| raw.normalize(&p, &Privacy::default(), 0).map_err(|e| e.to_string()));
        match result {
            Ok(_) => failures.push(format!("{case}: accepted")),
            Err(e) if !e.contains(words) => failures.push(format!("{case}: {e:?} does not name {words}")),
            Err(_) => {}
        }
    }
    let ok: RawEvent = serde_json::from_value(json!({"type": "a.b"})).unwrap();
    let ev = ok.normalize(&p, &Privacy::default(), 1_234).unwrap();
    assert_eq!(ev.at, 1_234, "an event without a time happens now");
    assert!(ev.id.starts_with("evt_"), "an event without an id gets one: {}", ev.id);
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_time_is_written_back_as_rfc3339() {
    let cases = [
        (0, "1970-01-01T00:00:00Z"),
        (1_709_164_800, "2024-02-29T00:00:00Z"),
        (1_792_413_120, "2026-10-19T12:32:00Z"),
    ];
    let mut failures = Vec::new();
    for (secs, text) in cases {
        let got = openfraud::event::format_time(secs);
        if got != text {
            failures.push(format!("{secs}: got {got}, want {text}"));
        }
        if parse_time(&json!(got)).ok() != Some(secs) {
            failures.push(format!("{secs}: does not read back"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_contact_list_is_measured_before_it_is_pseudonymized() {
    let p = pseudo();
    let privacy = Privacy {
        contact_attrs: vec!["to".into()],
        id_attrs: vec![],
    };
    // (case, list, roles, invalid)
    let cases: Vec<(&str, Vec<&str>, u64, u64)> = vec![
        ("people", vec!["ann@example.org", "bob.smith@example.com"], 0, 0),
        (
            "role addresses",
            vec![
                "admin@example.org",
                "Info@example.com",
                "no-reply@example.net",
                "sales+eu@example.com",
                "ann@example.org",
            ],
            4,
            0,
        ),
        (
            "invalid addresses",
            vec!["ann@", "bob example.com", "@example.org", "carol@localhost", "dave@example.org"],
            0,
            4,
        ),
    ];
    let mut failures = Vec::new();
    for (case, list, roles, invalid) in cases {
        let raw: RawEvent = serde_json::from_value(json!({"type": "message.contacts_imported", "attrs": {"to": list}})).unwrap();
        let ev = raw.normalize(&p, &privacy, 1_000).unwrap();
        let shape = &ev.attrs["to_shape"];
        if shape["count"] != json!(list.len()) || shape["roles"] != json!(roles) || shape["invalid"] != json!(invalid) {
            failures.push(format!("{case}: {shape}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
