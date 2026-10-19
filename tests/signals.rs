//! Email signals rules can call: which mailbox provider an address belongs
//! to, how many providers a recipient list spans, and whether recipients
//! look like the sender. They work on pseudonyms, as rules see them.
#![allow(clippy::type_complexity)]

use openfraud::event::Pseudonymizer;
use openfraud::signals::{alike, freemail_share, provider, providers};

fn p() -> Pseudonymizer {
    Pseudonymizer::new(b"signals-test-key-signals-test-key".to_vec())
}

#[test]
fn a_domain_maps_to_its_mailbox_provider() {
    let cases = [
        ("gmail.com", "google"),
        ("yahoo.com", "yahoo"),
        ("yahoo.fr", "yahoo"),
        ("ymail.com", "yahoo"),
        ("outlook.com", "microsoft"),
        ("hotmail.fr", "microsoft"),
        ("live.be", "microsoft"),
        ("msn.com", "microsoft"),
        ("icloud.com", "apple"),
        ("me.com", "apple"),
        ("gmx.de", "gmx"),
        ("web.de", "gmx"),
        ("proton.me", "proton"),
        ("protonmail.com", "proton"),
        ("aol.com", "aol"),
        ("yandex.ru", "yandex"),
        ("mail.ru", "mailru"),
        ("acme.io", ""),
        ("mail.acme.io", ""),
        ("notgmail.com", ""),
    ];
    let mut failures = Vec::new();
    for (domain, want) in cases {
        let got = provider(&format!("abc.def@{domain}"));
        if got != want {
            failures.push(format!("{domain}: got {got:?}, want {want:?}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_recipient_list_is_measured_by_providers_and_freemail_share() {
    let p = p();
    // (case, recipients, providers, freemail share)
    let cases: Vec<(&str, Vec<&str>, i64, f64)> = vec![
        (
            "the inbox placement probe: one address per big provider",
            vec!["a1@gmail.com", "b2@yahoo.com", "c3@outlook.com", "d4@icloud.com"],
            4,
            1.0,
        ),
        ("a company list", vec!["ann@acme.io", "bob@acme.io", "eve@corp.example"], 0, 0.0),
        (
            "a mixed real audience",
            vec!["ann@acme.io", "x@gmail.com", "y@gmail.com", "z@hotmail.com"],
            2,
            0.75,
        ),
        ("an empty list", vec![], 0, 0.0),
    ];
    let mut failures = Vec::new();
    for (case, recipients, want_providers, want_share) in cases {
        let list: Vec<String> = recipients.iter().map(|r| p.email(r)).collect();
        let got = providers(&list);
        if got != want_providers {
            failures.push(format!("{case}: providers {got}, want {want_providers}"));
        }
        let share = freemail_share(&list);
        if (share - want_share).abs() > 1e-9 {
            failures.push(format!("{case}: share {share}, want {want_share}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn recipients_that_look_like_the_sender_are_counted() {
    let p = p();
    // (case, sender, recipients, how many look like the sender)
    let cases: Vec<(&str, &str, Vec<&str>, i64)> = vec![
        (
            "the same stem with digits on every provider",
            "openai7623@gmail.com",
            vec![
                "openai1@yahoo.com",
                "openai22@outlook.com",
                "open.ai@icloud.com",
                "friend@gmail.com",
            ],
            3,
        ),
        (
            "the sender's own mailbox with a plus tag",
            "max@gmail.com",
            vec!["max+test@gmail.com", "m.a.x@gmail.com"],
            2,
        ),
        ("strangers", "max@gmail.com", vec!["ann@acme.io", "bob@yahoo.com"], 0),
    ];
    let mut failures = Vec::new();
    for (case, sender, recipients, want) in cases {
        let list: Vec<String> = recipients.iter().map(|r| p.email(r)).collect();
        let got = alike(&list, &p.email(sender));
        if got != want {
            failures.push(format!("{case}: got {got}, want {want}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
