//! Email signals rules can call: which mailbox provider an address belongs
//! to, how many providers a recipient list spans, and whether recipients
//! look like the sender. They work on pseudonyms, as rules see them.
#![allow(clippy::type_complexity)]

use openfraud::event::Pseudonymizer;
use openfraud::signals::{EmailShape, alike, email_shape, freemail_share, provider, providers};

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

#[test]
fn an_address_is_measured_before_it_becomes_a_pseudonym() {
    // (case, address, expected shape: tagged, length, digits, digit_run, numeric, no_vowels, role, generated)
    let cases: Vec<(&str, &str, Option<(bool, i64, i64, i64, bool, bool, bool, bool)>)> = vec![
        (
            "a plain name",
            "john.smith@gmail.com",
            Some((false, 10, 0, 0, false, false, false, false)),
        ),
        (
            "a plus tag",
            "John+promo@gmail.com",
            Some((true, 10, 0, 0, false, false, false, false)),
        ),
        (
            "gmail dots are not a tag",
            "j.o.h.n@gmail.com",
            Some((false, 7, 0, 0, false, false, false, false)),
        ),
        (
            "a birth year",
            "hirsch1990@web.de",
            Some((false, 10, 4, 4, false, false, false, false)),
        ),
        ("only digits", "12345678@qq.com", Some((false, 8, 8, 8, true, false, false, false))),
        ("no vowel", "xkqzvbtw@mail.com", Some((false, 8, 0, 0, false, true, false, true))),
        (
            "letters and digits shuffled",
            "a8f3k2j9x1@outlook.com",
            Some((false, 10, 5, 1, false, false, false, true)),
        ),
        (
            "a long consonant run",
            "qwrtzpaul@mail.com",
            Some((false, 9, 0, 0, false, false, false, true)),
        ),
        (
            "a function mailbox",
            "Info@company.com",
            Some((false, 4, 0, 0, false, false, true, false)),
        ),
        (
            "a real name with a run of four",
            "anna.schwarz@x.org",
            Some((false, 12, 0, 0, false, false, false, false)),
        ),
        ("not an address", "not an address", None),
    ];
    let mut failures = Vec::new();
    for (case, address, want) in cases {
        let got = email_shape(address).map(|s: EmailShape| {
            (
                s.tagged,
                s.length,
                s.digits,
                s.digit_run,
                s.numeric,
                s.no_vowels,
                s.role,
                s.generated,
            )
        });
        if got != want {
            failures.push(format!("{case}: {address} gave {got:?}, want {want:?}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_phone_number_and_a_country_have_a_calling_code() {
    use openfraud::signals::{calling_code, phone_code};
    // (case, number, its calling code)
    let numbers = [
        ("Belgium", "+32470123456", "+32"),
        ("the United States", "+14155550100", "+1"),
        ("Kazakhstan shares Russia's code", "+77011234567", "+7"),
        ("a three-digit code", "+351912345678", "+351"),
        ("not a number", "0470123456", ""),
    ];
    // (case, country, its calling code)
    let countries = [
        ("Belgium", "BE", "+32"),
        ("lower case", "fr", "+33"),
        ("Canada shares the US code", "CA", "+1"),
        ("Jersey uses the UK code", "JE", "+44"),
        ("an unknown country", "ZZ", ""),
    ];
    let mut failures = Vec::new();
    for (case, number, want) in numbers {
        if phone_code(number) != want {
            failures.push(format!("{case}: {number} gave {:?}", phone_code(number)));
        }
    }
    for (case, country, want) in countries {
        if calling_code(country) != want {
            failures.push(format!("{case}: {country} gave {:?}", calling_code(country)));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn an_address_domain_is_reduced_to_the_domain_someone_registered() {
    use openfraud::signals::registered_domain;
    // (case, domain, registered domain)
    let cases: Vec<(&str, &str, Option<&str>)> = vec![
        ("a plain domain", "example.com", Some("example.com")),
        ("a subdomain", "mail.a.example.com", Some("example.com")),
        ("a two-level suffix", "x.example.co.uk", Some("example.co.uk")),
        ("a suffix of a hosting service", "ann.github.io", Some("ann.github.io")),
        ("under a wildcard suffix", "a.b.ck", Some("a.b.ck")),
        ("an exception to a wildcard", "x.www.ck", Some("www.ck")),
        ("an unknown top-level domain", "a.b.zzzz", Some("b.zzzz")),
        ("case and a trailing dot", "Mail.Example.COM.", Some("example.com")),
        ("a public suffix alone", "co.uk", None),
        ("no dot", "localhost", None),
    ];
    let mut failures = Vec::new();
    for (case, domain, want) in cases {
        let got = registered_domain(domain);
        if got.as_deref() != want {
            failures.push(format!("{case}: {got:?}, want {want:?}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_mail_exchanger_answer_says_whether_a_domain_takes_mail() {
    use openfraud::signals::{mx_query, mx_reachable};
    let query = mx_query("example.com", 0x1234);
    // A reply: the query's header and question, then the answer section.
    let reply = |rcode: u8, answers: &[&[u8]]| -> Vec<u8> {
        let mut r = query.clone();
        r[2] = 0x81;
        r[3] = 0x80 | rcode;
        r[6] = 0;
        r[7] = answers.len() as u8;
        for a in answers {
            r.extend_from_slice(a);
        }
        r
    };
    // name pointer to the question, type MX, class IN, ttl, length, preference, exchange
    let mx = |preference: u8, exchange: &[u8]| -> Vec<u8> {
        let mut a = vec![0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01, 0, 0, 0x0e, 0x10];
        a.extend_from_slice(&((2 + exchange.len()) as u16).to_be_bytes());
        a.extend_from_slice(&[0, preference]);
        a.extend_from_slice(exchange);
        a
    };
    let mail = mx(10, b"\x04mail\x07example\x03com\x00");
    let null = mx(0, b"\x00");
    // (case, reply, takes mail: None when it cannot be told)
    let cases: Vec<(&str, Vec<u8>, Option<bool>)> = vec![
        ("a mail exchanger", reply(0, &[&mail]), Some(true)),
        ("no such domain", reply(3, &[]), Some(false)),
        ("a null mail exchanger (RFC 7505)", reply(0, &[&null]), Some(false)),
        ("no record: mail goes to the address record", reply(0, &[]), Some(true)),
        ("a server failure", reply(2, &[]), None),
        (
            "another query's answer",
            {
                let mut r = reply(0, &[&mail]);
                r[0] ^= 0xff;
                r
            },
            None,
        ),
        ("a truncated reply", reply(0, &[&mail])[..20].to_vec(), None),
    ];
    let mut failures = Vec::new();
    for (case, bytes, want) in cases {
        let got = mx_reachable(&bytes, 0x1234);
        if got != want {
            failures.push(format!("{case}: {got:?}, want {want:?}"));
        }
    }
    if &query[12..25] != b"\x07example\x03com\x00" || query[25..29] != [0, 0x0f, 0, 1] {
        failures.push(format!("the question asks for MX records of example.com: {query:?}"));
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
