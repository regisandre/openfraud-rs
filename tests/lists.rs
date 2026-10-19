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
