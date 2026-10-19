//! Sliding-window counters: how many events, or how many distinct values,
//! a key had over the last span of time.
// Case tables are tuples on purpose: one row per case, read at a glance.
#![allow(clippy::type_complexity)]

use openfraud::window::{Counter, parse_duration};

#[test]
fn a_duration_is_a_number_and_a_unit() {
    // (text, seconds or None when refused)
    let cases: Vec<(&str, Option<u64>)> = vec![
        ("30s", Some(30)),
        ("15m", Some(900)),
        ("1h", Some(3_600)),
        ("24h", Some(86_400)),
        ("7d", Some(604_800)),
        (" 2h ", Some(7_200)),
        ("0s", None),
        ("h", None),
        ("10", None),
        ("5w", None),
        ("-1h", None),
        ("400d", None),
    ];
    let mut failures = Vec::new();
    for (text, want) in cases {
        let got = parse_duration(text).ok();
        if got != want {
            failures.push(format!("{text:?}: got {got:?}, want {want:?}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_counter_counts_what_happened_inside_its_window() {
    // (case, window seconds, distinct, events as (key, at, value), query key, query time, want)
    let cases: Vec<(&str, u64, bool, Vec<(&str, u64, Option<&str>)>, &str, u64, u64)> = vec![
        (
            "two events of one key",
            3_600,
            false,
            vec![("ip1", 1_000, None), ("ip1", 1_500, None)],
            "ip1",
            1_500,
            2,
        ),
        (
            "another key does not count",
            3_600,
            false,
            vec![("ip1", 1_000, None), ("ip2", 1_500, None)],
            "ip1",
            1_500,
            1,
        ),
        (
            "an unknown key is zero",
            3_600,
            false,
            vec![("ip1", 1_000, None)],
            "nobody",
            1_500,
            0,
        ),
        (
            "an event older than the window is forgotten",
            3_600,
            false,
            vec![("ip1", 0, None), ("ip1", 7_200, None)],
            "ip1",
            7_200,
            1,
        ),
        (
            "an event exactly one window old is forgotten",
            3_600,
            false,
            vec![("ip1", 3_600, None), ("ip1", 7_200, None)],
            "ip1",
            7_200,
            1,
        ),
        (
            "distinct counts each value once",
            86_400,
            true,
            vec![("ip1", 10, Some("u1")), ("ip1", 20, Some("u1")), ("ip1", 30, Some("u2"))],
            "ip1",
            30,
            2,
        ),
        (
            "distinct forgets a value seen only before the window",
            3_600,
            true,
            vec![("card", 0, Some("u1")), ("card", 4_000, Some("u2")), ("card", 4_100, Some("u3"))],
            "card",
            4_100,
            2,
        ),
        (
            "distinct keeps a value seen again inside the window",
            3_600,
            true,
            vec![("card", 0, Some("u1")), ("card", 4_000, Some("u1")), ("card", 4_100, Some("u2"))],
            "card",
            4_100,
            2,
        ),
        (
            "an event without a value is not counted by a distinct counter",
            3_600,
            true,
            vec![("card", 10, None), ("card", 20, Some("u1"))],
            "card",
            20,
            1,
        ),
        (
            "an event that arrives late still counts while inside the window",
            3_600,
            false,
            vec![("ip1", 5_000, None), ("ip1", 4_000, None)],
            "ip1",
            5_000,
            2,
        ),
    ];
    let mut failures = Vec::new();
    for (case, span, distinct, events, key, now, want) in cases {
        let mut counter = Counter::new(span, distinct);
        for (k, at, value) in events {
            counter.add(k, at, value);
        }
        let got = counter.get(key, now);
        if got != want {
            failures.push(format!("{case}: got {got}, want {want}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn pruning_drops_keys_with_nothing_left_in_their_window() {
    let mut counter = Counter::new(60, false);
    counter.add("old", 0, None);
    counter.add("new", 1_000, None);
    counter.prune(1_000);
    assert_eq!(counter.keys(), 1, "only the key with a recent event stays");
    assert_eq!(counter.get("new", 1_000), 1, "the recent key keeps its count");
}

#[test]
fn memory_per_key_stays_bounded() {
    // A hot key with an event every second for a day keeps a fixed number
    // of buckets, and a distinct counter keeps at most its cap of values.
    let mut counter = Counter::new(86_400, false);
    for at in 0..86_400 {
        counter.add("hot", at, None);
    }
    assert_eq!(counter.get("hot", 86_399), 86_400, "every event counted");
    assert!(counter.buckets("hot") <= 121, "buckets: {}", counter.buckets("hot"));

    let mut distinct = Counter::new(86_400, true);
    for i in 0..20_000 {
        distinct.add("hot", 10, Some(&format!("v{i}")));
    }
    assert_eq!(
        distinct.get("hot", 10),
        openfraud::window::MAX_DISTINCT as u64,
        "a distinct counter saturates at its cap"
    );
}

#[test]
fn a_counter_can_say_what_it_would_count_without_counting() {
    // (case, distinct, events, probe value, want)
    let cases: Vec<(&str, bool, Vec<Option<&str>>, Option<&str>, u64)> = vec![
        ("a plain counter adds the event", false, vec![None, None], None, 3),
        ("a new distinct value adds one", true, vec![Some("u1")], Some("u2"), 2),
        ("a known distinct value adds nothing", true, vec![Some("u1")], Some("u1"), 1),
        ("no value adds nothing to a distinct counter", true, vec![Some("u1")], None, 1),
    ];
    let mut failures = Vec::new();
    for (case, distinct, events, probe, want) in cases {
        let mut counter = Counter::new(3_600, distinct);
        for value in events {
            counter.add("k", 100, value);
        }
        let got = counter.count_with("k", 100, probe);
        if got != want {
            failures.push(format!("{case}: got {got}, want {want}"));
        }
        if counter.count_with("k", 100, probe) != got {
            failures.push(format!("{case}: asking twice changed the answer"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_sum_counter_adds_up_amounts() {
    let mut counter = Counter::new(3_600, false);
    counter.add_weighted("store", 100, None, 2_500);
    counter.add_weighted("store", 200, None, 1_000);
    assert_eq!(counter.get("store", 300), 3_500, "two amounts in the window");
    counter.add_weighted("store", 5_000, None, 7);
    assert_eq!(counter.get("store", 5_000), 7, "the old amounts left the window");
    assert_eq!(
        counter.count_with_weight("store", 5_000, None, 10),
        17,
        "what it would be with one more amount"
    );
    assert_eq!(counter.get("store", 5_000), 7, "asking did not add");

    // Huge amounts saturate: a sum never wraps back to a small number.
    counter.add_weighted("whale", 100, None, u64::MAX / 2 + 1);
    counter.add_weighted("whale", 100, None, u64::MAX / 2 + 1);
    counter.add_weighted("whale", 200, None, u64::MAX);
    assert_eq!(counter.get("whale", 300), u64::MAX, "the sum saturates");
    assert_eq!(counter.count_with_weight("whale", 300, None, 5), u64::MAX, "and so does asking");
}

#[test]
fn merging_two_keys_adds_their_counts() {
    // (case, distinct, events of "a", events of "b", want for "b" after merging "a" into it)
    let cases: Vec<(&str, bool, Vec<Option<&str>>, Vec<Option<&str>>, u64)> = vec![
        ("plain counts add up", false, vec![None, None], vec![None], 3),
        ("into a key never seen", false, vec![None, None], vec![], 2),
        (
            "distinct values are a union",
            true,
            vec![Some("x"), Some("y")],
            vec![Some("y"), Some("z")],
            3,
        ),
    ];
    let mut failures = Vec::new();
    for (case, distinct, a, b, want) in cases {
        let mut counter = Counter::new(3_600, distinct);
        for v in a {
            counter.add("a", 100, v);
        }
        for v in b {
            counter.add("b", 100, v);
        }
        counter.merge_key("a", "b");
        let got = counter.get("b", 200);
        if got != want {
            failures.push(format!("{case}: got {got}, want {want}"));
        }
        if counter.get("a", 200) != 0 {
            failures.push(format!("{case}: the merged key is still counted"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
