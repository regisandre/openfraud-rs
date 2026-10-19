//! Distances between countries, for impossible travel: from one country's
//! centre to another's, so only big jumps count.
#![allow(clippy::type_complexity)]

use openfraud::geo::distance_km;

#[test]
fn the_distance_between_two_countries_is_between_their_centres() {
    // (case, from, to, at least km, at most km)
    let cases: Vec<(&str, &str, &str, f64, f64)> = vec![
        ("the same country", "BE", "BE", 0.0, 0.0),
        ("neighbours", "BE", "FR", 150.0, 600.0),
        ("across the Atlantic", "BE", "US", 6_500.0, 8_500.0),
        ("across the world", "BE", "AU", 14_000.0, 16_500.0),
        ("lower case is read", "be", "fr", 150.0, 600.0),
    ];
    let mut failures = Vec::new();
    for (case, a, b, lo, hi) in cases {
        match distance_km(a, b) {
            Some(d) if d >= lo && d <= hi => {}
            other => failures.push(format!("{case}: {other:?}, want {lo} to {hi}")),
        }
    }
    assert_eq!(distance_km("BE", "XX"), None, "an unknown country has no distance");
    assert_eq!(distance_km("UM", "BE"), None, "a country without a centre has no distance");
    assert!(failures.is_empty(), "{failures:#?}");
}
