//! Country centres, for impossible travel. The table is Google's DSPL
//! canonical `countries.csv` (BSD 3-Clause, see NOTICE): one point per ISO
//! 3166 alpha-2 code. A country is wide, so distances are coarse: rules only
//! use jumps of hundreds of kilometres.

use std::collections::HashMap;
use std::sync::LazyLock;

static CENTRES: LazyLock<HashMap<String, (f64, f64)>> = LazyLock::new(|| {
    let mut out = HashMap::new();
    for line in include_str!("../data/countries.csv").lines().skip(1) {
        let mut parts = line.splitn(4, ',');
        let (Some(code), Some(lat), Some(lon)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        if let (Ok(lat), Ok(lon)) = (lat.parse::<f64>(), lon.parse::<f64>()) {
            out.insert(code.to_owned(), (lat, lon));
        }
    }
    out
});

/// The centre of a country (latitude, longitude), or `None` when unknown.
pub fn centre(country: &str) -> Option<(f64, f64)> {
    CENTRES.get(&country.to_ascii_uppercase()).copied()
}

/// The great-circle distance between the centres of two countries, or
/// `None` when either is unknown.
pub fn distance_km(a: &str, b: &str) -> Option<f64> {
    let (a, b) = (a.to_ascii_uppercase(), b.to_ascii_uppercase());
    let (lat1, lon1) = *CENTRES.get(&a)?;
    let (lat2, lon2) = *CENTRES.get(&b)?;
    if a == b {
        return Some(0.0);
    }
    let (p1, p2) = (lat1.to_radians(), lat2.to_radians());
    let dp = (lat2 - lat1).to_radians();
    let dl = (lon2 - lon1).to_radians();
    let h = (dp / 2.0).sin().powi(2) + p1.cos() * p2.cos() * (dl / 2.0).sin().powi(2);
    Some(2.0 * 6_371.0 * h.sqrt().asin())
}
