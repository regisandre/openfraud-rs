//! Sliding-window counters: how many events a key had over the last span of
//! time, or how many distinct values it was seen with.
//!
//! A plain counter keeps per key a fixed number of time buckets (a span
//! divided into [`BUCKETS`]), so a hot key costs the same memory as a quiet
//! one. An event belongs to the window when its bucket starts after
//! `now - span`: the window edge is exact to one bucket, which is 1/120 of
//! the span (30 seconds for one hour). A distinct counter keeps the last time
//! each value was seen, up to [`MAX_DISTINCT`] values per key.

use std::collections::{BTreeMap, HashMap};

/// Buckets per span for plain counters.
pub const BUCKETS: u64 = 120;
/// Values kept per key by a distinct counter. Past it, new values are not
/// counted until older ones leave the window.
pub const MAX_DISTINCT: usize = 10_000;
/// The longest window: retention bounds what can be counted anyway.
pub const MAX_SPAN: u64 = 366 * 86_400;

/// `30s`, `15m`, `1h`, `7d`: a positive whole number and a unit.
pub fn parse_duration(text: &str) -> Result<u64, String> {
    let text = text.trim();
    let refuse = || format!("`{text}` is not a duration such as 30s, 15m, 1h or 7d");
    let unit = text.chars().last().ok_or_else(refuse)?;
    let factor = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3_600,
        'd' => 86_400,
        _ => return Err(refuse()),
    };
    let number = &text[..text.len() - 1];
    if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
        return Err(refuse());
    }
    let seconds = number.parse::<u64>().ok().and_then(|n| n.checked_mul(factor)).ok_or_else(refuse)?;
    if seconds == 0 {
        return Err(refuse());
    }
    if seconds > MAX_SPAN {
        return Err(format!("`{text}` is longer than the longest window, 366d"));
    }
    Ok(seconds)
}

/// The text form [`parse_duration`] reads, in the largest exact unit.
pub fn format_duration(seconds: u64) -> String {
    for (unit, factor) in [('d', 86_400), ('h', 3_600), ('m', 60)] {
        if seconds.is_multiple_of(factor) {
            return format!("{}{unit}", seconds / factor);
        }
    }
    format!("{seconds}s")
}

#[derive(Debug)]
enum Series {
    /// Bucket index to number of events.
    Count(BTreeMap<u64, u64>),
    /// Value to the last time it was seen, and the oldest of those times
    /// (so a full set skips a sweep that cannot free anything).
    Distinct(HashMap<String, u64>, u64),
}

#[derive(Debug)]
pub struct Counter {
    span: u64,
    granularity: u64,
    distinct: bool,
    keys: HashMap<String, Series>,
}

impl Counter {
    pub fn new(span: u64, distinct: bool) -> Self {
        let span = span.max(1);
        Counter {
            span,
            granularity: (span / BUCKETS).max(1),
            distinct,
            keys: HashMap::new(),
        }
    }

    pub fn span(&self) -> u64 {
        self.span
    }

    pub fn is_distinct(&self) -> bool {
        self.distinct
    }

    /// The first time still inside a window that ends at `now`.
    fn floor(&self, now: u64) -> i128 {
        i128::from(now) - i128::from(self.span)
    }

    /// Records an event of `key` at `at`. A distinct counter ignores an event
    /// without a value.
    pub fn add(&mut self, key: &str, at: u64, value: Option<&str>) {
        self.add_weighted(key, at, value, 1);
    }

    /// Records `weight` (an amount) for `key` at `at`; a distinct counter
    /// ignores the weight.
    pub fn add_weighted(&mut self, key: &str, at: u64, value: Option<&str>, weight: u64) {
        if self.distinct && value.is_none() {
            return;
        }
        let distinct = self.distinct;
        let granularity = self.granularity;
        let floor = self.floor(at);
        let series = self.keys.entry(key.to_owned()).or_insert_with(|| {
            if distinct {
                Series::Distinct(HashMap::new(), u64::MAX)
            } else {
                Series::Count(BTreeMap::new())
            }
        });
        match series {
            Series::Count(buckets) => {
                *buckets.entry(at / granularity).or_default() += weight;
                // Forget the buckets that left the window of the newest event.
                let newest = *buckets.keys().next_back().unwrap_or(&0);
                let newest_floor = i128::from(newest * granularity) - i128::from(granularity) - i128::from(self.span);
                while let Some((&first, _)) = buckets.first_key_value() {
                    if i128::from(first * granularity) <= newest_floor {
                        buckets.pop_first();
                    } else {
                        break;
                    }
                }
            }
            Series::Distinct(values, oldest) => {
                let value = value.unwrap_or_default();
                if let Some(seen) = values.get_mut(value) {
                    *seen = (*seen).max(at);
                    return;
                }
                if values.len() >= MAX_DISTINCT && i128::from(*oldest) <= floor {
                    values.retain(|_, seen| i128::from(*seen) > floor);
                    *oldest = values.values().copied().min().unwrap_or(u64::MAX);
                }
                if values.len() < MAX_DISTINCT {
                    values.insert(value.to_owned(), at);
                    *oldest = (*oldest).min(at);
                }
            }
        }
    }

    /// Events (or distinct values) of `key` inside the window ending at `now`.
    pub fn get(&self, key: &str, now: u64) -> u64 {
        let floor = self.floor(now);
        match self.keys.get(key) {
            None => 0,
            Some(Series::Count(buckets)) => buckets
                .iter()
                .filter(|(idx, _)| i128::from(**idx * self.granularity) > floor)
                .map(|(_, n)| n)
                .sum(),
            Some(Series::Distinct(values, _)) => values.values().filter(|seen| i128::from(**seen) > floor).count() as u64,
        }
    }

    /// What [`Counter::get`] would answer once an event of `key` with `value`
    /// is added at `now`, without adding it.
    pub fn count_with(&self, key: &str, now: u64, value: Option<&str>) -> u64 {
        self.count_with_weight(key, now, value, 1)
    }

    /// [`Counter::count_with`] for an amount.
    pub fn count_with_weight(&self, key: &str, now: u64, value: Option<&str>, weight: u64) -> u64 {
        let current = self.get(key, now);
        if !self.distinct {
            return current + weight;
        }
        let Some(value) = value else {
            return current;
        };
        let floor = self.floor(now);
        let known = match self.keys.get(key) {
            Some(Series::Distinct(values, _)) => values.get(value).is_some_and(|seen| i128::from(*seen) > floor),
            _ => false,
        };
        if known { current } else { current + 1 }
    }

    /// Drops what left the window ending at `now`, and the keys left empty.
    pub fn prune(&mut self, now: u64) {
        let floor = self.floor(now);
        let granularity = self.granularity;
        self.keys.retain(|_, series| match series {
            Series::Count(buckets) => {
                buckets.retain(|idx, _| i128::from(*idx * granularity) > floor);
                !buckets.is_empty()
            }
            Series::Distinct(values, oldest) => {
                values.retain(|_, seen| i128::from(*seen) > floor);
                *oldest = values.values().copied().min().unwrap_or(u64::MAX);
                !values.is_empty()
            }
        });
    }

    /// Moves the series of `from` into `into`, adding them up: when two
    /// clusters join, their counts become one.
    pub fn merge_key(&mut self, from: &str, into: &str) {
        if from == into {
            return;
        }
        let Some(old) = self.keys.remove(from) else {
            return;
        };
        let Some(target) = self.keys.get_mut(into) else {
            self.keys.insert(into.to_owned(), old);
            return;
        };
        match (target, old) {
            (Series::Count(to), Series::Count(from)) => {
                for (idx, n) in from {
                    *to.entry(idx).or_default() += n;
                }
            }
            (Series::Distinct(to, oldest), Series::Distinct(from, _)) => {
                for (value, seen) in from {
                    if to.len() >= MAX_DISTINCT && !to.contains_key(&value) {
                        continue;
                    }
                    let e = to.entry(value).or_insert(seen);
                    *e = (*e).max(seen);
                }
                *oldest = to.values().copied().min().unwrap_or(u64::MAX);
            }
            _ => {}
        }
    }

    pub fn keys(&self) -> usize {
        self.keys.len()
    }

    /// Buckets (or values) kept for `key`: for tests and sizing.
    pub fn buckets(&self, key: &str) -> usize {
        match self.keys.get(key) {
            None => 0,
            Some(Series::Count(buckets)) => buckets.len(),
            Some(Series::Distinct(values, _)) => values.len(),
        }
    }
}
