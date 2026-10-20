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

/// What an aggregate counter gives of the values in its window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Agg {
    /// The average, rounded to a whole number.
    Avg,
    Min,
    Max,
    /// The value of the latest event.
    Last,
}

/// The values of one bucket of an aggregate counter.
#[derive(Debug, Clone, Copy)]
struct Stat {
    count: u64,
    sum: u64,
    min: u64,
    max: u64,
    last_at: u64,
    last: u64,
}

impl Stat {
    fn of(at: u64, value: u64) -> Stat {
        Stat {
            count: 1,
            sum: value,
            min: value,
            max: value,
            last_at: at,
            last: value,
        }
    }

    fn join(&mut self, other: Stat) {
        self.count = self.count.saturating_add(other.count);
        self.sum = self.sum.saturating_add(other.sum);
        self.min = self.min.min(other.min);
        self.max = self.max.max(other.max);
        if other.last_at >= self.last_at {
            self.last_at = other.last_at;
            self.last = other.last;
        }
    }
}

fn answer(agg: Agg, all: Option<Stat>) -> u64 {
    match all {
        None => 0,
        Some(s) => match agg {
            Agg::Avg => ((s.sum as f64) / (s.count.max(1) as f64)).round() as u64,
            Agg::Min => s.min,
            Agg::Max => s.max,
            Agg::Last => s.last,
        },
    }
}

#[derive(Debug)]
enum Series {
    /// Bucket index to number of events.
    Count(BTreeMap<u64, u64>),
    /// Value to the last time it was seen, and the oldest of those times
    /// (so a full set skips a sweep that cannot free anything).
    Distinct(HashMap<String, u64>, u64),
    /// Bucket index to the values seen in it.
    Stats(BTreeMap<u64, Stat>),
}

#[derive(Debug)]
pub struct Counter {
    span: u64,
    granularity: u64,
    distinct: bool,
    agg: Option<Agg>,
    keys: HashMap<String, Series>,
}

impl Counter {
    pub fn new(span: u64, distinct: bool) -> Self {
        let span = span.max(1);
        Counter {
            span,
            granularity: (span / BUCKETS).max(1),
            distinct,
            agg: None,
            keys: HashMap::new(),
        }
    }

    /// A counter that keeps the values of its events, and gives their
    /// average, least, most or last.
    pub fn with_agg(span: u64, agg: Agg) -> Self {
        Counter {
            agg: Some(agg),
            ..Counter::new(span, false)
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
        let aggregate = self.agg.is_some();
        let granularity = self.granularity;
        let floor = self.floor(at);
        let series = self.keys.entry(key.to_owned()).or_insert_with(|| {
            if distinct {
                Series::Distinct(HashMap::new(), u64::MAX)
            } else if aggregate {
                Series::Stats(BTreeMap::new())
            } else {
                Series::Count(BTreeMap::new())
            }
        });
        match series {
            Series::Stats(buckets) => {
                match buckets.get_mut(&(at / granularity)) {
                    Some(stat) => stat.join(Stat::of(at, weight)),
                    None => {
                        buckets.insert(at / granularity, Stat::of(at, weight));
                    }
                }
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
            Series::Count(buckets) => {
                let bucket = buckets.entry(at / granularity).or_default();
                *bucket = bucket.saturating_add(weight);
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
                .fold(0u64, |total, (_, n)| total.saturating_add(*n)),
            Some(Series::Distinct(values, _)) => values.values().filter(|seen| i128::from(**seen) > floor).count() as u64,
            Some(Series::Stats(_)) => answer(self.agg.unwrap_or(Agg::Avg), self.stats(key, now)),
        }
    }

    /// The values of `key` inside the window ending at `now`, joined.
    fn stats(&self, key: &str, now: u64) -> Option<Stat> {
        let floor = self.floor(now);
        let Some(Series::Stats(buckets)) = self.keys.get(key) else {
            return None;
        };
        buckets
            .iter()
            .filter(|(idx, _)| i128::from(**idx * self.granularity) > floor)
            .fold(None, |all: Option<Stat>, (_, s)| match all {
                None => Some(*s),
                Some(mut a) => {
                    a.join(*s);
                    Some(a)
                }
            })
    }

    /// What [`Counter::get`] would answer once an event of `key` with `value`
    /// is added at `now`, without adding it.
    pub fn count_with(&self, key: &str, now: u64, value: Option<&str>) -> u64 {
        self.count_with_weight(key, now, value, 1)
    }

    /// [`Counter::count_with`] for an amount.
    pub fn count_with_weight(&self, key: &str, now: u64, value: Option<&str>, weight: u64) -> u64 {
        if let Some(agg) = self.agg {
            let mut all = self.stats(key, now).unwrap_or(Stat::of(now, weight));
            if self.stats(key, now).is_some() {
                all.join(Stat::of(now, weight));
            }
            return answer(agg, Some(all));
        }
        let current = self.get(key, now);
        if !self.distinct {
            return current.saturating_add(weight);
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
            Series::Stats(buckets) => {
                buckets.retain(|idx, _| i128::from(*idx * granularity) > floor);
                !buckets.is_empty()
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
                    let bucket = to.entry(idx).or_default();
                    *bucket = bucket.saturating_add(n);
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
            (Series::Stats(to), Series::Stats(from)) => {
                for (idx, s) in from {
                    match to.get_mut(&idx) {
                        Some(t) => t.join(s),
                        None => {
                            to.insert(idx, s);
                        }
                    }
                }
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
            Some(Series::Stats(buckets)) => buckets.len(),
        }
    }
}
