//! Lists: domains (with their subdomains), IP addresses and ranges, and
//! plain values. They read the plain-text formats public lists use: one item
//! per line, `#` comments, blank lines ignored.

use aho_corasick::AhoCorasick;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListKind {
    /// A domain matches itself and every subdomain. An email address is
    /// looked up by its domain.
    Domain,
    /// Single addresses and CIDR ranges, IPv4 and IPv6.
    Ip,
    /// Exact values.
    Value,
    /// Beginnings: `+32` matches `+32470123456`.
    Prefix,
}

#[derive(Debug, Clone)]
pub struct List {
    kind: ListKind,
    items: BTreeSet<String>,
    /// Items kept for a while: the time (Unix seconds) they stop matching.
    /// An item absent from here is kept for good.
    ends: HashMap<String, u64>,
    v4: Vec<(u128, u128)>,
    v6: Vec<(u128, u128)>,
    /// The ranges of the items kept for a while, each with its end.
    ending: Vec<(u128, u128, bool, u64)>,
    /// The items of the last download, under the items above. Shared by
    /// every copy of the list.
    downloaded: Arc<Downloaded>,
    /// The lowercased items as one automaton, built at the first
    /// `mentioned_in` after a change: one pass over the text, whatever the
    /// size of the list.
    matcher: OnceLock<Option<AhoCorasick>>,
}

/// An IP item as a range of numbers, and whether it is IPv6.
fn parse_range(item: &str) -> Option<(u128, u128, bool)> {
    let (addr, bits) = match item.split_once('/') {
        Some((a, b)) => (a, Some(b.parse::<u32>().ok()?)),
        None => (item, None),
    };
    let ip: IpAddr = addr.parse().ok()?;
    let (value, width, v6) = match ip {
        IpAddr::V4(v4) => (u128::from(u32::from(v4)), 32, false),
        IpAddr::V6(v6) => (u128::from(v6), 128, true),
    };
    let bits = bits.unwrap_or(width);
    if bits > width {
        return None;
    }
    let host_bits = width - bits;
    let mask: u128 = if host_bits == 128 { u128::MAX } else { (1u128 << host_bits) - 1 };
    Some((value & !mask, value | mask, v6))
}

fn merge(mut ranges: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    ranges.sort_unstable();
    let mut out: Vec<(u128, u128)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match out.last_mut() {
            Some(last) if start <= last.1.saturating_add(1) => last.1 = last.1.max(end),
            _ => out.push((start, end)),
        }
    }
    out
}

fn in_ranges<T: Ord + Copy>(ranges: &[(T, T)], value: T) -> bool {
    let i = ranges.partition_point(|(start, _)| *start <= value);
    i > 0 && ranges[i - 1].1 >= value
}

/// The items of a download, held compactly: sorted, without duplicates, in
/// one buffer. A public list of 100,000 domains takes about 2 MB here instead
/// of about 10 MB as separate strings.
#[derive(Debug, Default)]
struct Downloaded {
    text: String,
    /// Where each item ends in `text`.
    ends: Vec<u32>,
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl Downloaded {
    fn new(mut items: Vec<String>, kind: ListKind) -> Downloaded {
        items.sort_unstable();
        items.dedup();
        let mut out = Downloaded {
            text: String::with_capacity(items.iter().map(String::len).sum()),
            ends: Vec::with_capacity(items.len()),
            ..Downloaded::default()
        };
        let (mut v4, mut v6) = (Vec::new(), Vec::new());
        for item in &items {
            out.text.push_str(item);
            out.ends.push(out.text.len() as u32);
            if kind == ListKind::Ip
                && let Some((start, end, is_v6)) = parse_range(item)
            {
                if is_v6 { v6.push((start, end)) } else { v4.push((start, end)) }
            }
        }
        out.v4 = merge(v4).into_iter().map(|(s, e)| (s as u32, e as u32)).collect();
        out.v4.shrink_to_fit();
        out.v6 = merge(v6);
        out.v6.shrink_to_fit();
        out
    }

    fn len(&self) -> usize {
        self.ends.len()
    }

    fn item(&self, i: usize) -> &str {
        let start = if i == 0 { 0 } else { self.ends[i - 1] as usize };
        &self.text[start..self.ends[i] as usize]
    }

    fn iter(&self) -> impl Iterator<Item = &str> {
        (0..self.len()).map(|i| self.item(i))
    }

    fn contains(&self, item: &str) -> bool {
        let (mut low, mut high) = (0, self.len());
        while low < high {
            let mid = (low + high) / 2;
            match self.item(mid).cmp(item) {
                std::cmp::Ordering::Less => low = mid + 1,
                std::cmp::Ordering::Greater => high = mid,
                std::cmp::Ordering::Equal => return true,
            }
        }
        false
    }
}

impl List {
    pub fn new(kind: ListKind) -> Self {
        List {
            kind,
            items: BTreeSet::new(),
            ends: HashMap::new(),
            v4: Vec::new(),
            v6: Vec::new(),
            ending: Vec::new(),
            downloaded: Arc::default(),
            matcher: OnceLock::new(),
        }
    }

    pub fn kind(&self) -> ListKind {
        self.kind
    }

    /// The items kept by hand and the downloaded ones, each counted once.
    pub fn len(&self) -> usize {
        self.downloaded.len() + self.items.iter().filter(|i| !self.downloaded.contains(i)).count()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty() && self.downloaded.len() == 0
    }

    pub fn items(&self) -> impl Iterator<Item = &str> {
        let own = self.items.iter().map(String::as_str);
        own.chain(self.downloaded.iter().filter(|i| !self.items.contains(*i)))
    }

    /// The item as the list keeps it, or why it cannot be one.
    pub fn normalize_item(&self, item: &str) -> Result<String, String> {
        let item = item.trim();
        if item.is_empty() {
            return Err("an empty item".into());
        }
        match self.kind {
            ListKind::Domain => {
                let d = item.trim_start_matches("*.").trim_end_matches('.').to_ascii_lowercase();
                if d.contains(char::is_whitespace) || d.contains('@') || d.contains('/') || !d.contains('.') {
                    return Err(format!("`{item}` is not a domain"));
                }
                Ok(d)
            }
            ListKind::Ip => {
                parse_range(item).ok_or_else(|| format!("`{item}` is not an IP address or CIDR range"))?;
                Ok(item.to_owned())
            }
            ListKind::Value | ListKind::Prefix => Ok(item.to_owned()),
        }
    }

    fn rebuild(&mut self) {
        self.matcher = OnceLock::new();
        if self.kind != ListKind::Ip {
            return;
        }
        let (mut v4, mut v6, mut ending) = (Vec::new(), Vec::new(), Vec::new());
        for item in &self.items {
            if let Some((start, end, is_v6)) = parse_range(item) {
                match self.ends.get(item) {
                    Some(until) => ending.push((start, end, is_v6, *until)),
                    None if is_v6 => v6.push((start, end)),
                    None => v4.push((start, end)),
                }
            }
        }
        self.v4 = merge(v4);
        self.v6 = merge(v6);
        self.ending = ending;
    }

    /// Adds every line of `text`. Returns one message per refused line.
    pub fn extend_from_text(&mut self, text: &str) -> Vec<String> {
        let (items, problems) = self.read_lines(text);
        self.items.extend(items);
        self.rebuild();
        problems
    }

    /// Replaces the items of the last download with every line of `text`,
    /// and keeps the items added by hand. Returns one message per refused
    /// line.
    pub fn set_downloaded(&mut self, text: &str) -> Vec<String> {
        let (items, problems) = self.read_lines(text);
        self.downloaded = Arc::new(Downloaded::new(items, self.kind));
        self.matcher = OnceLock::new();
        problems
    }

    /// The items of `text`, one per line, and one message per refused line.
    fn read_lines(&self, text: &str) -> (Vec<String>, Vec<String>) {
        let (mut items, mut problems) = (Vec::new(), Vec::new());
        for (n, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or_default().trim();
            // Some lists put a comment or a count after the item.
            let line = line.split(|c: char| c.is_whitespace() || c == ';').next().unwrap_or_default();
            if line.is_empty() {
                continue;
            }
            match self.normalize_item(line) {
                Ok(item) => items.push(item),
                // The line itself is not repeated: a list file may be any
                // file the server can read, secrets included.
                Err(_) => problems.push(format!(
                    "line {} is not a valid {} item",
                    n + 1,
                    format!("{:?}", self.kind()).to_lowercase()
                )),
            }
        }
        (items, problems)
    }

    pub fn insert(&mut self, item: &str) -> Result<bool, String> {
        self.insert_until(item, None)
    }

    /// Adds an item that stops matching at `until` (Unix seconds), or for
    /// good with `None`. Adding an item again moves its end; an item kept for
    /// good stays for good.
    pub fn insert_until(&mut self, item: &str, until: Option<u64>) -> Result<bool, String> {
        let item = self.normalize_item(item)?;
        let kept_for_good = self.items.contains(&item) && !self.ends.contains_key(&item);
        match until {
            None => {
                self.ends.remove(&item);
            }
            Some(_) if kept_for_good => {}
            Some(t) => {
                self.ends.insert(item.clone(), t);
            }
        }
        let added = self.items.insert(item);
        self.rebuild();
        Ok(added)
    }

    pub fn remove(&mut self, item: &str) -> bool {
        let Ok(item) = self.normalize_item(item) else {
            return false;
        };
        self.ends.remove(&item);
        let removed = self.items.remove(&item);
        self.rebuild();
        removed
    }

    /// Whether an item still matches at `at`.
    fn alive(&self, item: &str, at: u64) -> bool {
        (self.items.contains(item) && self.ends.get(item).is_none_or(|until| *until > at)) || self.downloaded.contains(item)
    }

    /// Whether `text` contains an item, in any case.
    pub fn mentioned_in(&self, text: &str) -> bool {
        let matcher = self.matcher.get_or_init(|| {
            let items: Vec<String> = self.items().filter(|i| !i.is_empty()).map(str::to_lowercase).collect();
            if items.is_empty() {
                return None;
            }
            AhoCorasick::new(items).ok()
        });
        matcher.as_ref().is_some_and(|m| m.is_match(&text.to_lowercase()))
    }

    /// Whether the list holds `probe`, counting the items kept for a while
    /// as alive.
    pub fn contains(&self, probe: &str) -> bool {
        self.contains_at(probe, 0)
    }

    /// Whether the list holds `probe` at `at`: an item kept for a while
    /// matches until its end.
    pub fn contains_at(&self, probe: &str, at: u64) -> bool {
        let probe = probe.trim();
        match self.kind {
            ListKind::Domain => {
                let domain = probe.rsplit('@').next().unwrap_or(probe).to_ascii_lowercase();
                let mut rest = domain.as_str();
                loop {
                    if self.alive(rest, at) {
                        return true;
                    }
                    match rest.split_once('.') {
                        Some((_, parent)) if parent.contains('.') => rest = parent,
                        _ => return false,
                    }
                }
            }
            ListKind::Ip => probe.parse::<IpAddr>().is_ok_and(|ip| self.contains_ip_at(ip, at)),
            ListKind::Value => self.alive(probe, at),
            ListKind::Prefix => {
                self.items.iter().any(|p| probe.starts_with(p.as_str()) && self.alive(p, at))
                    || probe
                        .char_indices()
                        .any(|(i, c)| self.downloaded.contains(&probe[..i + c.len_utf8()]))
            }
        }
    }

    pub fn contains_ip(&self, ip: IpAddr) -> bool {
        self.contains_ip_at(ip, 0)
    }

    pub fn contains_ip_at(&self, ip: IpAddr, at: u64) -> bool {
        let (value, is_v6) = match ip {
            IpAddr::V4(v4) => (u128::from(u32::from(v4)), false),
            IpAddr::V6(v6) => (u128::from(v6), true),
        };
        let kept = if is_v6 {
            in_ranges(&self.v6, value) || in_ranges(&self.downloaded.v6, value)
        } else {
            in_ranges(&self.v4, value) || in_ranges(&self.downloaded.v4, value as u32)
        };
        kept || self
            .ending
            .iter()
            .any(|(start, end, v6, until)| *v6 == is_v6 && *start <= value && value <= *end && *until > at)
    }
}
