//! Which network announces an address: its autonomous system number, the
//! operator's name and the country the operator is registered in. The data
//! is the IPtoASN dataset (public domain), one range per line:
//! `range_start range_end as_number country_code as_description`, IPv4 and
//! IPv6, plain or gzipped. The country is the operator's, not the user's:
//! a cloud provider registered in the US answers `US` for its servers in
//! Frankfurt.

use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::Path;

/// Where the dataset is downloaded from when `[networks] url` is not set.
pub const DEFAULT_URL: &str = "https://iptoasn.com/data/ip2asn-combined.tsv.gz";

/// The network an address belongs to.
#[derive(Debug, Clone, PartialEq)]
pub struct Network {
    pub asn: u32,
    /// ISO 3166 alpha-2 of the operator's registration, or `""`.
    pub country: String,
    pub org: String,
}

#[derive(Debug, Clone, Copy)]
struct Range {
    start: u128,
    end: u128,
    asn: u32,
    country: [u8; 2],
    org: u32,
}

/// Every announced range, sorted, for a binary search.
#[derive(Debug, Default)]
pub struct NetworkTable {
    v4: Vec<Range>,
    v6: Vec<Range>,
    orgs: Vec<String>,
}

impl NetworkTable {
    /// Reads the TSV text. Unrouted ranges (AS 0) and lines that cannot be
    /// read are skipped.
    pub fn parse(text: &str) -> NetworkTable {
        NetworkTable::read(text.as_bytes()).unwrap_or_default()
    }

    /// Reads the TSV line by line, so a download is never held whole in
    /// memory next to the table.
    fn read(reader: impl BufRead) -> std::io::Result<NetworkTable> {
        let mut table = NetworkTable::default();
        let mut names: HashMap<String, u32> = HashMap::new();
        for line in reader.lines() {
            let line = line?;
            let line = line.as_str();
            let mut cols = line.splitn(5, '\t');
            let (Some(start), Some(end), Some(asn), Some(country)) = (cols.next(), cols.next(), cols.next(), cols.next()) else {
                continue;
            };
            let org = cols.next().unwrap_or("").trim();
            let Ok(asn) = asn.trim().parse::<u32>() else { continue };
            if asn == 0 {
                continue;
            }
            let (Ok(start), Ok(end)) = (start.trim().parse::<IpAddr>(), end.trim().parse::<IpAddr>()) else {
                continue;
            };
            let code = country.trim().as_bytes();
            let country = if code.len() == 2 && code.iter().all(u8::is_ascii_alphabetic) {
                [code[0].to_ascii_uppercase(), code[1].to_ascii_uppercase()]
            } else {
                [0, 0]
            };
            let next = names.len() as u32;
            let org = *names.entry(org.to_owned()).or_insert(next);
            if org == next {
                table.orgs.push(org_name(line));
            }
            let range = |s, e| Range {
                start: s,
                end: e,
                asn,
                country,
                org,
            };
            match (start, end) {
                (IpAddr::V4(s), IpAddr::V4(e)) => table.v4.push(range(u128::from(u32::from(s)), u128::from(u32::from(e)))),
                (IpAddr::V6(s), IpAddr::V6(e)) => table.v6.push(range(u128::from(s), u128::from(e))),
                _ => continue,
            }
        }
        table.v4.sort_by_key(|r| r.start);
        table.v6.sort_by_key(|r| r.start);
        table.v4.shrink_to_fit();
        table.v6.shrink_to_fit();
        table.orgs.shrink_to_fit();
        Ok(table)
    }

    /// Reads a download, gzipped or not. An empty or unreadable one is an
    /// error, so a failed download never replaces a good table.
    pub fn from_bytes(bytes: &[u8]) -> Result<NetworkTable> {
        let table = if bytes.starts_with(&[0x1f, 0x8b]) {
            NetworkTable::read(BufReader::new(flate2::read::GzDecoder::new(bytes)))?
        } else {
            NetworkTable::read(bytes)?
        };
        if table.is_empty() {
            bail!("the network dataset holds no range");
        }
        Ok(table)
    }

    /// Ranges loaded, IPv4 and IPv6.
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<Network> {
        let (ranges, value) = match ip {
            IpAddr::V4(v4) => (&self.v4, u128::from(u32::from(v4))),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => (&self.v4, u128::from(u32::from(v4))),
                None => (&self.v6, u128::from(v6)),
            },
        };
        let i = ranges.partition_point(|r| r.start <= value).checked_sub(1)?;
        let r = ranges[i];
        (value <= r.end).then(|| Network {
            asn: r.asn,
            country: if r.country == [0, 0] {
                String::new()
            } else {
                String::from_utf8_lossy(&r.country).into_owned()
            },
            org: self.orgs.get(r.org as usize).cloned().unwrap_or_default(),
        })
    }
}

/// The table `[networks]` asks for: `None` when it is off. A file of your
/// own wins; otherwise the cached download, downloaded again once older
/// than `refresh_hours`. A failed download keeps a stale cache.
pub fn load(
    settings: &crate::config::Networks,
    cache: &Path,
    fetch_allowed: bool,
    refresh_hours: u64,
    fetch: &dyn Fn(&str) -> Result<Vec<u8>>,
) -> Result<Option<NetworkTable>> {
    if !settings.enabled {
        return Ok(None);
    }
    if let Some(file) = &settings.file {
        let bytes = std::fs::read(file).with_context(|| format!("cannot read {}", file.display()))?;
        return NetworkTable::from_bytes(&bytes).map(Some);
    }
    let age = std::fs::metadata(cache)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .map(|d| d.as_secs());
    let fresh = age.is_some_and(|a| a < refresh_hours.saturating_mul(3_600));
    if !fresh && fetch_allowed {
        match fetch(&settings.url).and_then(|bytes| NetworkTable::from_bytes(&bytes).map(|t| (bytes, t))) {
            Ok((bytes, table)) => {
                std::fs::write(cache, &bytes).with_context(|| format!("cannot write {}", cache.display()))?;
                return Ok(Some(table));
            }
            Err(e) if age.is_some() => tracing::warn!(error = %e, "the network dataset could not be refreshed; the cached copy stays"),
            Err(e) => return Err(e.context("the network dataset could not be downloaded")),
        }
    }
    if age.is_some() {
        let bytes = std::fs::read(cache)?;
        return NetworkTable::from_bytes(&bytes).map(Some);
    }
    bail!("[networks] is on but has no data: set `file`, or `[server] fetch_lists = true` to download it")
}

fn org_name(line: &str) -> String {
    line.splitn(5, '\t').nth(4).unwrap_or("").trim().to_owned()
}
