//! Which network announces an address: its autonomous system number, the
//! operator's name and the country the operator is registered in. The data
//! is the IPtoASN dataset (public domain), one range per line:
//! `range_start range_end as_number country_code as_description`, IPv4 and
//! IPv6, plain or gzipped. The country is the operator's, not the user's:
//! a cloud provider registered in the US answers `US` for its servers in
//! Frankfurt.
//!
//! The dataset can also be compiled ahead of time (`openfraud networks
//! compile`). A compiled file is mapped rather than read, so the instances
//! of one host that open the same file share a single copy in memory.

use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
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

// The compiled table, little-endian, read in place:
//
//   magic "OFNET\0", format u16 = 1
//   v4 ranges u64, v6 ranges u64, operators u64, names length u64
//   v4 ranges: start u32, end u32, asn u32, country [u8; 2], 0u16, operator u32
//   v6 ranges: start u128, end u128, asn u32, country [u8; 2], 0u16, operator u32
//   operator name offsets: (operators + 1) x u32 into the names
//   names: UTF-8, end to end
//
// Ranges are sorted by start.
const MAGIC: &[u8; 8] = b"OFNET\0\x01\0";
const HEADER: usize = 40;
const V4: usize = 20;
const V6: usize = 44;

enum Bytes {
    Owned(Vec<u8>),
    Mapped(memmap2::Mmap),
}

impl std::ops::Deref for Bytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Bytes::Owned(v) => v,
            Bytes::Mapped(m) => m,
        }
    }
}

/// Every announced range, sorted, for a binary search, in the compiled
/// form: held in memory, or mapped from a compiled file.
pub struct NetworkTable {
    bytes: Bytes,
    v4: usize,
    v6: usize,
    orgs: usize,
}

impl std::fmt::Debug for NetworkTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkTable")
            .field("v4", &self.v4)
            .field("v6", &self.v6)
            .field("orgs", &self.orgs)
            .field("mapped", &self.is_mapped())
            .finish()
    }
}

impl Default for NetworkTable {
    fn default() -> Self {
        NetworkTable::compile(Vec::new(), Vec::new(), &[])
    }
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

fn u128_at(b: &[u8], at: usize) -> u128 {
    u128::from_le_bytes(b[at..at + 16].try_into().unwrap())
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
        let (mut v4, mut v6, mut orgs) = (Vec::new(), Vec::new(), Vec::new());
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
                orgs.push(org_name(line));
            }
            let range = |s, e| Range {
                start: s,
                end: e,
                asn,
                country,
                org,
            };
            match (start, end) {
                (IpAddr::V4(s), IpAddr::V4(e)) => v4.push(range(u128::from(u32::from(s)), u128::from(u32::from(e)))),
                (IpAddr::V6(s), IpAddr::V6(e)) => v6.push(range(u128::from(s), u128::from(e))),
                _ => continue,
            }
        }
        drop(names);
        Ok(NetworkTable::compile(v4, v6, &orgs))
    }

    fn compile(mut v4: Vec<Range>, mut v6: Vec<Range>, orgs: &[String]) -> NetworkTable {
        v4.sort_by_key(|r| r.start);
        v6.sort_by_key(|r| r.start);
        let names: usize = orgs.iter().map(String::len).sum();
        let mut out = Vec::with_capacity(HEADER + v4.len() * V4 + v6.len() * V6 + (orgs.len() + 1) * 4 + names);
        out.extend_from_slice(MAGIC);
        for n in [v4.len(), v6.len(), orgs.len(), names] {
            out.extend_from_slice(&(n as u64).to_le_bytes());
        }
        let tail = |out: &mut Vec<u8>, r: &Range| {
            out.extend_from_slice(&r.asn.to_le_bytes());
            out.extend_from_slice(&r.country);
            out.extend_from_slice(&[0, 0]);
            out.extend_from_slice(&r.org.to_le_bytes());
        };
        for r in &v4 {
            out.extend_from_slice(&(r.start as u32).to_le_bytes());
            out.extend_from_slice(&(r.end as u32).to_le_bytes());
            tail(&mut out, r);
        }
        for r in &v6 {
            out.extend_from_slice(&r.start.to_le_bytes());
            out.extend_from_slice(&r.end.to_le_bytes());
            tail(&mut out, r);
        }
        let mut offset = 0u32;
        out.extend_from_slice(&offset.to_le_bytes());
        for name in orgs {
            offset += name.len() as u32;
            out.extend_from_slice(&offset.to_le_bytes());
        }
        for name in orgs {
            out.extend_from_slice(name.as_bytes());
        }
        NetworkTable {
            bytes: Bytes::Owned(out),
            v4: v4.len(),
            v6: v6.len(),
            orgs: orgs.len(),
        }
    }

    /// Checks that compiled bytes hold what their header says, so a lookup
    /// never reads past the end.
    fn checked(bytes: Bytes) -> Result<NetworkTable> {
        let b = &bytes[..];
        if b.len() < HEADER || &b[..8] != MAGIC {
            bail!("not a compiled network table");
        }
        let count = |at| usize::try_from(u64_at(b, at)).ok();
        let (Some(v4), Some(v6), Some(orgs), Some(names)) = (count(8), count(16), count(24), count(32)) else {
            bail!("the compiled network table is damaged");
        };
        let size = v4
            .checked_mul(V4)
            .and_then(|n| n.checked_add(v6.checked_mul(V6)?))
            .and_then(|n| n.checked_add(orgs.checked_add(1)?.checked_mul(4)?))
            .and_then(|n| n.checked_add(names)?.checked_add(HEADER));
        if size != Some(b.len()) {
            bail!("the compiled network table is truncated or damaged");
        }
        let table = NetworkTable { bytes, v4, v6, orgs };
        let at = table.offsets_at();
        let mut last = 0;
        for i in 0..=orgs {
            let offset = u32_at(&table.bytes, at + i * 4) as usize;
            if offset < last || offset > names {
                bail!("the compiled network table has a damaged name");
            }
            last = offset;
        }
        Ok(table)
    }

    /// Reads a download or a file, gzipped or not, or already compiled. An
    /// empty or unreadable one is an error, so a failed download never
    /// replaces a good table.
    pub fn from_bytes(bytes: &[u8]) -> Result<NetworkTable> {
        let table = if bytes.starts_with(MAGIC) {
            NetworkTable::checked(Bytes::Owned(bytes.to_vec()))?
        } else if bytes.starts_with(&[0x1f, 0x8b]) {
            NetworkTable::read(BufReader::new(flate2::read::GzDecoder::new(bytes)))?
        } else {
            NetworkTable::read(bytes)?
        };
        if table.is_empty() {
            bail!("the network dataset holds no range");
        }
        Ok(table)
    }

    /// Opens a file of the dataset. A compiled file (`openfraud networks
    /// compile`) is mapped: it must then be replaced by renaming a new file
    /// over it, never rewritten in place. Any other file is read.
    pub fn open(path: &Path) -> Result<NetworkTable> {
        let mut file = std::fs::File::open(path).with_context(|| format!("cannot read {}", path.display()))?;
        let mut head = [0u8; 8];
        let compiled = file.read_exact(&mut head).is_ok() && &head == MAGIC;
        if !compiled {
            let bytes = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
            return NetworkTable::from_bytes(&bytes);
        }
        // SAFETY: the mapping is only read. The file is documented as
        // replaced by a rename, which leaves this mapping on the old file,
        // and its sizes are checked before any lookup.
        let map = unsafe { memmap2::Mmap::map(&file) }.with_context(|| format!("cannot map {}", path.display()))?;
        let table = NetworkTable::checked(Bytes::Mapped(map)).with_context(|| path.display().to_string())?;
        if table.is_empty() {
            bail!("{} holds no range", path.display());
        }
        Ok(table)
    }

    /// The compiled form, as `openfraud networks compile` writes it.
    pub fn compiled(&self) -> &[u8] {
        &self.bytes
    }

    /// Whether the table is mapped from a compiled file rather than held
    /// in this process's memory.
    pub fn is_mapped(&self) -> bool {
        matches!(self.bytes, Bytes::Mapped(_))
    }

    /// Ranges loaded, IPv4 and IPv6.
    pub fn len(&self) -> usize {
        self.v4 + self.v6
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn v6_at(&self) -> usize {
        HEADER + self.v4 * V4
    }

    fn offsets_at(&self) -> usize {
        self.v6_at() + self.v6 * V6
    }

    fn range(&self, v6: bool, i: usize) -> Range {
        let b = &self.bytes;
        let (at, width) = if v6 { (self.v6_at() + i * V6, 16) } else { (HEADER + i * V4, 4) };
        let (start, end) = if v6 {
            (u128_at(b, at), u128_at(b, at + 16))
        } else {
            (u128::from(u32_at(b, at)), u128::from(u32_at(b, at + 4)))
        };
        let t = at + 2 * width;
        Range {
            start,
            end,
            asn: u32_at(b, t),
            country: [b[t + 4], b[t + 5]],
            org: u32_at(b, t + 8),
        }
    }

    fn org(&self, i: u32) -> String {
        let i = i as usize;
        if i >= self.orgs {
            return String::new();
        }
        let at = self.offsets_at();
        let names = at + (self.orgs + 1) * 4;
        let (from, to) = (
            u32_at(&self.bytes, at + i * 4) as usize,
            u32_at(&self.bytes, at + i * 4 + 4) as usize,
        );
        String::from_utf8_lossy(&self.bytes[names + from..names + to]).into_owned()
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<Network> {
        let (v6, value) = match ip {
            IpAddr::V4(v4) => (false, u128::from(u32::from(v4))),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => (false, u128::from(u32::from(v4))),
                None => (true, u128::from(v6)),
            },
        };
        let (mut lo, mut hi) = (0, if v6 { self.v6 } else { self.v4 });
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.range(v6, mid).start <= value {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        let r = self.range(v6, lo.checked_sub(1)?);
        (value <= r.end).then(|| Network {
            asn: r.asn,
            country: if r.country == [0, 0] {
                String::new()
            } else {
                String::from_utf8_lossy(&r.country).into_owned()
            },
            org: self.org(r.org),
        })
    }
}

/// What tells two copies of a file apart: its size, its modification time
/// and, on Unix, its inode, so a file renamed over the old one is noticed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    len: u64,
    modified: Option<std::time::SystemTime>,
    inode: u64,
}

/// The version of `path`, `None` when it cannot be read.
pub fn version(path: &Path) -> Option<Version> {
    let meta = std::fs::metadata(path).ok()?;
    #[cfg(unix)]
    let inode = std::os::unix::fs::MetadataExt::ino(&meta);
    #[cfg(not(unix))]
    let inode = 0;
    Some(Version {
        len: meta.len(),
        modified: meta.modified().ok(),
        inode,
    })
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
        return NetworkTable::open(file).map(Some);
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
