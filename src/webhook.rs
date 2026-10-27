//! Webhooks to the application, signed with the Standard Webhooks scheme
//! (https://www.standardwebhooks.com): headers `webhook-id`,
//! `webhook-timestamp` and `webhook-signature`, the signature being
//! `v1,` and the base64 HMAC-SHA256 of `id.timestamp.body` under the secret
//! (`whsec_` and the base64 key). Any Standard Webhooks library verifies
//! them; [`verify`] is the same check, for Rust receivers and for tests.

use anyhow::{Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::net::IpAddr;
use std::time::Duration;
use subtle::ConstantTimeEq;

/// How far a receiver accepts a timestamp from its own clock.
pub const TOLERANCE_SECS: u64 = 300;

/// Delays before each retry, in seconds: about two days for twelve
/// attempts, then once a day.
const DELAYS: [u64; 11] = [5, 30, 120, 600, 1_800, 3_600, 7_200, 14_400, 28_800, 43_200, 86_400];

pub fn retry_delay(attempt: u32) -> u64 {
    DELAYS[(attempt as usize).min(DELAYS.len() - 1)]
}

pub fn generate_secret() -> String {
    let mut key = [0u8; 24];
    getrandom::fill(&mut key).expect("the operating system random source failed");
    format!("whsec_{}", STANDARD.encode(key))
}

/// Whether `secret` is a Standard Webhooks secret openfraud can sign with:
/// `whsec_` and the base64 of at least 16 bytes.
pub fn check_secret(secret: &str) -> Result<()> {
    let Some(encoded) = secret.strip_prefix("whsec_") else {
        bail!("the webhook secret must start with `whsec_`");
    };
    let key = STANDARD
        .decode(encoded)
        .map_err(|_| anyhow!("the webhook secret is not `whsec_` and base64"))?;
    if key.len() < 16 {
        bail!("the webhook secret must hold at least 16 bytes");
    }
    Ok(())
}

fn key_of(secret: &str) -> Result<Vec<u8>> {
    let encoded = secret.strip_prefix("whsec_").unwrap_or(secret);
    STANDARD
        .decode(encoded)
        .map_err(|_| anyhow!("the webhook secret is not `whsec_` and base64"))
}

fn mac(key: &[u8], id: &str, timestamp: u64, body: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes a key of any length");
    mac.update(id.as_bytes());
    mac.update(b".");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    mac.finalize().into_bytes().to_vec()
}

/// The `webhook-signature` header value.
pub fn sign(secret: &str, id: &str, timestamp: u64, body: &[u8]) -> Result<String> {
    Ok(format!("v1,{}", STANDARD.encode(mac(&key_of(secret)?, id, timestamp, body))))
}

/// Checks a received webhook: one of the space-separated `v1` signatures
/// matches, and the timestamp is within five minutes of `now`.
pub fn verify(secret: &str, id: &str, timestamp: u64, header: &str, body: &[u8], now: u64) -> Result<()> {
    if timestamp.abs_diff(now) > TOLERANCE_SECS {
        bail!("the webhook timestamp is more than {TOLERANCE_SECS} seconds away");
    }
    let expected = mac(&key_of(secret)?, id, timestamp, body);
    for part in header.split_whitespace() {
        if let Some(sig) = part.strip_prefix("v1,")
            && let Ok(sig) = STANDARD.decode(sig)
            && bool::from(sig.ct_eq(&expected))
        {
            return Ok(());
        }
    }
    bail!("no webhook signature matches")
}

#[derive(Debug, Clone, PartialEq)]
pub enum Delivery {
    Done,
    /// Try again later, for this reason.
    Retry(String),
    /// The receiver answered 410: the endpoint is gone, stop.
    Gone,
}

/// An HTTP client for posts: a redirect is not followed, so a signed body
/// only ever reaches the configured address.
pub fn agent(timeout_ms: u64) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_millis(timeout_ms)))
        .http_status_as_error(false)
        .max_redirects(0)
        .user_agent(concat!("openfraud/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

/// Redirects a download follows before it gives up.
const MAX_REDIRECTS: usize = 5;

/// Downloads `url` (a list, the network dataset), reading at most `limit`
/// bytes. A redirect is followed only where [`redirect_allowed`] says, and a
/// name on the internet only connects to addresses on the internet, so a list
/// source cannot point the download at the private network.
pub fn download(url: &str, timeout_ms: u64, limit: u64) -> Result<Vec<u8>> {
    let agent: ureq::Agent = ureq::Agent::with_parts(
        ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_millis(timeout_ms)))
            .http_status_as_error(false)
            .max_redirects(0)
            .user_agent(concat!("openfraud/", env!("CARGO_PKG_VERSION")))
            .build(),
        ureq::unversioned::transport::DefaultConnector::default(),
        PublicResolver,
    );
    let mut current = url.to_owned();
    for _ in 0..=MAX_REDIRECTS {
        let site = origin(&current);
        let mut response = agent
            .get(&current)
            .call()
            .map_err(|e| anyhow!("{site}: {}", e.to_string().replace(&current, "<url>")))?;
        let status = response.status().as_u16();
        if (300..400).contains(&status) {
            let Some(next) = response
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .map(|location| join(&current, location))
            else {
                bail!("{site} answered {status} without a location");
            };
            if !redirect_allowed(url, &next) {
                bail!("{site} redirects to {}, which a download does not follow", origin(&next));
            }
            current = next;
            continue;
        }
        if status != 200 {
            bail!("{site} answered {status}");
        }
        return Ok(response.body_mut().with_config().limit(limit).read_to_vec()?);
    }
    bail!("{} redirects more than {MAX_REDIRECTS} times", origin(url))
}

/// `location` read against `base`: an absolute URL, a path on the same
/// origin, or a path relative to the base's directory.
fn join(base: &str, location: &str) -> String {
    if location.contains("://") {
        return location.to_owned();
    }
    let root = origin(base);
    if let Some(rest) = location.strip_prefix("//") {
        let scheme = base.split("://").next().unwrap_or("https");
        return format!("{scheme}://{rest}");
    }
    if location.starts_with('/') {
        return format!("{root}{location}");
    }
    let path = base[root.len()..].split(['?', '#']).next().unwrap_or_default();
    let dir = path.rsplit_once('/').map_or("", |(dir, _)| dir);
    format!("{root}{dir}/{location}")
}

/// Whether a download that started at `from` may follow a redirect to `to`:
/// the target is an address a list may be downloaded from (https, or plain
/// http on the private network), and it is on the private network only when
/// the operator's own address already was.
pub fn redirect_allowed(from: &str, to: &str) -> bool {
    let private = |url: &str| {
        url.split_once("://")
            .is_some_and(|(_, rest)| crate::config::private_host(&crate::config::host_of(rest)))
    };
    crate::config::download_address(to) && (!private(to) || private(from))
}

/// Whether `ip` is an address on the internet: not loopback, private,
/// link-local, shared (CGNAT), documentation, benchmarking, multicast or
/// reserved, also when written as an IPv4-mapped or NAT64 IPv6 address.
pub fn global_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                || a == 0
                || a >= 240
                || (a == 100 && (64..128).contains(&b))
                || (a == 192 && b == 0 && c == 0)
                || (a == 198 && (18..20).contains(&b)))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return global_address(IpAddr::V4(v4));
            }
            let s = v6.segments();
            if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0; 4] {
                let [a, b] = s[6].to_be_bytes();
                let [c, d] = s[7].to_be_bytes();
                return global_address(IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d)));
            }
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] == 0x2001 && s[1] == 0x0db8))
        }
    }
}

/// Resolves names as the system does, but a name on the internet keeps only
/// its addresses on the internet: a DNS answer cannot turn it into the host
/// itself, the private network or a cloud metadata address. A name on the
/// private network, which only the operator can write, resolves as is.
#[derive(Debug)]
struct PublicResolver;

impl ureq::unversioned::resolver::Resolver for PublicResolver {
    fn resolve(
        &self,
        uri: &ureq::http::Uri,
        config: &ureq::config::Config,
        timeout: ureq::unversioned::transport::NextTimeout,
    ) -> Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
        let all = ureq::unversioned::resolver::DefaultResolver::default().resolve(uri, config, timeout)?;
        let host = uri.host().unwrap_or_default().trim_matches(['[', ']']).to_ascii_lowercase();
        if crate::config::private_host(&host) {
            return Ok(all);
        }
        let mut kept = self.empty();
        for addr in all.iter().filter(|addr| global_address(addr.ip())) {
            kept.push(*addr);
        }
        if kept.is_empty() {
            return Err(ureq::Error::HostNotFound);
        }
        Ok(kept)
    }
}

/// The scheme, host and port of `url`, for messages: the path and the query
/// of a Slack or Telegram URL are the secret.
pub fn origin(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or_default();
    if scheme.is_empty() {
        host.to_owned()
    } else {
        format!("{scheme}://{host}")
    }
}

/// Posts one signed webhook. A 2xx is delivered, a 410 is gone, anything
/// else (an error status, a timeout, a refused connection) is retried.
pub fn deliver(url: &str, secret: &str, id: &str, timestamp: u64, body: &str, timeout_ms: u64) -> Delivery {
    let signature = match sign(secret, id, timestamp, body.as_bytes()) {
        Ok(s) => s,
        Err(e) => return Delivery::Retry(format!("{e:#}")),
    };
    let result = agent(timeout_ms)
        .post(url)
        .header("content-type", "application/json")
        .header("webhook-id", id)
        .header("webhook-timestamp", timestamp.to_string())
        .header("webhook-signature", signature)
        .send(body);
    match result {
        Ok(response) => match response.status().as_u16() {
            200..=299 => Delivery::Done,
            410 => Delivery::Gone,
            status => Delivery::Retry(format!("the receiver answered {status}")),
        },
        Err(e) => Delivery::Retry(format!("{}: {}", origin(url), e.to_string().replace(url, "<url>"))),
    }
}
