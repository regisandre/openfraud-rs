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

/// An HTTP client for downloads (lists), which may sit behind a redirect.
pub fn download_agent(timeout_ms: u64) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_millis(timeout_ms)))
        .http_status_as_error(false)
        .user_agent(concat!("openfraud/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
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
