//! Events: what the application reports, and the form rules see.
//!
//! A [`RawEvent`] is what arrives over the API. [`RawEvent::normalize`]
//! checks it and turns it into an [`Event`]: the time read, the email
//! addresses replaced by keyed pseudonyms that keep their domain, the IP
//! address reduced to a keyed hash and a network prefix, and the
//! identifiers (the values that link two accounts) gathered in `ids`. Rules
//! only ever see the normalized event, and it is the form that is stored, so
//! a replay sees exactly what the live decision saw. The raw IP address stays
//! in memory for list lookups and is never serialized.

use crate::config::Privacy;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::net::IpAddr;

pub const MAX_ID_LEN: usize = 128;
pub const MAX_USER_LEN: usize = 256;
/// How far ahead of the server's clock an event may be dated: a client clock
/// a little fast is fine, a date in the future would corrupt the counters.
pub const MAX_CLOCK_SKEW: u64 = 300;
pub const MAX_TYPE_LEN: usize = 64;

/// An event type: lowercase words of letters, digits and `_`, joined by dots,
/// each word starting with a letter. `account.created`, `x.my_event`.
pub fn valid_type(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_TYPE_LEN
        && name.split('.').all(|word| {
            word.starts_with(|c: char| c.is_ascii_lowercase())
                && word.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        })
}

/// Unix seconds, from a number of seconds or an RFC 3339 text such as
/// `2026-10-19T14:32:00+02:00`. Fractions of a second are dropped.
pub fn parse_time(value: &serde_json::Value) -> Result<u64, String> {
    match value {
        serde_json::Value::Number(n) => match n.as_f64() {
            Some(f) if f >= 0.0 && f.is_finite() => Ok(f as u64),
            _ => Err(format!("`at` must be a positive number of seconds, not {n}")),
        },
        serde_json::Value::String(s) => {
            parse_rfc3339(s).ok_or_else(|| format!("`at` must be RFC 3339, such as 2026-10-19T14:32:00Z, not `{s}`"))
        }
        other => Err(format!("`at` must be a number or a text, not {other}")),
    }
}

fn parse_rfc3339(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't') || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let num = |from: usize, to: usize| -> Option<i64> {
        let part = s.get(from..to)?;
        part.bytes().all(|c| c.is_ascii_digit()).then(|| part.parse().ok())?
    };
    let (year, month, day) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (hour, minute, second) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let mut rest = &s[19..];
    if let Some(fraction) = rest.strip_prefix('.') {
        let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        rest = &fraction[digits..];
    }
    let offset = match rest {
        "Z" | "z" => 0,
        _ => {
            let r = rest.as_bytes();
            if r.len() != 6 || !matches!(r[0], b'+' | b'-') || r[3] != b':' {
                return None;
            }
            let h: i64 = rest.get(1..3)?.parse().ok()?;
            let m: i64 = rest.get(4..6)?.parse().ok()?;
            let sign = if r[0] == b'-' { -1 } else { 1 };
            sign * (h * 3_600 + m * 60)
        }
    };
    let days = days_from_civil(year, month, day);
    let t = days * 86_400 + hour * 3_600 + minute * 60 + second - offset;
    u64::try_from(t).ok()
}

/// Unix seconds as RFC 3339 in UTC: `2026-10-19T12:32:00Z`.
pub fn format_time(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rest = secs % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3_600,
        (rest % 3_600) / 60,
        rest % 60
    )
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Keyed hashes for personal data. The key lives in the state file; another
/// key gives other pseudonyms, so the key is never changed once events exist.
#[derive(Clone)]
pub struct Pseudonymizer {
    key: Vec<u8>,
}

impl Pseudonymizer {
    pub fn new(key: Vec<u8>) -> Self {
        Pseudonymizer { key }
    }

    /// The first `hex_len` hex digits of HMAC-SHA256(key, `kind:value`).
    pub fn hash(&self, kind: &str, value: &str, hex_len: usize) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC takes a key of any length");
        mac.update(kind.as_bytes());
        mac.update(b":");
        mac.update(value.as_bytes());
        let digest = mac.finalize().into_bytes();
        let mut out: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        out.truncate(hex_len);
        out
    }

    /// `<12 hex>.<8 hex>@domain`: the first part identifies the mailbox (the
    /// address as its provider reads it), the second its stem (the letters
    /// of the local part), so `openai7623@x` and `openai@y` share a stem.
    pub fn email(&self, address: &str) -> String {
        match canonical_email(address) {
            Some((local, domain)) => {
                let stem: String = local.chars().filter(|c| c.is_alphabetic()).collect();
                let stem = if stem.is_empty() { local.clone() } else { stem };
                format!(
                    "{}.{}@{domain}",
                    self.hash("email", &format!("{local}@{domain}"), 12),
                    self.hash("stem", &stem, 8)
                )
            }
            None => format!(
                "{}.{}@invalid",
                self.hash("email", address.trim(), 12),
                self.hash("stem", address.trim(), 8)
            ),
        }
    }
}

/// The local part and domain as the provider reads them: lower case, no
/// `+tag`, and for Gmail no dots and `googlemail.com` read as `gmail.com`.
pub fn canonical_email(address: &str) -> Option<(String, String)> {
    let address = address.trim().to_lowercase();
    let (local, domain) = address.rsplit_once('@')?;
    if local.is_empty()
        || domain.is_empty()
        || !domain.contains('.')
        || domain.contains(char::is_whitespace)
        || local.contains(char::is_whitespace)
    {
        return None;
    }
    let local = local.split('+').next().unwrap_or(local);
    let (local, domain) = match domain {
        "gmail.com" | "googlemail.com" => (local.replace('.', ""), "gmail.com".to_owned()),
        _ => (local.to_owned(), domain.to_owned()),
    };
    if local.is_empty() {
        return None;
    }
    Some((local, domain))
}

/// The network an address belongs to, as a stored prefix: /24 for IPv4,
/// /48 for IPv6.
pub fn ip_prefix(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
    }
}

/// What counts as one address: itself for IPv4, its /64 for IPv6.
fn ip_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
    }
}

/// The schema version of events: bumped only by a breaking change.
pub const EVENT_SCHEMA: &str = "openfraud.event/v1";

/// The event types openfraud knows, in ten families. Attributes are free.
/// Any other type must be declared in `[events] custom`.
pub const VOCABULARY: [&str; 55] = [
    // account: the life of an account
    "account.created",
    "account.updated",
    "account.verified",
    "account.email_changed",
    "account.phone_changed",
    "account.referred",
    "account.deleted",
    // session: signing in and the credentials
    "session.login",
    "session.login_failed",
    "session.logout",
    "session.password_reset",
    "session.mfa_changed",
    // challenge: proof asked for after a step_up, and its result
    "challenge.requested",
    "challenge.succeeded",
    "challenge.failed",
    // payment: money in
    "payment.method_added",
    "payment.attempted",
    "payment.succeeded",
    "payment.failed",
    "payment.refunded",
    "payment.disputed",
    "payment.fraud_warning",
    "payment.promo_redeemed",
    // subscription: plans and trials
    "subscription.trial_started",
    "subscription.created",
    "subscription.upgraded",
    "subscription.downgraded",
    "subscription.canceled",
    "subscription.invoice_paid",
    // resource: what an account creates
    "resource.created",
    "resource.updated",
    "resource.deleted",
    "resource.exported",
    "resource.feature_enabled",
    "resource.apikey_created",
    "resource.webhook_created",
    "resource.domain_added",
    // message: email, SMS, push
    "message.send_requested",
    "message.test_requested",
    "message.contacts_imported",
    "message.delivered",
    "message.bounced",
    "message.complained",
    "message.otp_requested",
    // payout: money out
    "payout.destination_changed",
    "payout.requested",
    "payout.sent",
    // usage: metered consumption
    "usage.recorded",
    "usage.quota_exceeded",
    "usage.credit_granted",
    // content: what an account publishes or uploads
    "content.published",
    "content.uploaded",
    "content.moderated",
    "content.reported",
    "content.removed",
];

/// A type of the vocabulary, or one the configuration declares.
pub fn known_type(kind: &str, custom: &[String]) -> bool {
    VOCABULARY.contains(&kind) || custom.iter().any(|c| c == kind)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Subject {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
}

/// An event as the application sends it.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawEvent {
    /// Unique per event: a retry with the same id is answered from the
    /// first decision and not counted twice. Generated when absent.
    #[serde(default)]
    pub id: Option<String>,
    #[serde(rename = "type", default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub at: Option<serde_json::Value>,
    /// Who acts, in the application's own ids.
    #[serde(default, alias = "user")]
    pub actor_id: Option<String>,
    /// When the actor's account was created, for accounts that existed
    /// before openfraud saw them. Used only while openfraud knows no
    /// creation date for the actor.
    #[serde(default)]
    pub actor_created_at: Option<serde_json::Value>,
    /// The workspace, team, organisation or store acted on.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// The tenant's owner.
    #[serde(default)]
    pub owner_id: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    /// E.164: `+` and the country code.
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub device: Option<String>,
    /// The `User-Agent` header of the request: read into facts, never kept.
    #[serde(default)]
    pub user_agent: Option<String>,
    /// The `Accept-Language` header, or a language tag: its primary language
    /// (`fr` for `fr-BE,fr;q=0.9`) is kept.
    #[serde(default)]
    pub language: Option<String>,
    /// ISO 3166 alpha-2 country of the request, for example from a CDN header.
    #[serde(default)]
    pub country: Option<String>,
    /// The token of the browser script (`sdk/device`), as the page sent it.
    #[serde(default)]
    pub device_token: Option<String>,
    /// What the event is about: a page, an order, a campaign.
    #[serde(default)]
    pub subject: Option<Subject>,
    #[serde(default)]
    pub attrs: Option<serde_json::Value>,
    /// What the account is, kept on it from event to event: `{"plan":
    /// "pro", "seats": 4}`. Texts, numbers and booleans.
    #[serde(default)]
    pub traits: Option<serde_json::Value>,
    /// Who saw the event happen: `server` (default), or `client` for an
    /// event a page or an app reports on its own. A client's claims about
    /// the account are not trusted: its actor, tenant and owner are dropped.
    #[serde(default)]
    pub reported_by: Option<String>,
    /// Ignored: the version of the event schema the sender follows.
    #[serde(default)]
    pub schema: Option<String>,
}

/// An event as rules see it and as it is stored.
/// Who saw an event happen.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// The application's own backend, which knows who is signed in.
    #[default]
    Server,
    /// A page or an app, which anyone can imitate.
    Client,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Event {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub at: u64,
    /// `server` or `client`; rules read it as `event.reported_by`.
    #[serde(default)]
    pub reported_by: Source,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// The account's creation date claimed by the application, never after `at`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_created_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_domain: Option<String>,
    /// What the address looked like before it became a pseudonym.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_shape: Option<crate::signals::EmailShape>,
    /// The domain below its public suffix: `fraudco.net` for
    /// `a.fraudco.net`, `example.co.uk` for itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_registered_domain: Option<String>,
    /// Whether the domain takes mail, when `[email] mx_check` asked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_reachable: Option<bool>,
    /// A short keyed hash of the address as typed, tag included: one mailbox
    /// signing up as `ann+1@` and `ann+2@` has one `email` and two aliases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_alias: Option<String>,
    /// `+` and the first six digits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone_prefix: Option<String>,
    /// The international calling code of the number (`+32`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_prefix: Option<String>,
    /// The IP lists the address was found in when the event arrived.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip_lists: Vec<String>,
    /// The autonomous system announcing the address, its operator and the
    /// country the operator is registered in, when the network table is on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_asn: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_org: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_country: Option<String>,
    /// In memory only: list lookups need it, storage never sees it.
    #[serde(skip)]
    pub ip: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// What the user agent says: browser, system, device, automation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<crate::agent::Agent>,
    /// The primary language of the request (`fr`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// The device token: `ok`, `replayed` (used before for this kind of
    /// event), `stale`, `invalid`, `missing` (none where one is required)
    /// or `mock` (a sandbox's).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_token: Option<String>,
    /// What the device script read: time zone, platform, touch, webdriver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_info: Option<crate::device::DeviceInfo>,
    /// In memory only: the token as read, for the engine's checks.
    #[serde(skip)]
    pub token: Option<crate::device::Token>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<Subject>,
    #[serde(default)]
    pub attrs: serde_json::Map<String, serde_json::Value>,
    /// The traits the event sends, kept on the actor.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub traits: serde_json::Map<String, serde_json::Value>,
    /// Identifier kind to keyed hash: the values that link accounts.
    #[serde(default)]
    pub ids: BTreeMap<String, String>,
}

/// `+` and digits, from a number written with spaces, dashes, dots or
/// brackets. `None` without the leading `+` or with 8 to 15 digits missing.
pub fn e164(number: &str) -> Option<String> {
    let trimmed = number.trim();
    let digits: String = trimmed.chars().filter(char::is_ascii_digit).collect();
    let clean = trimmed.chars().all(|c| c.is_ascii_digit() || " -.()+".contains(c));
    (trimmed.starts_with('+') && clean && (8..=15).contains(&digits.len())).then(|| format!("+{digits}"))
}

/// `+` and the first six digits: the country and the operator range.
pub fn phone_prefix(e164: &str) -> String {
    e164.chars().take(7).collect()
}

/// The longest `User-Agent` accepted.
pub const MAX_USER_AGENT_LEN: usize = 1_024;

/// The primary language of a tag or an `Accept-Language` header, lower case:
/// `fr` for `fr-BE,fr;q=0.9`. `None` for an empty value or `*`.
fn primary_language(text: &str) -> Result<Option<String>, String> {
    let first = text.split(',').next().unwrap_or("").split(';').next().unwrap_or("").trim();
    if first.is_empty() || first == "*" {
        return Ok(None);
    }
    let primary = first.split(['-', '_']).next().unwrap_or("");
    if (2..=3).contains(&primary.len()) && primary.bytes().all(|b| b.is_ascii_alphabetic()) {
        Ok(Some(primary.to_ascii_lowercase()))
    } else {
        Err(text.chars().take(40).collect())
    }
}

fn check_id(name: &str, value: &Option<String>, max: usize) -> Result<(), String> {
    match value {
        Some(v) if v.is_empty() || v.len() > max => Err(format!("the `{name}` must have 1 to {max} characters")),
        _ => Ok(()),
    }
}

impl RawEvent {
    /// Checks the event and builds its normalized form: `privacy` names the
    /// attributes holding contacts (email addresses or phone numbers, a text
    /// or a list of texts) and identifiers (a card fingerprint); both are
    /// replaced by pseudonyms.
    pub fn normalize(self, p: &Pseudonymizer, privacy: &Privacy, now: u64) -> Result<Event, String> {
        let kind = self.kind.ok_or("the event needs a `type`")?;
        if !valid_type(&kind) {
            return Err(format!(
                "the `type` `{kind}` must be lowercase words joined by dots, such as account.created"
            ));
        }
        let at = match &self.at {
            None | Some(serde_json::Value::Null) => now,
            Some(value) => parse_time(value)?,
        };
        if at > now.saturating_add(MAX_CLOCK_SKEW) {
            return Err(format!(
                "the `at` is in the future: more than {MAX_CLOCK_SKEW} seconds ahead of the server's clock"
            ));
        }
        let actor_created_at = match &self.actor_created_at {
            None | Some(serde_json::Value::Null) => None,
            Some(value) => Some(parse_time(value).map_err(|e| format!("actor_created_at: {e}"))?.min(at)),
        };
        let id = match self.id {
            Some(id) if id.is_empty() || id.len() > MAX_ID_LEN => {
                return Err(format!("the `id` must have 1 to {MAX_ID_LEN} characters"));
            }
            Some(id) => id,
            None => format!("evt_{}", random_hex(12)),
        };
        let reported_by = match self.reported_by.as_deref() {
            None | Some("server") => Source::Server,
            Some("client") => Source::Client,
            Some(other) => return Err(format!("the `reported_by` `{other}` must be `server` or `client`")),
        };
        check_id("actor_id", &self.actor_id, MAX_USER_LEN)?;
        check_id("tenant_id", &self.tenant_id, MAX_USER_LEN)?;
        check_id("owner_id", &self.owner_id, MAX_USER_LEN)?;
        let ip = match &self.ip {
            None => None,
            // An IPv4 address sent in its IPv6-mapped form is the same host.
            Some(text) => Some(
                text.trim()
                    .parse::<IpAddr>()
                    .map_err(|_| format!("the `ip` `{text}` is not an IP address"))?
                    .to_canonical(),
            ),
        };
        let phone = match &self.phone {
            None => None,
            Some(text) => {
                Some(e164(text).ok_or_else(|| format!("the `phone` `{text}` is not an international number such as +32470123456"))?)
            }
        };
        let agent = match &self.user_agent {
            Some(ua) if ua.chars().count() > MAX_USER_AGENT_LEN => {
                return Err(format!("the `user_agent` must have at most {MAX_USER_AGENT_LEN} characters"));
            }
            Some(ua) => Some(crate::agent::parse(ua)),
            None => None,
        };
        let language = match self.language.as_deref().map(primary_language) {
            None | Some(Ok(None)) => None,
            Some(Ok(Some(tag))) => Some(tag),
            Some(Err(text)) => {
                return Err(format!(
                    "the `language` `{text}` must be a language tag or an Accept-Language header, such as fr-BE or fr-BE,fr;q=0.9"
                ));
            }
        };
        let country = match self.country {
            None => None,
            Some(c) if c.len() == 2 && c.bytes().all(|b| b.is_ascii_alphabetic()) => Some(c.to_ascii_uppercase()),
            Some(c) => return Err(format!("the `country` `{c}` must be two letters, such as BE")),
        };
        let mut attrs = match self.attrs {
            None | Some(serde_json::Value::Null) => serde_json::Map::new(),
            Some(serde_json::Value::Object(map)) => map,
            Some(_) => return Err("the `attrs` must be an object".into()),
        };
        payment_attrs(&mut attrs);
        let traits = match self.traits {
            None | Some(serde_json::Value::Null) => serde_json::Map::new(),
            Some(serde_json::Value::Object(map)) => plain_traits(map),
            Some(_) => return Err("the `traits` must be an object".into()),
        };
        if let Some(subject) = &self.subject
            && (subject.kind.is_empty() || subject.id.is_empty() || subject.kind.len() > MAX_ID_LEN || subject.id.len() > MAX_ID_LEN)
        {
            return Err(format!("the `subject` needs a `type` and an `id` of 1 to {MAX_ID_LEN} characters"));
        }

        let mut ids = BTreeMap::new();
        let email = self.email.as_deref().map(|e| p.email(e));
        let email_shape = self.email.as_deref().and_then(crate::signals::email_shape);
        let email_alias = self
            .email
            .as_deref()
            .filter(|_| email_shape.is_some())
            .map(|e| p.hash("alias", &e.trim().to_lowercase(), 8));
        let email_domain = email.as_deref().and_then(|e| e.rsplit_once('@')).map(|(_, d)| d.to_owned());
        if let Some(e) = &email {
            ids.insert("email".to_owned(), e.split('.').next().unwrap_or(e).to_owned());
        }
        if let Some(number) = &phone {
            ids.insert("phone".to_owned(), p.hash("phone", number, 16));
        }
        // A host of an IPv6 network holds a whole /64 and rotates inside it at will,
        // so counters and links see the /64, as one address.
        let ip_hash = ip.map(|ip| p.hash("ip", &ip_key(ip), 16));
        if let Some(h) = &ip_hash {
            ids.insert("ip".to_owned(), h.clone());
        }
        let prefix = ip.map(ip_prefix);
        if let Some(net) = &prefix {
            ids.insert("ip_prefix".to_owned(), net.clone());
        }
        let token = self.device_token.as_deref().map(crate::device::read_token);
        // The script's own id stands in for a device the application did not send.
        let token_device = match &token {
            Some(crate::device::Token::Script(t)) => t.id.clone(),
            _ => None,
        };
        let device = self.device.as_deref().or(token_device.as_deref()).map(|d| p.hash("device", d, 16));
        if let Some(d) = &device {
            ids.insert("device".to_owned(), d.clone());
        }
        for name in &privacy.contact_attrs {
            if let Some(value) = attrs.get_mut(name) {
                let shape = list_shape(value);
                pseudonymize_contacts(value, p);
                if let Some(shape) = shape {
                    attrs.insert(format!("{name}_shape"), shape);
                }
            }
        }
        for name in &privacy.id_attrs {
            if let Some(value) = attrs.get_mut(name) {
                let text = match value {
                    serde_json::Value::String(s) if !s.is_empty() => s.clone(),
                    serde_json::Value::Number(n) => n.to_string(),
                    _ => continue,
                };
                let hashed = p.hash(name, &text, 16);
                ids.insert(name.clone(), hashed.clone());
                *value = serde_json::Value::String(hashed);
            }
        }

        // A client's word about the account is a claim, never an identity.
        let trusted = reported_by == Source::Server;
        Ok(Event {
            id,
            kind,
            at,
            reported_by,
            actor: self.actor_id.filter(|_| trusted),
            actor_created_at: actor_created_at.filter(|_| trusted),
            tenant: self.tenant_id.filter(|_| trusted),
            owner: self.owner_id.filter(|_| trusted),
            email,
            email_registered_domain: email_domain
                .as_deref()
                .filter(|d| *d != "invalid")
                .and_then(crate::signals::registered_domain),
            email_reachable: None,
            email_domain,
            email_shape,
            email_alias,
            phone_prefix: phone.as_deref().map(phone_prefix),
            phone_code: phone.as_deref().map(crate::signals::phone_code).filter(|c| !c.is_empty()),
            ip_hash,
            ip_prefix: prefix,
            ip_lists: Vec::new(),
            ip_asn: None,
            ip_org: None,
            ip_country: None,
            ip,
            device,
            agent,
            language,
            country,
            device_token: token.as_ref().map(|t| match t {
                crate::device::Token::Script(_) => "ok".to_owned(),
                crate::device::Token::Mock(_) => "mock".to_owned(),
                crate::device::Token::Invalid => "invalid".to_owned(),
            }),
            device_info: match &token {
                Some(crate::device::Token::Script(t)) => Some(t.info.clone()),
                _ => None,
            },
            token,
            subject: self.subject,
            attrs,
            traits,
            ids,
        })
    }
}

/// Payment attributes never kept: the card holder's name, the card number
/// and code, and the postal addresses.
pub const DROPPED_ATTRS: [&str; 8] = [
    "holder_name",
    "card_holder",
    "card_number",
    "pan",
    "cvc",
    "cvv",
    "billing_address",
    "shipping_address",
];

/// The most traits an account keeps, and the longest text of one.
pub const MAX_TRAITS: usize = 50;
pub const MAX_TRAIT_LEN: usize = 256;

/// Keeps the country of each postal address (`billing_country`,
/// `shipping_country`), then drops the addresses, the holder's name and the
/// card number.
fn payment_attrs(attrs: &mut serde_json::Map<String, serde_json::Value>) {
    for (address, country) in [("billing_address", "billing_country"), ("shipping_address", "shipping_country")] {
        let code = attrs
            .get(address)
            .and_then(|a| a.get("country_code").or_else(|| a.get("country")))
            .and_then(serde_json::Value::as_str)
            .filter(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_alphabetic()))
            .map(str::to_ascii_uppercase);
        if let Some(code) = code {
            attrs.entry(country).or_insert(serde_json::Value::String(code));
        }
    }
    for name in ["billing_country", "shipping_country", "card_country"] {
        if let Some(serde_json::Value::String(c)) = attrs.get_mut(name) {
            *c = c.to_ascii_uppercase();
        }
    }
    for name in DROPPED_ATTRS {
        attrs.remove(name);
    }
}

/// The traits worth keeping: plain values under a plain name.
fn plain_traits(map: serde_json::Map<String, serde_json::Value>) -> serde_json::Map<String, serde_json::Value> {
    map.into_iter()
        .filter(|(name, value)| {
            !name.is_empty()
                && name.len() <= 64
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.')
                && match value {
                    serde_json::Value::String(s) => s.chars().count() <= MAX_TRAIT_LEN,
                    serde_json::Value::Number(_) | serde_json::Value::Bool(_) => true,
                    _ => false,
                }
        })
        .take(MAX_TRAITS)
        .collect()
}

/// An account's traits after an event's: a trait keeps the type it first
/// had, and an account keeps at most [`MAX_TRAITS`].
pub fn merge_traits(
    kept: &std::collections::BTreeMap<String, serde_json::Value>,
    new: &serde_json::Map<String, serde_json::Value>,
) -> std::collections::BTreeMap<String, serde_json::Value> {
    let same_type = |a: &serde_json::Value, b: &serde_json::Value| {
        matches!(
            (a, b),
            (serde_json::Value::String(_), serde_json::Value::String(_))
                | (serde_json::Value::Number(_), serde_json::Value::Number(_))
                | (serde_json::Value::Bool(_), serde_json::Value::Bool(_))
        )
    };
    let mut out = kept.clone();
    for (name, value) in new {
        match out.get(name) {
            Some(old) if same_type(old, value) => {
                out.insert(name.clone(), value.clone());
            }
            Some(_) => {}
            None if out.len() < MAX_TRAITS => {
                out.insert(name.clone(), value.clone());
            }
            None => {}
        }
    }
    out
}

/// For a list holding phone numbers, before they are hashed: how many,
/// how many distinct prefixes, and the longest run of consecutive numbers
/// (`...101`, `...102`, `...103`), the mark of a generated list.
/// Mailboxes that belong to a function, not a person: a list full of them
/// was scraped or bought, not collected.
pub const ROLE_MAILBOXES: [&str; 24] = [
    "abuse",
    "admin",
    "administrator",
    "billing",
    "careers",
    "contact",
    "enquiries",
    "hello",
    "help",
    "hostmaster",
    "info",
    "jobs",
    "marketing",
    "no-reply",
    "noreply",
    "office",
    "postmaster",
    "privacy",
    "root",
    "sales",
    "security",
    "support",
    "team",
    "webmaster",
];

/// An address a mail server would accept the shape of: one `@`, a local
/// part, and a domain with a dot and no space.
fn plausible_address(text: &str) -> bool {
    let Some((local, domain)) = text.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.contains('@')
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !text.contains(char::is_whitespace)
}

/// The shape of a contact list, measured before pseudonyms replace it:
/// `count` items, `roles` (admin@, info@ ...), `invalid` (neither an address
/// nor a phone number), and for phone numbers how many country prefixes and
/// the longest run of consecutive numbers. `None` for a single contact.
fn list_shape(value: &serde_json::Value) -> Option<serde_json::Value> {
    let items = value.as_array()?;
    let (mut roles, mut invalid) = (0, 0);
    let mut numbers: Vec<u64> = Vec::new();
    let mut prefixes = std::collections::BTreeSet::new();
    for item in items {
        let Some(text) = item.as_str().map(str::trim) else {
            invalid += 1;
            continue;
        };
        if !text.contains('@')
            && let Some(n) = e164(text)
        {
            prefixes.insert(phone_prefix(&n));
            if let Ok(v) = n[1..].parse::<u64>() {
                numbers.push(v);
            }
        } else if plausible_address(text) {
            let local = text.split('@').next().unwrap_or_default().to_ascii_lowercase();
            let local = local.split('+').next().unwrap_or_default();
            if ROLE_MAILBOXES.contains(&local) {
                roles += 1;
            }
        } else {
            invalid += 1;
        }
    }
    numbers.sort_unstable();
    numbers.dedup();
    let mut longest = usize::from(!numbers.is_empty());
    let mut run = 1;
    for pair in numbers.windows(2) {
        run = if pair[1] == pair[0] + 1 { run + 1 } else { 1 };
        longest = longest.max(run);
    }
    Some(serde_json::json!({"count": items.len(), "roles": roles, "invalid": invalid, "prefixes": prefixes.len(), "longest_run": longest}))
}

fn pseudonymize_contact(text: &str, p: &Pseudonymizer) -> String {
    match e164(text) {
        Some(n) if !text.contains('@') => format!("{}~{}", phone_prefix(&n), p.hash("phone", &n, 10)),
        _ => p.email(text),
    }
}

fn pseudonymize_contacts(value: &mut serde_json::Value, p: &Pseudonymizer) {
    match value {
        serde_json::Value::String(s) => *s = pseudonymize_contact(s, p),
        serde_json::Value::Array(items) => {
            for item in items {
                if let serde_json::Value::String(s) = item {
                    *s = pseudonymize_contact(s, p);
                }
            }
        }
        _ => {}
    }
}

pub fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).expect("the operating system random source failed");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}
