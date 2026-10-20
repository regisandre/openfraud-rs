//! The device token: what the browser script (`sdk/device`) says about the
//! device, in one short text the application forwards in the event's
//! `device_token`.
//!
//! The script has no secret, so a token proves nothing about who made it:
//! openfraud checks that it is fresh, used once per kind of event, and
//! consistent with the request (the time zone against the country, the
//! platform against the user agent). No fingerprint: the token carries the
//! device id, a random nonce, the time, the time zone, the platform, whether
//! the screen is touch, and the `navigator.webdriver` flag.
//!
//! A sandbox instance (`[server] sandbox = true`) also reads mock tokens,
//! `test|device:chrome_on_mac|ip:se|verdict:block|score:80`, to test an
//! integration before the script is in place. Anywhere else they are invalid.

use crate::agent::Agent;
use crate::config::Decision;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

/// The longest token read.
pub const MAX_TOKEN_LEN: usize = 2_048;

/// What the script read on the device.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// The IANA time zone (`Europe/Brussels`), or `""`.
    pub timezone: String,
    /// The platform as a system family: `windows`, `macos`, `ios`,
    /// `android`, `linux`, `linux_arm`, `chromeos`, `other` or `""`.
    pub platform: String,
    /// The screen takes touch.
    pub touch: bool,
    /// The browser says a script drives it (`navigator.webdriver`).
    pub webdriver: bool,
}

/// A token the script made.
#[derive(Debug, Clone, PartialEq)]
pub struct ScriptToken {
    pub id: Option<String>,
    pub nonce: String,
    pub issued_at: u64,
    pub info: DeviceInfo,
}

/// A mock token's parameters, for a sandbox.
#[derive(Debug, Clone, PartialEq)]
pub struct Mock {
    /// `chrome_on_mac`, `firefox_on_windows`, `bot_on_linux` ...
    pub device: String,
    /// The country the request is said to come from.
    pub country: Option<String>,
    /// The decision the answer is forced to.
    pub verdict: Option<Decision>,
    /// The score the answer is given.
    pub score: Option<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Script(ScriptToken),
    Mock(Mock),
    Invalid,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    v: u8,
    #[serde(default)]
    id: Option<String>,
    n: String,
    t: u64,
    #[serde(default)]
    tz: String,
    #[serde(default)]
    p: String,
    #[serde(default)]
    touch: bool,
    #[serde(default)]
    wd: bool,
}

/// The system family of `navigator.platform`.
pub fn platform_family(platform: &str) -> &'static str {
    let p = platform.trim();
    let lower = p.to_ascii_lowercase();
    if p.is_empty() {
        ""
    } else if lower.starts_with("win") {
        "windows"
    } else if lower.starts_with("mac") {
        "macos"
    } else if lower.starts_with("iphone") || lower.starts_with("ipad") || lower.starts_with("ipod") {
        "ios"
    } else if lower.contains("android") {
        "android"
    } else if lower.contains("cros") {
        "chromeos"
    } else if lower.starts_with("linux") && (lower.contains("arm") || lower.contains("aarch64")) {
        "linux_arm"
    } else if lower.starts_with("linux") {
        "linux"
    } else {
        "other"
    }
}

fn short(text: &str, max: usize) -> bool {
    text.chars().count() <= max && !text.chars().any(char::is_control)
}

fn read_mock(text: &str) -> Token {
    let mut device = None;
    let mut mock = Mock {
        device: String::new(),
        country: None,
        verdict: None,
        score: None,
    };
    for part in text.split('|').skip(1) {
        let Some((key, value)) = part.split_once(':') else {
            return Token::Invalid;
        };
        let value = value.trim();
        match key.trim() {
            "device" if !value.is_empty() && short(value, 64) => device = Some(value.to_owned()),
            "ip" => {
                let country = value.split('-').next().unwrap_or_default();
                if country.len() != 2 || !country.bytes().all(|b| b.is_ascii_alphabetic()) {
                    return Token::Invalid;
                }
                mock.country = Some(country.to_ascii_uppercase());
            }
            "verdict" | "policy.action" => {
                mock.verdict = match value {
                    "deny" => Some(Decision::Block),
                    "challenge" => Some(Decision::StepUp),
                    other => match Decision::parse(other) {
                        Some(d) => Some(d),
                        None => return Token::Invalid,
                    },
                }
            }
            "score" => match value.parse::<i64>() {
                Ok(s) if (0..=1_000).contains(&s) => mock.score = Some(s),
                _ => return Token::Invalid,
            },
            "risk" => match value.parse::<f64>() {
                Ok(r) if (0.0..=1.0).contains(&r) => mock.score = Some((r * 100.0).round() as i64),
                _ => return Token::Invalid,
            },
            _ => return Token::Invalid,
        }
    }
    match device {
        Some(d) => {
            mock.device = d;
            Token::Mock(mock)
        }
        None => Token::Invalid,
    }
}

/// Reads a device token: one the script made, a mock one, or neither.
pub fn read_token(text: &str) -> Token {
    let text = text.trim();
    if text.len() > MAX_TOKEN_LEN {
        return Token::Invalid;
    }
    if text.starts_with("test|") {
        return read_mock(text);
    }
    let Some(encoded) = text.strip_prefix("of1.") else {
        return Token::Invalid;
    };
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(encoded.trim_end_matches('=')) else {
        return Token::Invalid;
    };
    let Ok(body) = serde_json::from_slice::<Body>(&bytes) else {
        return Token::Invalid;
    };
    let nonce_ok = (16..=64).contains(&body.n.len()) && body.n.bytes().all(|b| b.is_ascii_hexdigit());
    let id_ok = body.id.as_deref().is_none_or(|id| !id.is_empty() && short(id, 128));
    if body.v != 1 || !nonce_ok || !id_ok || !short(&body.tz, 64) || !short(&body.p, 64) {
        return Token::Invalid;
    }
    Token::Script(ScriptToken {
        id: body.id,
        nonce: body.n.to_ascii_lowercase(),
        issued_at: body.t,
        info: DeviceInfo {
            timezone: body.tz,
            platform: platform_family(&body.p).to_owned(),
            touch: body.touch,
            webdriver: body.wd,
        },
    })
}

/// Latitude and longitude boxes of the time zone areas that are land.
fn area_boxes(area: &str) -> Option<&'static [(f64, f64, f64, f64)]> {
    // (lowest latitude, highest latitude, westmost longitude, eastmost longitude)
    Some(match area {
        "Europe" => &[(34.0, 72.0, -25.0, 45.0), (45.0, 82.0, 45.0, 180.0)],
        "America" => &[(-56.0, 84.0, -170.0, -30.0)],
        "Asia" => &[(-11.0, 82.0, 25.0, 180.0)],
        "Africa" => &[(-35.0, 38.0, -26.0, 52.0)],
        "Australia" => &[(-45.0, -9.0, 110.0, 155.0)],
        "Pacific" => &[(-50.0, 30.0, 120.0, 180.0), (-50.0, 30.0, -180.0, -120.0)],
        _ => return None,
    })
}

/// Whether the area of a time zone (`Europe/Paris`) holds the centre of a
/// country. `None` when it cannot be told: an ocean zone, `UTC`, an
/// unknown country. Coarse: a country is placed by its centre.
pub fn timezone_matches(timezone: &str, country: &str) -> Option<bool> {
    let (area, _) = timezone.split_once('/')?;
    let boxes = area_boxes(area)?;
    let (lat, lon) = crate::geo::centre(country)?;
    Some(
        boxes
            .iter()
            .any(|(lat0, lat1, lon0, lon1)| (*lat0..=*lat1).contains(&lat) && (*lon0..=*lon1).contains(&lon)),
    )
}

/// Whether what the script read contradicts the user agent: another system
/// family, or a phone or a tablet without a touch screen.
pub fn spoofed(info: &DeviceInfo, agent: &Agent) -> bool {
    let os = agent.os.as_str();
    let compatible = match info.platform.as_str() {
        "" | "other" => true,
        _ if os.is_empty() => true,
        "windows" => os == "windows",
        "macos" => os == "macos" || os == "ios",
        "ios" => os == "ios",
        "android" => os == "android",
        "linux_arm" => matches!(os, "android" | "linux" | "chromeos"),
        "linux" => matches!(os, "linux" | "chromeos" | "android"),
        "chromeos" => matches!(os, "chromeos" | "linux"),
        _ => true,
    };
    let touchless_phone = matches!(agent.device.as_str(), "mobile" | "tablet") && !info.touch;
    !compatible || touchless_phone
}
