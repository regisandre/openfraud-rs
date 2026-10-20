//! The device token the browser script makes: what it carries, when it is
//! read as invalid, and the checks between what it says and what the
//! request says (time zone against the country, platform against the user
//! agent).
#![allow(clippy::type_complexity)]

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openfraud::device::{Token, read_token, spoofed, timezone_matches};
use serde_json::json;

fn token(body: serde_json::Value) -> String {
    format!("of1.{}", URL_SAFE_NO_PAD.encode(body.to_string()))
}

#[test]
fn a_device_token_is_read_or_refused() {
    let good = json!({"v": 1, "id": "dev_1", "n": "a1b2c3d4e5f60718", "t": 1_000, "tz": "Europe/Brussels", "p": "Win32", "touch": false, "wd": false});
    // (case, token, what it is read as)
    let cases: Vec<(&str, String, &str)> = vec![
        ("a token from the script", token(good.clone()), "token"),
        ("not a token", "hello".into(), "invalid"),
        (
            "another version",
            token(json!({"v": 2, "n": "a1b2c3d4e5f60718", "t": 1_000})),
            "invalid",
        ),
        ("no nonce", token(json!({"v": 1, "t": 1_000})), "invalid"),
        (
            "a nonce too short to be random",
            token(json!({"v": 1, "n": "ab", "t": 1_000})),
            "invalid",
        ),
        ("broken base64", "of1.!!!".into(), "invalid"),
        ("far too long", format!("of1.{}", "A".repeat(5_000)), "invalid"),
        (
            "a mock token",
            "test|device:chrome_on_mac|ip:se|verdict:block|score:80".into(),
            "mock",
        ),
        ("a mock token without its device", "test|ip:se".into(), "invalid"),
    ];
    let mut failures = Vec::new();
    for (case, text, want) in cases {
        let got = match read_token(&text) {
            Token::Script(_) => "token",
            Token::Invalid => "invalid",
            Token::Mock(_) => "mock",
        };
        if got != want {
            failures.push(format!("{case}: read as {got}, want {want}"));
        }
    }
    match read_token(&token(good)) {
        Token::Script(t) => {
            let read = (
                t.id.as_deref(),
                t.nonce.as_str(),
                t.issued_at,
                t.info.timezone.as_str(),
                t.info.platform.as_str(),
            );
            if read != (Some("dev_1"), "a1b2c3d4e5f60718", 1_000, "Europe/Brussels", "windows") {
                failures.push(format!("the token's fields: {read:?}"));
            }
        }
        _ => failures.push("the good token is read".into()),
    }
    match read_token("test|device:bot_on_linux|ip:jp|verdict:deny") {
        Token::Mock(m) => {
            if (m.device.as_str(), m.country.as_deref(), m.verdict.map(|d| d.as_str())) != ("bot_on_linux", Some("JP"), Some("block")) {
                failures.push(format!("the mock token's parameters: {m:?}"));
            }
        }
        _ => failures.push("a mock token with deny".into()),
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_time_zone_is_checked_against_the_country_of_the_request() {
    // (case, time zone, country, matches: None when it cannot be told)
    let cases: Vec<(&str, &str, &str, Option<bool>)> = vec![
        ("Brussels in Belgium", "Europe/Brussels", "BE", Some(true)),
        ("Moscow in Russia", "Europe/Moscow", "RU", Some(true)),
        ("Istanbul in Turkey", "Europe/Istanbul", "TR", Some(true)),
        ("New York in the United States", "America/New_York", "US", Some(true)),
        ("Sao Paulo in Brazil", "America/Sao_Paulo", "BR", Some(true)),
        ("Tokyo in Japan", "Asia/Tokyo", "JP", Some(true)),
        ("Dubai in the Emirates", "Asia/Dubai", "AE", Some(true)),
        ("Lagos in Nigeria", "Africa/Lagos", "NG", Some(true)),
        ("Cairo in Egypt", "Africa/Cairo", "EG", Some(true)),
        ("Sydney in Australia", "Australia/Sydney", "AU", Some(true)),
        ("a Paris clock in Vietnam", "Europe/Paris", "VN", Some(false)),
        ("a Shanghai clock in the United States", "Asia/Shanghai", "US", Some(false)),
        ("a New York clock in Germany", "America/New_York", "DE", Some(false)),
        ("an ocean zone tells nothing", "Atlantic/Canary", "ES", None),
        ("UTC tells nothing", "UTC", "FR", None),
        ("an unknown country tells nothing", "Europe/Paris", "ZZ", None),
    ];
    let mut failures = Vec::new();
    for (case, tz, country, want) in cases {
        let got = timezone_matches(tz, country);
        if got != want {
            failures.push(format!("{case}: {got:?}, want {want:?}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_platform_that_contradicts_the_user_agent_is_a_spoof() {
    let windows_chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
    let iphone = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1";
    let android = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36";
    let mac = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15";
    // (case, user agent, platform, touch, spoofed)
    let cases: Vec<(&str, &str, &str, bool, bool)> = vec![
        ("Windows says Windows", windows_chrome, "Win32", false, false),
        ("an iPhone says iPhone", iphone, "iPhone", true, false),
        ("Android reads as Linux on ARM", android, "Linux armv81", true, false),
        ("an iPad asks for the desktop site", mac, "MacIntel", true, false),
        ("a Linux machine claiming Windows", windows_chrome, "Linux x86_64", false, true),
        ("a desktop claiming to be an iPhone", iphone, "Win32", false, true),
        ("a phone without a touch screen", android, "Linux armv81", false, true),
        ("an empty platform tells nothing", windows_chrome, "", false, false),
    ];
    let mut failures = Vec::new();
    for (case, ua, platform, touch, want) in cases {
        let agent = openfraud::agent::parse(ua);
        let info = openfraud::device::DeviceInfo {
            timezone: String::new(),
            platform: openfraud::device::platform_family(platform).to_owned(),
            touch,
            webdriver: false,
        };
        if spoofed(&info, &agent) != want {
            failures.push(format!("{case}: want {want}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

// ------------------------------------------------- tokens in the engine

use openfraud::config::Config;
use openfraud::engine::{Engine, Options, Outcome};
use openfraud::event::RawEvent;
use serde_json::Value;
use std::path::Path;

const WINDOWS: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
const IPHONE: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1";

fn engine_with(text: &str) -> Engine {
    let config = Config::parse(text, Path::new(".")).unwrap();
    Engine::open(config, b"device-test-key-device-test-key!".to_vec(), None).unwrap()
}

fn send(e: &Engine, value: Value) -> Outcome {
    let raw: RawEvent = serde_json::from_value(value).unwrap();
    e.process(raw, Options::default()).unwrap()
}

fn script_token(nonce: &str, t: u64, tz: &str, platform: &str, touch: bool, webdriver: bool) -> String {
    token(json!({"v": 1, "id": "dev_script_1", "n": nonce, "t": t, "tz": tz, "p": platform, "touch": touch, "wd": webdriver}))
}

#[test]
fn a_device_token_is_fresh_once_and_consistent_with_the_request() {
    let e = engine_with("[safety]\nrequire_replay = false\n\n[device]\nrequire_token = true\n");
    let login = |actor: &str, kind: &str, at: u64, token: Option<String>, ua: &str, country: &str| {
        let mut v = json!({"type": kind, "actor_id": actor, "at": at, "user_agent": ua, "country": country, "ip": "198.51.100.7"});
        if let Some(t) = token {
            v["device_token"] = json!(t);
        }
        v
    };
    let fresh = script_token("00112233445566778899aabbccddeeff", 1_000, "Europe/Brussels", "Win32", false, false);
    // (case, event, token status, signals present, signals absent)
    let cases: Vec<(&str, Value, &str, Vec<&str>, Vec<&str>)> = vec![
        (
            "a fresh token",
            login("u1", "session.login", 1_010, Some(fresh.clone()), WINDOWS, "BE"),
            "ok",
            vec![],
            vec![
                "replayed_device_data",
                "invalid_device_data",
                "spoofed_device",
                "timezone_area_mismatch",
            ],
        ),
        (
            "the same token for the same kind of event",
            login("u1", "session.login", 1_020, Some(fresh.clone()), WINDOWS, "BE"),
            "replayed",
            vec!["replayed_device_data"],
            vec![],
        ),
        (
            "the same token for another kind of event",
            login("u1", "challenge.requested", 1_030, Some(fresh), WINDOWS, "BE"),
            "ok",
            vec![],
            vec!["replayed_device_data"],
        ),
        (
            "a token older than two minutes",
            login(
                "u1",
                "session.login",
                2_000,
                Some(script_token(
                    "ffeeddccbbaa99887766554433221100",
                    1_000,
                    "Europe/Brussels",
                    "Win32",
                    false,
                    false,
                )),
                WINDOWS,
                "BE",
            ),
            "stale",
            vec!["invalid_device_data"],
            vec![],
        ),
        (
            "no token where one is required",
            login("u1", "session.login", 2_010, None, WINDOWS, "BE"),
            "missing",
            vec!["missing_device_data"],
            vec![],
        ),
        (
            "a token that is no token",
            login("u1", "session.login", 2_020, Some("garbage".into()), WINDOWS, "BE"),
            "invalid",
            vec!["invalid_device_data"],
            vec![],
        ),
        (
            "a Paris clock in Vietnam on a Linux box claiming Windows",
            login(
                "u2",
                "session.login",
                3_000,
                Some(script_token(
                    "0123456789abcdef0123456789abcdef",
                    2_990,
                    "Europe/Paris",
                    "Linux x86_64",
                    false,
                    false,
                )),
                WINDOWS,
                "VN",
            ),
            "ok",
            vec!["timezone_area_mismatch", "spoofed_device"],
            vec![],
        ),
        (
            "a browser under remote control",
            login(
                "u3",
                "session.login",
                3_100,
                Some(script_token(
                    "aaaabbbbccccddddeeeeffff00001111",
                    3_095,
                    "Europe/Brussels",
                    "Win32",
                    false,
                    true,
                )),
                WINDOWS,
                "BE",
            ),
            "ok",
            vec!["headless_browser"],
            vec![],
        ),
        (
            "a mock token outside a sandbox",
            login(
                "u4",
                "session.login",
                3_200,
                Some("test|device:chrome_on_mac|verdict:block".into()),
                WINDOWS,
                "BE",
            ),
            "invalid",
            vec!["invalid_device_data"],
            vec![],
        ),
    ];
    let mut failures = Vec::new();
    for (case, event, status, present, absent) in cases {
        let out = send(&e, event.clone());
        let stored = e.user_events(event["actor_id"].as_str().unwrap(), 1).unwrap();
        let got = stored.first().and_then(|(ev, _)| ev.device_token.clone()).unwrap_or_default();
        if got != status {
            failures.push(format!("{case}: token {got:?}, want {status:?}"));
        }
        for name in present {
            if !out.signals.contains_key(name) {
                failures.push(format!("{case}: {name} missing from {:?}", out.signals.keys().collect::<Vec<_>>()));
            }
        }
        for name in absent {
            if out.signals.contains_key(name) {
                failures.push(format!("{case}: {name} should not be there"));
            }
        }
    }
    let first = e.user_events("u1", 50).unwrap().into_iter().last().unwrap().0;
    if first.device.is_none() {
        failures.push("the token's device id becomes the event's device".into());
    }
    // A dry run does not spend the token.
    let once = script_token("99999999999999999999999999999999", 4_000, "Europe/Brussels", "Win32", false, false);
    let dry: RawEvent = serde_json::from_value(login("u5", "session.login", 4_001, Some(once.clone()), WINDOWS, "BE")).unwrap();
    e.process(dry, Options { dry_run: true, now: None }).unwrap();
    if send(&e, login("u5", "session.login", 4_002, Some(once), WINDOWS, "BE"))
        .signals
        .contains_key("replayed_device_data")
    {
        failures.push("a dry run spends the token".into());
    }
    // A new kind of device for the account.
    send(&e, login("u6", "session.login", 5_000, None, WINDOWS, "BE"));
    if !send(&e, login("u6", "session.login", 5_100, None, IPHONE, "BE"))
        .signals
        .contains_key("new_device_type")
    {
        failures.push("a phone after a desktop is a new device type".into());
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_sandbox_reads_mock_tokens_and_says_so() {
    let e = engine_with("[server]\nsandbox = true\n\n[safety]\nrequire_replay = false\n");
    let out = send(
        &e,
        json!({"type": "session.login", "actor_id": "s1", "at": 1_000, "device_token": "test|device:bot_on_linux|ip:jp|verdict:deny|score:90"}),
    );
    let mut failures = Vec::new();
    if (out.decision.as_str(), out.score, out.sandbox) != ("block", 90, true) {
        failures.push(format!(
            "the mock token sets the answer: {} {} sandbox {}",
            out.decision.as_str(),
            out.score,
            out.sandbox
        ));
    }
    let (event, _) = e.user_events("s1", 1).unwrap().remove(0);
    if (event.country.as_deref(), event.device.is_some(), event.device_token.as_deref()) != (Some("JP"), true, Some("mock")) {
        failures.push(format!("the mock token sets the country and the device: {event:?}"));
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
