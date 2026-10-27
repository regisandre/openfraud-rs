//! The user agent, read into the few facts rules need: the browser and its
//! major version, the operating system, the kind of device, and whether a
//! crawler, an AI crawler, an automated browser or an HTTP library sent the
//! request.

use openfraud::agent::parse;

#[test]
fn a_user_agent_is_read_into_browser_system_device_and_automation() {
    // (case, user agent, browser, major, os, device, bot, ai_bot, automation, http_client)
    type Want = (&'static str, i64, &'static str, &'static str, bool, bool, bool, bool);
    let cases: Vec<(&str, &str, Want)> = vec![
        (
            "Chrome on Windows",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            ("chrome", 131, "windows", "desktop", false, false, false, false),
        ),
        (
            "Edge is not Chrome",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.2903.70",
            ("edge", 131, "windows", "desktop", false, false, false, false),
        ),
        (
            "Opera is not Chrome",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 OPR/115.0.0.0",
            ("opera", 115, "windows", "desktop", false, false, false, false),
        ),
        (
            "Safari on an iPhone",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
            ("safari", 18, "ios", "mobile", false, false, false, false),
        ),
        (
            "Safari on an iPad",
            "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
            ("safari", 17, "ios", "tablet", false, false, false, false),
        ),
        (
            "Safari on a Mac",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
            ("safari", 17, "macos", "desktop", false, false, false, false),
        ),
        (
            "Chrome on an Android phone",
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
            ("chrome", 131, "android", "mobile", false, false, false, false),
        ),
        (
            "an Android tablet",
            "Mozilla/5.0 (Linux; Android 13; SM-X700) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
            ("chrome", 130, "android", "tablet", false, false, false, false),
        ),
        (
            "Firefox on Linux",
            "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
            ("firefox", 133, "linux", "desktop", false, false, false, false),
        ),
        (
            "Chrome on iOS is Safari's engine but Chrome's name",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/126.0.6478.54 Mobile/15E148 Safari/604.1",
            ("chrome", 126, "ios", "mobile", false, false, false, false),
        ),
        (
            "headless Chrome",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36",
            ("chrome", 120, "linux", "desktop", false, false, true, false),
        ),
        (
            "PhantomJS",
            "Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/538.1 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/538.1",
            ("", 0, "linux", "desktop", false, false, true, false),
        ),
        ("curl", "curl/8.4.0", ("", 0, "", "unknown", false, false, false, true)),
        (
            "Python requests",
            "python-requests/2.31.0",
            ("", 0, "", "unknown", false, false, false, true),
        ),
        (
            "Go's HTTP client",
            "Go-http-client/2.0",
            ("", 0, "", "unknown", false, false, false, true),
        ),
        (
            "a search crawler",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            ("", 0, "", "unknown", true, false, false, false),
        ),
        (
            "an AI crawler",
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)",
            ("", 0, "", "unknown", true, true, false, false),
        ),
        ("nothing", "", ("", 0, "", "unknown", false, false, false, false)),
    ];
    let mut failures = Vec::new();
    for (case, ua, want) in cases {
        let a = parse(ua);
        let got = (
            a.browser.as_str(),
            a.browser_major,
            a.os.as_str(),
            a.device.as_str(),
            a.bot,
            a.ai_bot,
            a.automation,
            a.http_client,
        );
        let want_owned = want;
        if got != want_owned {
            failures.push(format!("{case}: got {got:?}, want {want_owned:?}"));
        }
        if a.empty != ua.is_empty() {
            failures.push(format!("{case}: empty should be {}", ua.is_empty()));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
