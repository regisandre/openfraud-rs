//! The user agent of a request, read into the few facts rules need. Only
//! these facts are kept, never the text itself.

use serde::{Deserialize, Serialize};

/// What a user agent says about the client.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Agent {
    /// `chrome`, `edge`, `firefox`, `safari`, `opera`, `samsung`, or `""`.
    pub browser: String,
    /// The browser's major version, 0 when unknown.
    pub browser_major: i64,
    /// `windows`, `macos`, `ios`, `android`, `linux`, `chromeos`, or `""`.
    pub os: String,
    /// `desktop`, `mobile`, `tablet`, or `unknown` (crawlers and libraries too).
    pub device: String,
    /// A crawler that says so (search engines, link previews, AI crawlers).
    pub bot: bool,
    /// A crawler collecting data for AI models (GPTBot, ClaudeBot, CCBot ...).
    pub ai_bot: bool,
    /// A browser driven by a script: headless Chrome, PhantomJS, Selenium.
    pub automation: bool,
    /// An HTTP library or a command-line tool: curl, python-requests, Go.
    pub http_client: bool,
    /// No user agent at all.
    pub empty: bool,
}

const AI_BOTS: [&str; 16] = [
    "gptbot",
    "chatgpt-user",
    "oai-searchbot",
    "claudebot",
    "claude-web",
    "anthropic-ai",
    "perplexitybot",
    "ccbot",
    "bytespider",
    "google-extended",
    "amazonbot",
    "applebot-extended",
    "meta-externalagent",
    "cohere-ai",
    "diffbot",
    "youbot",
];

const BOT_MARKS: [&str; 8] = [
    "bot/",
    "bot;",
    "crawler",
    "spider",
    "slurp",
    "facebookexternalhit",
    "bingpreview",
    "+http",
];

/// Libraries and tools; the HTTP stacks of native apps (okhttp on Android,
/// Dart for Flutter) are left out: an app is a person's client.
const HTTP_CLIENTS: [&str; 20] = [
    "curl/",
    "wget/",
    "python-requests/",
    "python-urllib/",
    "python-httpx/",
    "aiohttp/",
    "go-http-client/",
    "java/",
    "apache-httpclient/",
    "libwww-perl/",
    "node-fetch/",
    "axios/",
    "undici",
    "node",
    "postmanruntime/",
    "insomnia/",
    "httpie/",
    "php/",
    "guzzlehttp/",
    "reqwest/",
];

const AUTOMATION: [&str; 8] = [
    "headlesschrome",
    "phantomjs",
    "selenium",
    "webdriver",
    "puppeteer",
    "playwright",
    "slimerjs",
    "htmlunit",
];

/// The major version after `token` (`chrome/` in `Chrome/131.0`), 0 if none.
fn major(lower: &str, token: &str) -> i64 {
    lower
        .find(token)
        .map(|i| &lower[i + token.len()..])
        .map(|rest| rest.chars().take_while(char::is_ascii_digit).collect::<String>())
        .and_then(|d| d.parse().ok())
        .unwrap_or(0)
}

pub fn parse(user_agent: &str) -> Agent {
    let ua = user_agent.trim();
    let lower = ua.to_ascii_lowercase();
    let has = |marks: &[&str]| marks.iter().any(|m| lower.contains(m));
    let ai_bot = has(&AI_BOTS);
    let bot = ai_bot || has(&BOT_MARKS);
    let http_client = !bot && HTTP_CLIENTS.iter().any(|c| lower.starts_with(c));
    let automation = has(&AUTOMATION);

    let mut agent = Agent {
        bot,
        ai_bot,
        automation,
        http_client,
        empty: ua.is_empty(),
        device: "unknown".into(),
        ..Agent::default()
    };
    if bot || http_client || ua.is_empty() {
        return agent;
    }

    let browser = [
        ("edge", &["edg/", "edga/", "edgios/"][..]),
        ("opera", &["opr/", "opera/"][..]),
        ("samsung", &["samsungbrowser/"][..]),
        ("firefox", &["firefox/", "fxios/"][..]),
        ("chrome", &["crios/", "headlesschrome/", "chrome/", "chromium/"][..]),
    ]
    .iter()
    .find_map(|(name, tokens)| tokens.iter().find(|t| lower.contains(*t)).map(|t| (*name, major(&lower, t))));
    if let Some((name, version)) = browser {
        agent.browser = name.into();
        agent.browser_major = version;
    } else if lower.contains("safari/") && lower.contains("version/") {
        agent.browser = "safari".into();
        agent.browser_major = major(&lower, "version/");
    }

    let (os, device) = if lower.contains("ipad") {
        ("ios", "tablet")
    } else if lower.contains("iphone") || lower.contains("ipod") {
        ("ios", "mobile")
    } else if lower.contains("android") {
        ("android", if lower.contains("mobile") { "mobile" } else { "tablet" })
    } else if lower.contains("windows") {
        ("windows", "desktop")
    } else if lower.contains("macintosh") || lower.contains("mac os x") {
        ("macos", "desktop")
    } else if lower.contains("cros") {
        ("chromeos", "desktop")
    } else if lower.contains("linux") || lower.contains("x11") {
        ("linux", "desktop")
    } else {
        ("", "unknown")
    };
    agent.os = os.into();
    agent.device = device.into();
    agent
}
