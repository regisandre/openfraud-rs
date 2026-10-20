//! Email signals for rules. They read pseudonyms (`<mailbox>.<stem>@domain`,
//! see [`crate::event::Pseudonymizer::email`]) and plain addresses alike:
//! only the domain and the two hashes are used.

/// The free mailbox provider a domain belongs to, or `""` when it is not one
/// of the big ones. Country variants count (`yahoo.fr`, `hotmail.be`).
pub fn provider(address: &str) -> &'static str {
    let domain = address.rsplit('@').next().unwrap_or(address).trim().to_ascii_lowercase();
    let d = domain.as_str();
    let starts = |prefixes: &[&str]| prefixes.iter().any(|p| d.starts_with(p) && d.len() > p.len());
    match d {
        "gmail.com" | "googlemail.com" => "google",
        "msn.com" | "windowslive.com" | "passport.com" => "microsoft",
        "icloud.com" | "me.com" | "mac.com" => "apple",
        "web.de" => "gmx",
        "proton.me" | "protonmail.com" | "protonmail.ch" | "pm.me" => "proton",
        "aol.com" | "aim.com" => "aol",
        "ya.ru" => "yandex",
        "mail.ru" | "inbox.ru" | "list.ru" | "bk.ru" => "mailru",
        "zoho.com" | "zohomail.com" => "zoho",
        "tutanota.com" | "tuta.io" | "tuta.com" => "tuta",
        "qq.com" | "163.com" | "126.com" => "china",
        _ if starts(&["yahoo.", "ymail.", "rocketmail."]) => "yahoo",
        _ if starts(&["hotmail.", "outlook.", "live."]) => "microsoft",
        _ if starts(&["gmx."]) => "gmx",
        _ if starts(&["yandex."]) => "yandex",
        _ => "",
    }
}

/// How many distinct free mailbox providers the addresses span.
pub fn providers(addresses: &[String]) -> i64 {
    let mut seen: Vec<&str> = addresses.iter().map(|a| provider(a)).filter(|p| !p.is_empty()).collect();
    seen.sort_unstable();
    seen.dedup();
    seen.len() as i64
}

/// The share of addresses at a free mailbox provider, from 0 to 1; 0 for an
/// empty list.
pub fn freemail_share(addresses: &[String]) -> f64 {
    if addresses.is_empty() {
        return 0.0;
    }
    let free = addresses.iter().filter(|a| !provider(a).is_empty()).count();
    free as f64 / addresses.len() as f64
}

/// The mailbox and stem hashes of a pseudonym.
fn parts(pseudonym: &str) -> Option<(&str, &str)> {
    let local = pseudonym.rsplit_once('@')?.0;
    local.split_once('.')
}

/// How many addresses are the owner's mailbox, or share its stem (the
/// letters of the local part: `openai7623` and `open.ai1` share one).
pub fn alike(addresses: &[String], owner: &str) -> i64 {
    let Some((mailbox, stem)) = parts(owner) else {
        return 0;
    };
    addresses
        .iter()
        .filter_map(|a| parts(a))
        .filter(|(m, s)| *m == mailbox || *s == stem)
        .count() as i64
}

/// What an address looks like, measured on the address as typed before it
/// becomes a pseudonym. Only these numbers are kept, never the local part.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EmailShape {
    /// A `+tag`: an alias of another mailbox. Gmail's dot variants are not
    /// flagged here (a dotted name is common); `email_alias` tells them apart.
    pub tagged: bool,
    /// Characters in the local part, tag included.
    pub length: i64,
    pub digits: i64,
    /// The longest run of consecutive digits.
    pub digit_run: i64,
    /// The local part is digits only.
    pub numeric: bool,
    /// Letters, and not one vowel among them.
    pub no_vowels: bool,
    /// A function mailbox (`admin`, `info`, `noreply` ...).
    pub role: bool,
    /// Looks typed by a script: five consonants in a row, almost no vowels,
    /// or letters and digits shuffled together.
    pub generated: bool,
}

/// The shape of an address, or `None` when it is not one.
pub fn email_shape(address: &str) -> Option<EmailShape> {
    crate::event::canonical_email(address)?;
    let typed = address.trim().to_lowercase();
    let local = typed.rsplit_once('@').map(|(l, _)| l)?;
    let untagged = local.split('+').next().unwrap_or(local);
    let tagged = local.contains('+');

    let is_vowel = |c: char| "aeiouy".contains(c);
    let (mut digits, mut digit_run, mut run) = (0i64, 0i64, 0i64);
    let (mut letters, mut vowels, mut consonant_run, mut consonants) = (0i64, 0i64, 0i64, 0i64);
    let (mut switches, mut last_digit) = (0i64, None::<bool>);
    for c in untagged.chars() {
        if c.is_ascii_digit() {
            digits += 1;
            run += 1;
            digit_run = digit_run.max(run);
        } else {
            run = 0;
        }
        if c.is_ascii_lowercase() {
            letters += 1;
            if is_vowel(c) {
                vowels += 1;
                consonants = 0;
            } else {
                consonants += 1;
                consonant_run = consonant_run.max(consonants);
            }
        } else {
            consonants = 0;
        }
        if c.is_ascii_alphanumeric() {
            let digit = c.is_ascii_digit();
            if last_digit.is_some_and(|d| d != digit) {
                switches += 1;
            }
            last_digit = Some(digit);
        }
    }
    let no_vowels = letters > 0 && vowels == 0;
    let generated = consonant_run >= 5 || (letters >= 6 && vowels * 100 < letters * 15) || switches >= 6;
    Some(EmailShape {
        tagged,
        length: local.chars().count() as i64,
        digits,
        digit_run,
        numeric: !untagged.is_empty() && untagged.chars().all(|c| c.is_ascii_digit()),
        no_vowels,
        role: crate::event::ROLE_MAILBOXES.contains(&untagged),
        generated,
    })
}

/// Country to international calling code, from Google's libphonenumber
/// metadata (Apache-2.0, see NOTICE). Several countries share a code: the
/// US and Canada `+1`, Russia and Kazakhstan `+7`.
static CALLING_CODES: std::sync::LazyLock<std::collections::HashMap<&'static str, &'static str>> = std::sync::LazyLock::new(|| {
    include_str!("../data/calling_codes.csv")
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(','))
        .collect()
});

/// The calling code of a country (`+32` for `BE`), or `""` when unknown.
pub fn calling_code(country: &str) -> String {
    CALLING_CODES
        .get(country.trim().to_ascii_uppercase().as_str())
        .map(|code| format!("+{code}"))
        .unwrap_or_default()
}

/// The calling code a number starts with (`+32` for `+32470123456`), or
/// `""`. Calling codes are prefix-free, so one at most matches.
pub fn phone_code(number: &str) -> String {
    let Some(digits) = number.trim().strip_prefix('+') else {
        return String::new();
    };
    (1..=3)
        .filter_map(|n| digits.get(..n))
        .find(|prefix| CALLING_CODES.values().any(|code| code == prefix))
        .map(|code| format!("+{code}"))
        .unwrap_or_default()
}

/// The public suffix list (publicsuffix.org, MPL-2.0): normal rules,
/// wildcard rules (the part after `*.`) and exceptions (after `!`).
struct Suffixes {
    normal: std::collections::HashSet<String>,
    wildcard: std::collections::HashSet<String>,
    exception: std::collections::HashSet<String>,
}

static SUFFIXES: std::sync::LazyLock<Suffixes> = std::sync::LazyLock::new(|| {
    let mut s = Suffixes {
        normal: Default::default(),
        wildcard: Default::default(),
        exception: Default::default(),
    };
    for line in include_str!("../data/public_suffix_list.dat").lines() {
        let rule = line.split_whitespace().next().unwrap_or_default().to_lowercase();
        if rule.is_empty() || rule.starts_with("//") {
            continue;
        }
        if let Some(r) = rule.strip_prefix("*.") {
            s.wildcard.insert(r.to_owned());
        } else if let Some(r) = rule.strip_prefix('!') {
            s.exception.insert(r.to_owned());
        } else {
            s.normal.insert(rule);
        }
    }
    s
});

/// The domain someone registered, below its public suffix:
/// `example.co.uk` for `mail.example.co.uk`, `ann.github.io` for itself.
/// `None` for a public suffix alone or a name without a dot.
pub fn registered_domain(domain: &str) -> Option<String> {
    let domain = domain.trim().trim_end_matches('.').to_lowercase();
    if !domain.contains('.') || domain.split('.').any(str::is_empty) {
        return None;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    let n = labels.len();
    let s = &*SUFFIXES;
    // The longest rule that matches decides the suffix; an exception wins.
    let mut suffix = 1;
    for i in 0..n {
        let candidate = labels[i..].join(".");
        if s.exception.contains(&candidate) {
            suffix = n - i - 1;
            break;
        }
        if s.normal.contains(&candidate) {
            suffix = n - i;
            break;
        }
        if i + 1 < n && s.wildcard.contains(&labels[i + 1..].join(".")) {
            suffix = n - i;
            break;
        }
    }
    (suffix < n).then(|| labels[n - suffix - 1..].join("."))
}

/// A DNS query for the mail exchangers (MX) of a domain.
pub fn mx_query(domain: &str, id: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(32 + domain.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in domain.trim_end_matches('.').split('.') {
        let label = &label.as_bytes()[..label.len().min(63)];
        q.push(label.len() as u8);
        q.extend_from_slice(label);
    }
    q.extend_from_slice(&[0, 0, 0x0f, 0, 1]);
    q
}

/// The position after a name in a DNS message.
fn skip_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *buf.get(pos)? as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xc0 == 0xc0 {
            buf.get(pos + 1)?;
            return Some(pos + 2);
        }
        pos += 1 + len;
    }
}

/// Whether the reply to an MX query says the domain takes mail: no such
/// domain or only a null exchanger (RFC 7505) is `false`, a mail exchanger
/// or no record at all (mail then goes to the address) is `true`. `None`
/// when it cannot be told: another query's reply, a failure, a broken reply.
pub fn mx_reachable(reply: &[u8], id: u16) -> Option<bool> {
    if reply.len() < 12 || reply[..2] != id.to_be_bytes() || reply[2] & 0x80 == 0 {
        return None;
    }
    match reply[3] & 0x0f {
        3 => return Some(false),
        0 => {}
        _ => return None,
    }
    let questions = u16::from_be_bytes([reply[4], reply[5]]);
    let answers = u16::from_be_bytes([reply[6], reply[7]]);
    let mut pos = 12;
    for _ in 0..questions {
        pos = skip_name(reply, pos)? + 4;
    }
    let (mut exchanger, mut null) = (false, false);
    for _ in 0..answers {
        pos = skip_name(reply, pos)?;
        let header = reply.get(pos..pos + 10)?;
        let kind = u16::from_be_bytes([header[0], header[1]]);
        let len = u16::from_be_bytes([header[8], header[9]]) as usize;
        let data = reply.get(pos + 10..pos + 10 + len)?;
        if kind == 15 {
            if data.len() >= 3 && data[2] == 0 {
                null = true;
            } else {
                exchanger = true;
            }
        }
        pos += 10 + len;
    }
    Some(exchanger || !null)
}

/// Asks a DNS resolver (`1.1.1.1:53`) whether a domain takes mail, waiting
/// at most `timeout_ms`. `None` when no answer could be read.
pub fn mx_lookup(domain: &str, resolver: &str, timeout_ms: u64) -> Option<bool> {
    let mut id = [0u8; 2];
    getrandom::fill(&mut id).ok()?;
    let id = u16::from_be_bytes(id);
    let socket = std::net::UdpSocket::bind(if resolver.starts_with('[') { "[::]:0" } else { "0.0.0.0:0" }).ok()?;
    socket
        .set_read_timeout(Some(std::time::Duration::from_millis(timeout_ms.max(1))))
        .ok()?;
    socket.send_to(&mx_query(domain, id), resolver).ok()?;
    let mut buf = [0u8; 1_500];
    let (n, _) = socket.recv_from(&mut buf).ok()?;
    mx_reachable(&buf[..n], id)
}
