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
