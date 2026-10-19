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
