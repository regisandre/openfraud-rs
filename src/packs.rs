//! The core rules and the rule packs, embedded in the binary.
//!
//! A pack is a TOML file with the same `lists`, `counters`, `workflows` and
//! `events` sections as the configuration, plus a `[pack]` header. Every
//! pack rule ships in shadow mode: it records what it would decide and acts
//! only once a person promotes it after a replay. A deployment switches packs
//! on with `packs = [...]`; `packs_dir` adds packs of its own.

use anyhow::{Result, bail};
use std::path::Path;

/// The packs shipped with openfraud: name and text.
pub const BUILTIN: [(&str, &str); 6] = [
    ("free-tier-and-trial", include_str!("../packs/free-tier-and-trial/pack.toml")),
    ("card-and-payments", include_str!("../packs/card-and-payments/pack.toml")),
    ("messaging", include_str!("../packs/messaging/pack.toml")),
    (
        "marketplace-and-payouts",
        include_str!("../packs/marketplace-and-payouts/pack.toml"),
    ),
    ("api-and-compute", include_str!("../packs/api-and-compute/pack.toml")),
    ("hosting-and-content", include_str!("../packs/hosting-and-content/pack.toml")),
];

/// The core parts, always loaded unless `[core]` turns one off.
pub fn core(part: &str) -> &'static str {
    match part {
        "blocklists" => include_str!("../core/blocklists.toml"),
        "trust" => include_str!("../core/trust.toml"),
        "account-takeover" => include_str!("../core/account-takeover.toml"),
        "networks" => include_str!("../core/networks.toml"),
        "activity" => include_str!("../core/activity.toml"),
        "email" => include_str!("../core/email.toml"),
        _ => "",
    }
}

/// The text of a pack: from `dir/<name>/pack.toml` when it exists there,
/// else the built-in one.
pub fn text(name: &str, dir: Option<&Path>) -> Result<String> {
    if let Some(dir) = dir {
        let path = dir.join(name).join("pack.toml");
        if path.exists() {
            return Ok(std::fs::read_to_string(&path)?);
        }
    }
    match BUILTIN.iter().find(|(n, _)| *n == name) {
        Some((_, text)) => Ok((*text).to_owned()),
        None => bail!(
            "there is no pack `{name}`: the built-in packs are {}",
            BUILTIN.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ")
        ),
    }
}
