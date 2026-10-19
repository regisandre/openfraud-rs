//! The state file: API keys and the admin token, kept as SHA-256 digests,
//! and the two secrets openfraud makes on first start and keeps.
//!
//! API keys come from three places: `OPENFRAUD_API_KEYS`, the
//! `api_keys_file` (one key per line) and the state file the admin interface
//! manages. A generated key or token is shown once, then only its digest is
//! kept. The secrets are random 192-bit values, so a plain SHA-256 digest is
//! enough (a slow password hash protects guessable passwords, not random
//! keys).
//!
//! The state file also holds, in clear, the pseudonym key (every hashed
//! email, IP address and identifier depends on it: lose it and returning
//! accounts are no longer recognized) and the webhook signing secret. Keep
//! it private and back it up.

use crate::files::write_atomic;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

/// External keys shorter than this are refused: they could be guessed.
pub const MIN_KEY_LEN: usize = 24;

pub fn digest(secret: &str) -> [u8; 32] {
    Sha256::digest(secret.trim().as_bytes()).into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    unhex(s)?.try_into().ok()
}

/// `prefix` followed by 48 random hex digits (192 bits).
pub fn generate(prefix: &str) -> String {
    let mut buf = [0u8; 24];
    getrandom::fill(&mut buf).expect("the operating system random source failed");
    format!("{prefix}{}", hex(&buf))
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_token_sha256: Option<String>,
    /// Set when the first-run setup is finished or skipped.
    #[serde(default)]
    pub setup_done: bool,
    /// 32 random bytes as hex. Never change it once events exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pseudonym_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_secret: Option<String>,
    #[serde(default)]
    pub api_keys: Vec<StoredKey>,
}

/// What an API key may do. `events` sends events and reads its decisions
/// (`/v1/decide`, `/v1/events`, appeals, statements): the key a front-facing
/// service holds. `full` also acts on accounts, cases, lists and personal
/// data. Keys from `OPENFRAUD_API_KEYS` and `api_keys_file` are full.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    #[default]
    Full,
    Events,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Full => "full",
            Scope::Events => "events",
        }
    }

    pub fn parse(text: &str) -> Option<Scope> {
        match text {
            "full" => Some(Scope::Full),
            "events" => Some(Scope::Events),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredKey {
    /// Stable id for revocation: the start of the digest.
    pub id: String,
    pub name: String,
    /// The first characters of the key, so its owner can recognize it.
    pub prefix: String,
    pub sha256: String,
    /// Unix seconds.
    pub created: u64,
    /// Keys made before scopes existed are full.
    #[serde(default)]
    pub scope: Scope,
}

const HEADER: &str = "# Managed by openfraud. Keep this file private and back it up: it holds the\n\
# pseudonym key (lose it and returning accounts are no longer recognized) and\n\
# the webhook secret. API keys and the admin token are SHA-256 digests only.\n\n";

impl State {
    /// A missing file is an empty state.
    pub fn load(path: &Path) -> Result<State> {
        match std::fs::read_to_string(path) {
            Ok(raw) => toml::from_str(&raw).with_context(|| format!("parsing {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let body = toml::to_string_pretty(self)?;
        write_atomic(path, format!("{HEADER}{body}").as_bytes(), true)
    }

    /// Makes the pseudonym key and the webhook secret if missing. True when
    /// something was made and the state needs saving.
    pub fn ensure_secrets(&mut self) -> bool {
        let mut changed = false;
        if self.pseudonym_key.as_deref().and_then(unhex32).is_none() {
            let mut key = [0u8; 32];
            getrandom::fill(&mut key).expect("the operating system random source failed");
            self.pseudonym_key = Some(hex(&key));
            changed = true;
        }
        if self.webhook_secret.is_none() {
            self.webhook_secret = Some(crate::webhook::generate_secret());
            changed = true;
        }
        changed
    }

    pub fn pseudonym_key(&self) -> Option<Vec<u8>> {
        self.pseudonym_key.as_deref().and_then(unhex32).map(|k| k.to_vec())
    }

    /// Creates a full API key named `name` and returns it. It is never shown
    /// again.
    pub fn add_key(&mut self, name: &str) -> Result<String> {
        self.add_key_with(name, Scope::Full)
    }

    /// Creates an API key limited to `scope`.
    pub fn add_key_with(&mut self, name: &str, scope: Scope) -> Result<String> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 60 || name.chars().any(char::is_control) {
            bail!("a key name is 1 to 60 printable characters");
        }
        let key = generate("of_");
        let sha = hex(&digest(&key));
        self.api_keys.push(StoredKey {
            id: sha[..12].to_string(),
            name: name.to_string(),
            prefix: key[..7].to_string(),
            sha256: sha,
            created: now(),
            scope,
        });
        Ok(key)
    }

    /// Removes the key with this id; false when there is none.
    pub fn revoke(&mut self, id: &str) -> bool {
        let before = self.api_keys.len();
        self.api_keys.retain(|k| k.id != id);
        self.api_keys.len() != before
    }

    /// Replaces the admin token and returns the new one. The old token and
    /// every session opened with it stop working.
    pub fn rotate_admin_token(&mut self) -> String {
        let token = generate("ofa_");
        self.admin_token_sha256 = Some(hex(&digest(&token)));
        token
    }

    pub fn admin_digest(&self) -> Option<[u8; 32]> {
        self.admin_token_sha256.as_deref().and_then(unhex32)
    }

    pub fn is_admin(&self, token: &str) -> bool {
        !token.trim().is_empty() && self.admin_digest().is_some_and(|d| bool::from(d.ct_eq(&digest(token))))
    }
}

/// Every accepted API key, as digests compared in constant time.
#[derive(Debug, Clone, Default)]
pub struct KeySet {
    digests: Vec<([u8; 32], Scope)>,
}

impl KeySet {
    /// Keys one per line or item: blanks and `#` comments are skipped, and
    /// a key shorter than `MIN_KEY_LEN` is refused.
    pub fn from_lines<'a>(lines: impl Iterator<Item = &'a str>) -> Result<KeySet> {
        let mut digests = Vec::new();
        for line in lines.map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            if line.len() < MIN_KEY_LEN {
                bail!("API keys must be at least {MIN_KEY_LEN} characters long");
            }
            digests.push((digest(line), Scope::Full));
        }
        Ok(KeySet { digests })
    }

    /// `OPENFRAUD_API_KEYS` (comma separated) and `api_keys_file`.
    pub fn external(api_keys_file: Option<&Path>) -> Result<KeySet> {
        let env = std::env::var("OPENFRAUD_API_KEYS").unwrap_or_default();
        let mut keys = KeySet::from_lines(env.split(','))?;
        if let Some(path) = api_keys_file {
            let raw = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
            keys.digests.extend(KeySet::from_lines(raw.lines())?.digests);
        }
        Ok(keys)
    }

    pub fn extend_state(&mut self, state: &State) {
        self.digests
            .extend(state.api_keys.iter().filter_map(|k| Some((unhex32(&k.sha256)?, k.scope))));
    }

    pub fn len(&self) -> usize {
        self.digests.len()
    }

    pub fn is_empty(&self) -> bool {
        self.digests.is_empty()
    }

    pub fn matches(&self, presented: &str) -> bool {
        self.scope_of(presented).is_some()
    }

    /// The scope of the presented key, or `None` when no key matches.
    pub fn scope_of(&self, presented: &str) -> Option<Scope> {
        if presented.trim().is_empty() {
            return None;
        }
        let d = digest(presented);
        // Compare with every key so the timing does not tell which matched.
        self.digests.iter().fold(None, |found, (k, scope)| {
            let hit = bool::from(k.ct_eq(&d));
            if hit && found.is_none() { Some(*scope) } else { found }
        })
    }
}

/// When the state file last changed, as far as a `stat` can tell.
type Stamp = Option<(SystemTime, u64)>;

fn stamp(path: &Path) -> Stamp {
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.modified().ok()?, meta.len()))
}

/// The accepted keys, kept in step with the state file: a key created or
/// revoked by `openfraud key` in another process applies at the next
/// request, without a restart. One `stat` per call; the file is read again
/// only when its modification time or size changed.
pub struct LiveKeys {
    external: KeySet,
    state_path: PathBuf,
    seen: Stamp,
    keys: KeySet,
}

impl LiveKeys {
    pub fn load(external: KeySet, state_path: &Path) -> Result<LiveKeys> {
        let seen = stamp(state_path);
        let mut keys = external.clone();
        keys.extend_state(&State::load(state_path)?);
        Ok(LiveKeys {
            external,
            state_path: state_path.to_path_buf(),
            seen,
            keys,
        })
    }

    pub fn state_path(&self) -> &Path {
        &self.state_path
    }

    /// The keys, re-read first if the state file changed. A file that no
    /// longer parses keeps the keys already loaded, and says so.
    pub fn current(&mut self) -> &KeySet {
        let now = stamp(&self.state_path);
        if now != self.seen {
            self.seen = now;
            match State::load(&self.state_path) {
                Ok(state) => {
                    let mut keys = self.external.clone();
                    keys.extend_state(&state);
                    self.keys = keys;
                }
                Err(e) => tracing::error!(
                    error = %format!("{e:#}"),
                    "the state file changed but does not parse: keeping the API keys loaded before"
                ),
            }
        }
        &self.keys
    }
}

/// The admin token's digest, kept in step with the state file like
/// [`LiveKeys`]: a token rotated by `openfraud admin-token` applies at the
/// next request, and the file is parsed only when it changed.
pub struct LiveAdmin {
    state_path: PathBuf,
    seen: Stamp,
    digest: Option<[u8; 32]>,
}

impl LiveAdmin {
    pub fn load(state_path: &Path) -> LiveAdmin {
        let mut live = LiveAdmin {
            state_path: state_path.to_path_buf(),
            seen: None,
            digest: None,
        };
        live.refresh(true);
        live
    }

    fn refresh(&mut self, force: bool) {
        let now = stamp(&self.state_path);
        if !force && now == self.seen {
            return;
        }
        self.seen = now;
        match State::load(&self.state_path) {
            Ok(state) => self.digest = state.admin_digest(),
            Err(e) => tracing::error!(
                error = %format!("{e:#}"),
                "the state file changed but does not parse: keeping the admin token loaded before"
            ),
        }
    }

    pub fn is_admin(&mut self, token: &str) -> bool {
        self.refresh(false);
        !token.trim().is_empty() && self.digest.is_some_and(|d| bool::from(d.ct_eq(&digest(token))))
    }
}
