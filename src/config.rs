//! The configuration file, `openfraud.toml`, and how it is assembled with
//! the core rules and the rule packs it switches on.
//!
//! [`Config::parse`] reads the file; [`Config::assemble`] adds the core
//! (blocklists, trust, account takeover) and the packs listed in `packs`,
//! then applies `[overrides]`; [`Config::compile`] checks everything that
//! can be checked before the first event and returns every problem found,
//! or the [`Compiled`] form the engine runs.

use crate::event::{known_type, valid_type};
use crate::expr::{Expr, Known};
use crate::lists::{List, ListKind};
use crate::window::parse_duration;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub const DEFAULT_CONFIG: &str = include_str!("../openfraud.toml");

/// What an event gets back. Ordered from the mildest to the strictest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    #[default]
    Allow,
    /// Ask for proof first: MFA, 3-D Secure, a CAPTCHA, an email check.
    StepUp,
    /// Let it through; a person looks at the case.
    Review,
    /// Pause this action until a person releases it, or for a set time.
    Hold,
    /// Refuse this action.
    Block,
    /// Refuse, and restrict the account until a person releases it.
    Quarantine,
}

impl Decision {
    pub const ALL: [Decision; 6] = [
        Decision::Allow,
        Decision::StepUp,
        Decision::Review,
        Decision::Hold,
        Decision::Block,
        Decision::Quarantine,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::StepUp => "step_up",
            Decision::Review => "review",
            Decision::Hold => "hold",
            Decision::Block => "block",
            Decision::Quarantine => "quarantine",
        }
    }

    pub fn parse(text: &str) -> Option<Decision> {
        Decision::ALL.into_iter().find(|d| d.as_str() == text)
    }

    /// The action a decision asks of the application by itself.
    pub fn implied_action(self) -> Option<&'static str> {
        match self {
            Decision::Allow | Decision::Block => None,
            Decision::StepUp => Some("step_up"),
            Decision::Review => Some("review"),
            Decision::Hold => Some("hold"),
            Decision::Quarantine => Some("quarantine"),
        }
    }

    /// A decision that restricts something: hold, block, quarantine.
    pub fn restricts(self) -> bool {
        self >= Decision::Hold
    }
}

/// The standing of an actor or a tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    #[default]
    Normal,
    /// Under review: nothing is restricted because of it alone.
    Review,
    /// Every later event is blocked until a person releases it.
    Quarantined,
    /// Vouched for by a person: automatic restrictions become holds.
    Trusted,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Normal => "normal",
            Status::Review => "review",
            Status::Quarantined => "quarantined",
            Status::Trusted => "trusted",
        }
    }

    pub fn parse(text: &str) -> Option<Status> {
        serde_json::from_value(serde_json::Value::String(text.to_owned())).ok()
    }
}

/// `act` applies what a rule decides; `shadow` only records what it would
/// have done.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Act,
    Shadow,
}

/// The kind of harm a rule's points count towards, for the three scores
/// of an answer: an account taken over, an account abused (fake, farmed,
/// spamming, defrauding), a script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    Takeover,
    #[default]
    Abuse,
    Bot,
}

/// Whom a rule's actions restrict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    #[default]
    Actor,
    Tenant,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Server {
    pub bind: String,
    pub max_body_bytes: usize,
    pub allow_unauthenticated: bool,
    pub api_keys_file: Option<PathBuf>,
    pub state_file: PathBuf,
    pub database: PathBuf,
    /// Events and decisions older than this are deleted.
    pub retention_days: u64,
    /// Download the lists that have a `url`. Off by default: openfraud makes
    /// no call to a third party unless told to.
    pub fetch_lists: bool,
    /// How often lists with a `url` are downloaded again.
    pub lists_refresh_hours: u64,
    /// One address that serves every downloaded file under its own name
    /// (`<list>.txt` and `ip2asn-combined.tsv.gz`), for instances that reach
    /// nothing but their host: the lists then come from it, not from their
    /// own sites.
    pub lists_mirror: Option<String>,
    /// A test instance: mock device tokens set the answer. Never on an
    /// instance that protects real users.
    pub sandbox: bool,
}

impl Default for Server {
    fn default() -> Self {
        Server {
            bind: "127.0.0.1:8092".into(),
            max_body_bytes: 65_536,
            allow_unauthenticated: false,
            api_keys_file: None,
            state_file: "openfraud-state.toml".into(),
            database: "openfraud.db".into(),
            retention_days: 90,
            fetch_lists: false,
            lists_refresh_hours: 24,
            lists_mirror: None,
            sandbox: false,
        }
    }
}

/// Checks on email addresses that ask the network.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Email {
    /// Ask DNS whether an address's domain takes mail (its MX records), once
    /// a day per domain: `unreachable_email`. Off by default: openfraud makes
    /// no call to a third party unless told to.
    pub mx_check: bool,
    /// The DNS resolver asked.
    pub resolver: String,
    /// How long one question may take; past it, nothing is said.
    pub timeout_ms: u64,
}

impl Default for Email {
    fn default() -> Self {
        Email {
            mx_check: false,
            resolver: "1.1.1.1:53".into(),
            timeout_ms: 800,
        }
    }
}

/// The device token of the browser script.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Device {
    /// An event without `device_token` is read as `missing`: for hosts
    /// whose every page sends one.
    pub require_token: bool,
    /// How long a token is fresh after the script made it.
    pub token_lifetime: String,
}

impl Default for Device {
    fn default() -> Self {
        Device {
            require_token: false,
            token_lifetime: "120s".into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Admin {
    pub enabled: bool,
    pub bind: String,
}

impl Default for Admin {
    fn default() -> Self {
        Admin {
            enabled: true,
            bind: "127.0.0.1:8093".into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Privacy {
    /// Attributes holding contacts: email addresses or phone numbers, a
    /// text or a list of texts.
    #[serde(alias = "email_attrs")]
    pub contact_attrs: Vec<String>,
    /// Attributes that identify a person or a payment method across
    /// accounts, such as a card fingerprint. Hashed, and linked like `ip`.
    pub id_attrs: Vec<String>,
}

impl Default for Privacy {
    fn default() -> Self {
        Privacy {
            contact_attrs: vec!["recipients".into(), "billing_email".into(), "to".into()],
            id_attrs: vec!["card_fingerprint".into(), "payout_destination".into(), "custom_domain".into()],
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Trust {
    /// Automatic blocks and quarantines apply only to actors whose trust
    /// level is below this; above, the action is held for a person.
    pub act_below: u8,
}

impl Default for Trust {
    fn default() -> Self {
        Trust { act_below: 1 }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Events {
    /// Event types of your own, besides the vocabulary: `x.game_won`.
    pub custom: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Safety {
    /// A rule acts only once a replay over `replay_days` has been run and
    /// approved for it (the Rules page of the admin interface).
    pub require_replay: bool,
    pub replay_days: u64,
    /// The brake: when automatic restrictions in the last hour pass this
    /// number, or `baseline_multiple` times the average hour of the last 7
    /// days (and at least `min_per_hour`), every restriction becomes a review
    /// until a person releases the brake.
    pub max_auto_per_hour: u64,
    pub baseline_multiple: f64,
    pub min_per_hour: u64,
}

impl Default for Safety {
    fn default() -> Self {
        Safety {
            require_replay: true,
            replay_days: 30,
            max_auto_per_hour: 100,
            baseline_multiple: 5.0,
            min_per_hour: 10,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Graph {
    /// Identifier kinds that join two accounts in one cluster.
    pub link_on: Vec<String>,
    /// Two accounts on one IP /24 (/48) are joined only if seen there within
    /// this window; empty turns network links off.
    pub ip_prefix_window: String,
    /// An identifier shared by more accounts than this (an office, a mobile
    /// carrier) joins nothing.
    pub max_shared: u64,
    /// A cluster never grows past this many accounts: chains of weak links
    /// (a carrier's addresses, a shared office) cannot merge a whole user base.
    pub max_cluster: u64,
    /// Attributes that name another actor (`referrer_id`): rules read
    /// `related.<attr>` (`same_cluster`, `status`, `flagged`).
    pub related_attrs: Vec<String>,
}

impl Default for Graph {
    fn default() -> Self {
        Graph {
            link_on: [
                "card_fingerprint",
                "payout_destination",
                "device",
                "email",
                "phone",
                "custom_domain",
            ]
            .map(String::from)
            .to_vec(),
            ip_prefix_window: "1h".into(),
            max_shared: 50,
            max_cluster: 200,
            related_attrs: vec!["referrer_id".into(), "inviter_id".into()],
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Compliance {
    /// The ground a restriction rests on, as the statement of reasons says
    /// it: your terms of service and the section.
    pub ground: String,
    /// How the user asks a person to look again.
    pub redress: String,
    pub appeal_url: Option<String>,
    /// After an erasure request, keep a flagged marker linked to the hashed
    /// identifiers of an account labelled fraud, so it is recognized if it
    /// returns. Off by default: it needs a legal basis of your own.
    pub keep_fraud_flag_after_erasure: bool,
}

impl Default for Compliance {
    fn default() -> Self {
        Compliance {
            ground: "The terms of service of this platform".into(),
            redress: "You can ask a person to review this decision by replying to this notice.".into(),
            appeal_url: None,
            keep_fraud_flag_after_erasure: false,
        }
    }
}

/// The network table: which operator announces an address. Off by default:
/// it holds about half a million ranges in memory.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Networks {
    pub enabled: bool,
    /// The IPtoASN dataset, downloaded with `[server] fetch_lists` and
    /// refreshed every `lists_refresh_hours`.
    pub url: String,
    /// A copy of your own (TSV, gzipped or not) instead of the download.
    pub file: Option<PathBuf>,
}

impl Default for Networks {
    fn default() -> Self {
        Networks {
            enabled: false,
            url: crate::networks::DEFAULT_URL.into(),
            file: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Core {
    /// Lists `blocked_ips` and `blocked_actors`, enforced.
    pub blocklists: bool,
    /// A paid invoice raises trust to 1.
    pub trust: bool,
    /// Account takeover rules, in shadow mode until promoted.
    pub account_takeover: bool,
    /// Lists `tor_exits`, `datacenter_ips` and `vpn_providers`, downloaded
    /// only with `[server] fetch_lists`.
    pub networks: bool,
    /// Bursts of events far above an account's, a device's or an address's
    /// usual rate. Off by default: its counters cost memory.
    pub activity: bool,
    /// The list `fraud_email_domains`, filled from people's fraud labels.
    pub email: bool,
}

impl Default for Core {
    fn default() -> Self {
        Core {
            blocklists: true,
            trust: true,
            account_takeover: true,
            networks: true,
            activity: false,
            email: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    #[default]
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertKind {
    /// A signed JSON POST, like the decision webhooks.
    Webhook,
    /// A Slack incoming webhook (`{"text": ...}`).
    Slack,
    /// The Telegram Bot API `sendMessage`.
    Telegram,
    /// Mail through an SMTP server.
    Email,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AlertSpec {
    pub kind: AlertKind,
    #[serde(default)]
    pub min_severity: Severity,
    /// Gather alerts and send them together every `digest` (`1h`); critical
    /// alerts are never delayed.
    #[serde(default)]
    pub digest: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub bot_token_env: Option<String>,
    #[serde(default)]
    pub chat_id: Option<String>,
    #[serde(default)]
    pub smtp_host: Option<String>,
    #[serde(default)]
    pub smtp_port: Option<u16>,
    /// `starttls` (default), `tls`, or `none` for a relay on localhost.
    #[serde(default)]
    pub smtp_tls: Option<String>,
    #[serde(default)]
    pub username_env: Option<String>,
    #[serde(default)]
    pub password_env: Option<String>,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Vec<String>,
    /// Stand-in base URL for an API (tests, a proxy).
    #[serde(default)]
    pub api_base: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListSpec {
    pub kind: ListKind,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub items: Vec<String>,
    /// A file of one item per line, relative to the configuration file.
    #[serde(default)]
    pub file: Option<PathBuf>,
    /// Downloaded when `[server] fetch_lists = true`.
    #[serde(default)]
    pub url: Option<String>,
    /// The event field an item is (`actor`, `device`, `email_domain`,
    /// `attrs.<name>` ...): rules read `"name" in event.lists`, and the
    /// `list.add:<name>` action adds the event's value. Not for `ip` lists,
    /// which hold addresses.
    #[serde(default)]
    pub key: Option<String>,
    /// A second field: an item is a pair (an account and a device) and
    /// matches only an event with both values.
    #[serde(default)]
    pub second: Option<String>,
    /// How long an item added at run time stays (`14d`); for good when absent.
    #[serde(default)]
    pub expire: Option<String>,
}

/// One key, or several read together (`["actor", "device"]`).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(untagged)]
pub enum KeyList {
    One(String),
    Many(Vec<String>),
}

impl KeyList {
    pub fn names(&self) -> Vec<&str> {
        match self {
            KeyList::One(k) => vec![k.as_str()],
            KeyList::Many(keys) => keys.iter().map(String::as_str).collect(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CounterSpec {
    pub events: Vec<String>,
    pub by: KeyList,
    pub window: String,
    /// `avg`, `min`, `max` or `last` of the attribute `of`, instead of a count.
    #[serde(default)]
    pub agg: Option<crate::window::Agg>,
    /// The attribute an aggregate reads (`attrs.amount`).
    #[serde(default)]
    pub of: Option<String>,
    /// A longer span (`7d`) over which the counter learns its usual value per
    /// window: rules read it as `baselines.<name>`.
    #[serde(default)]
    pub baseline: Option<String>,
    /// Off: the counter is not kept, and a rule that reads it is refused.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Count distinct values of this key instead of events.
    #[serde(default)]
    pub distinct: Option<String>,
    /// Add up this attribute instead of counting (`attrs.amount`); rounded
    /// to a whole number.
    #[serde(default)]
    pub sum: Option<String>,
    /// Count only the events for which this condition on `event` is true.
    #[serde(default)]
    pub when: Option<String>,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    #[serde(default)]
    pub status: Option<Status>,
    #[serde(default)]
    pub actions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSpec {
    pub id: String,
    pub when: String,
    #[serde(default)]
    pub score: i64,
    #[serde(default)]
    pub decision: Option<Decision>,
    /// Sets the actor's trust level when the rule fires.
    #[serde(default)]
    pub trust: Option<u8>,
    #[serde(default)]
    pub actions: Vec<String>,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub mode: Option<Mode>,
    /// With `decision = "hold"`: how long, such as `7d`. The answer then
    /// carries `hold_until`.
    #[serde(default)]
    pub hold_for: Option<String>,
    /// Whom the actions restrict: the actor (default) or the tenant.
    #[serde(default)]
    pub target: Target,
    /// With `decision = "allow"`: when the rule acts, the event is allowed
    /// whatever the other workflows say, except the blocks of the core.
    #[serde(default)]
    pub stop: bool,
    /// The score its points count towards; the workflow's when absent.
    #[serde(default)]
    pub family: Option<Family>,
    /// A name the answer lists in `signals` whenever the rule fires, acting
    /// or in shadow: a signal of your own.
    #[serde(default)]
    pub signal: Option<String>,
    #[serde(default = "yes")]
    pub enabled: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowSpec {
    /// Event types, or `["*"]` for every event.
    pub events: Vec<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default = "yes")]
    pub enabled: bool,
    /// The score its rules' points count towards: `abuse` by default.
    #[serde(default)]
    pub family: Family,
    #[serde(default)]
    pub step_up_at: Option<i64>,
    #[serde(default)]
    pub review_at: Option<i64>,
    #[serde(default)]
    pub hold_at: Option<i64>,
    #[serde(default)]
    pub block_at: Option<i64>,
    #[serde(default)]
    pub quarantine_at: Option<i64>,
    /// The strictest decision this workflow may give: account takeover
    /// rules stop at `hold`, since the account's owner is the victim.
    #[serde(default)]
    pub max_decision: Option<Decision>,
    #[serde(default)]
    pub on_step_up: Outcome,
    #[serde(default)]
    pub on_review: Outcome,
    #[serde(default)]
    pub on_hold: Outcome,
    #[serde(default)]
    pub on_block: Outcome,
    #[serde(default)]
    pub on_quarantine: Outcome,
    #[serde(default)]
    pub rules: Vec<RuleSpec>,
}

/// A change to a rule from the core or a pack, which cannot be edited in place.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Override {
    #[serde(default)]
    pub mode: Option<Mode>,
    #[serde(default)]
    pub score: Option<i64>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Webhooks {
    pub url: String,
    /// The webhook types to send; all of [`WEBHOOK_EVENTS`] by default.
    pub events: Vec<String>,
    pub timeout_ms: u64,
    pub max_attempts: u32,
}

pub const WEBHOOK_EVENTS: [&str; 16] = [
    "decision.step_up",
    "decision.review",
    "decision.hold",
    "decision.block",
    "decision.quarantine",
    "case.opened",
    "case.updated",
    "case.resolved",
    "case.appealed",
    "actor.status_changed",
    "tenant.status_changed",
    "brake.engaged",
    "brake.released",
    "list_item.created",
    "list_item.archived",
    "list_item.unarchived",
];

impl Default for Webhooks {
    fn default() -> Self {
        Webhooks {
            url: String::new(),
            events: WEBHOOK_EVENTS.iter().map(|e| e.to_string()).collect(),
            timeout_ms: 5_000,
            max_attempts: 12,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Ai {
    pub enabled: bool,
    /// Any OpenAI-compatible chat completions endpoint: a hosted provider or
    /// a local Ollama or vLLM.
    pub base_url: String,
    pub model: String,
    /// The environment variable holding the API key; none for a local model.
    pub api_key_env: String,
    /// Write a summary for each new case.
    pub summarize_cases: bool,
    pub timeout_secs: u64,
    pub max_output_tokens: u32,
}

impl Default for Ai {
    fn default() -> Self {
        Ai {
            enabled: false,
            base_url: "https://api.openai.com/v1".into(),
            model: "gpt-5-mini".into(),
            api_key_env: "OPENFRAUD_AI_API_KEY".into(),
            summarize_cases: true,
            timeout_secs: 60,
            max_output_tokens: 800,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Stripe {
    pub enabled: bool,
    pub webhook_secret_env: String,
    pub api_key_env: String,
    pub api_base: String,
    /// The metadata key of Stripe objects that holds your actor id.
    pub user_metadata_key: String,
    /// Let openfraud call Stripe for the `stripe.*` actions.
    pub actions: bool,
    /// A Radar value list of type `card_fingerprint` for `stripe.block_cards`.
    pub radar_value_list: Option<String>,
}

impl Default for Stripe {
    fn default() -> Self {
        Stripe {
            enabled: false,
            webhook_secret_env: "STRIPE_WEBHOOK_SECRET".into(),
            api_key_env: "STRIPE_API_KEY".into(),
            api_base: "https://api.stripe.com".into(),
            user_metadata_key: "user_id".into(),
            actions: false,
            radar_value_list: None,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub server: Server,
    #[serde(default)]
    pub admin: Admin,
    #[serde(default)]
    pub privacy: Privacy,
    #[serde(default)]
    pub trust: Trust,
    #[serde(default)]
    pub events: Events,
    #[serde(default)]
    pub safety: Safety,
    #[serde(default)]
    pub graph: Graph,
    #[serde(default)]
    pub compliance: Compliance,
    #[serde(default)]
    pub core: Core,
    #[serde(default)]
    pub networks: Networks,
    #[serde(default)]
    pub device: Device,
    #[serde(default)]
    pub email: Email,
    /// Rule packs to load: `messaging`, `card-and-payments` ... (see packs/).
    #[serde(default)]
    pub packs: Vec<String>,
    /// A directory of packs of your own, one `<name>/pack.toml` each.
    #[serde(default)]
    pub packs_dir: Option<PathBuf>,
    #[serde(default)]
    pub lists: BTreeMap<String, ListSpec>,
    #[serde(default)]
    pub counters: BTreeMap<String, CounterSpec>,
    #[serde(default)]
    pub workflows: BTreeMap<String, WorkflowSpec>,
    #[serde(default)]
    pub overrides: BTreeMap<String, Override>,
    #[serde(default)]
    pub alerts: Vec<AlertSpec>,
    #[serde(default)]
    pub webhooks: Option<Webhooks>,
    #[serde(default)]
    pub ai: Ai,
    #[serde(default)]
    pub stripe: Stripe,
    /// The directory relative paths are read from.
    #[serde(skip)]
    pub base_dir: PathBuf,
    /// Where each workflow comes from: `core`, `pack:<name>` or `config`.
    #[serde(skip)]
    pub origins: BTreeMap<String, String>,
}

/// What a counter is keyed by, or counts distinct values of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Key {
    Actor,
    Tenant,
    Owner,
    Cluster,
    Ip,
    IpPrefix,
    /// The autonomous system announcing the address (`[networks]`).
    IpAsn,
    Email,
    EmailDomain,
    /// The letters of the address's local part (`john` for `john1990`).
    EmailStem,
    /// The address as typed, tag included.
    EmailAlias,
    /// The address's domain below its public suffix (`fraudco.net`).
    EmailRegisteredDomain,
    Phone,
    PhonePrefix,
    Device,
    Country,
    Subject,
    /// An identifier attribute (hashed).
    Id(String),
    /// A plain attribute.
    Attr(String),
}

pub const BUILTIN_KEYS: [&str; 18] = [
    "actor",
    "tenant",
    "owner",
    "cluster",
    "ip",
    "ip_prefix",
    "ip_asn",
    "email",
    "email_domain",
    "email_stem",
    "email_alias",
    "email_registered_domain",
    "phone",
    "phone_prefix",
    "device",
    "country",
    "subject",
    "user",
];

impl Key {
    pub fn parse(text: &str, id_attrs: &[String]) -> Option<Key> {
        Some(match text {
            "actor" | "user" => Key::Actor,
            "tenant" => Key::Tenant,
            "owner" => Key::Owner,
            "cluster" => Key::Cluster,
            "ip" => Key::Ip,
            "ip_prefix" => Key::IpPrefix,
            "ip_asn" => Key::IpAsn,
            "email" => Key::Email,
            "email_domain" => Key::EmailDomain,
            "email_stem" => Key::EmailStem,
            "email_alias" => Key::EmailAlias,
            "email_registered_domain" => Key::EmailRegisteredDomain,
            "phone" => Key::Phone,
            "phone_prefix" => Key::PhonePrefix,
            "device" => Key::Device,
            "country" => Key::Country,
            "subject" => Key::Subject,
            _ if id_attrs.iter().any(|a| a == text) => Key::Id(text.to_owned()),
            _ => match text.strip_prefix("attrs.") {
                Some(name) if valid_name(name) => Key::Attr(name.to_owned()),
                _ => return None,
            },
        })
    }
}

#[derive(Debug)]
pub struct CompiledRule {
    pub id: String,
    pub expr: Expr,
    pub score: i64,
    pub decision: Option<Decision>,
    pub trust: Option<u8>,
    pub actions: Vec<String>,
    pub reason: String,
    /// The mode the configuration asks for.
    pub mode: Mode,
    pub hold_for: Option<u64>,
    pub target: Target,
    /// An allow that ends every workflow but the core's blocks.
    pub stop: bool,
    pub family: Family,
    pub signal: Option<String>,
    /// What the safety check compares with an approval: the rule's logic.
    pub fingerprint: String,
}

#[derive(Debug)]
pub struct CompiledWorkflow {
    pub name: String,
    /// Empty: every event type.
    pub events: BTreeSet<String>,
    pub bands: crate::decision::Bands,
    pub rules: Vec<CompiledRule>,
    /// `core`, `pack:<name>` or `config`.
    pub origin: String,
}

impl CompiledWorkflow {
    pub fn listens(&self, kind: &str) -> bool {
        self.events.is_empty() || self.events.contains(kind)
    }
}

#[derive(Debug)]
pub struct CompiledCounter {
    pub name: String,
    pub events: BTreeSet<String>,
    pub by: Key,
    /// Further keys read with `by`: the counter keys on all of them.
    pub also: Vec<Key>,
    pub agg: Option<crate::window::Agg>,
    pub of: Option<Key>,
    /// The span the usual value per window is learned over.
    pub baseline: Option<u64>,
    pub distinct: Option<Key>,
    pub sum: Option<Key>,
    pub when: Option<Expr>,
    pub window: u64,
}

/// What an item of a list is made of, and how long one added at run time stays.
#[derive(Debug, Clone)]
pub struct ListKeys {
    pub kind: ListKind,
    pub key: Option<Key>,
    pub second: Option<Key>,
    pub expire: Option<u64>,
}

/// Between the two values of a pair item.
pub const PAIR_SEPARATOR: char = '\u{1f}';

#[derive(Debug)]
pub struct Compiled {
    pub workflows: Vec<CompiledWorkflow>,
    pub counters: Vec<CompiledCounter>,
    /// The lists whose items are event values, or addresses kept for a while.
    pub list_keys: BTreeMap<String, ListKeys>,
    /// Lists as read from the configuration (items and files); lists with a
    /// `url` get their downloaded items added later.
    pub lists: BTreeMap<String, List>,
}

/// A rule id, counter, list or workflow name: lowercase letters, digits and
/// `_`, starting with a letter.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// The actions an application carries out. Reversible by design: every
/// restriction has `release`.
pub const ACTIONS: [&str; 6] = ["quarantine", "release", "hold", "step_up", "review", "revoke_sessions"];
/// Actions that name what they apply to: `suspend_feature:email`, `limit:contacts`,
/// `throttle:15m` (a duration).
pub const PARAMETRIC_ACTIONS: [&str; 3] = ["suspend_feature", "limit", "throttle"];
/// Actions a module carries out itself.
pub const MODULE_ACTIONS: [&str; 3] = ["stripe.cancel_subscriptions", "stripe.block_cards", "stripe.detach_payment_methods"];

/// An action of the fixed vocabulary, or of a module.
pub fn valid_action(name: &str) -> bool {
    if ACTIONS.contains(&name) || MODULE_ACTIONS.contains(&name) {
        return true;
    }
    match name.split_once(':') {
        Some(("throttle", what)) => throttle_seconds(what).is_some(),
        Some(("list.add" | "list.remove", what)) => valid_name(what),
        Some((kind, what)) => PARAMETRIC_ACTIONS.contains(&kind) && valid_name(what),
        None => false,
    }
}

/// The length of a `throttle:<duration>` action: `30s` to `366d`.
pub fn throttle_seconds(duration: &str) -> Option<u64> {
    crate::window::parse_duration(duration).ok().filter(|s| *s > 0)
}

fn action_problem(here: &str, action: &str) -> String {
    format!(
        "{here}: `{action}` is not an action: use {}, suspend_feature:<name>, limit:<quota>, throttle:<duration>, list.add:<list>, list.remove:<list> or {}",
        ACTIONS.join(", "),
        MODULE_ACTIONS.join(", ")
    )
}

/// Where a list may be downloaded from: https anywhere, plain http only from
/// a host on the private network (loopback, a private or link-local address,
/// a single-label name, or `.internal`, `.local`, `.lan`, `.home.arpa`),
/// where nobody on the internet can rewrite it on the way.
pub fn download_address(url: &str) -> bool {
    if url.starts_with("https://") {
        return true;
    }
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or_default();
    let host = if let Some(v6) = host.strip_prefix('[') {
        v6.split(']').next().unwrap_or_default()
    } else {
        host.split(':').next().unwrap_or_default()
    }
    .to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
            std::net::IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80,
        };
    }
    host == "localhost"
        || !host.contains('.')
        || [".internal", ".local", ".lan", ".home.arpa", ".localhost"]
            .iter()
            .any(|suffix| host.ends_with(suffix))
}

/// Why a `list.add:<name>` or `list.remove:<name>` action cannot work: the
/// list does not exist, or holds nothing an event carries.
fn list_action_problem(action: &str, lists: &BTreeMap<String, ListKeys>) -> Option<String> {
    let name = action.strip_prefix("list.add:").or_else(|| action.strip_prefix("list.remove:"))?;
    match lists.get(name) {
        None => Some(format!("`{action}` names no list `{name}`")),
        Some(l) if l.kind != ListKind::Ip && l.key.is_none() => Some(format!(
            "`{action}`: the list `{name}` has no `key`, so no event value can go in it"
        )),
        Some(_) => None,
    }
}

/// A short hash of a rule's logic: an approval holds while it is unchanged.
pub fn rule_fingerprint(workflow: &str, spec: &WorkflowSpec, rule: &RuleSpec) -> String {
    use sha2::{Digest, Sha256};
    // The workflow's bands and outcomes turn the rule's score into an action:
    // they are part of what an approval looked at.
    let bands = format!(
        "{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}",
        spec.step_up_at,
        spec.review_at,
        spec.hold_at,
        spec.block_at,
        spec.quarantine_at,
        spec.max_decision,
        spec.on_step_up,
        spec.on_review,
        spec.on_hold,
        spec.on_block,
        spec.on_quarantine
    );
    let mut text = format!(
        "{workflow}|{bands}|{}|{}|{}|{:?}|{:?}|{:?}|{:?}|{:?}",
        rule.id, rule.when, rule.score, rule.decision, rule.hold_for, rule.actions, rule.target, rule.trust
    );
    // Only when set: approvals given before `stop` existed stay valid.
    if rule.stop {
        text.push_str("|stop");
    }
    Sha256::digest(text.as_bytes()).iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// The lists, counters, workflows and custom event types a pack or the core
/// adds.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Pack {
    #[serde(default)]
    pub pack: PackInfo,
    #[serde(default)]
    pub events: Events,
    #[serde(default)]
    pub lists: BTreeMap<String, ListSpec>,
    #[serde(default)]
    pub counters: BTreeMap<String, CounterSpec>,
    #[serde(default)]
    pub workflows: BTreeMap<String, WorkflowSpec>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackInfo {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// The event types the pack reads, for the documentation and the check.
    #[serde(default)]
    pub needs: Vec<String>,
}

impl Config {
    pub fn parse(text: &str, base_dir: &Path) -> Result<Config> {
        let mut config: Config = toml::from_str(text).context("the configuration is not valid")?;
        config.base_dir = base_dir.to_path_buf();
        Ok(config)
    }

    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
        let base = path.parent().map(Path::to_path_buf).unwrap_or_default();
        Config::parse(&text, &base).with_context(|| format!("in {}", path.display()))
    }

    pub fn resolve(&self, path: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.base_dir.join(path)
        }
    }

    /// The configuration with the core and the packs merged in and the
    /// overrides applied, or every problem found.
    pub fn assemble(&self) -> std::result::Result<Config, Vec<String>> {
        let mut out = self.clone();
        let mut problems = Vec::new();
        for name in out.workflows.keys() {
            out.origins.insert(name.clone(), "config".into());
        }
        let mut sources: Vec<(String, String)> = Vec::new();
        for (part, on) in [
            ("blocklists", self.core.blocklists),
            ("trust", self.core.trust),
            ("account-takeover", self.core.account_takeover),
            ("networks", self.core.networks),
            ("activity", self.core.activity),
            ("email", self.core.email),
        ] {
            if on {
                sources.push(("core".into(), crate::packs::core(part).to_owned()));
            }
        }
        let mut seen = BTreeSet::new();
        for name in &self.packs {
            if !seen.insert(name.clone()) {
                problems.push(format!("packs: `{name}` is listed twice"));
                continue;
            }
            match crate::packs::text(name, self.packs_dir.as_deref().map(|d| self.resolve(d)).as_deref()) {
                Ok(text) => sources.push((format!("pack:{name}"), text)),
                Err(e) => problems.push(format!("packs: {e}")),
            }
        }
        for (origin, text) in sources {
            let pack: Pack = match toml::from_str(&text) {
                Ok(p) => p,
                Err(e) => {
                    problems.push(format!("{origin}: {e}"));
                    continue;
                }
            };
            out.events.custom.extend(pack.events.custom);
            for (name, spec) in pack.lists {
                match out.lists.get_mut(&name) {
                    // Your list of the same name adds to the pack's.
                    Some(mine) if mine.kind == spec.kind => {
                        let mut items = spec.items.clone();
                        items.append(&mut mine.items);
                        mine.items = items;
                        if mine.description.is_empty() {
                            mine.description = spec.description;
                        }
                        if mine.url.is_none() {
                            mine.url = spec.url;
                        }
                    }
                    Some(_) => problems.push(format!("{origin}: list `{name}` exists with another kind")),
                    None => {
                        out.lists.insert(name, spec);
                    }
                }
            }
            for (name, spec) in pack.counters {
                if out.counters.insert(name.clone(), spec).is_some() {
                    problems.push(format!("{origin}: counter `{name}` is defined twice"));
                }
            }
            for (name, spec) in pack.workflows {
                if out.workflows.insert(name.clone(), spec).is_some() {
                    problems.push(format!("{origin}: workflow `{name}` is defined twice"));
                }
                out.origins.insert(name, origin.clone());
            }
        }
        if let Some(mirror) = &out.server.lists_mirror {
            let base = mirror.trim_end_matches('/');
            for (name, spec) in out.lists.iter_mut() {
                if spec.url.is_some() {
                    spec.url = Some(format!("{base}/{name}.txt"));
                }
            }
            out.networks.url = format!("{base}/ip2asn-combined.tsv.gz");
        }
        for (id, change) in &self.overrides {
            let mut found = false;
            for wf in out.workflows.values_mut() {
                for rule in wf.rules.iter_mut().filter(|r| &r.id == id) {
                    found = true;
                    if let Some(mode) = change.mode {
                        rule.mode = Some(mode);
                    }
                    if let Some(score) = change.score {
                        rule.score = score;
                    }
                    if let Some(enabled) = change.enabled {
                        rule.enabled = enabled;
                    }
                }
            }
            if !found {
                problems.push(format!("overrides: there is no rule `{id}`"));
            }
        }
        if problems.is_empty() { Ok(out) } else { Err(problems) }
    }

    /// Every check that needs no event, and the form the engine runs.
    /// What is valid but likely not what was meant. `openfraud validate`
    /// prints these.
    pub fn warnings(&self) -> Vec<String> {
        let Ok(full) = self.assemble() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let kept = full.server.retention_days * 86_400;
        if kept > 0 {
            for (name, spec) in &full.counters {
                if let Ok(window) = parse_duration(&spec.window)
                    && window > kept
                {
                    out.push(format!(
                        "counter `{name}`: its {} window is longer than `[server] retention_days = {}`: after a restart it counts only what is kept",
                        spec.window, full.server.retention_days
                    ));
                }
            }
        }
        out
    }

    pub fn compile(&self) -> std::result::Result<Compiled, Vec<String>> {
        let full = self.assemble()?;
        full.compile_assembled()
    }

    fn compile_assembled(&self) -> std::result::Result<Compiled, Vec<String>> {
        let mut problems = Vec::new();
        if let Some(mirror) = &self.server.lists_mirror
            && !download_address(mirror)
        {
            problems.push("server: lists_mirror must start with https://, or http:// for a host on the private network".to_string());
        }
        if let Err(e) = parse_duration(&self.device.token_lifetime) {
            problems.push(format!("device: token_lifetime: {e}"));
        }
        if !download_address(&self.networks.url) {
            problems.push("networks: the url must start with https://, or http:// for a host on the private network".to_string());
        }
        for kind in &self.events.custom {
            if !valid_type(kind) {
                problems.push(format!("events: `{kind}` is not an event type such as x.game_won"));
            }
        }

        let mut lists = BTreeMap::new();
        let mut list_keys = BTreeMap::new();
        for (name, spec) in &self.lists {
            if !valid_name(name) {
                problems.push(format!("list `{name}`: a name is lowercase letters, digits and _"));
            }
            let mut list = List::new(spec.kind);
            for item in &spec.items {
                if let Err(e) = list.insert(item) {
                    problems.push(format!("list `{name}`: {e}"));
                }
            }
            if let Some(file) = &spec.file {
                match std::fs::read_to_string(self.resolve(file)) {
                    Ok(text) => {
                        for e in list.extend_from_text(&text) {
                            problems.push(format!("list `{name}`, {}: {e}", file.display()));
                        }
                    }
                    Err(e) => problems.push(format!("list `{name}`: cannot read {}: {e}", file.display())),
                }
            }
            if let Some(url) = &spec.url
                && !download_address(url)
            {
                problems.push(format!(
                    "list `{name}`: the url must start with https://, or http:// for a host on the private network"
                ));
            }
            let here = format!("list `{name}`");
            let field = |text: &str, problems: &mut Vec<String>| {
                let key = Key::parse(text, &self.privacy.id_attrs);
                if key.is_none() {
                    problems.push(format!(
                        "{here}: `{text}` is not one of {}, an identifier attribute or attrs.<name>",
                        BUILTIN_KEYS.join(", ")
                    ));
                }
                key
            };
            let key = spec.key.as_deref().and_then(|k| field(k, &mut problems));
            let second = spec.second.as_deref().and_then(|k| field(k, &mut problems));
            if spec.kind == ListKind::Ip && spec.key.is_some() {
                problems.push(format!("{here}: an ip list holds addresses: it takes no `key`"));
            }
            if spec.second.is_some() && (spec.key.is_none() || spec.kind != ListKind::Value) {
                problems.push(format!("{here}: a `second` field needs `kind = \"value\"` and a `key`"));
            }
            // Pseudonymized fields hold keyed hashes: an item written by hand
            // would never match one.
            let hashed = |k: &Option<Key>| {
                matches!(
                    k,
                    Some(Key::Ip | Key::Email | Key::Phone | Key::Device | Key::Id(_) | Key::EmailAlias | Key::EmailStem)
                )
            };
            if (hashed(&key) || second.is_some()) && (!spec.items.is_empty() || spec.file.is_some() || spec.url.is_some()) {
                problems.push(format!(
                    "{here}: a list of pseudonymized values or pairs is filled through the API and rules, not with items, a file or a url"
                ));
            }
            let expire = match &spec.expire {
                None => None,
                Some(text) => parse_duration(text).map_err(|e| problems.push(format!("{here}: {e}"))).ok(),
            };
            list_keys.insert(
                name.clone(),
                ListKeys {
                    kind: spec.kind,
                    key,
                    second,
                    expire,
                },
            );
            lists.insert(name.clone(), list);
        }

        // A counter condition reads the event only: `"name" in event.ip_lists`
        // is event data, so the list names are known; list functions are not.
        let event_only = Known {
            counters: BTreeSet::new(),
            lists: lists.keys().cloned().collect(),
            disabled: BTreeSet::new(),
        };
        let mut counters = Vec::new();
        let mut disabled = BTreeSet::new();
        for (name, spec) in &self.counters {
            let here = format!("counter `{name}`");
            if !spec.enabled {
                disabled.insert(name.clone());
                continue;
            }
            if !valid_name(name) {
                problems.push(format!("{here}: a name is lowercase letters, digits and _"));
            }
            let events = if spec.events == ["*"] {
                BTreeSet::new()
            } else {
                self.check_events(&here, &spec.events, &mut problems)
            };
            let window = parse_duration(&spec.window).map_err(|e| problems.push(format!("{here}: {e}"))).ok();
            let key = |text: &str, field: &str, problems: &mut Vec<String>| {
                let key = Key::parse(text, &self.privacy.id_attrs);
                if key.is_none() {
                    problems.push(format!(
                        "{here}: `{field} = \"{text}\"` is not one of {}, an identifier attribute ({}) or attrs.<name>",
                        BUILTIN_KEYS.join(", "),
                        self.privacy.id_attrs.join(", ")
                    ));
                }
                key
            };
            let names = spec.by.names();
            if names.is_empty() || names.len() > 4 {
                problems.push(format!("{here}: `by` names one to four keys"));
            }
            let mut keys: Vec<Option<Key>> = names.iter().map(|n| key(n, "by", &mut problems)).collect();
            if keys.len() > 1 && keys.iter().any(|k| k.as_ref() == Some(&Key::Cluster)) {
                problems.push(format!("{here}: `cluster` is a key of its own, not one of several"));
            }
            let by = if keys.is_empty() { None } else { keys.remove(0) };
            let also: Vec<Key> = keys.into_iter().flatten().collect();
            let of = spec.of.as_deref().and_then(|s| key(s, "of", &mut problems));
            if spec.agg.is_some() && of.is_none() {
                problems.push(format!("{here}: an aggregate needs `of`, the attribute it reads (attrs.amount)"));
            }
            if spec.agg.is_some() && (spec.distinct.is_some() || spec.sum.is_some()) {
                problems.push(format!("{here}: `agg` is not used with `distinct` or `sum`"));
            }
            let baseline = match &spec.baseline {
                None => None,
                Some(text) => match parse_duration(text) {
                    Ok(b) if window.is_some_and(|w| b > w) => Some(b),
                    Ok(_) => {
                        problems.push(format!("{here}: the baseline must be longer than the window"));
                        None
                    }
                    Err(e) => {
                        problems.push(format!("{here}: baseline: {e}"));
                        None
                    }
                },
            };
            let distinct = spec.distinct.as_deref().and_then(|d| key(d, "distinct", &mut problems));
            if distinct.is_some() && distinct == by {
                problems.push(format!("{here}: a counter cannot count distinct values of its own key"));
            }
            let sum = spec.sum.as_deref().and_then(|s| key(s, "sum", &mut problems));
            if sum.is_some() && distinct.is_some() {
                problems.push(format!("{here}: a counter adds up `sum` or counts `distinct` values, not both"));
            }
            let when = match &spec.when {
                None => None,
                Some(text) => match Expr::compile_event_only(text, &event_only) {
                    Ok(e) => Some(e),
                    Err(e) => {
                        problems.push(format!("{here}, when: {e}"));
                        None
                    }
                },
            };
            if let (Some(by), Some(window)) = (by, window) {
                counters.push(CompiledCounter {
                    name: name.clone(),
                    events,
                    by,
                    also,
                    agg: spec.agg,
                    of,
                    baseline,
                    distinct,
                    sum,
                    when,
                    window,
                });
            }
        }

        let known = Known {
            counters: self.counters.iter().filter(|(_, c)| c.enabled).map(|(k, _)| k.clone()).collect(),
            lists: self.lists.keys().cloned().collect(),
            disabled,
        };
        let mut rule_ids = BTreeSet::new();
        let mut workflows = Vec::new();
        for (name, spec) in &self.workflows {
            let here = format!("workflow `{name}`");
            if !valid_name(name) {
                problems.push(format!("{here}: a name is lowercase letters, digits and _"));
            }
            let events = if spec.events == ["*"] {
                BTreeSet::new()
            } else {
                self.check_events(&here, &spec.events, &mut problems)
            };
            let bands = [
                ("step_up_at", spec.step_up_at),
                ("review_at", spec.review_at),
                ("hold_at", spec.hold_at),
                ("block_at", spec.block_at),
                ("quarantine_at", spec.quarantine_at),
            ];
            for (i, (a, x)) in bands.iter().enumerate() {
                for (b, y) in &bands[i + 1..] {
                    if let (Some(x), Some(y)) = (x, y)
                        && x > y
                    {
                        problems.push(format!(
                            "{here}: `{a} = {x}` is above `{b} = {y}`: a score reaches {a} only after {b}"
                        ));
                    }
                }
            }
            for (field, outcome) in [
                ("on_step_up", &spec.on_step_up),
                ("on_review", &spec.on_review),
                ("on_hold", &spec.on_hold),
                ("on_block", &spec.on_block),
                ("on_quarantine", &spec.on_quarantine),
            ] {
                for action in &outcome.actions {
                    if !valid_action(action) {
                        problems.push(action_problem(&format!("{here}, {field}"), action));
                    } else if let Some(p) = list_action_problem(action, &list_keys) {
                        problems.push(format!("{here}, {field}: {p}"));
                    }
                }
            }
            let mut rules = Vec::new();
            for rule in &spec.rules {
                let here = format!("rule `{}` of workflow `{name}`", rule.id);
                if !valid_name(&rule.id) {
                    problems.push(format!("{here}: an id is lowercase letters, digits and _"));
                }
                if !rule_ids.insert(rule.id.clone()) {
                    problems.push(format!(
                        "{here}: the id `{}` is used twice; ids are unique across workflows",
                        rule.id
                    ));
                }
                if rule.reason.trim().is_empty() {
                    problems.push(format!("{here}: a rule needs a `reason`, the sentence that explains a decision"));
                }
                if let Some(signal) = &rule.signal
                    && !valid_name(signal)
                {
                    problems.push(format!("{here}: the signal `{signal}` is lowercase letters, digits and _"));
                }
                if rule.score == 0 && rule.decision.is_none() && rule.trust.is_none() && rule.actions.is_empty() && rule.signal.is_none() {
                    problems.push(format!(
                        "{here}: the rule does nothing: give it a score, a decision, a trust level, actions or a signal"
                    ));
                }
                for action in &rule.actions {
                    if !valid_action(action) {
                        problems.push(action_problem(&here, action));
                    } else if let Some(p) = list_action_problem(action, &list_keys) {
                        problems.push(format!("{here}: {p}"));
                    }
                }
                if rule.stop && rule.decision != Some(Decision::Allow) {
                    problems.push(format!("{here}: `stop = true` goes with `decision = \"allow\"`"));
                }
                let hold_for = match &rule.hold_for {
                    None => None,
                    Some(text) => match parse_duration(text) {
                        Ok(secs) if rule.decision == Some(Decision::Hold) => Some(secs),
                        Ok(_) => {
                            problems.push(format!("{here}: `hold_for` needs `decision = \"hold\"`"));
                            None
                        }
                        Err(e) => {
                            problems.push(format!("{here}: {e}"));
                            None
                        }
                    },
                };
                match Expr::compile(&rule.when, &known) {
                    Ok(expr) if rule.enabled && spec.enabled => rules.push(CompiledRule {
                        id: rule.id.clone(),
                        expr,
                        score: rule.score,
                        decision: rule.decision,
                        trust: rule.trust,
                        actions: rule.actions.clone(),
                        reason: rule.reason.trim().to_owned(),
                        mode: rule.mode.unwrap_or(spec.mode),
                        hold_for,
                        target: rule.target,
                        stop: rule.stop,
                        family: rule.family.unwrap_or(spec.family),
                        signal: rule.signal.clone(),
                        fingerprint: rule_fingerprint(name, spec, rule),
                    }),
                    Ok(_) => {}
                    Err(e) => problems.push(format!("{here}: {e}")),
                }
            }
            if spec.enabled {
                workflows.push(CompiledWorkflow {
                    name: name.clone(),
                    events,
                    bands: crate::decision::Bands {
                        step_up_at: spec.step_up_at,
                        review_at: spec.review_at,
                        hold_at: spec.hold_at,
                        block_at: spec.block_at,
                        quarantine_at: spec.quarantine_at,
                        max_decision: spec.max_decision,
                        on_step_up: spec.on_step_up.clone(),
                        on_review: spec.on_review.clone(),
                        on_hold: spec.on_hold.clone(),
                        on_block: spec.on_block.clone(),
                        on_quarantine: spec.on_quarantine.clone(),
                    },
                    rules,
                    origin: self.origins.get(name).cloned().unwrap_or_else(|| "config".into()),
                });
            }
        }

        if let Some(hooks) = &self.webhooks {
            if !(hooks.url.starts_with("https://") || hooks.url.starts_with("http://")) {
                problems.push(format!("webhooks: the url `{}` must start with http:// or https://", hooks.url));
            }
            for event in &hooks.events {
                if !WEBHOOK_EVENTS.contains(&event.as_str()) {
                    problems.push(format!("webhooks: `{event}` is not one of {}", WEBHOOK_EVENTS.join(", ")));
                }
            }
        }
        for (i, alert) in self.alerts.iter().enumerate() {
            let here = format!("alerts[{i}]");
            let needs = |field: &str, ok: bool, problems: &mut Vec<String>| {
                if !ok {
                    problems.push(format!("{here}: a {:?} alert needs `{field}`", alert.kind));
                }
            };
            match alert.kind {
                AlertKind::Webhook | AlertKind::Slack => needs("url", alert.url.is_some(), &mut problems),
                AlertKind::Telegram => {
                    needs("bot_token_env", alert.bot_token_env.is_some(), &mut problems);
                    needs("chat_id", alert.chat_id.is_some(), &mut problems);
                }
                AlertKind::Email => {
                    needs("smtp_host", alert.smtp_host.is_some(), &mut problems);
                    needs("from", alert.from.is_some(), &mut problems);
                    needs("to", !alert.to.is_empty(), &mut problems);
                }
            }
            if let Some(d) = &alert.digest
                && let Err(e) = parse_duration(d)
            {
                problems.push(format!("{here}: {e}"));
            }
        }
        if self.ai.enabled && !(self.ai.base_url.starts_with("https://") || self.ai.base_url.starts_with("http://")) {
            problems.push("ai: the base_url must start with http:// or https://".into());
        }
        for name in self
            .privacy
            .id_attrs
            .iter()
            .chain(&self.privacy.contact_attrs)
            .chain(&self.graph.related_attrs)
        {
            if !valid_name(name) {
                problems.push(format!("privacy: `{name}` is not an attribute name"));
            }
            if BUILTIN_KEYS.contains(&name.as_str()) {
                problems.push(format!("privacy: `{name}` is a built-in key, not an attribute"));
            }
        }
        if !self.graph.ip_prefix_window.is_empty()
            && let Err(e) = parse_duration(&self.graph.ip_prefix_window)
        {
            problems.push(format!("graph: {e}"));
        }

        if problems.is_empty() {
            Ok(Compiled {
                workflows,
                counters,
                list_keys,
                lists,
            })
        } else {
            Err(problems)
        }
    }

    fn check_events(&self, here: &str, events: &[String], problems: &mut Vec<String>) -> BTreeSet<String> {
        if events.is_empty() {
            problems.push(format!("{here}: list at least one event type in `events`"));
        }
        for event in events {
            if !valid_type(event) {
                problems.push(format!("{here}: `{event}` is not an event type such as account.created"));
            } else if !known_type(event, &self.events.custom) {
                problems.push(format!(
                    "{here}: `{event}` is not in the event vocabulary; declare it in `[events] custom`"
                ));
            }
        }
        events.iter().cloned().collect()
    }
}
