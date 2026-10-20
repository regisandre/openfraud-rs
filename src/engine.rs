//! The engine: one event in, one decision out, and what it remembers.
//!
//! For each event, [`Engine::process`]:
//! 1. normalizes it (pseudonyms, hashes, the IP lists the address is on)
//!    and checks its type against the vocabulary;
//! 2. gathers the facts rules read: the actor and the tenant, the counters,
//!    the accounts sharing an identifier and the cluster they form, the
//!    account takeover signals, the other accounts the event names;
//! 3. runs the rules of every workflow listening to the event type and
//!    turns them into one decision ([`crate::decision`]): a rule asked to act
//!    but not yet approved by a replay stays in shadow, and the safety brake
//!    turns restrictions into reviews when they spike;
//! 4. decides whom the actions restrict: the actor, or the tenant only when
//!    its owner acted (a member never gets the owner restricted: the tenant
//!    gets a review case);
//! 5. unless it is a dry run, remembers it all in one transaction: event,
//!    counters, subjects, links, clusters, cases, statements of reasons, and
//!    the webhooks, alerts and module actions to deliver.

use crate::config::{Compiled, CompiledCounter, Config, Decision, Key, Mode, Status, Target};
use crate::decision::{Bands, Fired, Verdict, combine, decide, status_rank};
use crate::event::{Event, Pseudonymizer, RawEvent, format_time, known_type, now};
use crate::expr::{Facts, Lists, Scope};
use crate::lists::{List, ListKind};
use crate::store::{Case, Store, Subject, SubjectKind};
use crate::window::{Counter, parse_duration};
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::Instant;

/// Event types that change a credential, for `session.since_credential_change`.
pub const CREDENTIAL_CHANGES: [&str; 4] = [
    "session.password_reset",
    "session.mfa_changed",
    "account.email_changed",
    "account.phone_changed",
];

#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// Decide without remembering anything.
    pub dry_run: bool,
    /// The time an event without `at` happened; the clock when absent.
    pub now: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Label {
    Fraud,
    Legit,
    /// Legit, and the rules that hit it were wrong: counts against their precision.
    FalsePositive,
}

impl Label {
    pub fn as_str(self) -> &'static str {
        match self {
            Label::Fraud => "fraud",
            Label::Legit => "legit",
            Label::FalsePositive => "false_positive",
        }
    }

    pub fn parse(text: &str) -> Option<Label> {
        match text {
            "fraud" => Some(Label::Fraud),
            "legit" => Some(Label::Legit),
            "false_positive" => Some(Label::FalsePositive),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleResult {
    #[serde(rename = "rule", alias = "id")]
    pub id: String,
    pub workflow: String,
    pub score: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<u8>,
    pub reason: String,
    pub mode: Mode,
    /// Asked to act, waiting for an approved replay: counted as shadow.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pending: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleError {
    pub rule: String,
    pub workflow: String,
    pub error: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubjectView {
    pub id: String,
    pub status: Status,
    pub trust: u8,
}

/// One thing the application is asked to do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionItem {
    pub action: String,
    /// `actor` or `tenant`.
    pub target: String,
    pub id: String,
}

/// What the API answers for an event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Outcome {
    pub event_id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub at: u64,
    pub decision: Decision,
    pub score: i64,
    pub actions: Vec<ActionItem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<SubjectView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<SubjectView>,
    /// Every rule that fired, in act and in shadow mode.
    pub rules: Vec<RuleResult>,
    /// Rules that could not be decided (a missing attribute): not fired.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<RuleError>,
    /// The decision with the shadow (and pending) rules counted too.
    pub shadow_decision: Decision,
    /// A restriction turned into a hold because the actor is trusted.
    pub protected: bool,
    /// The safety brake turned a restriction into a review.
    #[serde(default)]
    pub brake: bool,
    /// The restriction only repeats one a person or an earlier event already
    /// made (a quarantined account): no new statement, not counted by the
    /// safety brake.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub repeat: bool,
    pub workflows: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_case_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement_id: Option<String>,
    /// For a hold with a length: when it ends (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hold_until: Option<u64>,
    /// Rules that would have fired but are snoozed for this actor.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub snoozed: Vec<String>,
    /// The actor is throttled for this event type: seconds until it may try again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u64>,
    /// The event id was seen before: this is the first answer.
    #[serde(default)]
    pub duplicate: bool,
    #[serde(default)]
    pub dry_run: bool,
    /// Microseconds spent deciding.
    #[serde(default)]
    pub took_us: u64,
}

/// Why an event was not processed.
#[derive(Debug)]
pub enum ProcessError {
    /// The event itself is wrong: answer 400 with this message.
    Invalid(String),
    Internal(anyhow::Error),
}

impl std::fmt::Display for ProcessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProcessError::Invalid(m) => write!(f, "{m}"),
            ProcessError::Internal(e) => write!(f, "{e:#}"),
        }
    }
}

impl From<anyhow::Error> for ProcessError {
    fn from(e: anyhow::Error) -> Self {
        ProcessError::Internal(e)
    }
}

/// The safety brake's state.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Brake {
    pub engaged: bool,
    pub since: Option<u64>,
    pub reason: Option<String>,
}

struct Runtime {
    /// The configuration file as written.
    config: Config,
    /// With the core and the packs merged in.
    assembled: Config,
    compiled: Compiled,
    counters: Vec<Counter>,
    /// Rule id to whether it may act.
    approved: HashMap<String, bool>,
    brake: Brake,
    restrictions_1h: Counter,
    restrictions_7d: Counter,
}

struct Inner {
    store: Store,
    rt: Runtime,
}

/// The case was appealed already: one appeal per case, so a flood of
/// appeals cannot flood the reviewers' alerts.
#[derive(Debug)]
pub struct AlreadyAppealed;

impl std::fmt::Display for AlreadyAppealed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the case was appealed already")
    }
}

impl std::error::Error for AlreadyAppealed {}

pub struct Engine {
    pseudo: Pseudonymizer,
    lists: Lists,
    /// Which operator announces an address: `[networks]`, off by default.
    networks: RwLock<Option<Arc<crate::networks::NetworkTable>>>,
    inner: Mutex<Inner>,
}

const BRAKE_KEY: &str = "auto";

/// Rules outside the workflows, which a snooze cannot silence.
const BUILTIN_RULES: [&str; 3] = ["actor_quarantined", "tenant_quarantined", "actor_throttled"];

/// A snooze named a rule that does not exist, or a built-in one.
#[derive(Debug)]
pub struct UnknownRule {
    pub message: String,
    pub builtin: bool,
}

impl std::fmt::Display for UnknownRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for UnknownRule {}

/// Longer attribute values are hashed before they become a counter or link
/// key: a key lives in memory for the whole window.
const MAX_KEY_LEN: usize = 128;

fn long_key(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(value.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
}

/// The value of `key` in an event, as counters and links use it. `cluster`
/// is the actor's cluster root at the time.
pub fn key_value(event: &Event, key: &Key, cluster: Option<&str>) -> Option<String> {
    match key {
        Key::Actor => event.actor.clone(),
        Key::Tenant => event.tenant.clone(),
        Key::Owner => event.owner.clone(),
        Key::Cluster => cluster.map(str::to_owned).or_else(|| event.actor.clone()),
        Key::Ip => event.ip_hash.clone(),
        Key::IpPrefix => event.ip_prefix.clone(),
        Key::IpAsn => event.ip_asn.map(|a| a.to_string()),
        Key::Email => event.ids.get("email").cloned(),
        Key::EmailDomain => event.email_domain.clone(),
        Key::EmailStem => event
            .email
            .as_deref()
            .and_then(|e| e.split_once('@'))
            .and_then(|(local, _)| local.split_once('.'))
            .map(|(_, stem)| stem.to_owned()),
        Key::EmailAlias => event.email_alias.clone(),
        Key::Phone => event.ids.get("phone").cloned(),
        Key::PhonePrefix => event.phone_prefix.clone(),
        Key::Device => event.device.clone(),
        Key::Country => event.country.clone(),
        Key::Subject => event.subject.as_ref().map(|s| format!("{}:{}", s.kind, s.id)),
        Key::Id(name) => event.ids.get(name).cloned(),
        Key::Attr(name) => match event.attrs.get(name)? {
            Value::String(s) if s.len() > MAX_KEY_LEN => Some(long_key(s)),
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            Value::Bool(b) => Some(b.to_string()),
            _ => None,
        },
    }
}

/// What an account is seen with, for the `session.new_*` facts: the
/// network operator, the operating system, the browser and the language.
fn seen_values(event: &Event) -> Vec<(&'static str, &'static str, String)> {
    let mut out = Vec::new();
    if let Some(asn) = event.ip_asn {
        out.push(("new_asn", "asn", asn.to_string()));
    }
    if let Some(agent) = &event.agent {
        if !agent.os.is_empty() {
            out.push(("new_os", "os", agent.os.clone()));
        }
        if !agent.browser.is_empty() {
            out.push(("new_browser", "browser", agent.browser.clone()));
        }
    }
    if let Some(language) = &event.language {
        out.push(("new_language", "language", language.clone()));
    }
    out
}

/// The amount a sum counter adds for an event: the attribute rounded, or 1
/// when absent.
fn weight(event: &Event, spec: &CompiledCounter) -> u64 {
    match &spec.sum {
        Some(Key::Attr(name)) => event
            .attrs
            .get(name)
            .and_then(Value::as_f64)
            .map(|v| v.max(0.0).round() as u64)
            .unwrap_or(1),
        _ => 1,
    }
}

/// Whether the counter's `when` lets the event count.
fn counts(spec: &CompiledCounter, event: &Event, scope: &mut Option<Scope>) -> bool {
    if !spec.events.contains(&event.kind) {
        return false;
    }
    match &spec.when {
        None => true,
        Some(expr) => {
            let scope = scope.get_or_insert_with(|| Scope::event_only(serde_json::to_value(event).unwrap_or_default(), event.at));
            expr.eval(scope).unwrap_or(false)
        }
    }
}

fn add_to_counters(compiled: &[CompiledCounter], counters: &mut [Counter], event: &Event, cluster: Option<&str>) {
    let mut scope = None;
    for (spec, counter) in compiled.iter().zip(counters.iter_mut()) {
        if !counts(spec, event, &mut scope) {
            continue;
        }
        if let Some(key) = key_value(event, &spec.by, cluster) {
            let value = spec.distinct.as_ref().and_then(|d| key_value(event, d, cluster));
            counter.add_weighted(&key, event.at, value.as_deref(), weight(event, spec));
        }
    }
}

/// The status a subject moves to. Automatic changes only make it stricter,
/// and never take a trusted subject below quarantine.
fn next_status(current: Status, proposed: Option<Status>) -> Status {
    match proposed {
        None => current,
        Some(p) if current == Status::Trusted && p != Status::Quarantined => current,
        Some(p) if status_rank(p) > status_rank(current) => p,
        Some(_) => current,
    }
}

fn lock(m: &Mutex<Inner>) -> MutexGuard<'_, Inner> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The lists as the configuration, the items added at run time and the
/// last downloads make them.
fn build_lists(config: &Config, compiled: &Compiled, store: &Store) -> Result<HashMap<String, List>> {
    let mut lists: HashMap<String, List> = compiled.lists.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    for (name, item) in store.list_items()? {
        if let Some(list) = lists.get_mut(&name) {
            let _ = list.insert(&item);
        }
    }
    for (name, spec) in &config.lists {
        if spec.url.is_some()
            && let (Some(list), Some((_, body))) = (lists.get_mut(name), store.list_cache(name)?)
        {
            list.extend_from_text(&body);
        }
    }
    Ok(lists)
}

fn approvals(store: &Store, assembled: &Config, compiled: &Compiled) -> Result<HashMap<String, bool>> {
    let stored: BTreeSet<(String, String)> = store.approvals()?.into_iter().collect();
    let mut out = HashMap::new();
    for wf in &compiled.workflows {
        for rule in &wf.rules {
            let ok =
                !assembled.safety.require_replay || wf.origin == "core" || stored.contains(&(rule.id.clone(), rule.fingerprint.clone()));
            out.insert(rule.id.clone(), ok);
        }
    }
    Ok(out)
}

fn runtime(config: Config, store: &Store, at: u64) -> std::result::Result<Runtime, Vec<String>> {
    let assembled = config.assemble()?;
    let compiled = config.compile()?;
    let counters = compiled
        .counters
        .iter()
        .map(|c| Counter::new(c.window, c.distinct.is_some()))
        .collect();
    let approved = approvals(store, &assembled, &compiled).map_err(|e| vec![format!("{e:#}")])?;
    let brake = store
        .get_kv("brake")
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();
    let mut rt = Runtime {
        config,
        assembled,
        compiled,
        counters,
        approved,
        brake,
        restrictions_1h: Counter::new(3_600, false),
        restrictions_7d: Counter::new(7 * 86_400, false),
    };
    rebuild(store, &mut rt, at).map_err(|e| vec![format!("{e:#}")])?;
    Ok(rt)
}

/// Counters and the brake's baseline, from the stored events.
fn rebuild(store: &Store, rt: &mut Runtime, at: u64) -> Result<()> {
    let longest = rt.compiled.counters.iter().map(|c| c.window).max().unwrap_or(0);
    if longest > 0 {
        let Runtime { compiled, counters, .. } = rt;
        store.events_since(at.saturating_sub(longest), |event, _| {
            let cluster = event.actor.as_deref().map(|a| store.cluster_root(a)).transpose()?.flatten();
            add_to_counters(&compiled.counters, counters, &event, cluster.as_deref());
            Ok(())
        })?;
    }
    for t in store.restriction_times(at.saturating_sub(7 * 86_400))? {
        rt.restrictions_1h.add(BRAKE_KEY, t, None);
        rt.restrictions_7d.add(BRAKE_KEY, t, None);
    }
    Ok(())
}

impl Engine {
    /// Opens the engine on a database file, or a private in-memory one.
    /// `key` is the pseudonym key from the state file.
    pub fn open(config: Config, key: Vec<u8>, database: Option<&Path>) -> Result<Engine> {
        let store = Store::open(database)?;
        let rt =
            runtime(config, &store, now()).map_err(|problems| anyhow!("the configuration is not valid:\n- {}", problems.join("\n- ")))?;
        let lists = build_lists(&rt.assembled, &rt.compiled, &store)?;
        Ok(Engine {
            pseudo: Pseudonymizer::new(key),
            lists: Arc::new(RwLock::new(lists)),
            networks: RwLock::new(None),
            inner: Mutex::new(Inner { store, rt }),
        })
    }

    /// Replaces the network table; `None` turns the lookup off.
    pub fn set_networks(&self, table: Option<Arc<crate::networks::NetworkTable>>) {
        *self.networks.write().unwrap_or_else(|e| e.into_inner()) = table;
    }

    /// Replaces the configuration. On a problem, the running one stays.
    pub fn reload(&self, config: Config) -> std::result::Result<(), Vec<String>> {
        let mut inner = lock(&self.inner);
        let rt = runtime(config, &inner.store, now())?;
        let lists = build_lists(&rt.assembled, &rt.compiled, &inner.store).map_err(|e| vec![format!("{e:#}")])?;
        inner.rt = rt;
        *self.lists.write().unwrap_or_else(|e| e.into_inner()) = lists;
        Ok(())
    }

    /// The configuration file as written.
    pub fn config(&self) -> Config {
        lock(&self.inner).rt.config.clone()
    }

    /// The configuration with the core and the packs merged in.
    pub fn assembled(&self) -> Config {
        lock(&self.inner).rt.assembled.clone()
    }

    /// Whether each rule may act (approved, or not needing approval).
    pub fn approvals(&self) -> HashMap<String, bool> {
        lock(&self.inner).rt.approved.clone()
    }

    pub fn pseudonymizer(&self) -> &Pseudonymizer {
        &self.pseudo
    }

    pub fn process(&self, raw: RawEvent, options: Options) -> std::result::Result<Outcome, ProcessError> {
        let started = Instant::now();
        let clock = options.now.unwrap_or_else(now);
        let privacy = lock(&self.inner).rt.assembled.privacy.clone();
        let mut event = raw.normalize(&self.pseudo, &privacy, clock).map_err(ProcessError::Invalid)?;
        if let Some(ip) = event.ip {
            let lists = self.lists.read().unwrap_or_else(|e| e.into_inner());
            let mut names: Vec<String> = lists
                .iter()
                .filter(|(_, l)| l.kind() == ListKind::Ip && l.contains_ip(ip))
                .map(|(n, _)| n.clone())
                .collect();
            names.sort();
            event.ip_lists = names;
            let networks = self.networks.read().unwrap_or_else(|e| e.into_inner());
            if let Some(network) = networks.as_ref().and_then(|t| t.lookup(ip)) {
                event.ip_asn = Some(network.asn);
                event.ip_org = Some(network.org).filter(|o| !o.is_empty());
                event.ip_country = Some(network.country).filter(|c| !c.is_empty());
            }
        }
        self.decide_event(event, options, started)
    }

    /// Decides an event already normalized, such as a stored one in a
    /// replay: its pseudonyms and IP list memberships are used as they are.
    pub fn process_event(&self, event: Event, options: Options) -> std::result::Result<Outcome, ProcessError> {
        self.decide_event(event, options, Instant::now())
    }

    fn decide_event(&self, event: Event, options: Options, started: Instant) -> std::result::Result<Outcome, ProcessError> {
        let mut inner = lock(&self.inner);
        if !known_type(&event.kind, &inner.rt.assembled.events.custom) {
            return Err(ProcessError::Invalid(format!(
                "`{}` is not an event type openfraud knows: use the vocabulary, or declare it in `[events] custom`",
                event.kind
            )));
        }
        if let Some(previous) = inner.store.outcome_of(&event.id)? {
            let mut outcome: Outcome = serde_json::from_str(&previous).context("a stored outcome cannot be read")?;
            outcome.duplicate = true;
            outcome.dry_run = options.dry_run;
            outcome.took_us = started.elapsed().as_micros() as u64;
            return Ok(outcome);
        }
        let (mut outcome, plan) = evaluate(&inner, &self.lists, &event)?;
        outcome.dry_run = options.dry_run;
        if !options.dry_run {
            let Inner { store, rt } = &mut *inner;
            store.atomically(|store| remember(store, rt, &event, &mut outcome, &plan))?;
        }
        outcome.took_us = started.elapsed().as_micros() as u64;
        Ok(outcome)
    }

    // ----------------------------------------------------- people's acts

    /// A person's verdict on an actor: `fraud` quarantines it, `legit` and
    /// `false_positive` trust it. Resolves its open case. The rest of its
    /// cluster gets a case to review: never an automatic restriction.
    /// Silences `rule` for `actor` until `until` (Unix seconds): the rule
    /// does not fire for that account, and answers list it in `snoozed`.
    pub fn snooze(&self, actor: &str, rule: &str, until: u64, by: &str, note: &str) -> Result<()> {
        let at = now();
        let inner = lock(&self.inner);
        if BUILTIN_RULES.contains(&rule) {
            bail!(UnknownRule {
                message: format!("`{rule}` is a built-in rule and cannot be snoozed"),
                builtin: true,
            });
        }
        if !inner.rt.compiled.workflows.iter().any(|w| w.rules.iter().any(|r| r.id == rule)) {
            bail!(UnknownRule {
                message: format!("there is no rule `{rule}`"),
                builtin: false,
            });
        }
        inner.store.atomically(|store| {
            store.snooze(actor, rule, until, by, note, at)?;
            store.audit(at, by, "snooze", actor, &format!("{rule} until {until} {note}"))
        })
    }

    /// Lifts a snooze; false when there was none.
    pub fn unsnooze(&self, actor: &str, rule: &str, by: &str) -> Result<bool> {
        let at = now();
        let inner = lock(&self.inner);
        inner.store.atomically(|store| {
            let lifted = store.unsnooze(actor, rule)?;
            if lifted {
                store.audit(at, by, "unsnooze", actor, rule)?;
            }
            Ok(lifted)
        })
    }

    pub fn snoozes(&self, actor: &str) -> Result<Vec<crate::store::Snooze>> {
        lock(&self.inner).store.snoozes_of(actor)
    }

    pub fn label(&self, actor: &str, label: Label, by: &str, note: &str) -> Result<Subject> {
        let at = now();
        let inner = lock(&self.inner);
        let Inner { store, rt } = &*inner;
        store.atomically(|store| {
            let mut state = store
                .subject(SubjectKind::Actor, actor)?
                .unwrap_or_else(|| Subject::new(SubjectKind::Actor, actor, at));
            let before = state.status;
            match label {
                Label::Fraud => state.status = Status::Quarantined,
                Label::Legit | Label::FalsePositive => {
                    state.status = Status::Trusted;
                    state.trust = state.trust.max(1);
                }
            }
            state.label = Some(label.as_str().to_owned());
            state.updated_at = at;
            if !note.is_empty() {
                state.note = Some(note.to_owned());
            }
            store.put_subject(&state)?;
            store.audit(at, by, &format!("label_{}", label.as_str()), actor, note)?;
            if let Some(case) = store.open_case_of(SubjectKind::Actor, actor)? {
                store.resolve_case(case, label.as_str(), note, by, at)?;
                queue_webhook(
                    store,
                    &rt.assembled,
                    "case.resolved",
                    json!({"case_id": case, "subject": {"kind": "actor", "id": actor}, "label": label.as_str(), "by": by}),
                    at,
                )?;
            }
            if before != state.status {
                status_changed(store, &rt.assembled, SubjectKind::Actor, actor, before, state.status, by, at)?;
                if state.status == Status::Quarantined {
                    let reasons = vec![format!("A person labelled the account as fraud: {note}")];
                    statement(
                        store,
                        &rt.assembled,
                        SubjectKind::Actor,
                        actor,
                        None,
                        Decision::Quarantine,
                        &["quarantine".to_owned()],
                        &reasons,
                        &[],
                        false,
                        None,
                        at,
                    )?;
                }
            }
            if label == Label::Fraud
                && let Some(root) = store.cluster_root(actor)?
            {
                for other in store.cluster_members(&root, 500)? {
                    if other == actor {
                        continue;
                    }
                    let linked = store.subject(SubjectKind::Actor, &other)?;
                    if linked.as_ref().is_some_and(|u| u.flagged() || u.status == Status::Trusted) {
                        continue;
                    }
                    let reasons = vec!["cluster_fraud".to_owned()];
                    let (case, new) =
                        store.record_case(SubjectKind::Actor, &other, at, "review", 0, &reasons, &format!("label:{actor}"))?;
                    case_changed(store, &rt.assembled, case, new, SubjectKind::Actor, &other, at)?;
                }
            }
            Ok(state)
        })
    }

    /// Sets a subject's status and trust by hand. Releasing a quarantine
    /// goes through here.
    pub fn set_status(&self, kind: SubjectKind, id: &str, status: Status, trust: Option<u8>, by: &str, note: &str) -> Result<Subject> {
        let at = now();
        let inner = lock(&self.inner);
        let Inner { store, rt } = &*inner;
        store.atomically(|store| {
            let mut state = store.subject(kind, id)?.unwrap_or_else(|| Subject::new(kind, id, at));
            let before = state.status;
            state.status = status;
            if let Some(trust) = trust {
                state.trust = trust;
            }
            state.updated_at = at;
            if !note.is_empty() {
                state.note = Some(note.to_owned());
            }
            store.put_subject(&state)?;
            store.audit(
                at,
                by,
                "set_status",
                id,
                &format!("{} {} trust {} {note}", kind.as_str(), status.as_str(), state.trust),
            )?;
            if before != status {
                status_changed(store, &rt.assembled, kind, id, before, status, by, at)?;
                if status == Status::Quarantined {
                    let reasons = vec![format!("A person restricted the account: {note}")];
                    statement(
                        store,
                        &rt.assembled,
                        kind,
                        id,
                        None,
                        Decision::Quarantine,
                        &["quarantine".to_owned()],
                        &reasons,
                        &[],
                        false,
                        None,
                        at,
                    )?;
                }
            }
            Ok(state)
        })
    }

    /// The reviewer's decision on a case.
    pub fn resolve_case(&self, id: i64, label: Label, by: &str, note: &str) -> Result<Subject> {
        let case = self.case(id)?.context("no such case")?;
        match case.subject_kind {
            SubjectKind::Actor => self.label(&case.subject_id, label, by, note),
            SubjectKind::Tenant => {
                let at = now();
                let inner = lock(&self.inner);
                let Inner { store, rt } = &*inner;
                store.atomically(|store| {
                    store.resolve_case(id, label.as_str(), note, by, at)?;
                    store.audit(at, by, &format!("resolve_{}", label.as_str()), &case.subject_id, note)?;
                    queue_webhook(
                        store,
                        &rt.assembled,
                        "case.resolved",
                        json!({"case_id": id, "subject": {"kind": "tenant", "id": case.subject_id}, "label": label.as_str(), "by": by}),
                        at,
                    )?;
                    let mut state = store
                        .subject(SubjectKind::Tenant, &case.subject_id)?
                        .unwrap_or_else(|| Subject::new(SubjectKind::Tenant, &case.subject_id, at));
                    state.label = Some(label.as_str().to_owned());
                    store.put_subject(&state)?;
                    Ok(state)
                })
            }
        }
    }

    /// The user's appeal, forwarded by the application. A case is appealed
    /// once: a second appeal fails with [`AlreadyAppealed`].
    pub fn appeal(&self, case_id: i64, message: &str) -> Result<Case> {
        let at = now();
        let message: String = message.chars().take(4_000).collect();
        let inner = lock(&self.inner);
        let Inner { store, rt } = &*inner;
        store.atomically(|store| {
            let case = store.case(case_id)?.context("no such case")?;
            if case.appealed_at.is_some() {
                return Err(AlreadyAppealed.into());
            }
            store.appeal_case(case_id, &message, at)?;
            store.audit(at, "user", "appeal", &case.subject_id, &format!("case {case_id}"))?;
            queue_webhook(
                store,
                &rt.assembled,
                "case.appealed",
                json!({"case_id": case_id, "subject": {"kind": case.subject_kind, "id": case.subject_id}}),
                at,
            )?;
            queue_alert(
                store,
                &rt.assembled,
                crate::config::Severity::Info,
                "Appeal",
                &format!("Case {case_id} was appealed"),
                at,
            )?;
            store.case(case_id)?.context("the case disappeared")
        })
    }

    // ------------------------------------------------------------ reading

    pub fn subject(&self, kind: SubjectKind, id: &str) -> Result<Option<Subject>> {
        lock(&self.inner).store.subject(kind, id)
    }

    /// The actor `id`.
    pub fn user(&self, id: &str) -> Result<Option<Subject>> {
        self.subject(SubjectKind::Actor, id)
    }

    pub fn subject_events(&self, kind: SubjectKind, id: &str, limit: usize) -> Result<Vec<(Event, Outcome)>> {
        let events = lock(&self.inner).store.subject_events(kind, id, limit)?;
        Ok(events
            .into_iter()
            .filter_map(|(e, o)| serde_json::from_str(&o).ok().map(|o| (e, o)))
            .collect())
    }

    pub fn user_events(&self, id: &str, limit: usize) -> Result<Vec<(Event, Outcome)>> {
        self.subject_events(SubjectKind::Actor, id, limit)
    }

    /// The identifier kinds of an actor, each with how many other actors
    /// share it and how many of those are flagged.
    pub fn user_links(&self, id: &str) -> Result<Vec<(String, u64, u64)>> {
        let inner = lock(&self.inner);
        let mut out: BTreeMap<String, (u64, u64)> = BTreeMap::new();
        for (kind, value) in inner.store.links_of(id)? {
            let (users, flagged) = inner.store.link_counts(&kind, &value, Some(id), 0)?;
            let e = out.entry(kind).or_default();
            e.0 += users;
            e.1 += flagged;
        }
        Ok(out.into_iter().map(|(k, (u, f))| (k, u, f)).collect())
    }

    /// The cluster of an actor: its members and the identifier kinds that
    /// join them.
    pub fn cluster(&self, id: &str) -> Result<Value> {
        let inner = lock(&self.inner);
        let store = &inner.store;
        let Some(root) = store.cluster_root(id)? else {
            return Ok(json!({"root": null, "size": 1, "members": [], "joined_by": []}));
        };
        let members = store.cluster_members(&root, 200)?;
        let (size, flagged, fraud, legit) = store.cluster_stats(&root)?;
        let mut kinds: BTreeMap<String, BTreeMap<String, BTreeSet<String>>> = BTreeMap::new();
        let mut list = Vec::new();
        for m in &members {
            let s = store.subject(SubjectKind::Actor, m)?;
            list.push(json!({
                "id": m,
                "status": s.as_ref().map(|s| s.status.as_str()).unwrap_or("normal"),
                "label": s.as_ref().and_then(|s| s.label.clone()),
                "trust": s.as_ref().map(|s| s.trust).unwrap_or(0),
            }));
            for (kind, value) in store.links_of(m)? {
                kinds.entry(kind).or_default().entry(value).or_default().insert(m.clone());
            }
        }
        let joined: Vec<Value> = kinds
            .into_iter()
            .filter_map(|(kind, values)| {
                let shared = values.values().filter(|actors| actors.len() > 1).count();
                (shared > 0).then(|| json!({"kind": kind, "shared_values": shared}))
            })
            .collect();
        Ok(json!({"root": root, "size": size, "flagged": flagged, "fraud": fraud, "legit": legit, "members": list, "joined_by": joined}))
    }

    pub fn case(&self, id: i64) -> Result<Option<Case>> {
        lock(&self.inner).store.case(id)
    }

    pub fn cases(&self, open_only: bool, limit: usize, offset: usize) -> Result<Vec<Case>> {
        lock(&self.inner).store.cases(open_only, limit, offset)
    }

    pub fn set_case_summary(&self, id: i64, summary: &str) -> Result<()> {
        lock(&self.inner).store.set_case_summary(id, summary)
    }

    pub fn statement(&self, id: &str) -> Result<Option<Value>> {
        lock(&self.inner).store.statement(id)
    }

    /// Runs `f` with the store, under the engine's lock.
    pub fn with_store<T>(&self, f: impl FnOnce(&Store) -> Result<T>) -> Result<T> {
        f(&lock(&self.inner).store)
    }

    // ---------------------------------------------------- GDPR art. 15, 17

    /// Every record about an actor.
    pub fn export(&self, id: &str) -> Result<Value> {
        let inner = lock(&self.inner);
        let store = &inner.store;
        let events: Vec<Value> = store
            .subject_events(SubjectKind::Actor, id, 100_000)?
            .into_iter()
            .map(|(e, o)| json!({"event": e, "outcome": serde_json::from_str::<Value>(&o).unwrap_or_default()}))
            .collect();
        Ok(json!({
            "actor": store.subject(SubjectKind::Actor, id)?,
            "events": events,
            "identifiers": store.links_of(id)?.into_iter().map(|(k, v)| json!({"kind": k, "value": v})).collect::<Vec<_>>(),
            "seen": store.seen_of(id)?.into_iter().map(|(k, v)| json!({"kind": k, "value": v})).collect::<Vec<_>>(),
            "snoozes": store.snoozes_of(id)?,
            "cluster": store.cluster_root(id)?,
            "cases": store.subject_cases(SubjectKind::Actor, id)?,
            "statements": store.subject_statements(SubjectKind::Actor, id)?,
            "audit": store.audit_of(id)?,
            "note": "Email addresses, phone numbers, IP addresses and devices are stored as keyed pseudonyms; the raw values were never kept.",
        }))
    }

    /// Erases every record about an actor. With
    /// `keep_fraud_flag_after_erasure`, an actor labelled fraud leaves an
    /// anonymous flagged marker on its hashed identifiers.
    pub fn erase(&self, id: &str, by: &str) -> Result<u64> {
        let at = now();
        let inner = lock(&self.inner);
        let Inner { store, rt } = &*inner;
        store.atomically(|store| {
            let state = store.subject(SubjectKind::Actor, id)?;
            let keep = rt.assembled.compliance.keep_fraud_flag_after_erasure
                && state.as_ref().is_some_and(|s| s.label.as_deref() == Some("fraud"));
            let links = store.links_of(id)?;
            let marker = format!("erased:{}", self.pseudo.hash("erased", id, 16));
            store.anonymize_audit(id, &marker)?;
            let n = store.erase_actor(id)?;
            if keep {
                let mut flag = Subject::new(SubjectKind::Actor, &marker, at);
                flag.status = Status::Quarantined;
                flag.label = Some("fraud".into());
                store.put_subject(&flag)?;
                let strong: BTreeMap<String, String> = links.into_iter().filter(|(k, _)| rt.assembled.graph.link_on.contains(k)).collect();
                store.add_links(&marker, &strong, at)?;
            }
            store.audit(at, by, "erase", &marker, if keep { "fraud flag kept" } else { "" })?;
            Ok(n)
        })
    }

    // ------------------------------------------------------- safety brake

    pub fn brake(&self) -> Brake {
        lock(&self.inner).rt.brake.clone()
    }

    pub fn release_brake(&self, by: &str) -> Result<()> {
        let at = now();
        let mut inner = lock(&self.inner);
        let Inner { store, rt } = &mut *inner;
        rt.brake = Brake::default();
        // Start the baseline again: the spike that engaged it is behind.
        rt.restrictions_1h = Counter::new(3_600, false);
        store.atomically(|store| {
            store.put_kv("brake", &json!(Brake::default()))?;
            store.audit(at, by, "brake_released", "", "")?;
            queue_webhook(store, &rt.assembled, "brake.released", json!({"by": by}), at)
        })
    }

    /// Records that a rule's replay was reviewed: from now on it may act
    /// while its logic is unchanged.
    pub fn approve(&self, rule: &str, report: &Value, by: &str) -> Result<()> {
        let at = now();
        let mut inner = lock(&self.inner);
        let fingerprint = inner
            .rt
            .compiled
            .workflows
            .iter()
            .flat_map(|w| &w.rules)
            .find(|r| r.id == rule)
            .map(|r| r.fingerprint.clone())
            .with_context(|| format!("there is no rule `{rule}`"))?;
        inner.store.put_approval(rule, &fingerprint, at, by, report)?;
        inner.store.audit(at, by, "rule_approved", rule, &report.to_string())?;
        let Inner { store, rt } = &mut *inner;
        rt.approved = approvals(store, &rt.assembled, &rt.compiled)?;
        Ok(())
    }

    // -------------------------------------------------------------- lists

    /// Every list: name, kind, number of items, description, url.
    pub fn lists(&self) -> Vec<(String, ListKind, usize, String, Option<String>)> {
        let config = self.assembled();
        let lists = self.lists.read().unwrap_or_else(|e| e.into_inner());
        let mut out: Vec<_> = lists
            .iter()
            .map(|(name, l)| {
                let spec = config.lists.get(name);
                (
                    name.clone(),
                    l.kind(),
                    l.len(),
                    spec.map(|s| s.description.clone()).unwrap_or_default(),
                    spec.and_then(|s| s.url.clone()),
                )
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// The items added at run time to `list`.
    pub fn list_items(&self, list: &str) -> Result<Vec<String>> {
        Ok(lock(&self.inner)
            .store
            .list_items()?
            .into_iter()
            .filter(|(l, _)| l == list)
            .map(|(_, i)| i)
            .collect())
    }

    pub fn add_list_item(&self, list: &str, item: &str, by: &str, note: &str) -> Result<bool> {
        let item = {
            let lists = self.lists.read().unwrap_or_else(|e| e.into_inner());
            let l = lists.get(list).with_context(|| format!("there is no list `{list}`"))?;
            l.normalize_item(item).map_err(|e| anyhow!(e))?
        };
        let at = now();
        let added = {
            let inner = lock(&self.inner);
            let added = inner.store.add_list_item(list, &item, note, at)?;
            inner.store.audit(at, by, "list_add", list, &item)?;
            added
        };
        if let Some(l) = self.lists.write().unwrap_or_else(|e| e.into_inner()).get_mut(list) {
            let _ = l.insert(&item);
        }
        Ok(added)
    }

    pub fn remove_list_item(&self, list: &str, item: &str, by: &str) -> Result<bool> {
        let at = now();
        let inner = lock(&self.inner);
        let removed = inner.store.remove_list_item(list, item.trim())?;
        inner.store.audit(at, by, "list_remove", list, item)?;
        let lists = build_lists(&inner.rt.assembled, &inner.rt.compiled, &inner.store)?;
        if let Some(fresh) = lists.get(list).cloned() {
            self.lists.write().unwrap_or_else(|e| e.into_inner()).insert(list.to_owned(), fresh);
        }
        Ok(removed)
    }

    /// Downloads every list with a `url` older than `max_age` seconds, with
    /// `fetch`, when `[server] fetch_lists` is on. One line per list tried.
    pub fn refresh_lists(&self, max_age: u64, fetch: &dyn Fn(&str) -> Result<String>) -> Vec<String> {
        let at = now();
        let (config, due): (Config, Vec<(String, String)>) = {
            let inner = lock(&self.inner);
            let config = inner.rt.assembled.clone();
            if !config.server.fetch_lists {
                return Vec::new();
            }
            let due = config
                .lists
                .iter()
                .filter_map(|(name, spec)| spec.url.clone().map(|u| (name.clone(), u)))
                .filter(|(name, _)| match inner.store.list_cache(name) {
                    Ok(Some((fetched, _))) => at.saturating_sub(fetched) >= max_age,
                    _ => true,
                })
                .collect();
            (config, due)
        };
        let mut report = Vec::new();
        for (name, url) in due {
            match fetch(&url) {
                Ok(body) => {
                    let inner = lock(&self.inner);
                    if let Err(e) = inner.store.put_list_cache(&name, at, &body) {
                        report.push(format!("{name}: cannot store: {e:#}"));
                        continue;
                    }
                    match build_lists(&config, &inner.rt.compiled, &inner.store) {
                        Ok(lists) => {
                            let n = lists.get(&name).map(List::len).unwrap_or(0);
                            if let Some(fresh) = lists.get(&name).cloned() {
                                self.lists.write().unwrap_or_else(|e| e.into_inner()).insert(name.clone(), fresh);
                            }
                            report.push(format!("{name}: {n} items"));
                        }
                        Err(e) => report.push(format!("{name}: {e:#}")),
                    }
                }
                Err(e) => report.push(format!("{name}: download failed: {e:#}")),
            }
        }
        report
    }

    // --------------------------------------------------------- maintenance

    /// Forgets what left the counters' windows and what is past retention.
    pub fn maintain(&self, now: u64) -> Result<u64> {
        let mut inner = lock(&self.inner);
        for counter in &mut inner.rt.counters {
            counter.prune(now);
        }
        let ended = inner.store.purge_throttles(now)? + inner.store.purge_snoozes(now)?;
        let days = inner.rt.assembled.server.retention_days;
        if days == 0 {
            return Ok(ended);
        }
        Ok(ended + inner.store.purge(now.saturating_sub(days * 86_400))?)
    }
}

/// What the decision asks to change, worked out before anything is written.
#[derive(Debug, Default)]
struct Plan {
    actor_status: Option<Status>,
    actor_trust: Option<u8>,
    tenant_status: Option<Status>,
    /// The trust level a tenant rule sets (a paid invoice of the workspace).
    tenant_trust: Option<u8>,
    /// The tenant gets a review case: its owner is never restricted for what
    /// a member did.
    tenant_review: bool,
    /// The actor's cluster after this event, and the actors it joins.
    joins: Vec<String>,
    cluster: Option<String>,
    /// The brake engages with this event.
    brake_trips: bool,
    facts_reasons: Vec<String>,
}

fn subject_view(s: &Subject, status: Status, trust: u8) -> SubjectView {
    SubjectView {
        id: s.id.clone(),
        status,
        trust,
    }
}

/// Everything up to the decision: no write.
fn evaluate(inner: &Inner, lists: &Lists, event: &Event) -> Result<(Outcome, Plan)> {
    let rt = &inner.rt;
    let store = &inner.store;
    let config = &rt.assembled;
    let at = event.at;
    let actor = match &event.actor {
        Some(id) => Some(
            store
                .subject(SubjectKind::Actor, id)?
                .unwrap_or_else(|| Subject::new(SubjectKind::Actor, id, at)),
        ),
        None => None,
    };
    let tenant = match &event.tenant {
        Some(id) => Some(
            store
                .subject(SubjectKind::Tenant, id)?
                .unwrap_or_else(|| Subject::new(SubjectKind::Tenant, id, at)),
        ),
        None => None,
    };
    let mut plan = Plan::default();

    // Links and the cluster this event puts the actor in.
    let ip_window = if config.graph.ip_prefix_window.is_empty() {
        None
    } else {
        parse_duration(&config.graph.ip_prefix_window).ok()
    };
    let mut links = serde_json::Map::new();
    let mut roots: BTreeSet<String> = BTreeSet::new();
    // Each involved cluster's stats, read once.
    let mut stats: HashMap<String, (u64, u64, u64, u64)> = HashMap::new();
    let mut stats_of = |root: &str| -> Result<(u64, u64, u64, u64)> {
        if let Some(s) = stats.get(root) {
            return Ok(*s);
        }
        let s = store.cluster_stats(root)?;
        stats.insert(root.to_owned(), s);
        Ok(s)
    };
    let actor_root = match &event.actor {
        Some(a) => store.cluster_root(a)?,
        None => None,
    };
    let mut cluster_size = 1;
    if let Some(root) = &actor_root {
        cluster_size = stats_of(root)?.0.max(1);
        roots.insert(root.clone());
    }
    for (kind, value) in &event.ids {
        let since = if kind == "ip_prefix" {
            at.saturating_sub(ip_window.unwrap_or(0))
        } else {
            0
        };
        let (users, flagged) = store.link_counts(kind, value, event.actor.as_deref(), since)?;
        links.insert(kind.clone(), json!({"users": users, "flagged": flagged}));
        let joins = config.graph.link_on.contains(kind) || (kind == "ip_prefix" && ip_window.is_some());
        if let Some(a) = &event.actor
            && joins
            && users > 0
            && users <= config.graph.max_shared
        {
            for other in store.link_actors(kind, value, a, since, config.graph.max_shared as usize)? {
                let root = store.cluster_root(&other)?.unwrap_or_else(|| other.clone());
                if !roots.contains(&root) {
                    // Joining stops at the cap: the link is kept, the merge is not.
                    if cluster_size >= config.graph.max_cluster {
                        continue;
                    }
                    let size = store.cluster_size(&root)?.max(1);
                    if cluster_size + size > config.graph.max_cluster {
                        continue;
                    }
                    cluster_size += size;
                    roots.insert(root);
                }
                if !plan.joins.contains(&other) {
                    plan.joins.push(other);
                }
            }
        }
    }
    let (mut size, mut flagged, mut fraud, mut legit) = (0, 0, 0, 0);
    for root in &roots {
        let (s, f, fr, l) = stats_of(root)?;
        // An actor not yet in a cluster table is a cluster of one.
        let s = if s == 0 { 1 } else { s };
        size += s;
        flagged += f;
        fraud += fr;
        legit += l;
    }
    if event.actor.is_some() && actor_root.is_none() {
        size += 1;
    }
    links.insert(
        "cluster".into(),
        json!({"size": size.max(1), "flagged": flagged, "fraud": fraud, "legit": legit}),
    );
    // The cluster key counters use: the root of the largest involved cluster.
    let mut best: Option<(u64, String)> = None;
    for root in &roots {
        let (s, ..) = stats_of(root)?;
        if best.as_ref().is_none_or(|(bs, br)| s > *bs || (s == *bs && root < br)) {
            best = Some((s, root.clone()));
        }
    }
    plan.cluster = best.map(|(_, r)| r).or_else(|| event.actor.clone());

    // Counters.
    let mut counters = serde_json::Map::new();
    let mut when_scope = None;
    for (spec, counter) in rt.compiled.counters.iter().zip(&rt.counters) {
        let value = match key_value(event, &spec.by, plan.cluster.as_deref()) {
            None => 0,
            Some(key) if counts(spec, event, &mut when_scope) => {
                let distinct = spec.distinct.as_ref().and_then(|d| key_value(event, d, plan.cluster.as_deref()));
                counter.count_with_weight(&key, at, distinct.as_deref(), weight(event, spec))
            }
            Some(key) => counter.get(&key, at),
        };
        counters.insert(spec.name.clone(), json!(value));
    }

    // Account takeover signals.
    let mut session = json!({
        "new_device": false, "new_country": false, "new_asn": false, "new_os": false, "new_browser": false,
        "new_language": false, "travel_km": 0, "travel_kmh": 0, "since_credential_change": -1,
    });
    if let (Some(a), Some(state)) = (&event.actor, &actor) {
        if let Some(device) = &event.device {
            let known = store.links_of(a)?.iter().filter(|(k, _)| k == "device").count();
            session["new_device"] = json!(known > 0 && !store.has_link(a, "device", device)?);
        }
        for (fact, kind, value) in seen_values(event) {
            session[fact] = json!(store.seen_count(a, kind)? > 0 && !store.has_seen(a, kind, &value)?);
        }
        if let Some(country) = &event.country {
            session["new_country"] = json!(!state.countries.is_empty() && !state.countries.contains_key(country));
            if let (Some(last), Some(last_at)) = (&state.country, state.country_at)
                && last != country
                && let Some(km) = crate::geo::distance_km(last, country)
            {
                let hours = (at.saturating_sub(last_at) as f64 / 3_600.0).max(1.0 / 60.0);
                session["travel_km"] = json!(km.round() as i64);
                session["travel_kmh"] = json!((km / hours).round() as i64);
            }
        }
        let last_change = CREDENTIAL_CHANGES.iter().filter_map(|k| state.lasts.get(*k)).max();
        if let Some(t) = last_change {
            session["since_credential_change"] = json!(at as i64 - *t as i64);
        }
    }

    // Other accounts the event names.
    let mut related = serde_json::Map::new();
    for attr in &config.graph.related_attrs {
        if let Some(Value::String(other)) = event.attrs.get(attr) {
            let s = store.subject(SubjectKind::Actor, other)?;
            let root = store.cluster_root(other)?;
            let same = root.as_ref().is_some_and(|r| roots.contains(r)) || plan.joins.contains(other);
            related.insert(
                attr.clone(),
                json!({
                    "id": other,
                    "same_cluster": same,
                    "status": s.as_ref().map(|s| s.status.as_str()).unwrap_or("normal"),
                    "flagged": s.as_ref().is_some_and(Subject::flagged),
                }),
            );
        }
    }

    let actor_facts = |s: &Subject| -> Value {
        let created = s
            .created_at
            .or(event.actor_created_at)
            .unwrap_or(if event.kind == "account.created" && s.firsts.is_empty() {
                at
            } else {
                s.first_seen
            });
        json!({
            "id": s.id, "status": s.status.as_str(), "trust": s.trust, "age": at.saturating_sub(created),
            "idle": if s.firsts.is_empty() { 0 } else { at.saturating_sub(s.last_seen) },
            "max_score": s.max_score, "label": s.label.clone().unwrap_or_default(),
            "country": event.country.clone().or_else(|| s.country.clone()).unwrap_or_default(),
            "known": !s.firsts.is_empty(),
        })
    };
    let mut event_facts = serde_json::to_value(event)?;
    if let Value::Object(map) = &mut event_facts {
        // Always there, so a rule can test membership without has().
        map.entry("ip_lists").or_insert_with(|| json!([]));
    }
    let tenant_facts = tenant
        .as_ref()
        .map(|t| {
            json!({
                "id": t.id, "status": t.status.as_str(), "trust": t.trust, "age": at.saturating_sub(t.first_seen), "max_score": t.max_score,
                "known": !t.firsts.is_empty(),
                "actor_is_owner": event.owner.is_some() && event.owner == event.actor,
            })
        })
        .unwrap_or_else(
            || json!({"id": "", "status": "normal", "trust": 0, "age": 0, "max_score": 0, "known": false, "actor_is_owner": false}),
        );
    let facts = Facts {
        event: event_facts,
        actor: actor.as_ref().map(actor_facts).unwrap_or_else(|| {
            json!({"id": "", "status": "normal", "trust": 0, "age": 0, "max_score": 0, "label": "", "country": event.country.clone().unwrap_or_default(), "known": false})
        }),
        tenant: tenant_facts,
        counters: Value::Object(counters),
        links: Value::Object(links),
        session,
        related: Value::Object(related),
        firsts: actor.as_ref().map(|s| s.firsts.clone()).unwrap_or_default(),
        lasts: actor.as_ref().map(|s| s.lasts.clone()).unwrap_or_default(),
        tenant_firsts: tenant.as_ref().map(|t| t.firsts.clone()).unwrap_or_default(),
        at,
    };
    let scope = Scope::new(&facts, lists.clone());
    let trust = actor.as_ref().map(|s| s.trust).unwrap_or(0);
    let act_below = config.trust.act_below;

    let mut actor_verdicts: Vec<Verdict> = Vec::new();
    let mut tenant_verdicts: Vec<Verdict> = Vec::new();
    let mut rules = Vec::new();
    let mut errors = Vec::new();
    let mut workflows = Vec::new();
    let builtin = |id: &str, reason: &str, verdicts: &mut Vec<Verdict>, rules: &mut Vec<RuleResult>| {
        let fired = Fired {
            id: id.into(),
            score: 0,
            decision: Some(Decision::Block),
            trust: None,
            actions: vec![],
            reason: reason.into(),
            mode: Mode::Act,
            hold_for: None,
        };
        let mut v = decide(&Bands::default(), std::slice::from_ref(&fired), 0, 1);
        v.status = None;
        verdicts.push(v);
        rules.push(RuleResult {
            id: id.into(),
            workflow: "status".into(),
            score: 0,
            decision: Some(Decision::Block),
            trust: None,
            reason: reason.into(),
            mode: Mode::Act,
            pending: false,
        });
    };
    let builtins_before = actor_verdicts.len();
    if actor.as_ref().is_some_and(|s| s.status == Status::Quarantined) {
        builtin("actor_quarantined", "The account is quarantined", &mut actor_verdicts, &mut rules);
    }
    if tenant.as_ref().is_some_and(|s| s.status == Status::Quarantined) {
        builtin(
            "tenant_quarantined",
            "The workspace is quarantined",
            &mut actor_verdicts,
            &mut rules,
        );
    }
    let snoozes = match &event.actor {
        Some(id) => store.snoozed_rules(id, at)?,
        None => Vec::new(),
    };
    let mut snoozed = Vec::new();
    let throttled_until = match &event.actor {
        Some(id) => store.throttled_until(id, &event.kind, at)?,
        None => None,
    };
    if throttled_until.is_some() {
        builtin(
            "actor_throttled",
            "Too many of these actions in a short time: try again later",
            &mut actor_verdicts,
            &mut rules,
        );
    }
    let builtins = actor_verdicts.len() - builtins_before;
    for wf in rt.compiled.workflows.iter().filter(|w| w.listens(&event.kind)) {
        workflows.push(wf.name.clone());
        let mut on_actor = Vec::new();
        let mut on_tenant = Vec::new();
        for rule in &wf.rules {
            match rule.expr.eval(&scope) {
                Ok(true) if snoozes.contains(&rule.id) => snoozed.push(rule.id.clone()),
                Ok(true) => {
                    let approved = rt.approved.get(&rule.id).copied().unwrap_or(false);
                    let pending = rule.mode == Mode::Act && !approved;
                    let mode = if pending { Mode::Shadow } else { rule.mode };
                    rules.push(RuleResult {
                        id: rule.id.clone(),
                        workflow: wf.name.clone(),
                        score: rule.score,
                        decision: rule.decision,
                        trust: rule.trust,
                        reason: rule.reason.clone(),
                        mode,
                        pending,
                    });
                    let fired = Fired {
                        id: rule.id.clone(),
                        score: rule.score,
                        decision: rule.decision,
                        trust: rule.trust,
                        actions: rule.actions.clone(),
                        reason: rule.reason.clone(),
                        mode,
                        hold_for: rule.hold_for,
                    };
                    match rule.target {
                        Target::Actor => on_actor.push(fired),
                        Target::Tenant => on_tenant.push(fired),
                    }
                }
                Ok(false) => {}
                Err(error) => errors.push(RuleError {
                    rule: rule.id.clone(),
                    workflow: wf.name.clone(),
                    error,
                }),
            }
        }
        actor_verdicts.push(decide(&wf.bands, &on_actor, trust, act_below));
        if !on_tenant.is_empty() {
            tenant_verdicts.push(decide(
                &wf.bands,
                &on_tenant,
                tenant.as_ref().map(|t| t.trust).unwrap_or(0),
                act_below,
            ));
        }
    }
    let mut on_actor = combine(&actor_verdicts);
    let mut on_tenant = combine(&tenant_verdicts);
    // What the rules decide on their own, without the status of a subject
    // already quarantined.
    let fresh = combine(&actor_verdicts[builtins..]).decision.max(on_tenant.decision);

    // The tenant's owner is never restricted for what a member did.
    let actor_is_owner = event.owner.is_some() && event.owner == event.actor;
    let member_acted = event.actor.is_some() && !actor_is_owner;
    if event.tenant.is_some() && member_acted && on_tenant.decision > Decision::Allow {
        plan.tenant_review = true;
        on_tenant = Verdict {
            decision: Decision::Review,
            score: on_tenant.score,
            shadow_decision: on_tenant.shadow_decision,
            ..Verdict::default()
        };
    }
    if event.tenant.is_some() && member_acted && on_actor.decision.restricts() {
        plan.tenant_review = true;
    }
    if event.tenant.is_none() && on_tenant.decision > Decision::Allow {
        // Nothing to restrict: the decision still stands for the request.
        on_tenant.actions.clear();
    }

    let mut decision = on_actor.decision.max(on_tenant.decision);
    let mut brake = false;
    let repeat = decision.restricts() && !fresh.restricts();
    if decision.restricts() && !repeat {
        let tripped = if rt.brake.engaged {
            true
        } else {
            let hour = rt.restrictions_1h.count_with(BRAKE_KEY, at, None);
            let avg = rt.restrictions_7d.get(BRAKE_KEY, at) as f64 / 168.0;
            let s = &config.safety;
            let trip = hour > s.max_auto_per_hour || (hour >= s.min_per_hour && hour as f64 > s.baseline_multiple * avg.max(1.0));
            plan.brake_trips = trip;
            trip
        };
        if tripped {
            brake = true;
            decision = Decision::Review;
            on_actor = Verdict {
                decision: Decision::Review,
                score: on_actor.score,
                shadow_decision: on_actor.shadow_decision,
                trust: on_actor.trust,
                ..Verdict::default()
            };
            on_actor.actions = vec!["review".into()];
            on_tenant = Verdict {
                decision: on_tenant.decision.min(Decision::Review),
                score: on_tenant.score,
                ..Verdict::default()
            };
        }
    }

    let mut actions = Vec::new();
    let push = |actions: &mut Vec<ActionItem>, action: &str, target: &str, id: &str| {
        let item = ActionItem {
            action: action.into(),
            target: target.into(),
            id: id.into(),
        };
        if !actions.contains(&item) {
            actions.push(item);
        }
    };
    if let Some(a) = &event.actor {
        for action in &on_actor.actions {
            push(&mut actions, action, "actor", a);
        }
    }
    if let Some(t) = &event.tenant {
        if plan.tenant_review {
            push(&mut actions, "review", "tenant", t);
        } else {
            for action in &on_tenant.actions {
                push(&mut actions, action, "tenant", t);
            }
        }
    }
    plan.actor_status = on_actor.status;
    plan.actor_trust = on_actor.trust;
    plan.tenant_trust = on_tenant.trust;
    if !plan.tenant_review && on_tenant.decision == Decision::Quarantine {
        plan.tenant_status = Some(Status::Quarantined);
    }
    plan.facts_reasons = rules.iter().filter(|r| r.mode == Mode::Act).map(|r| r.reason.clone()).collect();
    let hold_until = (decision == Decision::Hold)
        .then(|| on_actor.hold_for.max(on_tenant.hold_for))
        .flatten()
        .map(|h| at + h);

    let actor_view = actor.as_ref().map(|s| {
        let trust = plan.actor_trust.map_or(s.trust, |t| s.trust.max(t));
        subject_view(s, next_status(s.status, plan.actor_status), trust)
    });
    let tenant_view = tenant.as_ref().map(|t| {
        let trust = plan.tenant_trust.map_or(t.trust, |n| t.trust.max(n));
        subject_view(t, next_status(t.status, plan.tenant_status), trust)
    });
    let outcome = Outcome {
        event_id: event.id.clone(),
        kind: event.kind.clone(),
        at,
        decision,
        score: on_actor.score.max(on_tenant.score),
        actions,
        actor: actor_view,
        tenant: tenant_view,
        rules,
        errors,
        shadow_decision: on_actor.shadow_decision.max(on_tenant.shadow_decision),
        protected: on_actor.protected || on_tenant.protected,
        brake,
        repeat,
        workflows,
        case_id: None,
        tenant_case_id: None,
        statement_id: None,
        hold_until,
        retry_after: throttled_until.map(|u| u - at),
        snoozed,
        duplicate: false,
        dry_run: false,
        took_us: 0,
    };
    Ok((outcome, plan))
}

/// Everything after the decision, inside one transaction.
fn remember(store: &Store, rt: &mut Runtime, event: &Event, outcome: &mut Outcome, plan: &Plan) -> Result<()> {
    let at = event.at;
    // Clusters first: the counters key on the cluster after this event.
    let mut cluster = plan.cluster.clone();
    if let Some(a) = &event.actor {
        store.ensure_cluster(a)?;
        for other in &plan.joins {
            let before: Vec<String> = [store.cluster_root(a)?, store.cluster_root(other)?].into_iter().flatten().collect();
            let root = store.union_clusters(a, other)?;
            for old in before.iter().filter(|r| **r != root) {
                for (spec, counter) in rt.compiled.counters.iter().zip(rt.counters.iter_mut()) {
                    if spec.by == Key::Cluster {
                        counter.merge_key(old, &root);
                    }
                }
            }
        }
        cluster = store.cluster_root(a)?;
    }
    add_to_counters(&rt.compiled.counters, &mut rt.counters, event, cluster.as_deref());
    let config = &rt.assembled;

    let restricted = outcome.decision.restricts();
    if let Some(id) = &event.actor {
        for item in outcome.actions.iter().filter(|a| a.target == "actor") {
            // A refused attempt while throttled does not push the end back.
            if let Some(seconds) = item.action.strip_prefix("throttle:").and_then(crate::config::throttle_seconds)
                && outcome.retry_after.is_none()
            {
                store.throttle(id, &event.kind, at + seconds)?;
            }
            if item.action == "release" {
                store.clear_throttles(id)?;
            }
        }
    }
    if let (Some(id), Some(view)) = (&event.actor, &outcome.actor) {
        let mut state = store
            .subject(SubjectKind::Actor, id)?
            .unwrap_or_else(|| Subject::new(SubjectKind::Actor, id, at));
        let before = state.status;
        if event.kind == "account.created" && state.created_at.is_none() {
            state.created_at = Some(at);
        }
        if state.created_at.is_none() {
            state.created_at = event.actor_created_at;
        }
        state.firsts.entry(event.kind.clone()).or_insert(at);
        let last = state.lasts.entry(event.kind.clone()).or_insert(at);
        *last = (*last).max(at);
        state.first_seen = state.first_seen.min(at);
        state.last_seen = state.last_seen.max(at);
        state.max_score = state.max_score.max(outcome.score);
        if let Some(country) = &event.country {
            if state.country_at.is_none_or(|t| at >= t) {
                state.country = Some(country.clone());
                state.country_at = Some(at);
            }
            state.countries.insert(country.clone(), at);
        }
        state.trust = view.trust;
        state.status = view.status;
        state.updated_at = at;
        store.put_subject(&state)?;
        store.add_links(id, &event.ids, at)?;
        for (_, kind, value) in seen_values(event) {
            store.mark_seen(id, kind, &value, at)?;
        }
        if outcome.decision >= Decision::Review || (before != state.status && state.status == Status::Quarantined) {
            let reasons: Vec<String> = outcome.rules.iter().filter(|r| r.mode == Mode::Act).map(|r| r.id.clone()).collect();
            let (case, new) = store.record_case(
                SubjectKind::Actor,
                id,
                at,
                outcome.decision.as_str(),
                outcome.score,
                &reasons,
                &event.id,
            )?;
            outcome.case_id = Some(case);
            case_changed(store, config, case, new, SubjectKind::Actor, id, at)?;
            if new && config.ai.enabled && config.ai.summarize_cases {
                store.outbox_push("ai_summary", &json!({"case_id": case}).to_string(), at)?;
            }
        }
        if before != state.status {
            status_changed(store, config, SubjectKind::Actor, id, before, state.status, "openfraud", at)?;
            if state.status == Status::Quarantined {
                queue_alert(
                    store,
                    config,
                    crate::config::Severity::Warning,
                    "Account quarantined",
                    &format!(
                        "Actor {id} was quarantined automatically ({} points): {}",
                        outcome.score,
                        plan.facts_reasons.join("; ")
                    ),
                    at,
                )?;
            }
        }
        let actor_actions: Vec<String> = outcome
            .actions
            .iter()
            .filter(|a| a.target == "actor")
            .map(|a| a.action.clone())
            .collect();
        if restricted && !outcome.repeat || state.status == Status::Quarantined && before != Status::Quarantined {
            let rules: Vec<String> = outcome.rules.iter().filter(|r| r.mode == Mode::Act).map(|r| r.id.clone()).collect();
            let id_st = statement(
                store,
                config,
                SubjectKind::Actor,
                id,
                outcome.case_id,
                outcome.decision,
                &actor_actions,
                &plan.facts_reasons,
                &rules,
                true,
                outcome.hold_until,
                at,
            )?;
            outcome.statement_id = Some(id_st);
        }
    }
    if let (Some(id), Some(view)) = (&event.tenant, &outcome.tenant) {
        let mut state = store
            .subject(SubjectKind::Tenant, id)?
            .unwrap_or_else(|| Subject::new(SubjectKind::Tenant, id, at));
        let before = state.status;
        if let Some(owner) = &event.owner {
            state.owner = Some(owner.clone());
        }
        state.firsts.entry(event.kind.clone()).or_insert(at);
        let last = state.lasts.entry(event.kind.clone()).or_insert(at);
        *last = (*last).max(at);
        state.last_seen = state.last_seen.max(at);
        state.first_seen = state.first_seen.min(at);
        state.max_score = state.max_score.max(outcome.score);
        state.status = view.status;
        state.trust = view.trust;
        state.updated_at = at;
        store.put_subject(&state)?;
        let tenant_restricted = outcome.actions.iter().any(|a| a.target == "tenant" && a.action != "review");
        if plan.tenant_review || tenant_restricted {
            let reasons: Vec<String> = outcome.rules.iter().filter(|r| r.mode == Mode::Act).map(|r| r.id.clone()).collect();
            let decision = if plan.tenant_review { "review" } else { outcome.decision.as_str() };
            let (case, new) = store.record_case(SubjectKind::Tenant, id, at, decision, outcome.score, &reasons, &event.id)?;
            outcome.tenant_case_id = Some(case);
            case_changed(store, config, case, new, SubjectKind::Tenant, id, at)?;
        }
        if tenant_restricted {
            let actions: Vec<String> = outcome
                .actions
                .iter()
                .filter(|a| a.target == "tenant")
                .map(|a| a.action.clone())
                .collect();
            let rules: Vec<String> = outcome.rules.iter().filter(|r| r.mode == Mode::Act).map(|r| r.id.clone()).collect();
            let st = statement(
                store,
                config,
                SubjectKind::Tenant,
                id,
                outcome.tenant_case_id,
                outcome.decision,
                &actions,
                &plan.facts_reasons,
                &rules,
                true,
                outcome.hold_until,
                at,
            )?;
            outcome.statement_id.get_or_insert(st);
        }
        if before != state.status {
            status_changed(store, config, SubjectKind::Tenant, id, before, state.status, "openfraud", at)?;
        }
    }

    if restricted && !outcome.brake && !outcome.repeat {
        rt.restrictions_1h.add(BRAKE_KEY, at, None);
        rt.restrictions_7d.add(BRAKE_KEY, at, None);
    }
    if plan.brake_trips && !rt.brake.engaged {
        rt.brake = Brake {
            engaged: true,
            since: Some(at),
            reason: Some("automatic restrictions spiked: every restriction is a review until a person releases the brake".into()),
        };
        store.put_kv("brake", &serde_json::to_value(&rt.brake)?)?;
        queue_webhook(store, config, "brake.engaged", json!({"since": at, "reason": rt.brake.reason}), at)?;
        queue_alert(
            store,
            config,
            crate::config::Severity::Critical,
            "Safety brake engaged",
            "Automatic restrictions spiked. Every restriction is now a review until a person releases the brake.",
            at,
        )?;
    }

    store.insert_event(event, &serde_json::to_string(outcome)?)?;
    if outcome.decision != Decision::Allow {
        let kind = format!("decision.{}", outcome.decision.as_str());
        queue_webhook(store, config, &kind, serde_json::to_value(&*outcome)?, at)?;
    }
    if config.stripe.enabled && config.stripe.actions {
        for item in outcome
            .actions
            .iter()
            .filter(|a| a.action.starts_with("stripe.") && a.target == "actor")
        {
            let payload = json!({"action": item.action, "user": item.id, "event_id": event.id});
            store.outbox_push("stripe", &payload.to_string(), at)?;
        }
    }
    Ok(())
}

/// A statement of reasons (EU Digital Services Act, art. 17): what is
/// restricted and for how long, the facts, the rules, whether a machine or
/// a person decided, the ground, and how to appeal. Returns its id.
#[allow(clippy::too_many_arguments)]
fn statement(
    store: &Store,
    config: &Config,
    kind: SubjectKind,
    id: &str,
    case: Option<i64>,
    decision: Decision,
    actions: &[String],
    facts: &[String],
    rules: &[String],
    automated: bool,
    hold_until: Option<u64>,
    at: u64,
) -> Result<String> {
    let st_id = format!("st_{}", crate::event::random_hex(8));
    let scope: Vec<String> = actions
        .iter()
        .map(|a| match a.split_once(':') {
            Some(("suspend_feature", f)) => format!("the feature `{f}`"),
            Some(("limit", q)) => format!("the quota `{q}`"),
            _ if a == "quarantine" => "the account".into(),
            _ if a == "hold" => "the action asked for".into(),
            _ => a.clone(),
        })
        .collect();
    let duration = match hold_until {
        Some(t) => format!("until {}", format_time(t)),
        None if decision == Decision::Block => "this request only".into(),
        None => "until a person reviews it".into(),
    };
    let body = json!({
        "id": st_id,
        "subject": {"kind": kind, "id": id},
        "created_at": format_time(at),
        "case_id": case,
        "restriction": {"decision": decision, "actions": actions, "scope": scope, "duration": duration},
        "facts": facts,
        "rules": rules,
        "automated_detection": automated,
        "automated_decision": automated,
        "ground": config.compliance.ground,
        "redress": config.compliance.redress,
        "appeal_url": config.compliance.appeal_url,
    });
    store.put_statement(&st_id, kind, id, at, &body)?;
    Ok(st_id)
}

fn queue_webhook(store: &Store, config: &Config, kind: &str, data: Value, at: u64) -> Result<()> {
    let Some(hooks) = &config.webhooks else {
        return Ok(());
    };
    if !hooks.events.iter().any(|e| e == kind) {
        return Ok(());
    }
    let body = json!({"type": kind, "timestamp": format_time(at), "data": data});
    store.outbox_push("webhook", &body.to_string(), at)?;
    Ok(())
}

/// An alert for the configured notifiers.
pub fn queue_alert(store: &Store, config: &Config, severity: crate::config::Severity, title: &str, text: &str, at: u64) -> Result<()> {
    for alert in crate::alerts::rows(config, severity, title, text, at) {
        store.outbox_push("alert", &serde_json::to_string(&alert)?, at)?;
    }
    Ok(())
}

fn case_changed(store: &Store, config: &Config, case: i64, new: bool, kind: SubjectKind, id: &str, at: u64) -> Result<()> {
    let hook = if new { "case.opened" } else { "case.updated" };
    queue_webhook(
        store,
        config,
        hook,
        json!({"case_id": case, "subject": {"kind": kind, "id": id}}),
        at,
    )?;
    if new {
        queue_alert(
            store,
            config,
            crate::config::Severity::Info,
            "Case opened",
            &format!("Case {case} opened for {} {id}", kind.as_str()),
            at,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn status_changed(store: &Store, config: &Config, kind: SubjectKind, id: &str, from: Status, to: Status, by: &str, at: u64) -> Result<()> {
    let mut actions = Vec::new();
    if from == Status::Quarantined && to != Status::Quarantined {
        actions.push("release");
    }
    if to == Status::Quarantined {
        actions.push("quarantine");
    }
    let hook = match kind {
        SubjectKind::Actor => "actor.status_changed",
        SubjectKind::Tenant => "tenant.status_changed",
    };
    let data = json!({"subject": {"kind": kind, "id": id}, "from": from.as_str(), "to": to.as_str(), "by": by, "actions": actions});
    queue_webhook(store, config, hook, data, at)
}
