//! Replay: the stored events, oldest first, run through a candidate
//! configuration on a fresh in-memory engine. The report says which
//! decisions would change, and, for each rule, how often it fires and how
//! many of the accounts it hits a person labelled fraud or legit.
//!
//! The candidate sees the events as they were stored: pseudonyms, and the
//! IP lists each address was on at the time. Account statuses evolve from
//! the candidate's own decisions only; the people's labels are used to score
//! the rules, not replayed. Every rule of the candidate is replayed as
//! approved and the safety brake is off: the report shows what the rules
//! would do once they act, which is what an approval needs to know.

use crate::config::{Config, Decision, Mode};
use crate::engine::{Engine, Options, Outcome};
use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Debug, Clone, Serialize)]
pub struct Change {
    pub event_id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub actor: Option<String>,
    pub before: Decision,
    pub after: Decision,
    pub rules: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleStats {
    pub id: String,
    pub mode: Mode,
    /// Events it fired on.
    pub fired: u64,
    /// Distinct accounts it fired on.
    pub users: u64,
    /// Of those, labelled fraud, legit and false positive by a person.
    pub fraud: u64,
    pub legit: u64,
    pub false_positive: u64,
    /// Fraud among the labelled accounts it hit; `None` when it hit none.
    pub precision: Option<f64>,
    /// The accounts labelled fraud it hit, of every account labelled fraud.
    pub recall: Option<f64>,
}

#[derive(Debug, Default, Serialize)]
pub struct ReplayReport {
    pub events: u64,
    pub before: BTreeMap<Decision, u64>,
    pub after: BTreeMap<Decision, u64>,
    /// Up to 500 changed decisions, oldest first.
    pub changed: Vec<Change>,
    pub changed_total: u64,
    pub rules: Vec<RuleStats>,
    /// The first and last event replayed.
    pub from: Option<u64>,
    pub to: Option<u64>,
}

pub const MAX_CHANGES: usize = 500;

/// Replays the events of `source` from `since` through `candidate`.
pub fn replay(source: &Engine, mut candidate: Config, since: u64) -> Result<ReplayReport> {
    candidate.safety.require_replay = false;
    candidate.safety.max_auto_per_hour = u64::MAX;
    candidate.safety.min_per_hour = u64::MAX;
    candidate.webhooks = None;
    candidate.alerts.clear();
    let fresh =
        Engine::open(candidate, b"replay: events are already pseudonymized".to_vec(), None).context("the candidate configuration")?;
    let labels: HashMap<String, String> = source.with_store(|s| s.labels())?.into_iter().collect();
    let mut history = Vec::new();
    source.with_store(|s| {
        s.events_since(since, |event, outcome| {
            history.push((event, outcome));
            Ok(())
        })
    })?;

    let mut report = ReplayReport::default();
    let mut per_rule: BTreeMap<String, (Mode, u64, BTreeSet<String>)> = BTreeMap::new();
    for (event, stored) in history {
        let before: Outcome = serde_json::from_str(&stored).context("a stored outcome cannot be read")?;
        let user = event.actor.clone();
        report.from = Some(report.from.map_or(event.at, |f| f.min(event.at)));
        report.to = Some(report.to.map_or(event.at, |t| t.max(event.at)));
        let (id, kind) = (event.id.clone(), event.kind.clone());
        let after = fresh
            .process_event(event, Options { dry_run: false, now: None })
            .map_err(|e| anyhow::anyhow!("event {id}: {e}"))?;
        report.events += 1;
        *report.before.entry(before.decision).or_default() += 1;
        *report.after.entry(after.decision).or_default() += 1;
        for rule in &after.rules {
            let entry = per_rule.entry(rule.id.clone()).or_insert((rule.mode, 0, BTreeSet::new()));
            entry.1 += 1;
            if let Some(u) = &user {
                entry.2.insert(u.clone());
            }
        }
        if before.decision != after.decision {
            report.changed_total += 1;
            if report.changed.len() < MAX_CHANGES {
                report.changed.push(Change {
                    event_id: id,
                    kind,
                    actor: user,
                    before: before.decision,
                    after: after.decision,
                    rules: after.rules.iter().filter(|r| r.mode == Mode::Act).map(|r| r.id.clone()).collect(),
                });
            }
        }
    }
    let all_fraud = labels.values().filter(|l| *l == "fraud").count() as u64;
    report.rules = per_rule
        .into_iter()
        .map(|(id, (mode, fired, users))| {
            let count = |label: &str| users.iter().filter(|u| labels.get(*u).is_some_and(|l| l == label)).count() as u64;
            let (fraud, legit, false_positive) = (count("fraud"), count("legit"), count("false_positive"));
            let labelled = fraud + legit + false_positive;
            let precision = (labelled > 0).then(|| fraud as f64 / labelled as f64);
            let recall = (all_fraud > 0).then(|| fraud as f64 / all_fraud as f64);
            RuleStats {
                id,
                mode,
                fired,
                users: users.len() as u64,
                fraud,
                legit,
                false_positive,
                precision,
                recall,
            }
        })
        .collect();
    Ok(report)
}
