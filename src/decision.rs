//! From the rules that fired to a decision. Pure: no clock, no storage.
//!
//! In one workflow, the scores of the rules in `act` mode add up and the
//! total falls in a band (`step_up_at` ... `quarantine_at`). A rule may force
//! a decision: the strictest forced decision wins over the band, and a forced
//! `allow` (an allowlist) wins over everything. A workflow may cap its
//! decisions (`max_decision`). An account at or above the trust level
//! `act_below` is never blocked or quarantined automatically: the action is
//! held for a person instead. Rules in `shadow` mode change nothing; the
//! decision they would have given is `shadow_decision`. Workflows that ran on
//! the same event combine to the strictest of them.

use crate::config::{Decision, Mode, Outcome, Status};
use serde::Serialize;

/// A workflow's thresholds, its cap, and what each decision does.
#[derive(Debug, Clone, Default)]
pub struct Bands {
    pub step_up_at: Option<i64>,
    pub review_at: Option<i64>,
    pub hold_at: Option<i64>,
    pub block_at: Option<i64>,
    pub quarantine_at: Option<i64>,
    pub max_decision: Option<Decision>,
    pub on_step_up: Outcome,
    pub on_review: Outcome,
    pub on_hold: Outcome,
    pub on_block: Outcome,
    pub on_quarantine: Outcome,
}

impl Bands {
    fn band(&self, score: i64) -> Decision {
        let reached = |at: Option<i64>| at.is_some_and(|at| score >= at);
        [
            (self.quarantine_at, Decision::Quarantine),
            (self.block_at, Decision::Block),
            (self.hold_at, Decision::Hold),
            (self.review_at, Decision::Review),
            (self.step_up_at, Decision::StepUp),
        ]
        .into_iter()
        .find(|(at, _)| reached(*at))
        .map(|(_, d)| d)
        .unwrap_or(Decision::Allow)
    }

    pub fn outcome(&self, decision: Decision) -> Option<&Outcome> {
        match decision {
            Decision::Allow => None,
            Decision::StepUp => Some(&self.on_step_up),
            Decision::Review => Some(&self.on_review),
            Decision::Hold => Some(&self.on_hold),
            Decision::Block => Some(&self.on_block),
            Decision::Quarantine => Some(&self.on_quarantine),
        }
    }
}

/// A rule whose condition was true.
#[derive(Debug, Clone, Serialize)]
pub struct Fired {
    pub id: String,
    pub score: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust: Option<u8>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<String>,
    pub reason: String,
    pub mode: Mode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hold_for: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct Verdict {
    pub decision: Decision,
    pub score: i64,
    /// The account status the decision sets, if any.
    pub status: Option<Status>,
    pub actions: Vec<String>,
    /// The trust level a rule sets, if any.
    pub trust: Option<u8>,
    /// A block or quarantine turned into a hold because the account is trusted.
    pub protected: bool,
    /// The decision with the shadow rules counted too.
    pub shadow_decision: Decision,
    /// For a hold: how long, in seconds.
    pub hold_for: Option<u64>,
}

fn push_unique(list: &mut Vec<String>, items: impl IntoIterator<Item = String>) {
    for item in items {
        if !list.contains(&item) {
            list.push(item);
        }
    }
}

/// The score and decision of a set of rules, capped, before trust protection.
fn verdict_of<'a>(bands: &Bands, rules: impl Iterator<Item = &'a Fired> + Clone) -> (i64, Decision) {
    let score: i64 = rules.clone().map(|f| f.score).sum();
    let forced = rules.clone().filter_map(|f| f.decision);
    if forced.clone().any(|d| d == Decision::Allow) {
        return (score, Decision::Allow);
    }
    let decision = forced.fold(bands.band(score), Decision::max);
    (score, bands.max_decision.map_or(decision, |cap| decision.min(cap)))
}

pub fn decide(bands: &Bands, fired: &[Fired], user_trust: u8, act_below: u8) -> Verdict {
    let acting = fired.iter().filter(|f| f.mode == Mode::Act);
    let (score, mut decision) = verdict_of(bands, acting.clone());
    let (_, shadow_decision) = verdict_of(bands, fired.iter());
    let mut protected = false;
    if decision >= Decision::Block && user_trust >= act_below {
        decision = Decision::Hold;
        protected = true;
    }
    let mut actions = Vec::new();
    for rule in acting.clone() {
        push_unique(&mut actions, rule.actions.iter().cloned());
    }
    push_unique(&mut actions, decision.implied_action().map(str::to_owned));
    let outcome = bands.outcome(decision);
    if let Some(outcome) = outcome {
        push_unique(&mut actions, outcome.actions.iter().cloned());
    }
    let status = match decision {
        Decision::Quarantine => Some(Status::Quarantined),
        _ => outcome.and_then(|o| o.status),
    };
    let hold_for = if decision == Decision::Hold {
        acting.clone().filter_map(|f| f.hold_for).max()
    } else {
        None
    };
    Verdict {
        decision,
        score,
        status,
        actions,
        trust: acting.filter_map(|f| f.trust).max(),
        protected,
        shadow_decision,
        hold_for,
    }
}

/// How strict a status is, to combine workflows.
pub fn status_rank(status: Status) -> u8 {
    match status {
        Status::Normal => 0,
        Status::Trusted => 1,
        Status::Review => 2,
        Status::Quarantined => 3,
    }
}

pub fn combine(verdicts: &[Verdict]) -> Verdict {
    let mut all = Verdict::default();
    for v in verdicts {
        all.decision = all.decision.max(v.decision);
        all.shadow_decision = all.shadow_decision.max(v.shadow_decision);
        all.score = all.score.max(v.score);
        all.protected |= v.protected;
        all.trust = all.trust.max(v.trust);
        all.hold_for = all.hold_for.max(v.hold_for);
        all.status = match (all.status, v.status) {
            (Some(a), Some(b)) => Some(if status_rank(b) > status_rank(a) { b } else { a }),
            (a, b) => a.or(b),
        };
        push_unique(&mut all.actions, v.actions.iter().cloned());
    }
    all
}
