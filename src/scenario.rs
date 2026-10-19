//! Scenarios: a file of events and the answers they must get, run on a
//! fresh in-memory engine. They test a rule set the way a unit test tests
//! code: `openfraud simulate` runs one, and the repository's own scenarios
//! (examples/scenarios) run in its test suite.
//!
//! One JSON object per line: `{"event": {...}, "expect": {...}}`. `expect`
//! is optional and may hold:
//! - `decision`: the decision the acting rules give;
//! - `would`: the decision with the shadow rules counted too;
//! - `status`, `tenant_status`: the actor's and the tenant's status after;
//! - `rules`: ids that must fire and act; `shadow_rules`: ids that must fire
//!   in shadow; `not_rules`: ids that must not fire at all;
//! - `actions`: actions that must be asked, `quarantine` for the actor or
//!   `tenant:review` for the tenant;
//! - `case`, `tenant_case`: whether a case is opened (or updated).
//!
//! Lines starting with `#` are comments, except these directives:
//! - `# packs: messaging, card-and-payments` turns packs on (before the
//!   first event only);
//! - `# enforce` makes every rule act and skips the replay approval, to test
//!   what a pack would do once switched on (before the first event only);
//! - `# list: <name> <item>` adds an item to a list;
//! - `# label: <actor> fraud|legit|false_positive` records a person's verdict.

use crate::config::{Config, Decision, Mode, Status};
use crate::engine::{Engine, Label, Options, Outcome};
use crate::event::{RawEvent, parse_time};
use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expect {
    #[serde(default)]
    pub decision: Option<Decision>,
    #[serde(default)]
    pub would: Option<Decision>,
    #[serde(default)]
    pub status: Option<Status>,
    #[serde(default)]
    pub tenant_status: Option<Status>,
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(default)]
    pub shadow_rules: Vec<String>,
    #[serde(default)]
    pub not_rules: Vec<String>,
    #[serde(default)]
    pub actions: Vec<String>,
    #[serde(default)]
    pub case: Option<bool>,
    #[serde(default)]
    pub tenant_case: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Line {
    event: RawEvent,
    #[serde(default)]
    expect: Option<Expect>,
}

#[derive(Debug)]
pub struct Step {
    pub line: usize,
    pub outcome: Outcome,
    pub problems: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Report {
    pub steps: Vec<Step>,
}

impl Report {
    pub fn mismatches(&self) -> Vec<String> {
        self.steps
            .iter()
            .flat_map(|s| s.problems.iter().map(move |p| format!("line {} ({}): {p}", s.line, s.outcome.kind)))
            .collect()
    }
}

fn check(expect: &Expect, outcome: &Outcome) -> Vec<String> {
    let mut problems = Vec::new();
    let acting: Vec<&str> = outcome
        .rules
        .iter()
        .filter(|r| r.mode == Mode::Act)
        .map(|r| r.id.as_str())
        .collect();
    let shadow: Vec<&str> = outcome
        .rules
        .iter()
        .filter(|r| r.mode == Mode::Shadow)
        .map(|r| r.id.as_str())
        .collect();
    if let Some(want) = expect.decision
        && want != outcome.decision
    {
        problems.push(format!(
            "decision {} (score {}, acting {acting:?}), expected {}",
            outcome.decision.as_str(),
            outcome.score,
            want.as_str()
        ));
    }
    if let Some(want) = expect.would
        && want != outcome.shadow_decision
    {
        problems.push(format!(
            "would decide {} (shadow {shadow:?}, acting {acting:?}), expected {}",
            outcome.shadow_decision.as_str(),
            want.as_str()
        ));
    }
    for (what, want, got) in [
        ("status", expect.status, outcome.actor.as_ref().map(|u| u.status)),
        ("tenant status", expect.tenant_status, outcome.tenant.as_ref().map(|u| u.status)),
    ] {
        if let Some(want) = want
            && got != Some(want)
        {
            problems.push(format!("{what} {:?}, expected {}", got.map(|s| s.as_str()), want.as_str()));
        }
    }
    for rule in &expect.rules {
        if !acting.contains(&rule.as_str()) {
            problems.push(format!("rule {rule} did not act (acting {acting:?}, shadow {shadow:?})"));
        }
    }
    for rule in &expect.shadow_rules {
        if !shadow.contains(&rule.as_str()) {
            problems.push(format!("rule {rule} did not fire in shadow (acting {acting:?}, shadow {shadow:?})"));
        }
    }
    for rule in &expect.not_rules {
        if acting.contains(&rule.as_str()) || shadow.contains(&rule.as_str()) {
            problems.push(format!("rule {rule} fired"));
        }
    }
    let asked: Vec<String> = outcome
        .actions
        .iter()
        .map(|a| {
            if a.target == "actor" {
                a.action.clone()
            } else {
                format!("{}:{}", a.target, a.action)
            }
        })
        .collect();
    for action in &expect.actions {
        if !asked.contains(action) {
            problems.push(format!("action {action} not asked (asked {asked:?})"));
        }
    }
    for (what, want, got) in [
        ("case", expect.case, outcome.case_id),
        ("tenant case", expect.tenant_case, outcome.tenant_case_id),
    ] {
        if let Some(want) = want
            && want != got.is_some()
        {
            problems.push(format!("{what}: {got:?}, expected {}", if want { "one" } else { "none" }));
        }
    }
    for error in &outcome.errors {
        problems.push(format!("rule {} could not be decided: {}", error.rule, error.error));
    }
    problems
}

/// Every rule asked to act, without waiting for a replay.
fn enforce(config: &mut Config) -> Result<()> {
    let assembled = config
        .assemble()
        .map_err(|p| anyhow!("the configuration is not valid: {}", p.join("; ")))?;
    config.safety.require_replay = false;
    for wf in assembled.workflows.values() {
        for rule in &wf.rules {
            config.overrides.entry(rule.id.clone()).or_default().mode = Some(Mode::Act);
        }
    }
    Ok(())
}

/// Runs the scenario in `text` on a fresh engine with `config`.
pub fn run_scenario(mut config: Config, text: &str) -> Result<Report> {
    let mut lines = text.lines().enumerate().peekable();
    let mut enforced = false;
    // Directives that shape the engine come before the first event; the
    // others are kept to run once the engine is open.
    let mut early = Vec::new();
    while let Some((n, line)) = lines.peek() {
        let line = line.trim();
        if line.starts_with("# list:") || line.starts_with("# label:") {
            early.push((*n, line.to_owned()));
        } else if let Some(packs) = line.strip_prefix("# packs:") {
            for pack in packs.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                if !config.packs.iter().any(|p| p == pack) {
                    config.packs.push(pack.to_owned());
                }
            }
        } else if line == "# enforce" {
            enforced = true;
        } else if !(line.is_empty() || line.starts_with('#')) {
            break;
        }
        lines.next();
    }
    if enforced {
        enforce(&mut config)?;
    }
    let engine = Engine::open(config, b"openfraud-scenario-pseudonym-key".to_vec(), None)?;
    let mut report = Report::default();
    let mut clock = 0;
    let rest = lines.map(|(n, l)| (n, l.to_owned()));
    for (n, raw_line) in early.into_iter().chain(rest) {
        let trimmed = raw_line.trim();
        if let Some(rest) = trimmed.strip_prefix("# list:") {
            let (list, item) = rest
                .trim()
                .split_once(' ')
                .with_context(|| format!("line {}: `# list: <name> <item>`", n + 1))?;
            engine.add_list_item(list, item.trim(), "scenario", "")?;
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("# label:") {
            let (actor, label) = rest
                .trim()
                .split_once(' ')
                .with_context(|| format!("line {}: `# label: <actor> <label>`", n + 1))?;
            let label = Label::parse(label.trim()).with_context(|| format!("line {}: `{label}` is not a label", n + 1))?;
            engine.label(actor, label, "scenario", "")?;
            continue;
        }
        if trimmed.starts_with("# packs:") || trimmed == "# enforce" {
            bail!("line {}: `{trimmed}` must come before the first event", n + 1);
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let line: Line = serde_json::from_str(trimmed).with_context(|| format!("line {}: not a scenario line", n + 1))?;
        if let Some(at) = &line.event.at {
            clock = parse_time(at)
                .map_err(anyhow::Error::msg)
                .with_context(|| format!("line {}", n + 1))?;
        }
        let outcome = engine
            .process(
                line.event,
                Options {
                    dry_run: false,
                    now: Some(clock),
                },
            )
            .map_err(|e| anyhow!("line {}: {e}", n + 1))?;
        let problems = line.expect.as_ref().map(|e| check(e, &outcome)).unwrap_or_default();
        report.steps.push(Step {
            line: n + 1,
            outcome,
            problems,
        });
    }
    Ok(report)
}
