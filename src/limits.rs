//! Progressive limits: how much of a counter an account may use, growing as
//! the account ages and earns trust.
//!
//! A brand-new account gets a small allowance and a settled one a large one,
//! without anyone asking for it: the allowance is a function of the age of
//! the account (or workspace), whether it paid, and how high it ever scored.
//! Rules read it as `limits.<name>` next to `counters.<name>`; the answer
//! reports it so an application can show what is left.

use crate::config::LimitSpec;

/// Whose age, trust and score set the allowance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LimitSubject {
    /// The account that acts.
    #[default]
    Actor,
    /// The workspace, team or store it acts on.
    Tenant,
}

/// A limit ready to evaluate.
#[derive(Debug, Clone)]
pub struct Limit {
    pub name: String,
    /// The counter whose value the allowance bounds.
    pub counter: String,
    pub subject: LimitSubject,
    /// The allowance of a brand-new subject.
    pub base: u64,
    /// `(age in seconds, allowance)`, ages ascending, allowances never shrinking.
    pub steps: Vec<(u64, u64)>,
    pub trusted_factor: f64,
    pub risky_above: Option<i64>,
    pub risky_factor: f64,
    /// Refuse what goes over the allowance, or only report it.
    pub mode: crate::config::Mode,
    pub enabled: bool,
}

impl Limit {
    /// The allowance for a subject of this age, trusted or not, whose highest
    /// score so far is `max_score`. Rounded up, so a cut never reaches zero
    /// unless the base is zero or the factor is.
    pub fn allowance(&self, age: u64, trusted: bool, max_score: i64) -> u64 {
        let step = self
            .steps
            .iter()
            .rev()
            .find(|(from, _)| age >= *from)
            .map_or(self.base, |(_, max)| *max);
        let mut factor = 1.0_f64;
        if trusted {
            factor *= self.trusted_factor;
        }
        if self.risky_above.is_some_and(|above| max_score >= above) {
            factor *= self.risky_factor;
        }
        (step as f64 * factor).ceil() as u64
    }
}

/// What an answer says of one limit for the event's account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Reading {
    /// The allowance now.
    pub max: u64,
    /// The counter's value, this event included.
    pub used: u64,
}

/// The problems of a limit's definition, with the steps in seconds when it is
/// sound.
pub fn compile(name: &str, spec: &LimitSpec, counter_known: bool, counter_off: bool, problems: &mut Vec<String>) -> Option<Limit> {
    let here = format!("limit `{name}`");
    let before = problems.len();
    if !crate::config::valid_name(name) {
        problems.push(format!("{here}: a name is lowercase letters, digits and _"));
    }
    if counter_off {
        problems.push(format!(
            "{here}: the counter `{}` is switched off (`enabled = false`)",
            spec.counter
        ));
    } else if !counter_known {
        problems.push(format!("{here}: there is no counter `{}`", spec.counter));
    }
    let mut steps: Vec<(u64, u64)> = Vec::new();
    for step in &spec.steps {
        match crate::window::parse_duration(&step.age) {
            Ok(age) => {
                if steps.last().is_some_and(|(prev, _)| age <= *prev) {
                    problems.push(format!("{here}: the steps must be in ascending order of age, each age once"));
                }
                if steps.last().is_some_and(|(_, prev)| step.max < *prev) || step.max < spec.base {
                    problems.push(format!("{here}: the allowance must never shrink as the account ages"));
                }
                steps.push((age, step.max));
            }
            Err(_) => problems.push(format!("{here}: step age `{}` is not a duration such as 12h or 7d", step.age)),
        }
    }
    if !(spec.trusted_factor.is_finite() && (1.0..=1000.0).contains(&spec.trusted_factor)) {
        problems.push(format!("{here}: trusted_factor is between 1 and 1000"));
    }
    if !(spec.risky_factor.is_finite() && (0.0..=1.0).contains(&spec.risky_factor)) {
        problems.push(format!("{here}: risky_factor is between 0 and 1"));
    }
    (problems.len() == before).then(|| Limit {
        name: name.to_owned(),
        counter: spec.counter.clone(),
        subject: spec.subject,
        base: spec.base,
        steps,
        trusted_factor: spec.trusted_factor,
        risky_above: spec.risky_above,
        risky_factor: spec.risky_factor,
        mode: spec.mode,
        enabled: spec.enabled,
    })
}
