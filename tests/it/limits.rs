//! Progressive limits: an allowance that grows with the age of an account,
//! is larger for a paying one and shrinks for a risky one, read by rules as
//! `limits.<name>` and reported in every answer.
// Case tables are tuples on purpose: one row per case, read at a glance.
#![allow(clippy::type_complexity)]

use openfraud::config::{Config, Decision};
use openfraud::engine::{Engine, Options, Outcome};
use openfraud::event::RawEvent;
use serde_json::{Value, json};
use std::path::Path;

const DAY: u64 = 86_400;
const T0: u64 = 1_790_000_000;

const CONFIG: &str = r#"
[safety]
require_replay = false

[counters.sends_1d]
events = ["message.send_requested"]
by = "actor"
window = "1d"

[counters.crew_sends_1d]
events = ["message.send_requested"]
by = "tenant"
window = "1d"

[limits.sends]
counter = "sends_1d"
base = 2
trusted_factor = 5
risky_above = 50
risky_factor = 0.5
steps = [
  { age = "1d", max = 5 },
  { age = "7d", max = 20 },
  { age = "30d", max = 100 },
]

[limits.crew_sends]
counter = "crew_sends_1d"
subject = "tenant"
base = 3
steps = [{ age = "7d", max = 30 }]

[workflows.sending]
events = ["message.send_requested"]

[[workflows.sending.rules]]
id = "send_over_limit"
when = "counters.sends_1d > limits.sends"
decision = "block"
reason = "More sends today than this account may make yet"

[[workflows.sending.rules]]
id = "crew_over_limit"
when = "counters.crew_sends_1d > limits.crew_sends"
decision = "block"
reason = "More sends today than this workspace may make yet"

[workflows.flagging]
events = ["account.updated"]
review_at = 50

[[workflows.flagging.rules]]
id = "flag_me"
when = "true"
score = 60
reason = "A test account that scores high"
"#;

fn engine_with(text: &str) -> Engine {
    let config = Config::parse(text, Path::new(".")).unwrap();
    Engine::open(config, b"limits-test-key-limits-test-key!!".to_vec(), None).unwrap()
}

fn ev(value: Value) -> RawEvent {
    serde_json::from_value(value).unwrap()
}

fn send(engine: &Engine, value: Value) -> Outcome {
    engine.process(ev(value), Options::default()).unwrap()
}

/// `n` sends one second apart by `actor`, created `age` seconds before the
/// first one; the outcome of the last.
fn sends(engine: &Engine, actor: &str, age: u64, n: u64) -> Outcome {
    let mut last = None;
    for i in 0..n {
        last = Some(send(
            engine,
            json!({
                "id": format!("{actor}-{i}"), "type": "message.send_requested", "actor_id": actor,
                "actor_created_at": T0 - age, "at": T0 + i,
            }),
        ));
    }
    last.unwrap()
}

#[test]
fn the_allowance_follows_age_trust_and_risk() {
    let compiled = Config::parse(CONFIG, Path::new(".")).unwrap().compile().unwrap();
    let limit = compiled.limits.iter().find(|l| l.name == "sends").unwrap();
    // (case, age in seconds, trusted, max score, allowance)
    let cases: Vec<(&str, u64, bool, i64, u64)> = vec![
        ("a new account", 0, false, 0, 2),
        ("a second before the first step", DAY - 1, false, 0, 2),
        ("the first step starts at its age", DAY, false, 0, 5),
        ("between two steps", 6 * DAY, false, 0, 5),
        ("the second step", 7 * DAY, false, 0, 20),
        ("the last step holds for good", 400 * DAY, false, 0, 100),
        ("a paying account multiplies the base", 0, true, 0, 10),
        ("a paying account multiplies a step", 7 * DAY, true, 0, 100),
        ("a risky account below its first step is cut, never to zero", 0, false, 50, 1),
        ("a risky account on a step", 7 * DAY, false, 50, 10),
        ("just under the risk score", 7 * DAY, false, 49, 20),
        ("trust and risk together", 7 * DAY, true, 80, 50),
    ];
    let mut failures = Vec::new();
    for (case, age, trusted, score, want) in cases {
        let got = limit.allowance(age, trusted, score);
        if got != want {
            failures.push(format!("{case}: got {got}, want {want}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn a_new_account_is_cut_off_sooner_than_an_old_one() {
    let e = engine_with(CONFIG);
    // (case, actor, age, sends, decision of the last send, allowance, used)
    let cases: Vec<(&str, &str, u64, u64, Decision, i64, i64)> = vec![
        ("a new account may send twice", "a-new", 0, 2, Decision::Allow, 2, 2),
        ("and not a third time", "b-new", 0, 3, Decision::Block, 2, 3),
        ("a day-old account may send five times", "c-day", DAY, 5, Decision::Allow, 5, 5),
        ("and not a sixth", "d-day", DAY, 6, Decision::Block, 5, 6),
        (
            "a month-old account sends a hundred",
            "e-old",
            30 * DAY,
            100,
            Decision::Allow,
            100,
            100,
        ),
    ];
    let mut failures = Vec::new();
    for (case, actor, age, n, decision, allowance, used) in cases {
        let out = sends(&e, actor, age, n);
        let reading = out.limits.get("sends");
        if out.decision != decision || reading.map(|r| (r.max as i64, r.used as i64)) != Some((allowance, used)) {
            failures.push(format!("{case}: {:?} {:?} {:?}", out.decision, reading, out.rules));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn a_paying_account_gets_more_room_and_a_risky_one_less() {
    let e = engine_with(CONFIG);
    send(
        &e,
        json!({"type": "subscription.invoice_paid", "actor_id": "payer", "actor_created_at": T0}),
    );
    let paying = sends(&e, "payer", 0, 3);
    assert_eq!(paying.limits["sends"].max, 10, "a paying account has five times the base");
    assert_eq!(paying.decision, Decision::Allow, "{:?}", paying.rules);

    send(
        &e,
        json!({"type": "account.updated", "actor_id": "shady", "actor_created_at": T0 - 7 * DAY, "at": T0 - 5}),
    );
    let risky = sends(&e, "shady", 7 * DAY, 11);
    assert_eq!(risky.limits["sends"].max, 10, "a risky account has half of its step");
    assert_eq!(risky.decision, Decision::Block, "{:?}", risky.rules);
}

#[test]
fn a_workspace_limit_grows_with_the_age_of_the_workspace() {
    let e = engine_with(CONFIG);
    let from = |tenant: &str, actor: &str, at: u64, id: &str| {
        send(
            &e,
            json!({
                "id": id, "type": "message.send_requested", "actor_id": actor, "tenant_id": tenant,
                "actor_created_at": T0 - 400 * DAY, "at": at,
            }),
        )
    };
    // A workspace first seen now: three sends, however old the accounts of its members are.
    from("crew-new", "m1", T0, "n0");
    from("crew-new", "m2", T0 + 1, "n1");
    let third = from("crew-new", "m3", T0 + 2, "n2");
    let fourth = from("crew-new", "m4", T0 + 3, "n3");
    assert_eq!(third.limits["crew_sends"].max, 3);
    assert_eq!(third.decision, Decision::Allow, "{:?}", third.rules);
    assert_eq!(fourth.decision, Decision::Block, "{:?}", fourth.rules);

    // A workspace seen ten days ago may send thirty.
    from("crew-old", "m1", T0 - 10 * DAY, "o-first");
    let old = from("crew-old", "m1", T0, "o0");
    assert_eq!(old.limits["crew_sends"].max, 30);
}

#[test]
fn only_the_limits_of_the_counted_event_are_reported() {
    let e = engine_with(CONFIG);
    let out = send(&e, json!({"type": "account.updated", "actor_id": "quiet"}));
    assert!(out.limits.is_empty(), "{:?}", out.limits);
}

#[test]
fn a_limit_that_cannot_work_is_refused_when_the_configuration_loads() {
    let counter = "[counters.c]\nevents = [\"message.send_requested\"]\nby = \"actor\"\nwindow = \"1d\"\n";
    // (case, limit table, text the problem must contain)
    let cases: Vec<(&str, &str, &str)> = vec![
        ("no such counter", "[limits.l]\ncounter = \"nope\"\nbase = 1\n", "no counter `nope`"),
        (
            "a counter that is switched off",
            "[counters.off]\nevents = [\"message.send_requested\"]\nby = \"actor\"\nwindow = \"1d\"\nenabled = false\n[limits.l]\ncounter = \"off\"\nbase = 1\n",
            "switched off",
        ),
        (
            "steps out of order",
            "[limits.l]\ncounter = \"c\"\nbase = 1\nsteps = [{ age = \"7d\", max = 5 }, { age = \"1d\", max = 9 }]\n",
            "ascending",
        ),
        (
            "two steps at one age",
            "[limits.l]\ncounter = \"c\"\nbase = 1\nsteps = [{ age = \"1d\", max = 5 }, { age = \"24h\", max = 9 }]\n",
            "ascending",
        ),
        (
            "an allowance that shrinks with age",
            "[limits.l]\ncounter = \"c\"\nbase = 5\nsteps = [{ age = \"1d\", max = 2 }]\n",
            "never shrink",
        ),
        (
            "a step age that is not a duration",
            "[limits.l]\ncounter = \"c\"\nbase = 1\nsteps = [{ age = \"soon\", max = 5 }]\n",
            "not a duration",
        ),
        (
            "a trusted factor under one",
            "[limits.l]\ncounter = \"c\"\nbase = 1\ntrusted_factor = 0.5\n",
            "trusted_factor",
        ),
        (
            "a risky factor over one",
            "[limits.l]\ncounter = \"c\"\nbase = 1\nrisky_above = 50\nrisky_factor = 2\n",
            "risky_factor",
        ),
        ("a bad name", "[limits.BadName]\ncounter = \"c\"\nbase = 1\n", "lowercase"),
        (
            "a rule that reads a limit that does not exist",
            "[limits.l]\ncounter = \"c\"\nbase = 1\n[workflows.w]\nevents = [\"message.send_requested\"]\n[[workflows.w.rules]]\nid = \"r\"\nwhen = \"counters.c > limits.ghost\"\nscore = 1\nreason = \"x\"\n",
            "no limit `ghost`",
        ),
    ];
    let mut failures = Vec::new();
    for (case, limit, expect) in cases {
        let text = format!("{counter}{limit}");
        match Config::parse(&text, Path::new(".")).unwrap().compile() {
            Ok(_) => failures.push(format!("{case}: accepted")),
            Err(problems) if !problems.join("; ").contains(expect) => failures.push(format!("{case}: {problems:?}")),
            Err(_) => {}
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

const ENFORCED: &str = r#"
[safety]
require_replay = false

[counters.sends_1d]
events = ["message.send_requested"]
by = "actor"
window = "1d"

[limits.sends]
counter = "sends_1d"
base = 2
mode = "act"
steps = [{ age = "30d", max = 100 }]
"#;

#[test]
fn an_acting_limit_refuses_softly_and_a_refused_attempt_uses_none_of_the_allowance() {
    let e = engine_with(ENFORCED);
    let at = |i: u64| {
        send(
            &e,
            json!({"id": format!("s{i}"), "type": "message.send_requested", "actor_id": "u", "at": T0 + i}),
        )
    };
    let first = at(0);
    let second = at(1);
    let refused: Vec<Outcome> = (2..22).map(at).collect();
    // A day later the first two have left the window; the twenty refused did not use it.
    let later = send(
        &e,
        json!({"id": "later", "type": "message.send_requested", "actor_id": "u", "at": T0 + DAY + 1_000}),
    );
    for (case, out) in [("first", &first), ("second", &second)] {
        assert_eq!(out.decision, Decision::Allow, "{case}: {:?}", out.rules);
    }
    for (i, out) in refused.iter().enumerate() {
        assert_eq!(out.decision, Decision::Block, "refused {i}: {:?}", out.rules);
        assert!(out.rules.iter().any(|r| r.id == "limit_sends"), "refused {i}: {:?}", out.rules);
        assert!(
            out.repeat,
            "refused {i}: a limit is not a restriction: no statement, not counted by the brake"
        );
        assert!(out.statement_id.is_none() && out.case_id.is_none(), "refused {i}");
    }
    assert_eq!(later.decision, Decision::Allow, "{:?} {:?}", later.rules, later.limits);
    assert_eq!(later.limits["sends"].used, 1, "only the allowed sends were counted");
}

#[test]
fn a_limit_in_shadow_reports_what_it_would_refuse_and_an_override_turns_it_on() {
    let shadow = ENFORCED.replace("mode = \"act\"", "mode = \"shadow\"");
    let overridden = format!("{shadow}\n[limit_overrides.sends]\nmode = \"act\"\n");
    let off = format!("{ENFORCED}\n[limit_overrides.sends]\nenabled = false\n");
    // (case, configuration, decision of the third send, a limit_sends result in the rules, its mode)
    let cases: Vec<(&str, String, Decision, bool, &str)> = vec![
        ("shadow", shadow, Decision::Allow, true, "Shadow"),
        ("shadow turned on by an override", overridden, Decision::Block, true, "Act"),
        ("switched off by an override", off, Decision::Allow, false, ""),
    ];
    let mut failures = Vec::new();
    for (case, config, decision, listed, mode) in cases {
        let e = engine_with(&config);
        let out = sends(&e, "u", 0, 3);
        let rule = out.rules.iter().find(|r| r.id == "limit_sends");
        let got_mode = rule.map(|r| format!("{:?}", r.mode)).unwrap_or_default();
        if out.decision != decision || rule.is_some() != listed || got_mode != mode {
            failures.push(format!("{case}: {:?} {:?}", out.decision, out.rules));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn an_override_of_a_limit_that_does_not_exist_is_refused() {
    let text = format!("{ENFORCED}\n[limit_overrides.ghost]\nmode = \"act\"\n");
    let problems = Config::parse(&text, Path::new(".")).unwrap().compile().unwrap_err();
    assert!(problems.join("; ").contains("no limit `ghost`"), "{problems:?}");
}
