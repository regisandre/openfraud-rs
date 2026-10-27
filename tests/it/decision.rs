//! How the rules that fired become a decision: scores add up to a band,
//! a forced decision wins over the band, an allow rule wins over all,
//! shadow rules change nothing, a workflow can cap its decision, and a
//! trusted account is never blocked or quarantined automatically.
#![allow(clippy::type_complexity)]

use openfraud::config::{Decision, Mode, Outcome, Status};
use openfraud::decision::{Bands, Fired, combine, decide};

fn fired(id: &str, score: i64, decision: Option<Decision>, mode: Mode) -> Fired {
    Fired {
        id: id.into(),
        score,
        decision,
        trust: None,
        actions: vec![],
        reason: format!("{id} reason"),
        mode,
        hold_for: None,
    }
}

fn bands() -> Bands {
    Bands {
        step_up_at: Some(20),
        review_at: Some(40),
        hold_at: Some(60),
        block_at: Some(80),
        quarantine_at: Some(100),
        on_review: Outcome {
            status: Some(Status::Review),
            actions: vec!["suspend_feature:email".into()],
        },
        ..Bands::default()
    }
}

#[test]
fn fired_rules_become_a_decision() {
    use Decision::*;
    use Mode::*;
    // (case, fired rules, user trust, max decision, decision, score, status, actions, protected, shadow decision)
    let cases: Vec<(
        &str,
        Vec<Fired>,
        u8,
        Option<Decision>,
        Decision,
        i64,
        Option<Status>,
        Vec<&str>,
        bool,
        Decision,
    )> = vec![
        ("nothing fired", vec![], 0, None, Allow, 0, None, vec![], false, Allow),
        (
            "under every band",
            vec![fired("a", 10, None, Act)],
            0,
            None,
            Allow,
            10,
            None,
            vec![],
            false,
            Allow,
        ),
        (
            "step up band",
            vec![fired("a", 25, None, Act)],
            0,
            None,
            StepUp,
            25,
            None,
            vec!["step_up"],
            false,
            StepUp,
        ),
        (
            "review band, with the workflow's actions",
            vec![fired("a", 45, None, Act)],
            0,
            None,
            Review,
            45,
            Some(Status::Review),
            vec!["review", "suspend_feature:email"],
            false,
            Review,
        ),
        (
            "hold band",
            vec![fired("a", 30, None, Act), fired("b", 35, None, Act)],
            0,
            None,
            Hold,
            65,
            None,
            vec!["hold"],
            false,
            Hold,
        ),
        (
            "block band: refusing is the action",
            vec![fired("a", 85, None, Act)],
            0,
            None,
            Block,
            85,
            None,
            vec![],
            false,
            Block,
        ),
        (
            "quarantine band",
            vec![fired("a", 70, None, Act), fired("b", 70, None, Act)],
            0,
            None,
            Quarantine,
            140,
            Some(Status::Quarantined),
            vec!["quarantine"],
            false,
            Quarantine,
        ),
        (
            "a negative score lowers the total",
            vec![fired("a", 70, None, Act), fired("b", -30, None, Act)],
            0,
            None,
            Review,
            40,
            Some(Status::Review),
            vec!["review", "suspend_feature:email"],
            false,
            Review,
        ),
        (
            "a forced quarantine wins over a low score",
            vec![fired("a", 5, Some(Quarantine), Act)],
            0,
            None,
            Quarantine,
            5,
            Some(Status::Quarantined),
            vec!["quarantine"],
            false,
            Quarantine,
        ),
        (
            "a forced allow wins over everything",
            vec![fired("a", 200, Some(Quarantine), Act), fired("ok", 0, Some(Allow), Act)],
            0,
            None,
            Allow,
            200,
            None,
            vec![],
            false,
            Allow,
        ),
        (
            "a shadow rule changes nothing but is reported",
            vec![fired("a", 10, None, Act), fired("s", 90, None, Shadow)],
            0,
            None,
            Allow,
            10,
            None,
            vec![],
            false,
            Quarantine,
        ),
        (
            "a workflow capped at hold never blocks",
            vec![fired("a", 150, None, Act)],
            0,
            Some(Hold),
            Hold,
            150,
            None,
            vec!["hold"],
            false,
            Hold,
        ),
        (
            "a trusted account is held, not quarantined",
            vec![fired("a", 150, None, Act)],
            1,
            None,
            Hold,
            150,
            None,
            vec!["hold"],
            true,
            Quarantine,
        ),
        (
            "a forced block on a trusted account is held",
            vec![fired("a", 0, Some(Block), Act)],
            3,
            None,
            Hold,
            0,
            None,
            vec!["hold"],
            true,
            Block,
        ),
    ];
    let mut failures = Vec::new();
    for (case, fired, trust, cap, want, score, status, actions, protected, shadow) in cases {
        let mut b = bands();
        b.max_decision = cap;
        let v = decide(&b, &fired, trust, 1);
        let actions: Vec<String> = actions.into_iter().map(String::from).collect();
        let got = (v.decision, v.score, v.status, v.actions.clone(), v.protected, v.shadow_decision);
        let wanted = (want, score, status, actions, protected, shadow);
        if got != wanted {
            failures.push(format!("{case}: got {got:?}, want {wanted:?}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_rule_adds_its_own_actions_trust_and_hold_time() {
    let mut a = fired("paid", 0, None, Mode::Act);
    a.trust = Some(1);
    let mut b = fired("tag", 10, None, Mode::Act);
    b.actions = vec!["limit:contacts".into(), "limit:contacts".into()];
    let mut s = fired("shadow_trust", 0, None, Mode::Shadow);
    s.trust = Some(5);
    let mut h = fired("hold_payout", 0, Some(Decision::Hold), Mode::Act);
    h.hold_for = Some(7 * 86_400);
    let v = decide(&bands(), &[a, b, s, h], 0, 1);
    assert_eq!(v.trust, Some(1), "the act rule's trust applies, the shadow rule's does not");
    assert_eq!(
        v.actions,
        vec!["limit:contacts".to_owned(), "hold".to_owned()],
        "rule actions once each, then the decision's"
    );
    assert_eq!(
        (v.decision, v.hold_for),
        (Decision::Hold, Some(7 * 86_400)),
        "a hold can carry its length"
    );
}

#[test]
fn workflows_combine_to_the_strictest() {
    let review = decide(&bands(), &[fired("a", 45, None, Mode::Act)], 0, 1);
    let quarantine = decide(&bands(), &[fired("b", 120, None, Mode::Act)], 0, 1);
    let mut trust = decide(&bands(), &[], 0, 1);
    trust.trust = Some(1);
    let all = combine(&[review, quarantine, trust]);
    assert_eq!(all.decision, Decision::Quarantine, "the strictest decision");
    assert_eq!(all.score, 120, "the highest score");
    assert_eq!(all.status, Some(Status::Quarantined), "the strictest status");
    assert_eq!(all.trust, Some(1), "a trust change survives");
    assert_eq!(
        all.actions,
        vec!["review".to_owned(), "suspend_feature:email".to_owned(), "quarantine".to_owned()]
    );
    assert_eq!(combine(&[]).decision, Decision::Allow, "no workflow allows");
}
