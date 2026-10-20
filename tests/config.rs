//! The configuration file: what `openfraud validate` accepts, and the words
//! it uses when it refuses.
#![allow(clippy::type_complexity)]

use openfraud::config::{Config, DEFAULT_CONFIG};
use std::path::Path;

fn problems(text: &str) -> Vec<String> {
    match Config::parse(text, Path::new(".")) {
        Err(e) => vec![format!("{e:#}")],
        Ok(config) => config.compile().err().unwrap_or_default(),
    }
}

#[test]
fn a_counter_longer_than_retention_is_warned_about() {
    // (case, configuration, warned)
    let cases = [
        (
            "a window inside retention",
            "[server]\nretention_days = 90\n[counters.c]\nevents = [\"account.created\"]\nby = \"ip\"\nwindow = \"30d\"\n",
            false,
        ),
        (
            "a year with 90 days kept",
            "[server]\nretention_days = 90\n[counters.c]\nevents = [\"account.created\"]\nby = \"ip\"\nwindow = \"365d\"\n",
            true,
        ),
        ("a pack counter counts too", "packs = [\"free-tier-and-trial\"]\n", true),
        (
            "retention off",
            "packs = [\"free-tier-and-trial\"]\n[server]\nretention_days = 0\n",
            false,
        ),
    ];
    for (case, text, warned) in cases {
        let warnings = Config::parse(text, Path::new(".")).unwrap().warnings();
        assert_eq!(!warnings.is_empty(), warned, "{case}: {warnings:?}");
        assert!(warnings.iter().all(|w| w.contains("retention_days")), "{case}: {warnings:?}");
    }
}

#[test]
fn the_shipped_configuration_is_valid() {
    let found = problems(DEFAULT_CONFIG);
    assert!(found.is_empty(), "{found:#?}");
}

#[test]
fn a_mistake_in_the_configuration_is_named() {
    let base = r#"
[counters.signups_per_ip_1h]
events = ["account.created"]
by = "ip"
distinct = "user"
window = "1h"

[lists.disposable]
kind = "domain"
items = ["mailinator.com"]
"#;
    // (case, extra configuration, words in a problem; "" when valid)
    let cases: Vec<(&str, &str, &str)> = vec![
        (
            "a valid workflow",
            r#"
[workflows.signup]
events = ["account.created"]
review_at = 50
block_at = 80
[[workflows.signup.rules]]
id = "burst"
when = "counters.signups_per_ip_1h > 3"
score = 60
reason = "Many accounts from one IP"
"#,
            "",
        ),
        (
            "a counter that counts events from an IP list",
            "[lists.hosts]\nkind = \"ip\"\n[counters.c]\nevents = [\"account.created\"]\nby = \"ip_asn\"\nwindow = \"1h\"\nwhen = '\"hosts\" in event.ip_lists'\n",
            "",
        ),
        (
            "a counter that names an IP list that does not exist",
            "[counters.c]\nevents = [\"account.created\"]\nby = \"ip\"\nwindow = \"1h\"\nwhen = '\"nope\" in event.ip_lists'\n",
            "nope",
        ),
        (
            "a counter that calls a list function",
            "[counters.c]\nevents = [\"account.created\"]\nby = \"ip\"\nwindow = \"1h\"\nwhen = 'in_list(\"disposable\", event.email_domain)'\n",
            "in_list",
        ),
        (
            "an unknown key",
            "[workflows.signup]\nevents = [\"account.created\"]\nblock_after = 3\n",
            "block_after",
        ),
        (
            "a bad event type",
            "[workflows.signup]\nevents = [\"Account Created\"]\n",
            "Account Created",
        ),
        (
            "a workflow without events",
            "[workflows.signup]\nevents = []\n",
            "at least one event",
        ),
        (
            "review above block",
            "[workflows.signup]\nevents = [\"account.updated\"]\nreview_at = 90\nblock_at = 80\n",
            "review_at",
        ),
        (
            "a rule that does nothing",
            "[workflows.w]\nevents = [\"account.updated\"]\n[[workflows.w.rules]]\nid = \"r\"\nwhen = \"true\"\nreason = \"x\"\n",
            "does nothing",
        ),
        (
            "a rule without a reason",
            "[workflows.w]\nevents = [\"account.updated\"]\n[[workflows.w.rules]]\nid = \"r\"\nwhen = \"true\"\nscore = 5\n",
            "reason",
        ),
        (
            "a rule with a bad condition",
            "[workflows.w]\nevents = [\"account.updated\"]\n[[workflows.w.rules]]\nid = \"r\"\nwhen = \"counters.nope > 1\"\nscore = 5\nreason = \"x\"\n",
            "nope",
        ),
        (
            "two rules with one id",
            "[workflows.w]\nevents = [\"account.updated\"]\n[[workflows.w.rules]]\nid = \"r\"\nwhen = \"true\"\nscore = 5\nreason = \"x\"\n[[workflows.w.rules]]\nid = \"r\"\nwhen = \"true\"\nscore = 5\nreason = \"y\"\n",
            "twice",
        ),
        (
            "a bad rule id",
            "[workflows.w]\nevents = [\"account.updated\"]\n[[workflows.w.rules]]\nid = \"Bad Id\"\nwhen = \"true\"\nscore = 5\nreason = \"x\"\n",
            "Bad Id",
        ),
        (
            "an unknown decision",
            "[workflows.w]\nevents = [\"account.updated\"]\n[[workflows.w.rules]]\nid = \"r\"\nwhen = \"true\"\ndecision = \"ban\"\nreason = \"x\"\n",
            "ban",
        ),
        (
            "a throttle with a duration and a session revocation",
            "[workflows.w]
events = [\"account.updated\"]
[[workflows.w.rules]]
id = \"r\"
when = \"true\"
actions = [\"throttle:15m\", \"revoke_sessions\"]
reason = \"x\"
",
            "",
        ),
        (
            "a throttle without a duration",
            "[workflows.w]
events = [\"account.updated\"]
[[workflows.w.rules]]
id = \"r\"
when = \"true\"
actions = [\"throttle:soon\"]
reason = \"x\"
",
            "throttle:soon",
        ),
        (
            "an unknown status",
            "[workflows.w]\nevents = [\"account.updated\"]\non_block = { status = \"banned\" }\n",
            "banned",
        ),
        (
            "a bad counter window",
            "[counters.c]\nevents = [\"account.updated\"]\nby = \"ip\"\nwindow = \"1y\"\n",
            "1y",
        ),
        (
            "a counter by an unknown key",
            "[counters.c]\nevents = [\"account.updated\"]\nby = \"shoe_size\"\nwindow = \"1h\"\n",
            "shoe_size",
        ),
        (
            "a counter by an attribute",
            "[counters.c]\nevents = [\"account.updated\"]\nby = \"attrs.page_id\"\nwindow = \"1h\"\n",
            "",
        ),
        (
            "a counter by an identifier attribute",
            "[privacy]\nid_attrs = [\"card_fingerprint\"]\n[counters.c]\nevents = [\"account.updated\"]\nby = \"card_fingerprint\"\ndistinct = \"user\"\nwindow = \"1d\"\n",
            "",
        ),
        (
            "a counter that counts distinct values of its own key",
            "[counters.c]\nevents = [\"account.updated\"]\nby = \"ip\"\ndistinct = \"ip\"\nwindow = \"1h\"\n",
            "distinct",
        ),
        ("a list without a kind", "[lists.l]\nitems = [\"x\"]\n", "kind"),
        (
            "a list with a bad item",
            "[lists.l]\nkind = \"ip\"\nitems = [\"999.0.0.1\"]\n",
            "999.0.0.1",
        ),
        (
            "an event type outside the vocabulary",
            "[workflows.w]\nevents = [\"x.game_won\"]\n",
            "custom",
        ),
        (
            "a custom event type declared",
            "[events]\ncustom = [\"x.game_won\"]\n[workflows.w]\nevents = [\"x.game_won\"]\n",
            "",
        ),
        ("an unknown pack", "packs = [\"lottery\"]\n", "lottery"),
        (
            "every shipped pack at once",
            "packs = [\"free-tier-and-trial\", \"card-and-payments\", \"messaging\", \"marketplace-and-payouts\", \"api-and-compute\", \"hosting-and-content\"]\n",
            "",
        ),
        (
            "an override of a rule that does not exist",
            "[overrides.nope]\nmode = \"act\"\n",
            "nope",
        ),
        (
            "an override of a core rule",
            "[overrides.ato_impossible_travel]\nmode = \"act\"\n",
            "",
        ),
        (
            "a hold length on a rule that does not hold",
            "[workflows.w]\nevents = [\"account.updated\"]\n[[workflows.w.rules]]\nid = \"r\"\nwhen = \"true\"\ndecision = \"block\"\nhold_for = \"7d\"\nreason = \"x\"\n",
            "hold_for",
        ),
        (
            "an action outside the vocabulary",
            "[workflows.w]\nevents = [\"account.updated\"]\non_block = { actions = [\"ban_forever\"] }\n",
            "ban_forever",
        ),
        (
            "a webhook that is not http",
            "[webhooks]\nurl = \"ftp://example.com/hook\"\n",
            "http",
        ),
    ];
    let mut failures = Vec::new();
    for (case, extra, words) in cases {
        let found = problems(&format!("{extra}\n{base}"));
        match words {
            "" if !found.is_empty() => failures.push(format!("{case}: refused: {found:?}")),
            "" => {}
            _ if found.is_empty() => failures.push(format!("{case}: accepted, want a problem with {words:?}")),
            _ if !found.iter().any(|p| p.contains(words)) => failures.push(format!("{case}: {found:?} does not name {words:?}")),
            _ => {}
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
