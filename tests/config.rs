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
            "a pair list kept for a while, filled by a rule",
            "[lists.pairs]\nkind = \"value\"\nkey = \"actor\"\nsecond = \"device\"\nexpire = \"14d\"\n[workflows.w]\nevents = [\"session.login\"]\n[[workflows.w.rules]]\nid = \"r\"\nwhen = '\"pairs\" in event.lists'\ndecision = \"allow\"\nstop = true\nactions = [\"list.add:pairs\"]\nreason = \"x\"\n",
            "",
        ),
        (
            "a rule that fills a list that does not exist",
            "[workflows.w]\nevents = [\"session.login\"]\n[[workflows.w.rules]]\nid = \"r\"\nwhen = \"true\"\nactions = [\"list.add:nope\"]\nreason = \"x\"\n",
            "names no list",
        ),
        (
            "a rule that fills a list with no key",
            "[workflows.w]\nevents = [\"session.login\"]\n[[workflows.w.rules]]\nid = \"r\"\nwhen = \"true\"\nactions = [\"list.remove:disposable\"]\nreason = \"x\"\n",
            "no `key`",
        ),
        (
            "a rule that reads a keyed list that does not exist",
            "[workflows.w]\nevents = [\"session.login\"]\n[[workflows.w.rules]]\nid = \"r\"\nwhen = '\"nope\" in event.lists'\nscore = 1\nreason = \"x\"\n",
            "nope",
        ),
        (
            "a second field without a key",
            "[lists.pairs]\nkind = \"value\"\nsecond = \"device\"\n",
            "second",
        ),
        (
            "a key on an ip list",
            "[lists.ips]\nkind = \"ip\"\nkey = \"actor\"\n",
            "takes no `key`",
        ),
        (
            "devices written by hand",
            "[lists.devices]\nkind = \"value\"\nkey = \"device\"\nitems = [\"abc\"]\n",
            "through the API",
        ),
        (
            "a lifetime that is no duration",
            "[lists.l]\nkind = \"value\"\nkey = \"actor\"\nexpire = \"soon\"\n",
            "duration",
        ),
        (
            "a stop on a rule that does not allow",
            "[workflows.w]\nevents = [\"session.login\"]\n[[workflows.w.rules]]\nid = \"r\"\nwhen = \"true\"\nscore = 10\nstop = true\nreason = \"x\"\n",
            "stop",
        ),
        (
            "a rule that only names a signal, in a family",
            "[workflows.w]\nevents = [\"session.login\"]\nfamily = \"takeover\"\n[[workflows.w.rules]]\nid = \"r\"\nwhen = \"true\"\nsignal = \"seen_it\"\nfamily = \"bot\"\nreason = \"x\"\n",
            "",
        ),
        (
            "a signal that is no name",
            "[workflows.w]\nevents = [\"session.login\"]\n[[workflows.w.rules]]\nid = \"r\"\nwhen = \"true\"\nsignal = \"Seen It\"\nreason = \"x\"\n",
            "signal",
        ),
        (
            "a family that does not exist",
            "[workflows.w]\nevents = [\"session.login\"]\nfamily = \"spam\"\n",
            "family",
        ),
        (
            "a rule that reads a counter switched off",
            "[counters.off]
events = [\"account.created\"]
by = \"ip\"
window = \"1h\"
enabled = false
[workflows.w]
events = [\"account.created\"]
[[workflows.w.rules]]
id = \"r\"
when = \"counters.off > 1\"
score = 1
reason = \"x\"
",
            "switched off",
        ),
        (
            "an average with nothing to average",
            "[counters.c]
events = [\"account.created\"]
by = \"ip\"
window = \"1h\"
agg = \"avg\"
",
            "`of`",
        ),
        (
            "a baseline shorter than its window",
            "[counters.c]
events = [\"account.created\"]
by = \"ip\"
window = \"1d\"
baseline = \"1h\"
",
            "baseline",
        ),
        (
            "a cluster in a key of several fields",
            "[counters.c]
events = [\"account.created\"]
by = [\"cluster\", \"ip\"]
window = \"1h\"
",
            "cluster",
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

#[test]
fn a_mirror_serves_every_downloaded_list_and_the_network_table() {
    let text = r#"
packs = ["free-tier-and-trial"]

[server]
fetch_lists = true
lists_mirror = "http://mirror.internal:8112/mirror/"

[networks]
enabled = true

[lists.mine]
kind = "domain"
items = ["example.com"]
"#;
    let assembled = Config::parse(text, Path::new(".")).unwrap().assemble().unwrap();
    let list_url = |name: &str| assembled.lists.get(name).and_then(|l| l.url.clone());
    // (case, where it is downloaded from)
    let cases: Vec<(&str, Option<String>, Option<&str>)> = vec![
        (
            "a core list",
            list_url("tor_exits"),
            Some("http://mirror.internal:8112/mirror/tor_exits.txt"),
        ),
        (
            "a pack's list",
            list_url("disposable_domains"),
            Some("http://mirror.internal:8112/mirror/disposable_domains.txt"),
        ),
        ("a list with no url stays a list of its own", list_url("mine"), None),
        (
            "the network table",
            Some(assembled.networks.url.clone()),
            Some("http://mirror.internal:8112/mirror/ip2asn-combined.tsv.gz"),
        ),
    ];
    let mut failures = Vec::new();
    for (case, got, want) in cases {
        if got.as_deref() != want {
            failures.push(format!("{case}: {got:?}, want {want:?}"));
        }
    }
    // Plain http is for a host on the private network only: a list fetched in
    // clear over the internet can be rewritten on the way.
    // (case, configuration, accepted)
    let addresses: Vec<(&str, &str, bool)> = vec![
        (
            "a mirror that is no http address",
            "[server]\nlists_mirror = \"ftp://mirror.internal/\"\n",
            false,
        ),
        (
            "a mirror in clear on the internet",
            "[server]\nlists_mirror = \"http://mirror.example.com/\"\n",
            false,
        ),
        (
            "a mirror in clear on a private address",
            "[server]\nlists_mirror = \"http://10.0.4.2:8112/\"\n",
            true,
        ),
        (
            "a mirror in clear on localhost",
            "[server]\nlists_mirror = \"http://localhost:8112/\"\n",
            true,
        ),
        (
            "a mirror in clear on a single-label host",
            "[server]\nlists_mirror = \"http://mirror:8112/\"\n",
            true,
        ),
        (
            "a mirror over https",
            "[server]\nlists_mirror = \"https://mirror.example.com/\"\n",
            true,
        ),
        (
            "a list in clear on the internet",
            "[lists.x]\nkind = \"ip\"\nurl = \"http://lists.example.com/x.txt\"\n",
            false,
        ),
        (
            "a network table in clear on the internet",
            "[networks]\nurl = \"http://iptoasn.example.com/combined.tsv.gz\"\n",
            false,
        ),
        (
            "a list in clear on the private network",
            "[lists.x]\nkind = \"ip\"\nurl = \"http://lists.lan/x.txt\"\n",
            true,
        ),
    ];
    for (case, text, accepted) in addresses {
        let found = problems(text);
        if found.is_empty() != accepted {
            failures.push(format!("{case}: problems {found:?}, want accepted = {accepted}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
