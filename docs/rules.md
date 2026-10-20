> Status: shipped in 0.1, matches src/config.rs, src/expr.rs, src/decision.rs and src/scenario.rs
> Last checked: 2026-10-20

# Writing workflows and rules

A **rule** is a condition (CEL) with a score and a reason. A **workflow**
groups the rules that listen to the same event types and turns their total
score into a decision. **Counters** and **lists** feed the conditions. All of
it lives in `openfraud.toml`, or in a pack ([packs.md](packs.md)).

Check your work before it runs:

```sh
openfraud validate                       # compiles everything, core and packs merged in
openfraud simulate scenario.jsonl        # runs events and expectations, see below
```

`validate` reports every problem at once (unknown counter, unknown list, a
band out of order, a missing reason ...). The server refuses to start on an
invalid configuration, and the admin editor refuses to save one.

## A complete example

```toml
[lists.risky_domains]
kind = "domain"
items = ["example.net"]

[counters.signups_per_ip_1h]
events = ["account.created"]
by = "ip"
window = "1h"

[workflows.my_signup]
description = "Sign-up bursts"
events = ["account.created"]
mode = "shadow"
review_at = 50
hold_at = 70
quarantine_at = 100
on_review = { actions = ["step_up"] }

[[workflows.my_signup.rules]]
id = "my_signup_burst"
when = "counters.signups_per_ip_1h > 3"
score = 50
reason = "More than 3 accounts from one IP address in an hour"

[[workflows.my_signup.rules]]
id = "my_risky_domain"
when = 'in_list("risky_domains", event.email_domain)'
score = 30
reason = "The email domain is on the watch list"
```

Names (workflows, rules, counters, lists) are lowercase letters, digits and
`_`, starting with a letter, up to 64 characters. **Rule ids are unique across
all workflows**, packs included: prefix yours.

## Workflow (`[workflows.<name>]`)

| Key | Meaning |
|---|---|
| `events` | event types the workflow listens to, or `["*"]` for every event. Types must be in the vocabulary or `[events] custom` ([events.md](events.md)) |
| `description` | free text |
| `mode` | `act` (default) or `shadow`, for every rule that sets none |
| `enabled` | `false` switches the workflow off (default true) |
| `step_up_at`, `review_at`, `hold_at`, `block_at`, `quarantine_at` | score thresholds, each optional; they must not decrease in that order |
| `max_decision` | the strictest decision this workflow may give (`hold` for account takeover) |
| `on_step_up`, `on_review`, `on_hold`, `on_block`, `on_quarantine` | `{ status = "review", actions = ["limit:trial"] }`: extra actions, and an optional status for the actor, when the workflow ends on that decision |
| `rules` | the rules, as `[[workflows.<name>.rules]]` |

### How a decision is made

Within one workflow, for one event:

1. Every rule whose condition is true and whose mode is `act` adds its
   `score` (scores may be negative) to the total.
2. The total picks a band: the highest threshold it reaches. Decisions are
   ordered `allow < step_up < review < hold < block < quarantine`.
3. A rule with a `decision` forces it; the strictest forced decision wins
   over the band. A forced `allow` (an allowlist rule) wins over everything.
4. `max_decision` caps the result.
5. **Trust protection**: if the result is `block` or `quarantine` and the
   actor's trust is at least `[trust] act_below` (default 1), it becomes a
   `hold` and the answer carries `protected: true`. A person earns trust
   (labelling `legit`, the status route) or a paid invoice does (core).
6. The decision implies an action (`step_up`, `review`, `hold`,
   `quarantine`; `block` implies none: your application just refuses). Then
   the `actions` of the firing rules and the `on_<decision>` actions are
   added, without duplicates. `quarantine` sets the actor's status to
   `quarantined`.

Rules in shadow mode never change the decision; the decision they would have
given is reported as `shadow.decision` (`would` in `simulate`). If several
workflows listen to the same event, the answer is the strictest of their
decisions; the score is the highest, the actions are merged.

Three built-in rules sit outside the workflows: `actor_quarantined` and
`tenant_quarantined` block every event of a quarantined account or tenant,
and `actor_throttled` blocks an event type an acting `throttle:<duration>`
rule froze for that account, with `retry_after` in the answer. A refused
attempt does not push the end of the throttle back; a `release` lifts it.
A rate limit is a counter and a rule:

```toml
[counters.exports_per_actor_1h]
events = ["resource.exported"]
by = "actor"
window = "1h"

[[workflows.my_limits.rules]]
id = "my_export_burst"
when = "counters.exports_per_actor_1h > 20"
actions = ["throttle:1h"]
reason = "More than 20 exports in an hour"
```

### Who gets restricted

By default a rule's actions restrict the **actor**. With `target = "tenant"`
they restrict the tenant. A tenant is quarantined only when the tenant's
owner is the actor (`owner_id == actor_id`); when a member acted, the tenant
gets a `review` case and the actions become `review` on the tenant, and an
actor restriction also opens a tenant review case. See
[integration.md](integration.md). Without a `tenant_id` there is nothing to
restrict: the decision still stands for the request, the tenant actions drop.

## Rule (`[[workflows.<name>.rules]]`)

| Key | Meaning |
|---|---|
| `id` | unique, see above |
| `when` | the CEL condition, up to 2,000 characters |
| `reason` | required: the sentence that explains a decision; it appears in the answer and in the statement of reasons shown to the user, so write it for them |
| `score` | integer added to the workflow total (default 0) |
| `decision` | forces `allow`, `step_up`, `review`, `hold`, `block` or `quarantine` |
| `trust` | sets the trust level of the rule's target (the actor, or the tenant with `target = "tenant"`) when the rule fires in act mode (it only goes up) |
| `actions` | extra actions: `quarantine`, `release`, `hold`, `step_up`, `review`, `revoke_sessions`, `suspend_feature:<name>`, `limit:<quota>`, `throttle:<duration>`, or the `stripe.*` actions ([stripe.md](stripe.md)) |
| `mode` | `act` or `shadow`; overrides the workflow's |
| `hold_for` | with `decision = "hold"` only: a duration such as `7d`; the answer then has `hold_until` (the longest of the firing rules) |
| `target` | `actor` (default) or `tenant` |
| `enabled` | `false` switches the rule off |

A rule must do something: a score, a decision, a trust level or actions.

A rule that asks to act (`mode` `act`) but has no approved replay yet is
treated as shadow and flagged `pending_approval`. See [safety.md](safety.md).
Rules from the core are exempt.

## Core and pack rules: overrides

Rules that come from the core or a pack cannot be edited in place. Change
them with an override, keyed by rule id:

```toml
[overrides.msg_inbox_probe]
mode = "act"      # or "shadow"
score = 80
enabled = true    # false switches the rule off
```

An override of an unknown rule id is a configuration error. Changing `mode`
to `act` this way does not approve the rule: promote it through the admin
interface instead ([safety.md](safety.md)).

## Counters (`[counters.<name>]`)

A counter keeps, for each key, how many events (or what sum, or how many
distinct values) it saw in a sliding window. Rules read `counters.<name>`: the
value for the current event's key, **including the current event** if it
counts.

| Key | Meaning |
|---|---|
| `events` | event types counted (at least one) |
| `by` | the key: `actor` (alias `user`), `tenant`, `owner`, `cluster`, `ip`, `ip_prefix`, `email`, `email_domain`, `email_stem` (the letters of the local part), `email_alias` (the address as typed, tag included), `phone`, `phone_prefix`, `device`, `country`, `subject`, an `id_attrs` name (hashed), or `attrs.<name>` (a plain attribute: text, number or bool) |
| `window` | `30s`, `15m`, `1h`, `7d`: a whole number and a unit, up to `366d`. The edge is exact to 1/120 of the window |
| `distinct` | count distinct values of this key instead of events (same key syntax; not the same as `by`). At most 10,000 values per key |
| `sum` | add up an attribute (`attrs.amount`) instead of counting; rounded to a whole number, negatives count as 0, a missing value counts as 1. Not with `distinct` |
| `when` | a CEL condition on `event` and `now` only; count only the events for which it is true |
| `description` | free text |

`by = "cluster"` keys the counter by the actor's cluster
([graph.md](graph.md)). If an event lacks the `by` value (no `ip`, say) the
counter reads 0 for it. Counters live in memory and are rebuilt at start from
the stored events inside the longest window, so a window longer than
`[server] retention_days` is only as long as the history kept
([compliance.md](compliance.md)).

## Lists (`[lists.<name>]`)

```toml
[lists.vpn_ips]
kind = "ip"
description = "Ranges your users connect from"
items = ["192.0.2.0/24"]
file = "lists/vpn.txt"        # one item per line, # comments, relative to the config file
url = "https://example.org/list.txt"   # downloaded only with [server] fetch_lists = true
```

| `kind` | An item is | A probe matches when |
|---|---|---|
| `domain` | a domain (`*.` and a trailing dot are stripped) | it is the item or a subdomain of it; an address is looked up by its domain |
| `ip` | an address or CIDR range, IPv4 or IPv6 | the address is in a range |
| `value` | an exact text | equal |
| `prefix` | the beginning of a text (`+32`) | the probe starts with it |

Items from the file, the URL and the API (`POST /v1/lists/{name}/items`) are
added to those in the configuration. A list of the same name and kind in a
pack and in your configuration are merged ([packs.md](packs.md)). The core
defines `blocked_ips`, `blocked_actors` and `vpn_ips`.

## Conditions (CEL)

Conditions are written in the Common Expression Language: `&&`, `||`, `!`,
comparisons, `in`, `has(x.y)`, `size()`, `exists`, `all`, `startsWith`,
`contains`, `matches`, ternaries. They are compiled once when the
configuration loads; a typo is a configuration error, not a runtime surprise.
Whole numbers are signed integers; `share_in_list` and `freemail_share`
return floats, so compare them with `1.0`, not `1`.

A condition that cannot be evaluated (a missing attribute, a wrong type) does
not fire; the error is reported by `simulate` and the admin playground.
Guard optional attributes: `has(event.attrs.recipients) && size(...) > 3`.
Put single quotes around a condition that contains double quotes.

### Facts

| Variable | Content |
|---|---|
| `event` | the normalized event: `id`, `type`, `at`, `actor`, `actor_created_at` (if sent), `tenant`, `owner`, `email`, `email_domain`, `email_shape` (`.generated`, `.numeric`, `.digits` ... see [events.md](events.md)), `email_alias`, `phone_prefix`, `ip_hash`, `ip_prefix`, `ip_lists`, `device`, `country`, `subject` (`.type`, `.id`), `attrs`, `ids` |
| `actor` (alias `user`) | `id`, `status`, `trust`, `age` (seconds since `account.created`, or first seen), `max_score`, `label` (`""` if none), `country`, `known` (seen before) |
| `tenant` | `id`, `status`, `trust`, `age`, `max_score`, `known`, `actor_is_owner` |
| `counters` | `counters.<name>`, see above |
| `links` | per identifier kind present on the event: `links.<kind>.users` (other accounts sharing it) and `.flagged` (of those, quarantined or labelled fraud). `links.cluster`: `size`, `flagged`, `fraud`, `legit`. Test a kind with `has(links.device)` |
| `session` | `new_device`, `new_country`, `travel_km`, `travel_kmh`, `since_credential_change` ([account-takeover.md](account-takeover.md)) |
| `related` | for each attribute named in `[graph] related_attrs`: `related.<attr>.id`, `.same_cluster`, `.status`, `.flagged`; absent when the event lacks the attribute (use `has()`) |
| `now` | the event time, Unix seconds |

Without an actor, `actor.id` is `""`, status `normal`, trust 0.

### Functions

| Function | Returns |
|---|---|
| `in_list("name", value)` | whether the value is in the list (kind rules above). The list name must be a literal |
| `"name" in event.ip_lists` | whether the request IP is in the IP list (the raw IP is not available to rules) |
| `mentions("name", text)` | whether the text contains an item of the list, in any case (brand names in a title) |
| `list_size("name")` | number of items in the list |
| `share_in_list("name", addresses)` | share (0 to 1) of the items found in the list |
| `provider(address)` | the free mailbox provider (`google`, `microsoft`, `yahoo`, `apple`, `proton`, `gmx` ...) or `""` |
| `domain(address)` | the part after the last `@` |
| `providers(list)` | number of distinct free providers among the addresses |
| `freemail_share(list)` | share (0 to 1) of addresses at a free provider |
| `alike(list, address)` | how many addresses of the list share the mailbox or the stem of `address` (pseudonyms, see [events.md](events.md)) |
| `since("type")` | seconds since the actor's first event of that type before this one, `-1` if never |
| `since_last("type")` | seconds since the actor's last event of that type, `-1` if never |
| `tenant_since("type")` | seconds since the tenant's first event of that type before this one, `-1` if never: a trial started by the owner, read on a member's send |

## Scenarios: tests for rules

A scenario is a JSON Lines file run on a fresh in-memory engine with your
configuration. One object per line: `{"event": {...}, "expect": {...}}`;
`expect` is optional. The event is the API event; its `at` moves a virtual
clock, so a scenario can span days. The repository ships examples in
`examples/scenarios/`.

`expect` keys (all optional):

| Key | Checks |
|---|---|
| `decision` | the decision given by the rules that act |
| `would` | the decision with shadow rules counted too |
| `status`, `tenant_status` | the actor's and the tenant's status after the event |
| `rules` | ids that must fire and act |
| `shadow_rules` | ids that must fire in shadow |
| `not_rules` | ids that must not fire at all |
| `actions` | actions that must be asked: `quarantine` for the actor, `tenant:review` for the tenant |
| `case`, `tenant_case` | whether a case was opened or updated |

A rule that could not be evaluated is always a mismatch.

Lines starting with `#` are comments, except these directives:

| Directive | Effect |
|---|---|
| `# packs: messaging, card-and-payments` | turns packs on; before the first event only |
| `# enforce` | every rule acts and no replay approval is needed, to test what a pack does once on; before the first event only |
| `# list: <name> <item>` | adds an item to a list |
| `# label: <actor> fraud\|legit\|false_positive` | records a person's verdict, which also quarantines or trusts the actor |

Example:

```text
# packs: messaging
# enforce
{"event": {"id": "s1", "type": "message.send_requested", "at": "2026-10-19T09:00:00Z", "actor_id": "u1", "attrs": {"recipients": ["a@gmail.com", "b@yahoo.com", "c@outlook.com"]}}, "expect": {"decision": "quarantine", "rules": ["msg_inbox_probe"]}}
```

`openfraud simulate` prints one line per event (`line`, type, decision,
`would`, score, `ok` or `MISMATCH`) and exits non-zero with every mismatch
listed if any expectation failed. It uses the configuration given by
`--config` (default `openfraud.toml`); scenarios run in the test suite of the
repository the same way.
