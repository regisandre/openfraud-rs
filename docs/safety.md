> Status: shipped in 0.1, matches src/engine.rs, src/replay.rs, src/admin.rs and src/config.rs
> Last checked: 2026-10-19

# Safety: shadow mode, approved replays and the brake

A fraud engine that wrongly locks customers costs more than the fraud. Three
layers keep a new or wrong rule from doing damage.

## 1. Shadow mode

A rule (or a whole workflow) with `mode = "shadow"` is evaluated on every
event but changes nothing. The answer shows what it would have done:

- `shadow.decision` in the `/v1/decide` answer is the decision with the
  shadow rules counted; `shadow.reasons` lists them;
- the admin Rules page counts how often each rule fired over 30 days, and
  `openfraud replay` reports it for any window;
- `openfraud simulate` prints it as `would`.

Every rule of every pack ships in shadow, and the account takeover core rules
too. Only the blocklists and trust rules of the core act from the start,
because a list you fill by hand is a decision a person already made.

## 2. A rule acts only after an approved replay

```toml
[safety]
require_replay = true   # default
replay_days = 30        # default
```

With `require_replay` on, a rule whose mode is `act` still runs as **shadow**
(flagged `pending_approval: true` in the answer) until a person has run and
approved a replay of the last `replay_days` days for it. This covers rules of
packs and rules you wrote yourself. Rules of the core are exempt. Set
`require_replay = false` only for a test setup.

### What an approval is tied to: the fingerprint

An approval is stored for a rule id and a **fingerprint**: a short hash of
the rule's logic. It is made of the workflow name and the rule's `id`,
`when`, `score`, `decision`, `hold_for`, `actions`, `target` and `trust`.

- Change any of those and the old approval no longer matches: the rule drops
  back to shadow until it is promoted again.
- Change the wording (`reason`), the `mode`, `enabled`, or anything outside
  the rule (the workflow's thresholds, a counter, a list), and the approval
  stays. Re-run a replay yourself after such a change.

### Promoting a rule

In the admin interface, Rules page, press promote on a shadow rule. It calls
`POST /admin/api/rules/{id}/promote`, which:

1. loads the configuration file and sets `mode = "act"` for the rule in a
   candidate;
2. replays the last `replay_days` days of stored events through the candidate
   (below);
3. refuses if the stored history is shorter than the window (about 29 days
   for 30; keep the rule in shadow until the history has built up, or set
   `require_replay = false` at your own risk);
4. records the replay summary as the approval, appends
   `[overrides.<id>]` with `mode = "act"` to the configuration file, and
   reloads. The approval and the promotion are written to the audit log.

It refuses when the file already has an `[overrides.<id>]` section: edit that
one by hand (but note that a hand edit does not create an approval, so the
rule stays pending; remove the section and promote instead). To demote a
rule, set its override to `mode = "shadow"`.

### `openfraud replay`

```sh
openfraud replay --days 30                       # the current configuration
openfraud replay --days 30 --candidate new.toml  # a candidate file
```

It runs the stored events, oldest first, through the candidate on a fresh
in-memory engine and prints a JSON report. The candidate sees events as they
were stored (pseudonyms, and the IP lists each address was on at the time).
Account statuses evolve from the candidate's own decisions only; the people's
labels are used to score the rules, not replayed. Rules are treated as
approved and the brake is off, so the report shows what the rules would do
once they act. Webhooks and alerts are not sent. It needs the state file (for
the database) and does not write an approval; only the admin promote does.

Note: replaying the **current** configuration leaves shadow rules in shadow,
so `before` and `after` match. To see the effect of promoting a rule, replay
a candidate where it acts (an override with `mode = "act"`).

The report:

| Field | Meaning |
|---|---|
| `events`, `from`, `to` | how many events, the first and last time |
| `before`, `after` | decisions per kind, as stored and as the candidate gives |
| `changed_total`, `changed` | events whose decision differs; the first 500 with `before`, `after` and the acting rules |
| `rules[]` | per rule: `mode`, `fired` (events), `users` (distinct accounts), `fraud`, `legit`, `false_positive` (of those accounts, by label), `precision`, `recall` |

### Precision and recall from labels

Labels come from people: `fraud`, `legit` or `false_positive` on an account
(the label route, or resolving a case). For a rule:

- `precision` = accounts labelled `fraud` among the labelled accounts it hit
  (`fraud / (fraud + legit + false_positive)`). Absent when it hit none.
- `recall` = accounts labelled `fraud` it hit, of all accounts labelled
  `fraud`. Absent when nothing is labelled fraud.

Both are only as good as your labelling. A rule with no labelled hits shows
neither: read its `changed` events by hand. The admin Rules page shows the
same figures over the last 30 days of rule hits, shadow rules included.

## 3. The safety brake

Whatever the rules say, an engine that suddenly restricts many accounts is
more likely wrong than right. The brake watches automatic restrictions: any
decision of `hold`, `block` or `quarantine` that the brake itself did not
create (this includes the blocks of events from already quarantined accounts).

```toml
[safety]
max_auto_per_hour = 100
baseline_multiple = 5.0
min_per_hour = 10
```

For each restricting event, with `hour` the restrictions in the last hour
(this one included) and `average` the restrictions in the last 7 days divided
by 168:

- it trips if `hour > max_auto_per_hour`, or
- if `hour >= min_per_hour` and `hour > baseline_multiple * max(average, 1)`
  (the floor of 1 keeps a quiet system from tripping on a handful).

When it trips:

- this decision and every later restricting decision become a **review**
  (action `review`; the answer has `brake: true`) until a person releases it;
- the state is stored in the database, so it **survives a restart**; the
  counters are rebuilt from the stored events at start;
- a `brake.engaged` webhook (`{since, reason}`) and a **critical** alert
  ([alerts.md](alerts.md)) go out; a critical alert is never delayed by a
  digest.

Release it from the admin interface (`POST /admin/api/brake/release`): the
brake clears, the last-hour count restarts from zero, `brake.released` is
sent and the release is audited. Look first at what spiked: a broken
integration sending bad data, or a rule that went wrong, is the usual cause
(demote the rule, then release). `GET /admin/api/brake` shows the state and
the thresholds.

The brake never lifts anything on its own and never blocks a `step_up` or a
`review`.
