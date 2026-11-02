> Status: shipped in 0.14, matches src/limits.rs, src/config.rs and src/engine.rs
> Last checked: 2026-11-02

# Progressive limits

A flat rate limit is wrong for a young account and for an old one at the
same time: set low, it throttles your best customers; set high, a sign-up
made a minute ago can already create pages or send mail in bulk. A
**progressive limit** is an allowance that starts small and grows by itself
as the account (or the workspace) ages, with no setting for the user to see
and nothing for you to raise by hand.

The allowance is a function of three facts openfraud already keeps:

- **age**: seconds since the account was created (`actor.age`), or since the
  workspace was first seen (`tenant.age`);
- **trust**: a paid invoice, or a person's `legit` label, multiplies it;
- **risk**: an account whose highest score ever reached a threshold gets a
  fraction of it.

## Define one

```toml
[counters.sends_per_actor_1d]
events = ["message.send_requested"]
by = "actor"
window = "1d"

[limits.sends]
counter = "sends_per_actor_1d"     # the counter the allowance bounds
subject = "actor"                  # whose age sets it: actor (default) or tenant
base = 3                           # a brand-new account: 3 a day
trusted_factor = 10                # x10 when the account or its workspace paid
risky_above = 50                   # an account that ever scored 50 or more ...
risky_factor = 0.5                 # ... has half
mode = "act"                       # act (default) refuses, shadow only reports
steps = [
  { age = "1d", max = 10 },        # from its first day: 10
  { age = "7d", max = 40 },
  { age = "30d", max = 150 },
]
```

Ages are ascending and the allowance never shrinks. The allowance is
rounded up, so a cut never reaches zero unless the base or the factor is.
`openfraud validate` refuses an unknown counter, a counter switched off, steps
out of order, a shrinking step and a factor out of range.

## What it does

- **It refuses by itself.** When the counter goes over the allowance and the
  limit acts, the answer is `block` by the built-in rule `limit_<name>`, like
  `actor_throttled`: no case, no statement of reasons, nothing for the safety
  brake to count. The application answers like a rate limit (HTTP 429).
- **A refused attempt does not use the allowance.** A client that keeps
  retrying cannot lock itself out: once earlier uses leave the window, it is
  let through. After a restart the counters are rebuilt from the stored
  events, refused attempts included, so the first minutes can be stricter.
- **Shadow first.** With `mode = "shadow"` the answer still reports the
  allowance and lists `limit_<name>` as a shadow rule with
  `shadow.decision = "block"`; nothing is refused. The limits of the
  `progressive-limits` pack ship in shadow: turn one on with
  `[limit_overrides.<name>] mode = "act"`, or off with `enabled = false`.
- **Rules can read it.** `limits.<name>` is the allowance for the account of
  the current event, next to `counters.<name>`:
  `counters.sends_per_actor_1d > limits.sends / 2` is a rule that steps up
  at half the allowance.
- **The answer reports it.** `limits` maps each limit whose counter counts
  the event to `{"max", "used"}` (`used` includes the current event), so an
  application can show what is left.

## The pack

`packs = ["progressive-limits"]` adds nine limits on the actions a young
account abuses first: creations (`resource.created`), send requests and
recipients (`message.send_requested`, `attrs.recipients_count`), test sends,
API keys, and four custom events your application sends where it applies:
`x.invitation_sent`, `x.content_posted`, `x.report_filed`, `x.follow_added`.
See [the pack](../packs/progressive-limits/README.md).

## Limits of the design

- Age is calendar time: an account left idle for a month grows into a
  large allowance. Pair a limit with `actor.idle` or `since_last()` rules, or
  with the baselines of counters, to catch a sleeper that wakes up.
- The allowance counts the account, not the person: linked accounts share
  nothing here. The link graph and the `cluster` key do that ([graph.md](graph.md)).
- A limit is only as good as the events you send: call `/v1/decide` before the
  action and refuse on `block`.
