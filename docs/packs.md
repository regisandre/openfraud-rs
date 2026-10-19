> Status: shipped in 0.1, matches src/packs.rs and src/config.rs
> Last checked: 2026-10-19

# Rule packs

The generic core needs no knowledge of your product: it keeps counters,
links accounts, applies blocklists, trust and account takeover signals
([account-takeover.md](account-takeover.md)). A **pack** adds the rules for a
kind of product, as a TOML file with the same `lists`, `counters`,
`workflows` and `events` sections as the configuration, plus a `[pack]`
header. Packs are opt-in and **every rule of every shipped pack ships in
shadow mode**: it records what it would decide and acts only after you
promote it ([safety.md](safety.md)).

## The six packs

Each has a README with its events, its rules and what to send.

| Pack | Covers | Details |
|---|---|---|
| `free-tier-and-trial` | sign-up farms, throwaway mailboxes, trial and promo abuse, trial cycles, upgrade-use-cancel, referrals | [README](../packs/free-tier-and-trial/README.md) |
| `card-and-payments` | card testing, risky cards, cards of quarantined accounts, refund-rebuy loops, disputes | [README](../packs/card-and-payments/README.md) |
| `messaging` | email, SMS and push abuse: inbox probes, poor imported lists, bounce and complaint kill switch, SMS pumping | [README](../packs/messaging/README.md) |
| `marketplace-and-payouts` | exit scams by new sellers, payout destination hijacks, bulk-buying across linked accounts, seller refund and dispute rates | [README](../packs/marketplace-and-payouts/README.md) |
| `api-and-compute` | leaked or resold keys, usage far above plan, free-credit farming, credential stuffing, mining-shaped jobs | [README](../packs/api-and-compute/README.md) |
| `hosting-and-content` | phishing and impersonation pages, known-bad files, link spam, mass creation by young accounts, moderation verdicts | [README](../packs/hosting-and-content/README.md) |

`openfraud packs` lists the packs built into the binary with their
descriptions.

## Turning packs on

```toml
packs = ["messaging", "card-and-payments"]
```

Run `openfraud validate`, restart (or save the configuration from the admin
editor), and watch the rules in the admin Rules page. Send the events a pack
needs ([events.md](events.md) lists them per type): a pack whose events never
arrive does nothing. Listing a pack twice, or an unknown name, is a
configuration error.

Switching a pack on costs memory for its counters (windows of up to a year
for some) and a little time per event; rules only run for the event types
their workflow listens to.

## Your own packs

```toml
packs_dir = "packs"      # relative to the configuration file
packs = ["my-product"]
```

`packs_dir/<name>/pack.toml` is read for each name in `packs`. If a directory
there has the name of a built-in pack, it **replaces** the built-in one
entirely; otherwise the built-in pack is used. Pack names may contain
anything the directory name allows, but keep to lowercase letters and `-`.

Format:

```toml
[pack]
name = "my-product"
description = "One line shown by the tools"
needs = ["account.created", "x.game_won"]   # documentation only: not checked

[events]
custom = ["x.game_won"]                     # added to the configuration's custom types

[lists.my_words]
kind = "value"
items = ["foo", "bar"]

[counters.my_wins_per_actor_1d]
events = ["x.game_won"]
by = "actor"
window = "1d"

[workflows.my_wins]
description = "Too many wins"
events = ["x.game_won"]
mode = "shadow"                             # keep shadow: promote after a replay
review_at = 50

[[workflows.my_wins.rules]]
id = "my_wins_burst"
when = "counters.my_wins_per_actor_1d > 100"
score = 50
reason = "More than 100 wins in a day"
```

Write the rules as in [rules.md](rules.md). A pack may not carry an
`[overrides]` section, a `[server]` section or any other: the sections above
are the only ones accepted, and an unknown key is an error.

### How a pack merges with your configuration

- **Lists**: a list of the same name and the same kind in your configuration
  and in a pack are merged. Items are the pack's first, then yours; your
  `description` and `url` win, and the pack's fill in what you left empty.
  The same name with another kind is an error. This is how you extend
  `disposable_domains` or `impersonated_brands` or fill `vpn_ips`.
- **Counters and workflows**: names are global. A name defined twice, by two
  packs or by a pack and your configuration, is an error. Rule ids are
  unique across everything.
- **Custom event types** are added to `[events] custom`.
- **Changing a pack rule**: use `[overrides.<rule id>]` with `mode`, `score`
  and `enabled`. To change its logic, copy the rule into a workflow of your
  own (with a new id) and switch the original off.
- Each workflow remembers where it came from (`core`, `pack:<name>` or
  `config`); the admin interface shows it, and rules from `core` are exempt
  from the replay approval.
