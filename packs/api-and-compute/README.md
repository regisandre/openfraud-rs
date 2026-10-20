> Status: shipped in shadow mode, opt-in
> Last checked: 2026-10-20

# api-and-compute

## What it covers

API and compute products: leaked or shared keys, key resale to many end
users, usage far above the plan, free-credit farming, mining-shaped jobs,
suspicious API key creation and credential stuffing.

## Events it needs

| Event | Attrs read |
|---|---|
| `usage.recorded` | `attrs.key_id` (the API key), `attrs.units` (tokens, GPU seconds), `attrs.plan_units_per_day` (the plan's daily allowance), `attrs.end_user` (the caller's own user), `attrs.duration_s`, `attrs.gpu_pct`, `attrs.cpu_pct`, plus `ip` and `country` |
| `usage.credit_granted` | none (counted per cluster) |
| `usage.quota_exceeded` | none (the workflow listens, no rule reads it yet) |
| `resource.apikey_created` | none (account age and trust are read) |
| `session.login_failed`, `session.login` | `ip` |

`end_user` is a plain attribute, so it is not hashed unless you add it to
`[privacy] id_attrs`. Send an opaque id, never an email address.

## Rules

All rules ship in `mode = "shadow"`.

### Workflow `api_usage`

Bands: review at 40, hold at 60, block at 90.

| Rule | Catches | Score |
|---|---|---|
| `api_key_many_ips` | one key used from more than 20 IPs in an hour | 40 |
| `api_key_many_countries` | one key used from more than 5 countries in a day | 30 |
| `api_key_resale` | more than 500 end users behind one key of an account that never paid | 40 |
| `api_usage_spike` | usage today above 3 times `plan_units_per_day` | 60 |
| `api_credit_farming` | linked accounts collected free credits more than twice in 30 days | 60 |
| `api_mining_shape` | an hour or more at 95 percent GPU or CPU on an account that never paid | 50 |
| `api_fresh_key` | an API key for a day-old account that never paid | 40 |
| `api_key_burst` | more than 5 keys created in a day | 30 |

### Workflow `api_logins`

Bands: step-up at 30, block at 80.

| Rule | Catches | Score or decision |
|---|---|---|
| `stuffing_ip` | more than 20 accounts failing to log in from one IP in an hour | decision `block` |
| `stuffing_account` | one account failing from more than 5 IPs in an hour | 30 |

The stuffing rules carry the signal `credential_stuffing` and count towards
the `account_takeover` score of the answer (workflow `api_logins`,
`family = "takeover"`).

## Counters and lists

Counters: `api_ips_per_key_1h`, `api_countries_per_key_1d`,
`api_end_users_per_key_1d`, `api_units_per_actor_1d`,
`api_credits_per_cluster_30d`, `api_keys_per_actor_1d`,
`api_failed_accounts_per_ip_1h`, `api_failed_ips_per_actor_1h`.

Lists: none. Pair with the core `vpn_ips` and `blocked_ips` lists (fill them
yourself) if your users connect through known VPNs.

## Turn it on

```toml
packs = ["api-and-compute"]
```

## Tune

```toml
[overrides.api_key_many_countries]
score = 15

[overrides.api_mining_shape]
enabled = false
```

Rules cannot be edited in place; thresholds are part of the rule. Disable a rule
to replace it.

## Promote a rule from shadow to act

Run in shadow, open the Rules page of the admin interface, review the 30-day
replay of the rule, then promote it. `stuffing_ip` blocks by decision: replay it
against your real login traffic first.

## Known false positives

- Mobile apps and serverless backends call from many IPs and countries:
  `api_key_many_ips`, `api_key_many_countries`.
- Legitimate resellers and platforms built on your API: `api_key_resale` (only
  while the account never paid).
- Batch jobs and benchmarks: `api_usage_spike`, `api_mining_shape` (machine
  learning training is full load for hours).
- Offices, universities and carrier NAT sharing one IP with many accounts:
  `stuffing_ip`.
- A user who forgot their password and tries from a phone, a laptop and a VPN:
  `stuffing_account`.
- Hackathons and classes with several accounts on one device or network:
  `api_credit_farming`.
- The safety brake turns restrictions into reviews when they spike.

## Scenarios

- `examples/scenarios/pack-api-and-compute.jsonl`: all 10 rules in six stories and a paying customer as control. The 501-event shared-key story comes last because hundreds of restrictions in a row engage the safety brake.
- `examples/scenarios/pack-api-and-compute-shadow.jsonl`: shadow behaviour.

Run them with `cargo test --test scenarios`.
