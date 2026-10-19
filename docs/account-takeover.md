> Status: shipped in 0.1, matches core/account-takeover.toml and src/engine.rs
> Last checked: 2026-10-19

# Account takeover (core)

A held login or change also asks `revoke_sessions`: every session of the
account ends, the stranger is logged out, and the owner signs in again with
proof.

A stranger inside a real account looks different from a fraudster: the owner
is the victim. So these rules **never block and never quarantine**. The
workflow `account_takeover` has `max_decision = "hold"`: the strongest thing
it can ask is to hold the sensitive action until the owner confirms it, and
the mildest is a `step_up` (MFA, a confirmation email). It is on by default
(`[core] account_takeover = true`) and **in shadow mode**: it records what it
would do and acts only after you promote its rules ([safety.md](safety.md)).

To switch it off entirely: `[core] account_takeover = false`.

## Session facts

For every event with an `actor_id`, rules read the object `session`
([rules.md](rules.md)):

| Fact | Meaning |
|---|---|
| `session.new_device` | the event has a `device` and the account has used other devices before, but never this one. False on an account's first device |
| `session.new_country` | the event has a `country`, the account has been seen in other countries, and never this one |
| `session.travel_km` | distance in km between the country of the previous event and this one, when they differ; else 0 |
| `session.travel_kmh` | that distance over the time between the two events (at least one minute), rounded; else 0 |
| `session.since_credential_change` | seconds since the account's last `session.password_reset`, `session.mfa_changed`, `account.email_changed` or `account.phone_changed`; `-1` if none |

Distances are between **country centres** (one point per ISO 3166 alpha-2
code, from `data/countries.csv`, a table derived from Google's DSPL
`countries.csv`, BSD 3-Clause). A country is wide, so the figures are coarse:
a trip between two neighbouring countries is a few hundred km and the rules
only use jumps of at least 500 km. A country missing from the table gives no
distance. Without `country` on your events the travel and country facts stay
at their defaults, so send it (a CDN header such as `CF-IPCountry` will do).

## The rules

Workflow `account_takeover` listens to `session.login`,
`session.login_failed`, `session.password_reset`, `session.mfa_changed`,
`account.email_changed`, `account.phone_changed`, `resource.apikey_created`,
`payout.destination_changed`, `resource.exported` and `payment.method_added`.
Thresholds: `step_up_at = 30`, `hold_at = 60`, capped at `hold`.

| Rule | Fires when | Score |
|---|---|---|
| `ato_new_device_and_country` | a `session.login` from a device and a country never seen on the account | 40 |
| `ato_impossible_travel` | `travel_km >= 500`, `travel_kmh > 800`, and the IP is not in `vpn_ips` | 40 |
| `ato_sensitive_after_credential_change` | a payout destination change, API key creation, export, new payment method or email change less than 24 hours after a credential change | 60 |
| `ato_mfa_change_new_device` | `session.mfa_changed` from a new device | 60 |
| `ato_failed_logins` | more than 10 failed logins on the account in an hour (counter `ato_failed_logins_per_actor_1h`) | 30 |

Scores add up inside the workflow: a login that is both new-device-and-country
and impossible travel scores 80, which is a `hold`; alone each rule is a
`step_up`. A sensitive change straight after a password reset scores 60: a
`hold`.

What your application does with the answer: `step_up` means ask for proof
before continuing; `hold` means do not complete the login or the sensitive
change until the owner confirms through a channel you trust (the case also
shows in the admin interface for support). The account itself keeps its
status: it is not restricted.

## The `vpn_ips` list

```toml
[lists.vpn_ips]
kind = "ip"
items = ["192.0.2.0/24"]
```

An address in this list never counts as travel, since a VPN or a hosting
network moves a person across the world in a second. Fill it with the
ranges your users legitimately connect from (a corporate VPN, your own
offices). Items can also be added at run time with
`POST /v1/lists/vpn_ips/items`.

## Promoting a rule

Run in shadow for a few weeks, look at which accounts each `ato_*` rule hit
(admin Rules page, precision against labelled accounts), then promote rule
by rule. Start with the ones that fire rarely
(`ato_sensitive_after_credential_change`, `ato_mfa_change_new_device`); the
travel rule needs the `vpn_ips` list to be right first. A promoted rule is written as
`[overrides.ato_impossible_travel] mode = "act"`.

## The scenario

`examples/scenarios/core-account-takeover.jsonl` runs this story with
`# enforce` (every rule acts) and `# list: vpn_ips 192.0.2.0/24`:

1. The owner `own_1` logs in from home (BE, `dev_home`) twice: allowed, no
   rule fires.
2. Two hours later a login from the US on `dev_new` fires
   `ato_new_device_and_country` and `ato_impossible_travel` (score 80):
   decision `hold`, status stays `normal`, action `hold`.
3. The stranger resets the password: allowed.
4. Twenty minutes later `payout.destination_changed` fires
   `ato_sensitive_after_credential_change`: `hold`, and the account is
   not quarantined (`not_rules: ["actor_quarantined"]`).
5. The owner travels to Japan for real, on a home device through the company
   VPN (192.0.2.44, in `vpn_ips`): `ato_impossible_travel` does not fire.

```sh
openfraud simulate examples/scenarios/core-account-takeover.jsonl
```

Run it with the configuration of the repository; each line prints `ok` or
`MISMATCH` ([rules.md](rules.md) describes the file format).
