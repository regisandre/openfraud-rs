> Status: shipped in 0.1, matches core/account-takeover.toml and src/engine.rs
> Last checked: 2026-10-29 (0.11.0: attempts never act on the account they match)

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
would do and acts only after you promote its rules ([safety.md](safety.md)):
these core rules are not promoted by themselves, unlike the rules of a pack.

To switch it off entirely: `[core] account_takeover = false`.

## Session facts

For every event with an `actor_id`, rules read the object `session`
([rules.md](rules.md)):

| Fact | Meaning |
|---|---|
| `session.new_device` | the event has a `device` and the account has used other devices before, but never this one. False on an account's first device |
| `session.new_country` | the event has a `country`, the account has been seen in other countries, and never this one |
| `session.new_asn` | the event's IP is announced by a network operator the account never used, and it has used others; needs the network table ([networks.md](networks.md)) |
| `session.new_os`, `session.new_browser`, `session.new_language` | the event's `user_agent` (or `language`) shows a system, a browser or a language the account never used, and it has used others |
| `actor.idle` | seconds since the account's previous event |
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

Workflow `account_takeover` (`family = "takeover"`) listens to `session.login`,
`session.login_failed`, `session.password_reset`, `session.mfa_changed`, `challenge.failed`,
`account.email_changed`, `account.phone_changed`, `resource.apikey_created`,
`payout.destination_changed`, `resource.exported` and `payment.method_added`.
Thresholds: `step_up_at = 30`, `hold_at = 60`, capped at `hold`.

| Rule | Fires when | Score |
|---|---|---|
| `ato_new_device_and_country` | a `session.login` from a device and a country never seen on the account | 40 |
| `ato_new_device_and_network` | a `session.login` from a device and a network operator never seen on the account | 30 |
| `ato_tor_login` | a `session.login` from a Tor exit (`tor_exits`) | 30 |
| `ato_automated_login` | a `session.login` or `session.login_failed` sent by an automated browser or an HTTP library (`event.agent`) | 30 |
| `ato_dormant_return` | a `session.login` after 180 days without any event, from a new device | 30 |
| `ato_impossible_travel` | `travel_km >= 500`, `travel_kmh > 800`, and the IP is in none of `vpn_ips`, `vpn_providers`, `datacenter_ips`, `tor_exits` | 40 |
| `ato_sensitive_after_credential_change` | a payout destination change, API key creation, export, new payment method or email change less than 24 hours after a credential change | 60 |
| `ato_mfa_change_new_device` | `session.mfa_changed` from a new device | 60 |
| `ato_failed_logins` | more than 10 failed logins on the account in an hour (counter `ato_failed_logins_per_actor_1h`) | 30 |
| `ato_trusted_device` | a `session.login` from a device on `trusted_devices` for this account | `allow` |
| `ato_failed_challenges` | three `challenge.failed` on the account within an hour | 60 |
| `ato_stuffing_ip` | more than 10 different email addresses failed to sign in from one address in an hour; signal `credential_stuffing` | 60 |
| `ato_stuffing_network` | a network operator whose failed sign-ins in the hour are more than 10 and ten times its successful ones; signal `credential_stuffing` | 30 |
| `ato_replayed_device_token` | a login with a device token used before (`replayed_device_data`); family `bot` | 60 |
| `ato_spoofed_device` | a login whose user agent's system differs from the one the device token measured (`spoofed_device`); family `bot` | 30 |

`ato_automated_login`, `ato_replayed_device_token` and `ato_spoofed_device`
count towards the `bot` score of the answer, the others towards
`account_takeover` ([signals.md](signals.md)).

## Trusted devices and challenges

After a `step_up`, tell openfraud how the proof went: `challenge.requested`,
then `challenge.succeeded` or `challenge.failed`, with the account and the
device. A passed challenge puts the pair (account, device) on the
`trusted_devices` list for 14 days, through the rule `challenge_trusts_device`
of the workflow `core_challenges`, which acts from the start and decides
nothing. The next logins from that device are allowed by `ato_trusted_device`
instead of asking for proof again; each new pass restarts the 14 days.
Repeated failures are `ato_failed_challenges`.

A device stays trusted for one account only: the same device on another
account is a new device there. Archive a pair through
`POST /v1/lists/trusted_devices/items/archive` when the owner reports a lost
device.

## Credential stuffing

Most stuffing attempts come before sign-in: a `session.login_failed` with an
email and no actor. Send them anyway. `ato_stuffing_ip` counts the different
addresses tried from one IP; `ato_stuffing_network` compares a network's
failures with its successes, for attacks spread across many IPs of one
provider. When the email belongs to an account, the answer names it in
`matched_actor`, and rules read it as `matched` (`matched.flagged`,
`matched.status` ...).

These attempts never act on the account they match: an attacker who
types a victim's address a thousand times must not push the victim toward
a challenge, a hold or a quarantine. An event without an actor, or one
marked `"reported_by": "client"`, does not count under the account's keys
(`actor`, `email`, `phone`, `cluster`), writes none of them on a list, and
carries no action for the account; it never adds or removes a trusted
device. The stuffing counters key on the sender's address and network, so
they keep working. See [integration.md](integration.md).

## Device token

`deviceToken()` from `sdk/device` gives the page a fresh token for each
sensitive action; send it as `device_token`. openfraud checks that it is
recent (`[device] token_lifetime`, 120 s) and was not used before for the
same event type, and reads the time zone, the platform and the automation
flag it carries. A script served from your own site holds no secret, so the
token proves freshness and single use, not authenticity: a determined
attacker can forge one. It still stops replaying a captured request and
catches automated browsers that do not hide.

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
