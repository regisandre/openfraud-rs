> Status: shipped in 0.10.0, matches `builtin_signals` and `Scores` in src/engine.rs
> Last checked: 2026-10-20

# Signals and scores

Every answer of `POST /v1/decide` (and every stored decision) carries two
summaries next to the decision: `signals`, what the facts of the event show,
and `scores`, how much the rules that fired point to each kind of harm. They
explain a decision to a person and feed your own logic; neither changes the
decision by itself.

```json
"signals": {"new_device": {}, "tor_ip": {}, "credential_stuffing": {}},
"scores": {"account_takeover": 0.6, "account_abuse": 0.0, "bot": 0.3}
```

## Signals

A signal is a name. The answer lists it as a key (its value is an empty
object, kept for details later). Rules read the same names before they run:
`"tor_ip" in signals`.

| Signal | When |
|---|---|
| `new_device`, `new_country`, `new_os`, `new_browser`, `new_language`, `new_device_type` | the account's first event with that value, after it had another (the `session.new_*` facts) |
| `new_isp` | a network operator (AS) never seen on the account (`session.new_asn`) |
| `impossible_travel` | at least 500 km from the account's last place, faster than 800 km/h |
| `tor_ip` | the address is in `tor_exits` |
| `datacenter_ip` | the address is in `datacenter_ips` |
| `vpn_access` | the address is in `vpn_providers` or `vpn_ips` |
| `abuse_ip` | the address is in `abuse_ips` ([networks.md](networks.md)) |
| `multiple_accounts_per_device` | another account used this device |
| `multiple_aliases_per_email` | a tagged address (`name+tag@`) whose mailbox another account uses |
| `invalid_email` | the address could not be read |
| `unreachable_email` | the domain takes no mail (with `[email] mx_check`) |
| `disposable_email_domain` | the domain is in `disposable_domains` |
| `fraudulent_email_domain` | the registered domain is in `fraud_email_domains` (below) |
| `generated_email`, `low_quality_email` | the local part looks generated, or has no vowel ([events.md](events.md)) |
| `missing_device_data` | no device token, with `[device] require_token` |
| `invalid_device_data` | a device token that cannot be read, or too old |
| `replayed_device_data` | a device token used before for the same event type |
| `headless_browser` | an automated browser: the user agent says so, or the device token's `webdriver` flag |
| `spoofed_device` | the user agent's system differs from the platform the device token measured |
| `timezone_area_mismatch` | the device's time zone area is far from the event's country |
| `http_client_library`, `web_crawler`, `ai_crawler`, `missing_headers` | what the user agent says (`event.agent`) |
| `high_activity_account`, `high_activity_device`, `high_activity_ip` | more than 20 events in the hour and five times the usual hour of the last 7 days (with `[core] activity = true`) |

A rule adds its own with `signal = "credential_stuffing"`: the name is listed
whenever the rule fires, acting or in shadow. The core uses it for
`credential_stuffing`.

### Email domains of known fraud

When a person labels two accounts as fraud whose addresses share a registered
domain (any subdomain of `fraudco.net` counts as `fraudco.net`, read with
the Public Suffix List), the domain goes on the `fraud_email_domains` list
for 90 days. A free mailbox provider (gmail.com, outlook.com ...) is never
listed. Switch it off with `[core] email = false`.

## Scores

Three numbers from 0 to 1, rounded to two decimals:

| Score | Rules counted |
|---|---|
| `account_takeover` | rules of workflows with `family = "takeover"` (the core's `account_takeover`, the api pack's `api_logins`) |
| `account_abuse` | every other workflow's rules (the default family) |
| `bot` | rules with `family = "bot"`: automation, replayed and spoofed device data |

Each rule that fired, acting or in shadow, adds its score over 100, or more
when it forces a decision: 1 for `block` or `quarantine`, 0.8 for `hold`,
0.6 for `review`, 0.4 for `step_up`. The sum stops at 1. A rule's `family`
overrides its workflow's.

A score is a summary of your rules, not a trained model: two rules of 30
points make 0.6 whatever data stands behind them. Shadow rules count, so the
scores move before a rule is promoted.

## Configuration

```toml
[core]
activity = false   # the three activity counters, kept 7 days per account, device and address
email = true       # fraud_email_domains

[email]
mx_check = false            # ask DNS whether the domain takes mail
resolver = "1.1.1.1:53"
timeout_ms = 800

[device]
require_token = false       # an event without a device token is missing_device_data
token_lifetime = "120s"     # older tokens are stale
```

`mx_check` sends the domain (never the address) to the resolver; answers are
kept a day, at most 100,000 domains. Point `resolver` to your own when the
host should not reach a public one.
