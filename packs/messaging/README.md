> Status: shipped in shadow mode, opt-in
> Last checked: 2026-10-19

# messaging

## What it covers

Abuse of email, SMS and push sending: inbox placement probes from fresh
accounts, poor imported lists, bursts of sends and test sends, a kill switch on
bounce and complaint rates (per sender and per campaign), and SMS pumping.

## Events it needs

| Event | Attrs read |
|---|---|
| `message.send_requested`, `message.test_requested` | `attrs.recipients` (a list of addresses or phone numbers), `attrs.channel`, `email` of the sender |
| `message.contacts_imported` | `attrs.recipients`, `attrs.count`, `attrs.recipients_count`, `attrs.recipients_shape` (computed, see below), `attrs.bounced_before` |
| `message.delivered`, `message.bounced`, `message.complained` | `tenant_id` (the sender), `subject` (the campaign), `attrs.count` (how many at once) |
| `message.otp_requested` | `phone` (E.164), `ip` |

`recipients` is pseudonymized before any rule runs (the domain or the country
prefix stays; the sample `openfraud.toml` lists `recipients` in
`[privacy] contact_attrs`). Before that, the engine measures the list and
adds `recipients_shape`: `count` (items), `roles` (function mailboxes such
as admin@, info@, noreply@), `invalid` (neither an address nor a phone
number), `prefixes` (phone country prefixes) and `longest_run` (consecutive
phone numbers). `msg_poor_list` and `sms_sequential_numbers` read it. Send
the list itself, up to your body size limit: the shape is only as good as
the sample.

## Rules

All rules ship in `mode = "shadow"`.

### Workflow `msg_sending` (on sends, test sends, imports)

Bands: review at 40, hold at 60, quarantine at 100.

| Rule | Catches | Score |
|---|---|---|
| `msg_inbox_probe` | 2 to 10 recipients, all at free mailbox providers, at least 3 different providers | 70 |
| `msg_to_self` | 2 or more recipients that look like the sender's own address | 30 |
| `msg_fresh_account` | account under a day old | 20 |
| `msg_very_fresh_account` | account under an hour old | 15 |
| `msg_untrusted` | the account never paid (`actor.trust == 0`) | 10 |
| `msg_risky_account` | the account already scored 50 or more | 25 |
| `msg_fresh_import` | a send within 10 minutes of a contact import | 15 |
| `msg_send_burst` | more than 10 sends in a day | 30 |
| `msg_test_burst` | more than 5 test sends in a day | 30 |
| `msg_poor_list` | 20 or more imported addresses, over a fifth role or invalid | 40 |
| `msg_disposable_list` | 20 or more imported addresses, over a tenth throwaway domains | 40 |
| `msg_seen_bouncing` | `count` of 20 or more, over a tenth with `bounced_before` | 40 |

### Workflow `msg_reputation` (on bounces and complaints)

Review at 40, hold at 60. The sender rules act on the tenant.

| Rule | Catches | Score or decision |
|---|---|---|
| `msg_sender_bounces` | 50 or more delivered today and 5 percent or more bounced | `hold` on the tenant, `suspend_feature:email` |
| `msg_sender_complaints` | 50 or more delivered today and 0.1 percent or more complaints | `hold` on the tenant, `suspend_feature:email` |
| `msg_campaign_bounces` | 50 or more delivered in 7 days and 5 percent or more bounced | 50 |
| `msg_campaign_complaints` | 50 or more delivered in 7 days and 0.1 percent or more complaints | 50 |

### Workflow `msg_sms` (on OTP requests and sends)

Step-up at 30, hold at 60, block at 80.

| Rule | Catches | Score |
|---|---|---|
| `sms_country_not_allowed` | phone prefix not in `sms_allowed_prefixes` (silent while the list is empty) | 60 |
| `sms_prefix_flood` | 10 or more codes to one number range (`+` and 6 digits) in an hour | 60 |
| `sms_ip_flood` | more than 20 codes from one IP in an hour | 40 |
| `sms_sequential_numbers` | 5 or more consecutive numbers in `recipients` | 60 |

## Counters and lists

Counters: `msg_sends_per_actor_1d`, `msg_tests_per_actor_1d`,
`msg_delivered_per_tenant_1d`, `msg_bounced_per_tenant_1d`,
`msg_complaints_per_tenant_1d`, the three `..._per_campaign_7d` counterparts,
`msg_otp_per_prefix_1h`, `msg_otp_per_ip_1h`. Feed the delivered, bounced and
complained counts from your provider's webhooks.

Lists:

- `disposable_domains` (domain): downloaded only with `[server] fetch_lists = true`.
  Empty until then, so `msg_disposable_list` stays silent.
- `sms_allowed_prefixes` (prefix): empty until you fill it with the calling
  codes you send to (`+32`, `+33`). While empty, every destination is allowed
  and `sms_country_not_allowed` stays silent.

## Turn it on

```toml
packs = ["messaging"]
```

## Tune

```toml
[overrides.msg_untrusted]
enabled = false

[overrides.msg_send_burst]
score = 20
```

Rules cannot be edited in place; thresholds such as the 5 percent bounce rate
are in the rule and cannot be overridden. Disable the rule to replace it.

## Promote a rule from shadow to act

Run in shadow, open the Rules page of the admin interface, review the 30-day
replay of the rule, then promote it. Promote the sender rules of `msg_reputation`
last: they suspend a whole tenant's email.

## Known false positives

- A genuine organiser testing a campaign on a few of their own free-mail
  addresses: `msg_inbox_probe`, `msg_to_self`, `msg_test_burst`.
- Young accounts are normal at launch: `msg_fresh_account`, `msg_very_fresh_account`,
  `msg_untrusted` add up to 45 points on any send in the first hour, which is
  already a review. Consider lowering them if sellers send right after sign-up.
- An old list full of `info@` and `contact@` addresses (clubs, venues):
  `msg_poor_list`.
- A big first send after a long-ago import: `msg_seen_bouncing`.
- A small sender (50 delivered) with a few bounces trips the sender kill switch:
  `msg_sender_bounces`.
- Consecutive numbers in a legitimate company line range: `sms_sequential_numbers`.
- A shared office IP requesting many codes: `sms_ip_flood`.
- The safety brake turns restrictions into reviews when they spike.

## Scenarios

- `examples/scenarios/pack-messaging-sending.jsonl`: probe, own-address, import-then-send, bursts, poor lists, a paying organiser as control.
- `examples/scenarios/pack-messaging-reputation.jsonl`: bounce and complaint kill switch.
- `examples/scenarios/pack-messaging-sms.jsonl`: SMS pumping.
- `examples/scenarios/pack-messaging-shadow.jsonl`: shadow behaviour.
- `examples/scenarios/trial-probe.jsonl`, `trial-probe-shadow.jsonl`, `probe-without-trial.jsonl`: the probe with other packs.

Run them with `cargo test --test scenarios`.
