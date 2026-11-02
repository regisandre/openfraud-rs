> Status: shipped in shadow mode, opt-in
> Last checked: 2026-11-02

# progressive-limits

## What it covers

Allowances that grow with the age of an account: a new account may create a
couple of pages, send a few messages and invite a few people on its first
day, a month-old one many times that, a paying one more still. See
[progressive limits](../../docs/limits.md) for how an allowance is computed.

## Events it needs

| Event | Counted per | Limit | Base | Day 1 | Day 7 | Day 30 |
|---|---|---|---|---|---|---|
| `resource.created` | account, 1 day | `ramp_creations` | 2 | 5 | 15 | 50 |
| `message.send_requested` | account, 1 day | `ramp_sends` | 3 | 10 | 40 | 150 |
| `message.send_requested` (`attrs.recipients_count`) | account, 1 day | `ramp_recipients` | 20 | 100 | 1,000 | 5,000 |
| `message.test_requested` | account, 1 day | `ramp_tests` | 3 | 10 | 30 | 30 |
| `resource.apikey_created` | account, 1 day | `ramp_apikeys` | 1 | 1 | 5 | 20 |
| `x.invitation_sent` | account, 1 day | `ramp_invitations` | 5 | 20 | 60 | 200 |
| `x.content_posted` | account, 1 hour | `ramp_posts` | 10 | 30 | 60 | 120 |
| `x.report_filed` | account, 1 day | `ramp_reports` | 5 | 15 | 50 | 50 |
| `x.follow_added` | account, 1 hour | `ramp_follows` | 30 | 60 | 120 | 300 |

A paying account (or one in a paying workspace) has 3 to 10 times these
numbers, and an account that ever scored 50 has half (not for tests and
reports). Send `actor_created_at` while you adopt openfraud on existing
accounts, or every account starts as new.

## Turn one on

Every limit ships in shadow: the answer's `limits` shows the allowance and
`shadow.decision` says what would be refused. After watching it for a while:

```toml
packs = ["progressive-limits"]

[limit_overrides.ramp_creations]
mode = "act"
```
