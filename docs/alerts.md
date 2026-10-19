> Status: shipped in 0.1, matches src/alerts.rs, src/engine.rs and src/outbox.rs
> Last checked: 2026-10-19

# Alerts

Alerts tell people that something needs a look: a case, a quarantine, the
safety brake. They are separate from the decision webhooks, which tell your
application what to do ([api.md](api.md)). Configure one or more notifiers
with `[[alerts]]`; with none, no alert is sent.

## Notifiers

Common keys: `kind`, `min_severity` (`info`, `warning` or `critical`; default
`warning`) and `digest` (optional duration).

### `webhook`

A signed JSON POST, with the same Standard Webhooks headers as the decision
webhooks and the secret of the state file. Use it to feed your own paging
tool.

```toml
[[alerts]]
kind = "webhook"
url = "https://ops.example.com/openfraud-alerts"
min_severity = "critical"
```

Body: `{"type": "alert", "timestamp": "...", "data": {"notifier", "severity", "title", "text", "at", "digest"}}`.

### `slack`

A Slack incoming webhook URL; the message is `*<title>* (<severity>)` and the
text.

```toml
[[alerts]]
kind = "slack"
url = "https://hooks.slack.com/services/T000/B000/XXXX"
min_severity = "warning"
digest = "1h"
```

### `telegram`

The Bot API `sendMessage`. The token is never in the file: `bot_token_env`
names the environment variable that holds it.

```toml
[[alerts]]
kind = "telegram"
bot_token_env = "OPENFRAUD_TELEGRAM_TOKEN"
chat_id = "-1001234567890"
min_severity = "critical"
# api_base = "https://api.telegram.org"   # a proxy or a test double
```

Required: `bot_token_env` and `chat_id`.

### `email`

Mail through an SMTP server.

```toml
[[alerts]]
kind = "email"
smtp_host = "smtp.example.com"
smtp_port = 587
smtp_tls = "starttls"             # starttls (default) | tls | none
username_env = "OPENFRAUD_SMTP_USER"
password_env = "OPENFRAUD_SMTP_PASSWORD"
from = "openfraud@example.com"
to = ["fraud-team@example.com", "oncall@example.com"]
min_severity = "warning"
```

Required: `smtp_host`, `from`, a non-empty `to`. `smtp_tls = "tls"` is
implicit TLS (usually port 465), `starttls` upgrades a plain connection, and
`none` sends in clear and is only for a relay on localhost. Without
`smtp_port` the transport's default for the mode is used. Credentials are
read from the environment variables named by `username_env` and
`password_env` when `username_env` is set; leave both out for a relay that
needs none. The subject is `[openfraud] <severity>: <title>`.

## Routing by severity

Each alert is queued once per notifier whose `min_severity` it reaches. The
configuration is checked at load: a notifier missing a required key, or with
a bad `digest`, is refused.

| Severity | Raised when |
|---|---|
| `info` | a case is opened for an actor or a tenant (`Case opened`); a user's appeal is forwarded (`Appeal`) |
| `warning` | the engine quarantines an account on its own (`Account quarantined`, with the score and the reasons) |
| `critical` | the safety brake engages (`Safety brake engaged`) |

A quarantine decided by a person (a fraud label) raises no alert; neither
does a tenant quarantine.

A good starting point: Telegram or a webhook at `critical`, Slack or email at
`warning` with a one-hour digest, and `info` only where someone reads it.

## Digest

With `digest = "1h"` a notifier does not send each alert at once. Alerts
below `critical` are kept, and about once a minute the server checks whether
the period is over; if so it sends **one** message titled `N alerts` that
lists each as `- <time> <title>: <text>`, with the worst severity of the
group. **Critical alerts are never delayed**: they bypass the digest and go
out at once.

## Delivery

Alerts go through the same outbox as webhooks: they are written in the same
transaction as the decision, delivered by a background worker every two
seconds, and retried on failure (8 attempts, from 5 seconds to a few hours)
before being marked failed. Each attempt has a 10-second timeout. A failed
delivery is visible in the admin interface (outbox) and in the log. If you
reorder or remove `[[alerts]]` entries, alerts still waiting for an entry
that no longer exists are dropped, because they refer to a notifier by its
position.
