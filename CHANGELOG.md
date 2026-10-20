# Changelog

> Status: maintained with every release.
> Last checked: 2026-10-19

## 0.2.1 - 2026-10-20

- **Erasure**: deleting an account also deletes every outbox row (webhook
  or alert) that names it, sent or not, and removes it as the owner of the
  workspaces it owned. Its throttles were already deleted.
- **Retention**: throttles that have ended are deleted every minute, even
  with `retention_days = 0`, so an expired rate limit keeps no account id.

## 0.2.0 - 2026-10-19

- **Rate limits**: `throttle:<duration>`, a new action. When a rule that
  acts asks it, openfraud refuses the same event type from that account
  until the time is up: built-in rule `actor_throttled`, decision `block`,
  `retry_after` in the answer. A refused attempt does not extend it; a
  `release` lifts it. Kept in a new `throttles` table, so existing
  databases need nothing. `msg_send_burst` and `msg_test_burst` ask
  `throttle:1h`.
- **Sessions**: `revoke_sessions`, a new action: sign the account out
  everywhere. The account takeover workflow asks it with every hold.
- **messaging**: what a message says and links to. `attrs.subject` and
  `attrs.link_domains` on sends; rules `msg_shortener_link`,
  `msg_blocked_link` (decision `block`) and `msg_brand_subject`; lists
  `url_shorteners`, `blocked_domains` and `impersonated_brands`. Scenario
  `pack-messaging-content.jsonl`.
- **SDKs**: `hold_until` is a number of Unix seconds, as the server sends it
  (the Go SDK expected a string and could not read a hold with a length);
  `retry_after` added.

## 0.1.3 - 2026-10-19

- **Events**: `actor_created_at`, the date an account was really created,
  for products that adopt openfraud with an existing user base. Without it
  an account's age started at its first event, so rules about fresh
  accounts fired on every existing user. The first date learned is kept.
  In the TypeScript, Python and Go SDKs too. Scenario:
  `existing-accounts.jsonl`.

## 0.1.2 - 2026-10-19

- **Admin**: the Rules page failed with an internal error as soon as one
  event was stored (the 30-day hit count read the wrong key of the stored
  outcome). It now counts the hits again.

## 0.1.1 - 2026-10-19

- **Trust**: a `subscription.invoice_paid` with an `amount` of 0 (a trial's
  first invoice, a fully discounted one) no longer earns trust; forwarding
  such an invoice used to protect the account from automatic restrictions.
  A paid invoice that names a tenant now raises the tenant's trust too
  (`core_paid_invoice_tenant`), and rules read it as `tenant.trust`.
- **Rules**: `tenant_since("type")`, seconds since the tenant's first event
  of a type, so a member's action can be read against a trial the owner
  started.
- **messaging**: `msg_unpaid_trial` and `msg_trial_volume` catch a trial
  used to raise a sending quota before anything is paid; `msg_untrusted`
  stays silent for a member of a paying workspace. Scenario:
  `trial-quota-escalation.jsonl`.

## 0.1.0 - 2026-10-19

First release.

- **Core**: a versioned event vocabulary (`openfraud.event/v1`: account,
  session, payment, subscription, resource, message, payout, usage, content)
  plus custom types declared in `[events] custom`. Events carry an actor, a
  tenant and its owner; statuses, trust, scores and counters are kept per
  actor and per tenant.
- **API**: `POST /v1/decide` (synchronous, idempotent), `/v1/events` and
  `/v1/events/batch` (at-least-once with dedupe), actors, tenants, clusters,
  cases (resolve, appeal), statements of reasons, GDPR export and erasure,
  run-time lists. Signed webhooks (Standard Webhooks) for decisions, cases,
  status changes and the safety brake.
- **Link graph**: accounts sharing a card, payout destination, device,
  email, phone or custom domain (and, within a window, an IP /24) form a
  cluster, capped at `max_cluster` accounts. A fraud label opens a review
  case on the rest of the cluster, never a restriction.
- **Account takeover**: new device and country, impossible travel between
  country centres, sensitive changes within a day of a credential change.
  Step-up or hold only.
- **Safety**: rules asked to act wait in shadow until a 30-day replay is
  approved (logic changes, including the workflow's bands, withdraw the
  approval); the safety brake turns restrictions into reviews when they
  exceed an absolute threshold or a multiple of the weekly average.
- **Compliance**: statements of reasons for every restriction, appeals,
  labels (`fraud`, `legit`, `false_positive`) feeding per-rule precision and
  recall, pseudonymized storage, retention, audit log.
- **Packs**: free-tier-and-trial, card-and-payments, messaging,
  marketplace-and-payouts, api-and-compute, hosting-and-content. All rules
  ship in shadow, each with scenarios and a README.
- **Modules**: Stripe (off by default), AI assistant on an OpenAI-compatible
  API (off by default), alerts to webhook, Slack, Telegram and email with
  severity routing and digests.
- **Tools**: `openfraud serve | validate | packs | simulate | replay |
  admin-token | key`, an admin interface, SDKs for TypeScript, Python and
  Go, a device-id snippet, a Docker image.
- **Defaults**: the API listens on `127.0.0.1:8092` and the admin interface
  on `127.0.0.1:8093`, clear of the ports other self-hosted tools commonly use.
- **Configuration**: a hand edit of the configuration file is applied by the
  running server within a few seconds; an edit that does not validate is
  logged and the running configuration stays. `openfraud validate` warns
  when a counter window is longer than `retention_days`.
- **Retention and erasure**: inactive accounts and tenants are forgotten past
  `retention_days` unless restricted, labelled or with an open case; an
  erasure renames the audit entries to an anonymous marker and drops their
  notes.
- **Tests**: `e2e/run.sh` runs the TypeScript, Python and Go SDKs against a
  live server (decide, track, webhook signatures, fail-open) and checks a
  live configuration reload; CI runs it.
- **Security**: API keys have a scope (`full`, or `events` for a service
  that only sends events); an event dated in the future is refused; sum
  counters saturate instead of wrapping; long attribute values are hashed
  before they become counter keys; a case is appealed once; list files never
  echo their lines in errors; alert errors keep only the URL's origin (no
  Slack path, no Telegram token) and signed posts do not follow redirects;
  Slack alerts escape `<`, `>` and `&`; a blank Stripe webhook secret is
  refused, and the Go and Python SDKs refuse an empty webhook secret; CI
  checks the dependencies against RustSec advisories.
- **Performance**: a 64 MiB SQLite page cache and an index on recent link
  holders; `mentions()` matches a whole list in one pass. p50 1.7 ms, p99
  4.8 ms per decision with every pack acting after a 20,000-event history on
  a desktop, and p50 1.5 ms, p99 2.8 ms measured earlier on a Linux server
  limited to 2 CPUs (see README).
