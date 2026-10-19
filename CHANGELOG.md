# Changelog

> Status: maintained with every release.
> Last checked: 2026-10-19

## 0.1.0 - unreleased

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
- **Performance**: p50 1.5 ms, p99 2.8 ms per decision with every pack
  acting, after a 20,000-event history, on a Linux server limited to 2 CPUs
  (see README).
