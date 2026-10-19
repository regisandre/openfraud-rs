# openfraud

> Status: alpha. Works end to end; every pack rule ships in shadow mode and has scenarios.
> Last checked: 2026-10-19

Self-hosted fraud and abuse engine for SaaS, in one Rust binary with an
embedded SQLite database. Your application sends events (a sign-up, a
login, a card added, a send, a payout); openfraud answers with a decision
(`allow`, `step_up`, `review`, `hold`, `block`, `quarantine`), the reasons,
and the actions to take, and opens a case for a person when it matters.
Nothing leaves your server unless you turn a module on.

- **A generic core**: a versioned event vocabulary, scores and counters per
  actor and per tenant, a link graph that clusters accounts sharing a card,
  a device or a payout destination, account takeover signals, a fixed action
  vocabulary delivered as signed webhooks, cases, labels and appeals.
- **Opt-in rule packs** for the abuse each kind of product sees: free tiers
  and trials, cards and payments, messaging, marketplaces and payouts, APIs
  and compute, hosting and content. Every pack rule ships in shadow mode: it
  says what it would do, and acts only after a person promotes it on a
  30-day replay.
- **Safe by construction**: a tenant's owner is never restricted for what a
  member did; a trusted (paying) account is held for a person, never
  blocked automatically; account takeover rules ask for proof or hold,
  never ban; a safety brake turns automatic restrictions into reviews when
  they spike.
- **Compliance built in**: a statement of reasons (EU Digital Services Act,
  art. 17) for every restriction, appeals, GDPR export and erasure,
  pseudonymized storage (keyed hashes; raw IPs and addresses are never
  stored), retention, an audit log.
- **Workflows you write**: rules are CEL expressions over the event, the
  actor, the tenant, counters, links and session facts, in a TOML file you
  can test with scenario files and replay against your history.
- **Optional modules**: Stripe (webhooks in, card and subscription actions
  out), an AI assistant on any OpenAI-compatible API (case summaries, rule
  suggestions that always arrive in shadow), alerts to a webhook, Slack,
  Telegram or email.

**Contents**: [Quick start](#quick-start) | [How it decides](#how-it-decides) |
[Packs](#packs) | [Integrate](#integrate) | [A worked example](#a-worked-example) |
[Performance](#performance) | [Security](#security) | [Documentation](#documentation) |
[Development](#development)

## Quick start

You need Rust 1.92 or later ([rustup](https://rustup.rs)).

```sh
git clone https://github.com/regisandre/openfraud-rs
cd openfraud-rs
cargo build --release
./target/release/openfraud serve
```

The first start writes `openfraud.toml`, creates the state file (pseudonym
key, webhook secret) and prints the admin token once. The API listens on
`127.0.0.1:8092`, the admin interface on `127.0.0.1:8093`.

```sh
./target/release/openfraud key add my-backend        # prints an API key once
curl -s localhost:8092/v1/decide \
  -H "authorization: Bearer <key>" -H "content-type: application/json" \
  -d '{"type": "account.created", "actor_id": "u_1", "email": "someone@example.com", "ip": "203.0.113.7"}'
```

With Docker: `docker build -t openfraud .` then
`docker run -d -v openfraud-data:/data -p 8092:8092 -p 127.0.0.1:8093:8093 openfraud`
(`docker logs` shows the admin token).

Turn on the packs that match your product in `openfraud.toml`:

```toml
packs = ["free-tier-and-trial", "card-and-payments", "messaging"]
```

## How it decides

For each event, openfraud:

1. normalizes it: addresses, phone numbers, IPs, devices and identifier
   attributes become keyed pseudonyms; contact lists are measured (count,
   role addresses, invalid entries) before that;
2. gathers the facts rules read: the actor and the tenant (age, trust,
   status, best score), sliding-window counters, the accounts sharing each
   identifier and the cluster they form, account takeover signals (new
   device, new country, impossible travel, a sensitive change soon after a
   credential change);
3. runs every workflow listening to the event type. Rules add a score or
   force a decision; the score falls into the workflow's bands
   (`step_up_at`, `review_at`, `hold_at`, `block_at`, `quarantine_at`);
4. decides whom it restricts: the actor, or the tenant when its owner acted;
5. remembers it all in one transaction and queues the webhooks, alerts and
   module actions.

A retry with the same event id (or `Idempotency-Key`) gets the first answer
back and counts nothing. Clients fail open: on a timeout they proceed and
send the event again through `/v1/events`.

## Packs

| Pack | What it catches |
|---|---|
| [free-tier-and-trial](packs/free-tier-and-trial/README.md) | sign-up farms, throwaway mailboxes, one card or one cluster for many trials, trial cycles, upgrade-use-cancel, referral and promo farming |
| [card-and-payments](packs/card-and-payments/README.md) | card testing, prepaid and foreign cards, failed checks, cards of quarantined accounts, refund-rebuy loops, disputes, early fraud warnings |
| [messaging](packs/messaging/README.md) | inbox placement probes, poor imported lists, bounce and complaint kill switch per sender, SMS pumping |
| [marketplace-and-payouts](packs/marketplace-and-payouts/README.md) | new-seller exit risk (7-day payout hold), payout destination changes, bulk buying across linked accounts, seller refund and dispute rates |
| [api-and-compute](packs/api-and-compute/README.md) | leaked or resold keys, usage far above plan, free-credit farming, credential stuffing, mining-shaped compute |
| [hosting-and-content](packs/hosting-and-content/README.md) | phishing and brand impersonation pages, known-bad files, link spam, mass creation, outside moderation verdicts, user reports |

The core runs with no pack on: blocklists you fill by hand, trust earned by
paying, account takeover signals. Packs of your own go in `packs_dir`.

## Integrate

Call `POST /v1/decide` before a sensitive action and act on the answer:

```json
{
  "decision": "quarantine",
  "score": 140,
  "reasons": [{"rule": "msg_inbox_probe", "workflow": "msg_sending", "score": 70, "reason": "A handful of addresses, one per big mailbox provider: an inbox placement probe", "mode": "act"}],
  "actions": [{"action": "quarantine", "target": "actor", "id": "u_123"}],
  "case_id": 42,
  "statement_id": "st_9f2c...",
  "shadow": {"decision": "quarantine", "reasons": []}
}
```

Actions come from a fixed vocabulary (`quarantine`, `release`, `hold`,
`suspend_feature:<name>`, `step_up`, `review`, `limit:<quota>`) and also
arrive as signed webhooks (Standard Webhooks), with case and status changes.
SDKs for TypeScript, Python and Go, and a device-id snippet, are in
[`sdk/`](sdk). See the [integration guide](docs/integration.md) and the
[API](docs/api.md).

## A worked example

[`examples/scenarios/trial-probe.jsonl`](examples/scenarios/trial-probe.jsonl)
replays a real attack on an event platform: a fresh account signs up,
creates a page and a team, starts a paid-plan trial with a foreign debit
card in someone else's name, turns on email marketing and imports four
addresses of its own, one per big mailbox provider, to test inbox placement
before a spam run. With the packs acting, the trial is put on the free
plan's quotas for review and the account is quarantined at the contact
import, before any mail leaves; when the same person returns with a new
account and the same card, the trial is refused at once.
`trial-probe-shadow.jsonl` is the same attack with the packs as they ship:
nothing is restricted, and each answer says what would have happened.

```sh
openfraud simulate examples/scenarios/trial-probe.jsonl
```

## Performance

One engine lock serializes decisions; each one is a handful of indexed
SQLite reads and one transaction (WAL, checkpoints on a background thread).
`cargo run --release --example bench` replays a mixed synthetic history
with all six packs on and every rule acting, on a database file. 5,000
decisions after a 20,000-event history:

| Machine | p50 | p95 | p99 | max |
|---|---|---|---|---|
| Linux VPS, container limited to 2 CPUs | 1.5 ms | 2.2 ms | 2.8 ms | 6.4 ms |
| Windows 11 desktop, 16 cores, NVMe | 1.7 ms | 3.4 ms | 4.8 ms | 12.3 ms |

Decisions run one at a time, so a small server is enough as long as the
disk is fast. Run `cargo run --release --example bench -- 20000 5000` to
measure yours. The synthetic
history is harsh on the link graph (random identifiers chain every account
into capped clusters); most of the time goes there. The budget is p99 under
50 ms.

## Security

- The API needs an API key; the admin interface, on its own listener, the
  admin token. Keep the admin listener on loopback (SSH tunnel or an HTTPS
  reverse proxy).
- The state file holds the pseudonym key and the webhook secret: back it
  up and keep it private. API keys and the admin token are stored as
  SHA-256 digests.
- No third-party call by default: list downloads, the AI assistant and the
  Stripe module are off until you turn them on.

### Run it with CrowdSec and Fail2Ban

openfraud judges what accounts do inside your product. It does not see the
traffic that never reaches your application: SSH brute force, port scans,
floods of requests to your login page. Install these on the same server
too:

- [CrowdSec](https://www.crowdsec.net): reads your web server and system
  logs, detects scans, brute force and scraping, and blocks the address at
  the firewall or the reverse proxy through a bouncer. It also shares a
  community blocklist of addresses seen attacking other servers.
- [Fail2Ban](https://github.com/fail2ban/fail2ban): bans an address in the
  firewall after repeated failures in a log, SSH first of all.

They work at the network level, openfraud at the account level: a
stuffing run that CrowdSec slows down still reaches openfraud as failed
logins, and an address you block in CrowdSec can also go in openfraud's
`blocked_ips` list (`POST /v1/lists/blocked_ips/items`), whose core rule
blocks every event from it.

## Documentation

[Events](docs/events.md) | [Integration](docs/integration.md) |
[API](docs/api.md) | [Writing rules](docs/rules.md) | [Packs](docs/packs.md) |
[Shadow, replay and the safety brake](docs/safety.md) | [Link graph](docs/graph.md) |
[Account takeover](docs/account-takeover.md) | [Compliance](docs/compliance.md) |
[Alerts](docs/alerts.md) | [Stripe module](docs/stripe.md) | [AI assistant](docs/ai.md) |
[Deploy](docs/deploy.md)

## Development

```sh
cargo test                 # unit, API and scenario tests
cargo clippy --all-targets -- -D warnings
cargo run -- simulate examples/scenarios/<file>.jsonl
bash e2e/run.sh            # the SDKs against a live server (Node, Python, Go)
```

Every rule or behaviour comes with a scenario in `examples/scenarios` that
the test suite runs. Licensed under Apache-2.0; see [NOTICE](NOTICE) for
third-party data.
