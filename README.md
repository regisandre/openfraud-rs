# openfraud

> Status: alpha. Works end to end; every pack rule ships in shadow mode and has scenarios.
> Last checked: 2026-10-20

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
- **Snoozes**: a rule that wrongly hits one good customer can be silenced
  for that account alone, for a while, straight from the case page.
- **Safe by construction**: a tenant's owner is never restricted for what a
  member did; a trusted (paying) account is held for a person, never
  blocked automatically. Only money earns that trust: an invoice paid with
  an amount of 0 (a trial's first invoice, a full discount) earns none, and
  a paid invoice of a workspace makes the workspace trusted for all its
  members; account takeover rules ask for proof or hold,
  never ban; a safety brake turns automatic restrictions into reviews when
  they spike.
- **Compliance built in**: a statement of reasons (EU Digital Services Act,
  art. 17) for every restriction, appeals, GDPR export and erasure,
  pseudonymized storage (keyed hashes; raw IPs and addresses are never
  stored), retention, an audit log.
- **Workflows you write**: rules are CEL expressions over the event, the
  actor, the tenant, counters, links and session facts, in a TOML file you
  can test with scenario files and replay against your history.
- **Signals computed locally**: the shape of an email address (script-typed,
  numbered, aliased with a `+tag`) measured before it is hashed; the user
  agent read into browser, system and automation flags (headless browsers,
  HTTP libraries, crawlers and AI crawlers) and never stored; a new system,
  browser or language on an account, and a login after months of silence;
  with the
  optional network table, the operator and registration country behind an
  IP; Tor exits, hosting providers, VPNs and abusive addresses from lists
  openfraud downloads only when you allow it. Every answer names its
  `signals` and three `scores` (account takeover, account abuse, bot). No
  call to a third party at decision time, except the optional DNS check that
  an email domain takes mail.
- **Lists that rules fill**: lists keyed on an account, a device, an email
  domain or a pair of them, with an expiry; rules add and archive items
  (`list.add:trusted_devices`), every change is kept with its author and
  sent as a webhook.
- **A device token and a challenge loop**: the browser script makes a
  single-use token per sensitive action, so a replayed request or a spoofed
  platform shows; a passed challenge trusts the device for 14 days.
- **Explore and look up**: filter and group the stored events from the
  admin interface or its API, and ask what openfraud knows of an IP.
- **Optional modules**: Stripe (webhooks in, card and subscription actions
  out), an AI assistant on any OpenAI-compatible API (case summaries, rule
  suggestions that always arrive in shadow), alerts to a webhook, Slack,
  Telegram or email.

**Contents**: [Quick start](#quick-start) | [How it decides](#how-it-decides) |
[Shadow and act](#shadow-and-act-how-a-rule-goes-live) | [Packs](#packs) | [Integrate](#integrate) | [A worked example](#a-worked-example) |
[Performance](#performance) | [Choose what to load](#choose-what-to-load) | [Sizing](#sizing) | [Security](#security) | [Documentation](#documentation) |
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

## Shadow and act: how a rule goes live

Every rule runs in one of two modes.

| Mode | What it does |
|---|---|
| `shadow` | evaluated on every event, changes nothing. The answer reports what it would have done in `shadow.decision` and `shadow.reasons`; the admin Rules page counts its hits over 30 days. Every pack rule ships in this mode. |
| `act` | its score and decision count: the answer's `decision` and `actions` change, cases open, webhooks and statements of reasons go out. |

A rule moves from shadow to act in four steps:

1. **Run in shadow** on real traffic. Call `/v1/decide` where it matters and
   ignore `decision`; log `shadow.decision` next to what your application
   did.
2. **Wait for history.** A promotion needs `[safety] replay_days` (30 by
   default) of stored events.
3. **Read the replay.** The admin Rules page, or `openfraud replay`, re-runs
   the last 30 days with the rule acting and shows its hits, the decisions it
   would have changed, and its precision and recall against the labels people
   gave (`fraud`, `legit`, `false_positive`).
4. **Promote** from the Rules page. The approval is tied to the rule's logic
   (`when`, `score`, `decision`, `actions`, `target`...): change it and the
   rule goes back to shadow until a new replay is approved. A change outside
   the rule (the workflow's thresholds, a counter, a list) keeps the
   approval, so replay again yourself after one. Setting `mode = "act"` by hand
   without that approval leaves the rule in shadow, flagged
   `pending_approval: true` in the answer.

To take a rule back out of action, set `[overrides.<rule id>] mode =
"shadow"`. Only the core's blocklists and trust rules act from the start: a
list you fill by hand is a decision a person already made.

Two guards stay on once rules act:

- **Trust protection**: an account or workspace that paid (trust 1 or more)
  is never blocked or quarantined automatically; the decision becomes a
  `hold` for a person.
- **Safety brake**: when automatic restrictions spike (more than
  `max_auto_per_hour`, or `baseline_multiple` times the weekly average), new
  restrictions become reviews until a person releases the brake in the admin.

Details: [docs/safety.md](docs/safety.md).

## Packs

| Pack | What it catches |
|---|---|
| [free-tier-and-trial](packs/free-tier-and-trial/README.md) | sign-up farms, throwaway mailboxes, script-typed, numbered and aliased addresses, one card or one cluster for many trials, trial cycles, upgrade-use-cancel, referral and promo farming |
| [card-and-payments](packs/card-and-payments/README.md) | card testing, prepaid and foreign cards, failed checks, cards of quarantined accounts, refund-rebuy loops, disputes, early fraud warnings |
| [messaging](packs/messaging/README.md) | inbox placement probes, trials used to raise a sending quota before anything is paid, shortened and blocked links, brand names in subjects, send bursts throttled, poor imported lists, bounce and complaint kill switch per sender, SMS pumping |
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

**Already have users?** Send `actor_created_at` (the date the account was
really created) with their events while you adopt openfraud. Without it an
account's age starts at its first event, and every rule about fresh
accounts fires on people who signed up years ago.

Actions come from a fixed vocabulary (`quarantine`, `release`, `hold`,
`suspend_feature:<name>`, `step_up`, `review`, `limit:<quota>`,
`throttle:<duration>`, `revoke_sessions`) and also
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

[`trial-quota-escalation.jsonl`](examples/scenarios/trial-quota-escalation.jsonl)
is the variant where the trial itself is the weapon: a plan with a higher
sending quota, a zero-amount trial invoice reported as paid, then a large
import before any money has changed hands. The zero invoice earns no trust,
and `msg_unpaid_trial` and `msg_trial_volume` hold the import for a
person; a paying workspace, owner and members alike, imports the same list
untouched.

### Design choices behind these rules

- **Trust comes from money only.** Trust protects an account from automatic
  restrictions, so it must cost the attacker something. A payment provider
  reports a trial's first invoice and a fully discounted invoice as paid
  with an amount of 0; `core_paid_invoice` ignores those. Send
  `attrs.amount` with `subscription.invoice_paid`.
- **The workspace pays, the workspace is trusted.** In a B2B product the
  subscription belongs to the tenant. `core_paid_invoice_tenant` raises
  `tenant.trust`, so a member who never paid personally is not treated as
  an unpaid stranger, and `tenant_since()` reads a member's action against
  the trial the owner started.
- **An unpaid trial is not a paid plan.** Rules about sending read "a trial
  started and nothing paid yet" rather than the plan name, because the plan
  is exactly what the attacker borrowed. Volume during that window (500
  recipients or more) is the quota-escalation signal; it holds for a
  person, it does not ban.
- **Existing users keep their age.** `actor_created_at` lets an application
  that adopts openfraud late give each account its real creation date; the
  first date learned wins, so a later claim cannot make an account look
  older than openfraud already knows it is.

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

## Choose what to load

Everything heavy is off until you turn it on, so a small server runs the
core in about 12 MB:

| What | Setting | Resident memory (measured) |
|---|---|---|
| core and the six packs | `packs = [...]` | 13 MB |
| network table (operator and country of an IP) | `[networks] enabled = true` | about +35 MB |
| downloaded lists (disposable domains, Tor, data centres, VPNs, abusive addresses) | `[server] fetch_lists = true` | about +20 MB |
| activity baselines (events per hour of each account, device and address against its usual hour) | `[core] activity = true` | grows with the accounts, devices and addresses seen in 7 days: about +100 MB at 100,000 accounts |
| SQLite page cache | always | grows with the database, up to 64 MiB |

The admin interface has a Features page with a switch for each of these
(and for the AI assistant and the Stripe module): a switch edits the
configuration file, keeping your comments, and applies at once.

See [docs/networks.md](docs/networks.md) for the network table and lists.

## Sizing

Measured on 0.11.2 in a Docker container limited to 2 CPUs, on an NVMe
host: 60,000 mixed events sent to `POST /v1/decide` by 8 concurrent
clients, over up to 100,000 accounts (sign-ups, logins, failed logins
without an account, cards, payments, messages, payouts, usage). "Full" is
the six packs, the network table and the downloaded lists.

| Configuration | Memory at rest | Memory after 60,000 events | Disk (database and log) | Decisions per second | CPU per 1,000 decisions |
|---|---|---|---|---|---|
| core | 13 MB | 91 MB | 178 MB | 520 to 700 | 1.5 to 1.8 s |
| full | 78 MB | 186 MB | 179 MB | 450 to 610 | 1.7 to 2.1 s |
| full and `[core] activity` | 78 MB | 284 MB | 179 MB | 450 to 600 | 1.7 to 2.0 s |

What to plan for:

- **Memory.** Start from the memory at rest of what you load, then add
  what traffic brings: the SQLite page cache (up to 64 MiB) and the
  counters, which grow with the accounts, devices and addresses seen in
  their windows. Resident memory does not go back down when traffic
  stops. Give a container at least 256 MB with the network table and the
  lists, 192 MB without them, and 384 to 512 MB with activity baselines
  over many accounts; a limit below the memory under load gets the
  process killed.
- **CPU.** Decisions run one at a time, so one instance uses about one
  core: roughly 500 decisions per second. More cores do not make one
  instance faster; they leave room for the background work and for other
  instances.
- **Disk.** About 3 KB per stored event in the database, kept for
  `retention_days` (90 by default): events per day x 3 KB x retention
  days. Add up to about 64 MiB for the write-ahead log, which is cut back
  once it passes that size ([docs/deploy.md](docs/deploy.md)). A fast
  disk matters more than CPU.
- **Latency.** The median decision takes 10 to 14 ms in this test, client
  and HTTP included. Each time the log is cut back, decisions wait for one
  disk sync: 16 to 35 ms on an NVMe disk, but hundreds of milliseconds on
  slow or virtualised disks, which then shows in the p99. Measure the p99
  on your own disk; the SDKs time out at 300 ms and fail open.
- **Several instances on one host.** Every instance loads its own network
  table, lists and page cache, so memory adds up per instance. Serve the
  downloaded lists and the network table from one mirror
  (`[server] lists_mirror`) to download them once; each instance still
  keeps its own copy in memory. Turn on the network table, the lists and
  activity only where rules use them.
- **What to watch.** Resident memory, free disk, the size of
  `openfraud.db-wal` (it should stay under about 64 MiB plus a second of
  writes) and the decide latency seen by your application. The admin
  overview (`GET /admin/api/overview`) gives the first three under
  `stats.storage`: `database_bytes`, `wal_bytes` and `resident_bytes`.

Before 0.11.2 the write-ahead log grew without end under steady traffic
(several gigabytes after 60,000 events); upgrade before sizing disks.

## Security

- The API needs an API key; the admin interface, on its own listener, the
  admin token. Keep the admin listener on loopback (SSH tunnel or an HTTPS
  reverse proxy).
- The state file holds the pseudonym key and the webhook secret: back it
  up and keep it private. API keys and the admin token are stored as
  SHA-256 digests.
- No third-party call by default: list downloads, the AI assistant and the
  Stripe module are off until you turn them on.

### Run it with CrowdSec, Fail2Ban, ClamAV, AIDE, Lynis and Trivy

openfraud judges what accounts do inside your product. It does not see the
traffic that never reaches your application (SSH brute force, port scans,
floods of requests to your login page), and it does not open the files your
users upload. Install these on the same server too:

- [CrowdSec](https://www.crowdsec.net): reads your web server and system
  logs, detects scans, brute force and scraping, and blocks the address at
  the firewall or the reverse proxy through a bouncer. It also shares a
  community blocklist of addresses seen attacking other servers. Enroll the
  server in the free [CrowdSec Console](https://app.crowdsec.net)
  (`cscli console enroll <key>`, the key comes from your Console account) to
  see its alerts and decisions in one dashboard and to subscribe to more
  blocklists. It is optional.
- [Fail2Ban](https://github.com/fail2ban/fail2ban): bans an address in the
  firewall after repeated failures in a log, SSH first of all.
- [ClamAV](https://www.clamav.net): scans uploaded files for malware
  (`clamd`, called from your upload handler). Send its result to openfraud
  as a `content.moderated` event (`verdict: "reject"` on a detection), and
  put the SHA-256 of a detected file in the `malware_hashes` list so the
  hosting-and-content pack quarantines whoever uploads it again.
- [AIDE](https://aide.github.io/): keeps a signed database of file
  hashes and permissions on the server and reports any file that changes
  afterwards, such as a tampered binary, a rewritten `openfraud.toml` or a
  planted script. Run it from cron or a systemd timer and send the report
  somewhere an intruder cannot edit.
- [Lynis](https://cisofy.com/lynis/): a one-off audit of the server
  (`lynis audit system`). It checks SSH, users, kernel settings, firewall
  and installed packages, gives a hardening score and lists what to fix.
  Run it after the first install and again after big changes.
- [Trivy](https://trivy.dev): scans the Docker image you run for known
  vulnerabilities in its packages, plus leaked secrets and misconfigurations
  (`trivy image ghcr.io/regisandre/openfraud-rs:<version>`). Scan again when
  you pull a new version, and on a schedule, since new CVEs are published
  against images that did not change.

They work at the network, file and host level, openfraud at the account level: a
stuffing run that CrowdSec slows down still reaches openfraud as failed
logins, and an address you block in CrowdSec can also go in openfraud's
`blocked_ips` list (`POST /v1/lists/blocked_ips/items`), whose core rule
blocks every event from it.

## Documentation

[Events](docs/events.md) | [Integration](docs/integration.md) |
[API](docs/api.md) | [Writing rules](docs/rules.md) | [Packs](docs/packs.md) |
[Shadow, replay and the safety brake](docs/safety.md) | [Link graph](docs/graph.md) |
[Account takeover](docs/account-takeover.md) | [Signals and scores](docs/signals.md) | [Networks](docs/networks.md) | [Compliance](docs/compliance.md) |
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
