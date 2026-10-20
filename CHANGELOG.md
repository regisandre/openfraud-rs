# Changelog

> Status: maintained with every release.
> Last checked: 2026-10-20

## 0.11.2 - 2026-10-20

- **The write-ahead log no longer grows without end**: under steady traffic
  the passive checkpoint of the background thread never caught up, so
  `openfraud.db-wal` grew by about 25 KB per event (5 GB after 60,000
  events in a load test, for a 130 MB database) and every read slowed
  down with it. Once the log passes 64 MiB, the engine now copies what
  the background checkpoints left and cuts the file back to zero, between
  two decisions (one sync: 16 to 35 ms on an NVMe disk). In the same load
  test the database and its log end at 180 MB. The engine's transactions
  now take the write lock first (immediate), so a checkpoint running
  meanwhile makes them wait instead of fail.
- **TLS dependencies**: `rustls-webpki` 0.103.16 and `webpki-roots` 1.0.10
  (RUSTSEC-2026-0382, RUSTSEC-2026-0381: distrusted intermediates), used
  when openfraud downloads lists and the network table.

## 0.11.1 - 2026-10-20

- **Pack counters keyed on one account's id**: the counters of the shipped
  packs keyed on an attribute that names one account
  (`api_ips_per_key_1h`, `api_countries_per_key_1d` and
  `api_end_users_per_key_1d` on `attrs.key_id` in `api-and-compute`,
  `trial_referrals_per_referrer_1d` on `attrs.referrer_id` in
  `free-tier-and-trial`) count only events the server reported for an
  account. Before, a burst of events without an actor, or reported by a
  page, naming someone's API key or referral could fire `api_key_many_ips`,
  `api_key_many_countries`, `api_key_resale` or `referral_burst` on that
  account. 0.11.0 guards the built-in keys only; a key of your own is
  guarded the same way (see integration.md).

## 0.11.0 - 2026-10-20

- **Attempts never act on the account they match**: an event without an
  actor (a failed sign-in, a password reset typed by a visitor) no longer
  counts under a key that names one account (`actor`, `cluster`, `email`,
  `email_alias`, `phone`), and no longer writes such a key on a list.
  Before, a burst of failed sign-ins carrying a victim's address could
  raise the victim's own counters and lists, and change the decision on the
  victim's next real login. Counters on the sender's address, network,
  device and email domain keep counting; `matched_actor` stays information.
- **`reported_by`**: a new event field, `server` (default) or `client`. A
  client-reported event is treated like one without an actor: its
  `actor_id`, `tenant_id` and `owner_id` are dropped, so a page cannot trust
  a device, fail a challenge or ask an action for an account it names. Rules
  and counter conditions read `event.reported_by`; the SDK types carry it.

## 0.10.1 - 2026-10-20

- **Signals on an account's events**: `GET /v1/actors/{id}` gives each of
  its recent events the `signals` and `scores` its decision saw, so a person
  reviewing the account sees why without querying the events.

## 0.10.0 - 2026-10-20

What Castle (castle.io) offers an account-security team, rebuilt to run on
one host with no outside service at decision time. The plan is in
`docs/roadmap/castle-parity.md`.

- **Signals and scores in every answer**: `signals` names what the facts
  show (`new_device`, `impossible_travel`, `tor_ip`, `abuse_ip`,
  `disposable_email_domain`, `replayed_device_data`, `spoofed_device`,
  `timezone_area_mismatch` ...) and the `signal` of every rule that fired;
  `scores` gives `account_takeover`, `account_abuse` and `bot` from 0 to 1,
  summed from the rules that fired by `family` (a workflow's or a rule's
  `takeover`, `abuse` or `bot`). Rules read the names as `signals`.
  See `docs/signals.md`.
- **Lists v2**: a list can hold the values of one event field (`key =
  "actor"`, `"device"`, `"email_registered_domain"`, `"attrs.<name>"` ...)
  or pairs (`second = "device"`), and items can end (`expire = "14d"`). Rules
  read `"name" in event.lists`. Items added at run time keep their author,
  note, start and end; they are archived rather than deleted, can be given
  back, and exported as CSV. New routes `POST /v1/lists/{name}/items/archive`,
  `.../unarchive`, `GET /v1/lists/{name}/export` (cells that a spreadsheet
  would run as formulas are defused); items may be objects with
  `value`, `second`, `for` and `note`. Webhooks `list_item.created`,
  `list_item.archived` and `list_item.unarchived`.
- **List actions**: `list.add:<list>` and `list.remove:<list>` change a list
  from a rule or a workflow's `on_<decision>`; the answer names the change in
  `lists`.
- **An allow that stops**: `stop = true` on an allow rule allows the event
  over every other workflow, the core's blocks aside; the answer names it in
  `stopped_by`.
- **Challenge loop**: new events `challenge.requested`,
  `challenge.succeeded` and `challenge.failed`. A passed challenge puts the
  account and device on the core list `trusted_devices` for 14 days, and
  `ato_trusted_device` allows the next logins from it; three failures in an
  hour are `ato_failed_challenges`.
- **Credential stuffing and pre-sign-in matching**: `ato_stuffing_ip` and
  `ato_stuffing_network` count failed sign-ins per address and network
  operator, with or without an actor. An event without an actor whose email
  belongs to an account names it in `matched_actor` (full API keys only);
  rules read it as `matched`.
- **Device token**: `deviceToken()` in `sdk/device` makes a single-use token
  per sensitive action, sent as `device_token`. openfraud reads it as `ok`,
  `stale`, `replayed`, `invalid` or `missing` (with `[device]
  require_token`), and `event.device_info` (time zone, platform, touch,
  webdriver). New rules `ato_replayed_device_token` and
  `ato_spoofed_device`; new session fact `new_device_type`. The script holds
  no secret: the token proves freshness and single use, not authorship. A
  token is checked and spent under one lock, so two requests sent at once
  never both find it fresh.
- **Counters v2**: `by` may name up to four keys, `events = ["*"]` counts
  every event, `agg` (`avg`, `min`, `max`, `last`) of an attribute `of`,
  `baseline = "7d"` learns a counter's usual value per window (rules read
  `baselines.<name>`), and `enabled = false` turns one off (a rule that
  reads it is refused). New CEL functions `max(a, b)` and `min(a, b)`.
- **Unusual activity**: `[core] activity = true` counts each account's,
  device's and address's events per hour against its usual hour of the last
  7 days: `high_activity_account`, `high_activity_device`,
  `high_activity_ip`.
- **Email checks**: `event.email_registered_domain` from the Public Suffix
  List; `[email] mx_check` asks DNS whether the domain takes mail
  (`event.email_reachable`, signal `unreachable_email`); two accounts
  labelled fraud on one non-free domain list it on `fraud_email_domains` for
  90 days (`[core] email`, signal `fraudulent_email_domain`, pack rule
  `signup_fraud_domain`).
- **IP lookup**: `GET /v1/ips/{ip}` and `POST /v1/ips/query` (up to 1,000)
  answer the AS number, operator, country and lists of an address. New
  downloaded list `abuse_ips` (FireHOL abusers_1d), signal `abuse_ip`.
- **Account traits**: `traits` on an event are kept on the account (at most
  50, type fixed on first sight) and read as `actor.traits`.
- **Payment v2**: card numbers, holder names and postal addresses are
  dropped from payment `attrs` before storage; the countries of the billing
  and shipping addresses are kept. `event.payment.countries` counts the
  different countries; new card rules `card_countries_differ` and
  `card_high_risk_merchant` (list `high_risk_mcc`).
- **Explore**: `POST /admin/api/events/query` and `/group` filter and group
  the stored events (pseudonyms only, bound parameters, at most 366 days,
  1,000 rows or 200 groups), with `GET /admin/api/events/schema`, and an
  Explore page in the admin interface.
- **Admin views**: the overview compares the week with the week before
  (sign-ups, logins, failed logins, challenges) and lists the rules and
  signals that fired most; an account shows its devices, lists and traits;
  a list shows its items with author, end, archive and restore.
- **Sandbox**: `[server] sandbox = true` reads a mock token
  (`test|device:d1|verdict:deny|score:80`) and answers from it through the
  rule `sandbox_mock`, for integration tests. `GET /health` says `sandbox`.
- **Rule hits are indexed**: hits now live in their own table, so the rule
  pages and the overview stay fast on a large history (filled once from the
  stored decisions at the first start).
- **Fixed**: list and network downloads refuse plain `http://` except for a
  private host (loopback, private ranges, `.internal`, `.local`, `.lan` ...);
  a stray control character in this changelog's 0.8.0 heading.
- The SDK types (TypeScript, Python, Go) carry `device_token`, `traits` and
  the new answer fields.

## 0.9.0 - 2026-10-20

- **A rule's hits, for review**: `GET /admin/api/rules/{id}/hits` lists the
  accounts a rule fired on, shadow hits included, the latest first, each
  with its pseudonymized timeline and its label, so a person or a model can
  judge a rule before it is promoted. `GET /admin/api/rules` also says what
  each rule decides (`decision`, `score`, `actions`).

## 0.8.0 - 2026-10-20

- **Admin token from the environment**: `OPENFRAUD_ADMIN_TOKEN` (at least
  24 characters) sets the admin token at each start, for hosts that run many
  instances and cannot read the token printed at the first start. Only its
  digest is kept; `PUT /admin/api/rotate` answers `409 conflict` while it is
  set.
- **Webhook secret from the environment**: `OPENFRAUD_WEBHOOK_SECRET`
  (`whsec_` and the base64 of at least 16 bytes) replaces the signing secret
  the state file made, so a host can check the webhooks of every instance.
- **Rule reasons in the rule list**: `GET /admin/api/rules` gives each
  rule's `reason`, so a screen can name a rule in its own words next to its
  id. The admin interface shows a case's reasons that way.
- **A mirror for the downloaded lists**: `[server] lists_mirror` names one
  address that serves every list as `<name>.txt` and the network dataset as
  `ip2asn-combined.tsv.gz`, for instances that reach nothing but their host.
- **Blocks are never snoozed**: a snooze of a core block (`core_blocked_*`)
  is refused with 400, and resolving a case with `snooze` leaves its blocks
  out. A blocked account or address is taken out of its list instead.

## 0.7.0 - 2026-10-20

- **Phone signals**: `event.phone_code`, the international calling code of
  the event's number (`+32`), and the rule function `calling_code(country)`,
  from Google's libphonenumber metadata (Apache-2.0).
- **messaging**: `sms_country_mismatch`, a code asked for a number from
  another country than the request, the usual shape of SMS pumping.
  Scenario `pack-messaging-sms-country.jsonl`.

## 0.6.1 - 2026-10-20

- **Security**: a snooze could name a rule that restricts the workspace
  (`target = "tenant"`); it then fell silent for the whole workspace
  whenever the snoozed account acted. Such rules are now refused (400), and
  a snooze only ever silences rules about the account.

## 0.6.0 - 2026-10-20

- **Snoozes**: a rule can be silenced for one account for a while after a
  false positive, instead of being switched off for everyone.
  `POST /v1/actors/{id}/snoozes` (`{"rule", "for", "note"}`, at most
  `366d`), `DELETE /v1/actors/{id}/snoozes/{rule}`, and
  `POST /v1/cases/{id}/resolve` with `"snooze": "30d"` on a `legit` or
  `false_positive` verdict snoozes every rule that opened the case.
  Decisions list the silenced rules in `snoozed`; `GET /v1/actors/{id}`
  shows the snoozes. Built-in rules cannot be snoozed. Audited, exported,
  erased with the account, and deleted once ended.
- **Admin**: the case page offers to snooze the case's rules when resolving.
- **SDKs**: `snoozed` in the decision types.

## 0.5.0 - 2026-10-20

- **User agent and language**: events take `user_agent` (the end user's
  header) and `language` (`Accept-Language` or a tag). The user agent is
  read into `event.agent`: browser and major version, system, kind of
  device, and the flags `bot`, `ai_bot`, `automation` (headless Chrome,
  PhantomJS, Selenium) and `http_client` (curl, python-requests, Go; the
  HTTP stacks of native apps are not counted). The text is never stored;
  the language keeps its primary tag.
- **Session facts**: `session.new_os`, `session.new_browser`,
  `session.new_language` (kept in the `seen` table like the networks) and
  `actor.idle`, the time since the account's previous event.
- **Account takeover**: `ato_automated_login` (a login or failed login sent
  by a script) and `ato_dormant_return` (a login after 180 days of silence
  from a new device).
- **free-tier-and-trial**: `signup_automation`, `signup_webdriver`,
  `signup_http_client`, `signup_bot_agent`. **card-and-payments**:
  `card_automation`.
- **Device snippet**: `automated()` returns `navigator.webdriver`, sent as
  `attrs.webdriver`.
- **SDKs**: `user_agent` and `language` in the TypeScript, Python and Go
  event types.
- **Docs**: what to send about the request (integration.md). Scenario
  `core-agents.jsonl`.

## 0.4.0 - 2026-10-20

- **Network table** (`[networks]`, off by default, about 35 MB): which
  operator announces an IP and the country it is registered in, from the
  IPtoASN dataset (public domain), downloaded with `fetch_lists` and cached
  next to the database, or read from a `file` of your own. Rules read
  `event.ip_asn`, `event.ip_org`, `event.ip_country` and
  `session.new_asn`; counters can key on `ip_asn`. Turned on or off without
  a restart.
- **Network lists** (core, `[core] networks`): `tor_exits` (the Tor
  Project), `datacenter_ips` and `vpn_providers` (X4BNet, MIT), empty until
  `fetch_lists` downloads them.
- **Account takeover**: `ato_new_device_and_network` and `ato_tor_login`;
  `ato_impossible_travel` is no longer judged from a VPN, a data centre or
  Tor.
- **free-tier-and-trial**: `signup_tor_ip`, `signup_hosting_ip` and
  `signup_hosting_burst` (more than 5 sign-ups in an hour from one hosting
  operator's servers).
- **Rules**: a counter's `when` may test an IP list
  (`"name" in event.ip_lists`); a list function there is refused with a
  message that says so, where it used to fail silently at run time.
- **Privacy**: the networks an account used are kept in a new `seen` table,
  exported with the account, deleted with it, and forgotten past
  retention.
- **Scenarios**: `# network:` adds a range to the network table. Scenario
  `core-networks.jsonl`.
- **Docs**: [networks.md](docs/networks.md), and a "Choose what to load"
  table of measured memory in the README.

## 0.3.0 - 2026-10-20

- **Email signals**: before an address becomes a pseudonym, openfraud
  measures it and keeps only numbers, as `event.email_shape`: `tagged`
  (a `+tag`), `length`, `digits`, `digit_run`, `numeric`, `no_vowels`,
  `role` (a function mailbox) and `generated` (five consonants in a row,
  almost no vowels, letters and digits shuffled). `event.email_alias` is a
  short hash of the address as typed, so one mailbox signing up under
  several spellings is counted. New counter keys `email_stem` and
  `email_alias`.
- **free-tier-and-trial**: `signup_generated_email`, `signup_numeric_email`
  (not at Chinese providers), `signup_email_aliases` (one mailbox, more than
  2 spellings in 30 days) and `signup_stem_burst` (more than 3 numbered
  addresses with the same name in a day). Shadow, like every pack rule.
  Scenario `pack-free-tier-and-trial-email.jsonl`.

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
