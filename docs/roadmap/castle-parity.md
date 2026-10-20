> Status: built in 0.10.0: every item of section 2 shipped in one release; section 4 stays out of scope for the self-hosted engine
> Last checked: 2026-10-20

# Castle parity plan

Castle (castle.io) is a hosted account-security API: login and signup
protection, bot detection, lists, metrics and policies. This file maps every
Castle product to openfraud, says what openfraud already has, what it can
rebuild in Rust and self-host, and what it cannot copy. Source: the public
Castle docs (docs.castle.io, llms.txt index), read 2026-10-20.

The rule for everything below: self-hosted, no outside service at run time,
pseudonymous storage (no raw IP, email or fingerprint kept), every feature
behind a switch so a small host loads only what it uses.

## 1. Product map

| Castle product | What it does | openfraud today | Plan |
|---|---|---|---|
| Risk API (`/v1/risk`) | scores an authenticated event (`$login`, `$registration`, `$profile_update`, `$transaction` ...) and returns `policy.action` allow / challenge / deny, three scores and signals | have: `POST /v1/decide`, verdict allow / step_up / review / hold / block, rule list | add `scores` and `signals` to the answer (sections 2.1, 2.2) |
| Filter API (`/v1/filter`) | the same before sign-in: no user id, `matching_user_id` when the email matches an account | partial: an event without actor is accepted | `matching_actor` from the email pseudonym (2.3) |
| Log API | records an event without a verdict | have: `POST /v1/events`, `/v1/events/batch` | none |
| Event types and statuses | `$attempted` / `$succeeded` / `$failed` / `$requested` on each type | have: `session.login`, `session.login_failed` ... | add `challenge.*` (2.6) |
| Request token (Castle.js, mobile SDKs) | client fingerprint sent as an opaque, single-use, 120 s token; missing, invalid or replayed token is a signal | partial: `sdk/device` gives a device id | signed device token with replay check (2.4) |
| Device fingerprinting | persistent device id, spoofing and headless checks | partial: device id, user-agent parsing (`event.agent`) | tamper checks, privacy-safe (2.4) |
| Scores | Account Abuse, Account Takeover, Bot, 0 to 1, from ML trained on all customers | no | local scores from rule families (2.1); no cross-customer ML (section 4) |
| Signals | ~45 named facts in the answer | have most as facts or rules (table 3) | named `signals` in the answer (2.2) |
| Policies | ordered, first match wins, per event type plus "before all" / "after all", log-only mode, pass-through mode, actions add / remove list items | have: workflows, CEL rules, shadow mode, promotion after replay, actions | rule actions on lists (2.5); an `allow` rule that stops evaluation (2.5) |
| Lists | typed lists, color, author and comment per item, secondary field (user + device), auto-archive after N minutes, archive / unarchive, CSV export, API, webhooks | partial: typed lists (`ip`, `domain`, `value`, `prefix`), file / URL / API items | lists v2 (2.5) |
| Metrics | aggregations `$count`, `$count_unique`, `$sum`, `$avg`, `$min`, `$max`, `$first`, `$last`, several group-by keys, where filter, window up to 180 days, arithmetic between aggregations | partial: counters with count, distinct, sum, `by`, `when`, window up to 366 days; CEL can divide two counters | metrics v2 (2.7) |
| Custom signals | a named condition on fields and metrics that tags the event | have: a rule with score 0 does the same | name them as signals (2.2) |
| Custom parameters | `properties` per event, `user.traits` kept on the user, typed on first sight | partial: `attrs` per event, `id_attrs`, `contact_attrs` | actor traits (2.8) |
| Transaction object | type, amount, payment method (fingerprint, BIN, country, network, funding), billing and shipping address, merchant MCC | partial: `payment.*` with `card_fingerprint`, `card_country`, `card_funding`, `amount` | payment v2 (2.9) |
| Challenge events | `$challenge` requested / succeeded / failed, method and variant, link to the event that asked | partial: `step_up` action, no outcome event | challenge loop (2.6) |
| IP Intelligence API | `GET /v1/ips/{ip}`, `POST /v1/ips/query` (1 to 1,000), downloadable proxy datasets | partial: the network table and IP lists are used inside rules only | IP lookup API (2.10) |
| Events API (query, group, schema) | filter and group stored events, `$top_k`, `$count distinct` | no | events query API (2.11) |
| Webhooks | `$policy.matched`, `$list_item.created / archived / unarchived`, HMAC signature, 6 retries | have: Standard Webhooks, 12 retries, decision and case types | list item types (2.5) |
| Slack | message when a policy adds a list item | have: Slack notifier for alerts | route list item events to notifiers (2.5) |
| Dashboard Overview | logins and signups, failed logins, actions, top policies and signals, compared with the previous period, PNG / PDF export | partial: `/admin/api/overview` | top rules and signals, period compare (2.12) |
| Explore, user details | search events, a user's devices and lists | partial: actor page, cluster, cases | devices and lists on the actor page (2.12) |
| Sandbox environment, mock request tokens | `test|device:...|ip:...|policy.action:deny|risk:0.9` forces a result; refused in production; private IPs accepted only in sandbox | partial: scenario files, `simulate` | sandbox mode (2.13) |
| Server SDKs | Ruby, PHP, Python, Java, Node, .NET | have: TypeScript, Python, Go | no change planned |

## 2. What to build

### 2.1 Local scores

Castle returns three scores. openfraud can return the same three, computed
locally: each rule gets a `family` (`takeover`, `abuse`, `bot`) and the score
of a family is its fired rule points mapped onto 0 to 1 by the workflow bands.
Core and pack rules get a family by default. The answer gains
`scores: {account_takeover, account_abuse, bot}`. No model training: these
are a summary of the rules, documented as such.

### 2.2 Named signals in the answer

Castle lists its signals by name so the host can log and analyse them. Add
`signals: {name: {}}` to the decide answer and the decision record, built from
facts that are true on the event (`new_device`, `tor_ip`, `datacenter_ip`,
`generated_email` ...) and from rules declared `signal = true`. The names
follow table 3 where a matching fact exists, so a host coming from Castle
finds the same words.

### 2.3 Pre-sign-in matching

Castle's Filter API answers `matching_user_id` when an anonymous attempt
uses the email of a known account. openfraud keeps an email pseudonym per
actor already. A `session.login_failed` or `account.reset_requested` event
without actor but with an email resolves `matching_actor` from that pseudonym,
so counters and rules keyed by actor see attacks on an account before
sign-in. A new rule pair covers credential stuffing: many distinct email
pseudonyms failing from one IP, prefix or ASN, and a high failed / succeeded
ratio per network.

### 2.4 Device token

Castle's request token is opaque, single use and valid 120 s; a missing,
invalid or replayed token is a signal, and an invalid token is denied. Build:

- `sdk/device` produces a token: the collected traits, a random nonce and a
  timestamp, encoded; no secret lives in the browser, so the server checks
  freshness and single use, not authorship.
- The server keeps seen nonces for the token lifetime (memory, bounded) and
  sets `device.token`: `ok`, `missing`, `invalid`, `replayed`, `stale`.
- Tamper checks with plain rules: user-agent OS against the platform the
  script reads, timezone continent against the IP country
  (`timezone_area_mismatch`), webdriver flag, headless markers, touch support
  against device type.
- Only a hash of the stable traits is stored, as today. No canvas or WebGL
  image leaves the browser; a hash of it may.

The `$attempted` then `$succeeded` pair of one request may reuse the token,
as Castle allows: the replay check keys on nonce and event type family.

### 2.5 Lists v2 and list actions

| Castle feature | openfraud change |
|---|---|
| secondary field | a `pair` list kind: an item is `actor + device` (or any two keys); it matches only when both match the same item. First use: a core `trusted_devices` list |
| auto-archive | `expire = "14d"` on the list, `for` on an item; re-adding or a rule adding it again restarts the clock; expired items are archived, not deleted, then purged with retention |
| author and comment | each run-time item keeps `by` (`api`, `admin`, `rule:<id>`) and `note` |
| archive / unarchive | `POST /v1/lists/{name}/items/archive`, `/unarchive`; archived items do not match |
| export | `GET /v1/lists/{name}/export?format=csv` |
| policy adds or removes items | rule actions `list.add:<name>` and `list.remove:<name>`, applied by openfraud itself (like `throttle`), keyed by the list kind (an IP list takes the event's IP pseudonym) |
| webhooks | `list_item.created`, `list_item.archived`, `list_item.unarchived` |
| Slack on policy add | list item events go through the alert notifiers |
| allow lists first | a rule `verdict = "allow"` with `stop = true` ends the workflow before scoring: a trusted pair skips the challenge |

Lists that hold raw values (`ip`) keep storing the hash for run-time items,
as the rest of the store does.

### 2.6 Challenge loop

Castle's tutorials build a full loop: challenge a new device or country,
trust the device for 14 days when the user passes, keep challenging when
the user fails. Add event types `challenge.requested`, `challenge.succeeded`,
`challenge.failed` with `attrs.method` (`email`, `sms`, `totp`, `webauthn`,
`captcha`) and `attrs.trigger_event` (the event id that asked). A pack rule
adds `actor + device` to `trusted_devices` on success; repeated failures
feed an ATO rule. The decision record links the challenge outcome to the
step-up that asked for it, so replay shows how many step-ups were passed.

### 2.7 Metrics v2

Counters gain what Castle aggregations have and openfraud lacks:

- `agg = "avg" | "min" | "max" | "last"` next to count, distinct and sum
  (average transaction amount per account in 24 h).
- `by = ["actor", "device"]`: several keys, joined into one.
- `counters.<name>.prev` or `since_last` already gives time between events;
  document both in one place.
- Ratios stay in CEL (`counters.failed / max(counters.ok, 1)`); add a
  `max()` helper if missing.
- `enabled = false` on a counter, and a configuration error when an enabled
  rule reads a disabled counter (Castle silently stops matching; openfraud
  should refuse to load).

### 2.8 Actor traits

Castle keeps `user.traits` on the user and makes them filterable. Add
`traits` to the event: kept on the actor (typed on first sight, at most 50,
dotted names), read as `actor.traits.<name>` in rules. Values are plain
(plan, role, kyc_level); a trait listed in `[privacy]` is hashed like an
`id_attr`.

### 2.9 Payment v2

Extend `payment.*` attrs with Castle's transaction fields that drive rules:
`kind` (`purchase`, `sale`, `withdrawal`, `deposit`, `transfer`, `reward`),
`method` type, `card_bin` (6 or 8 digits, kept), `card_network`,
`billing_country`, `shipping_country`, `merchant_mcc`. Facts:
`payment.country_mismatch` (card, billing, shipping, IP), counters by
payment fingerprint (accounts per card, cards per account), a high-risk MCC
list. Holder name and street address are never stored.

### 2.10 IP lookup API

`GET /v1/ips/{ip}` and `POST /v1/ips/query` (1 to 1,000 addresses) answer
`{address, type, asn, org, country, continent, lists: [...]}` from the
network table and the IP lists (`tor_exits`, `vpn_providers`,
`datacenter_ips`, the host's own lists). The address is read, never stored.
`lists` plays the part of Castle's `tunnels`; there is no `last_seen_at`
because the sources are snapshots. Behind `[networks] api = true`.

### 2.11 Events query API

Castle's Events API filters and groups stored events. Add, on the admin
listener first: `POST /admin/api/events/query` with filters (`eq`, `neq`,
`in`, `exists`, `range`, `or` groups) and `count` or `records` with count;
`POST /admin/api/events/group` with `count`, `count_distinct`, `sum`, `top_k`
and `group_by`; `GET /admin/api/events/schema`. Only stored (pseudonymous)
fields are queryable. Bounded time range and row limit, one query at a time
per caller, SQLite indexes on `at`, `type`, `actor`.

### 2.12 Admin views

Overview: logins, failed logins and signups by day, verdicts, top rules and
signals, each against the previous period. Actor page: devices seen (hash,
browser, OS, first and last seen), list memberships, active trusted pairs.
UI only; no tests for the views, tests for the queries behind them.

### 2.13 Sandbox mode

`[server] sandbox = true` (refused when `enforce` is on) accepts mock device
tokens `test|device:chrome_on_mac|ip:se|verdict:block|score:80` and private
IPs, and marks every record `sandbox`. A host can wire its client before
the real device script is in place. A production server rejects mock tokens
as `invalid`.

### 2.14 Email checks

| Castle signal | openfraud |
|---|---|
| `disposable_email_domain` | have (free-tier pack list) |
| `generated_email`, `low_quality_email` | have: `email_shape` |
| `multiple_aliases_per_email` | have: `email_alias` counters |
| `invalid_email` | have: normalization refuses a malformed address; expose as a fact |
| `unreachable_email` | build: optional MX lookup on new domains only, cached per domain, behind `[email] mx_check = true`; off by default (needs DNS at run time) |
| `email.registered_domain` | build: public suffix list (bundled, refreshed with lists), so `a.evil.com` and `b.evil.com` count as one |
| `fraudulent_email_domain` | partial: build an auto list of domains whose accounts the host labelled fraud; Castle's version is cross-customer |

## 3. Signals: Castle name to openfraud

| Castle signal | openfraud | Gap |
|---|---|---|
| `bot_behavior` | `event.agent.automation`, device script checks | no mouse or keystroke biometrics (section 4) |
| `credential_stuffing` | ATO pack counters | pre-sign-in matching (2.3) |
| `generated_email` | `email_shape.generated` | none |
| `high_activity_account` / `_device` / `_ip` | fixed-threshold counters | learned baseline per key: build an EWMA of the hourly rate and flag N times above it |
| `impossible_travel` | `session.travel_kmh` | none |
| `multiple_accounts_per_device` | `links.device.users` | none |
| `missing_device_data`, `invalid_device_data`, `replayed_device_data` | no | device token (2.4) |
| `spoofed_device`, `headless_browser` | partial: `agent.automation`, webdriver | tamper checks (2.4) |
| `http_client_library`, `web_crawler` | `agent.http_client`, `agent.bot` | none |
| `missing_headers` | no | send `accept_language` presence and header count from the SDKs; rule on absence |
| `timezone_area_mismatch` | no | device token traits (2.4) |
| `carrier_ip_country_mismatch` | `sms_country_mismatch` on phone code | carrier comes from mobile SDKs only |
| `rooted_device`, `emulated_device` | no | native mobile SDKs only (section 4) |
| `disposable_email_domain`, `invalid_email`, `low_quality_email`, `multiple_aliases_per_email`, `unreachable_email`, `fraudulent_email_domain` | see 2.14 | see 2.14 |
| `abuse_ip` | partial: host lists | ship an opt-in abuse list (FireHOL level 1 or similar) in `core/networks.toml` |
| `datacenter_ip`, `tor_ip`, `vpn_access`, `proxy_ip` | `datacenter_ips`, `tor_exits`, `vpn_providers` lists | public proxy lists are weak; keep as opt-in |
| `residential_proxy_access` | no | section 4 |
| `new_country`, `new_device`, `new_os`, `new_language`, `new_isp` | `session.new_*` (`new_asn` for ISP) | `new_device_type` (desktop, mobile, tablet) from `agent.device` |
| Phone Call Active | no | native mobile SDKs only (section 4) |

## 4. What cannot be copied

- **Cross-customer data.** Castle's scores, IP and ISP reputation,
  `fraudulent_email_domain` and the learned "expected locations" come from
  all its customers' traffic. A self-hosted instance sees one host. openfraud
  replaces this with public lists and the host's own labels.
- **Residential proxy and VPN tunnel feeds with `last_seen_at`.** These are
  bought or run as honeypot networks. Free lists cover datacenter, Tor and
  known VPN ranges only.
- **ML scores.** Without labelled cross-customer data there is nothing to
  train; 2.1 gives rule-based scores and says so.
- **Mouse and keystroke biometrics at Castle's level.** A simple
  straight-line and timing check in the device script is possible later;
  anything deeper is an arms race that needs a team.
- **Native mobile signals** (root, emulator, carrier, sensors, phone call).
  They need iOS and Android SDKs, out of scope for now; a host can send them
  as `attrs` and write rules on them.
- **Encrypted, server-verifiable request tokens.** Castle's token is opaque
  because Castle controls the script delivery and its keys. A self-hosted
  script has no secret; 2.4 checks freshness and replay, not authorship.

## 5. Release

The plan first split section 2 into nine releases. It shipped as one,
0.10.0, built test first, with docs, a scenario file for every new rule
(`core-challenges`, `core-credential-stuffing`, `core-device-token`, and
additions to the free-tier email and card packs), and a switch where it
costs memory or I/O (`[core] activity`, `[core] email`, `[email] mx_check`,
`[device] require_token`, `[server] sandbox`). The reference for what was
built is in the user docs: [signals.md](../signals.md),
[rules.md](../rules.md), [api.md](../api.md), [events.md](../events.md),
[account-takeover.md](../account-takeover.md).
