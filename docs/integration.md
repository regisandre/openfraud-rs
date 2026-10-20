> Status: shipped in 0.1, matches src/server.rs, src/engine.rs and sdk/
> Last checked: 2026-10-20 (0.11.1: pack counters on one account's id)

# Integrating openfraud into a SaaS

openfraud is generic: it knows nothing about your product beyond the events
you send. This page is the checklist for wiring it into any application.
Routes and bodies are in [api.md](api.md), the event model in
[events.md](events.md).

## Decide or ingest?

| Use | When | Example events |
|---|---|---|
| `POST /v1/decide` | the action has not happened yet and you can refuse, hold or challenge it in the same request | `account.created` (sign-up), `session.login`, `payment.method_added`, `payment.attempted`, `subscription.trial_started`, `message.send_requested`, `message.contacts_imported`, `payout.requested`, `payout.destination_changed`, `resource.apikey_created`, `resource.domain_added`, `resource.exported`, `content.published`, `payment.promo_redeemed` |
| `POST /v1/events` (or `/v1/events/batch`) | something already happened and you only report it | `session.login_failed`, `session.logout`, `payment.succeeded`, `payment.failed`, `payment.refunded`, `payment.disputed`, `message.delivered`, `message.bounced`, `message.complained`, `usage.recorded`, `content.moderated`, `content.reported`, `subscription.invoice_paid`, `account.deleted` |

Both routes feed the same pipeline: counters move, rules run, cases open and
accounts can be quarantined on an ingested event. The only difference is
that `/v1/events` does not hand you the decision, so the consequence
reaches your application later through a webhook or the actor's status
([below](#handling-the-answer)). Use `decide` wherever you can act on the
answer in the request path; use events for facts, for bulk, and to backfill.

Send the same fields everywhere: `actor_id`, `ip` (the end user's address,
not your proxy's: read it from `X-Forwarded-For` the right way), `device`
(`sdk/device`), `country` (a CDN header), and `email`/`phone` when you have
them. Counters, links and clusters depend on them. Use a stable `id` for
each event (the request id, the order id): it makes retries safe.

## Fail open, with a short timeout

openfraud sits in your request path, so it must never be able to take the
product down.

- Time out after **300 ms**. The p99 target is 50 ms; the rest is margin for
  the network.
- On a timeout, a network error or a 5xx, **proceed as `allow`** and send the
  same event through `/v1/events` later (same `id`) so counters and rules do
  not lose it.
- **Fail closed** only where a false allow costs money you cannot get back,
  typically a payout: treat a failure as `hold` there, and say so in the
  code (the SDKs have a `failClosed` option that returns `hold`).
- A 4xx is a bug in your call (bad field, unknown type): log it loudly, do
  not retry.

## Idempotency

An event `id` is processed once. A second call with the same id returns the
first answer with `duplicate: true` and counts nothing, so at-least-once
delivery from queues and retries is safe. On `/v1/decide` the
`Idempotency-Key` header overrides the id. Idempotency lasts as long as the
event is stored (`retention_days`).

## Actor, tenant, owner

- **actor**: the end-user account performing the action (`actor_id`).
- **tenant**: the workspace, team, organisation or store it acts on
  (`tenant_id`). Leave it out if your product has no such level.
- **owner**: the tenant's owner (`owner_id`). Send it on every event that has
  a `tenant_id`.

Restrictions land on the actor by default. A rule with `target = "tenant"`
restricts the tenant, but **the owner is never automatically restricted for
what another member did**: if a member's event would restrict the tenant,
the tenant gets a `review` case instead and the action asked of you is
`review` on the tenant, while the member is restricted as usual. When the
owner is the actor (`owner_id == actor_id`), the tenant itself can be
restricted. Without `owner_id`, nobody counts as the owner, so a tenant is
never auto-restricted: send it.

## What to send about the request

Pass the end user's request details through, not your server's:

- `ip`: the client address (behind a proxy, the first trusted
  `X-Forwarded-For` entry);
- `user_agent`: the browser's `User-Agent` header. A backend that sends its
  own (`node`, `python-requests`) makes every event look scripted to
  `signup_http_client` and `ato_automated_login`;
- `language`: the `Accept-Language` header;
- `device`: the id from `sdk/device`, and `attrs.webdriver` from its
  `automated()`; or better, `device_token` from its `deviceToken()`, made
  fresh by the page for each sensitive action: it carries the device id and
  lets openfraud catch a replayed or forged request
  ([account-takeover.md](account-takeover.md));
- `country`: from your CDN (`CF-IPCountry`, `CloudFront-Viewer-Country`);
- `traits`: what the account is (`{"plan": "pro", "seats": 12}`), whenever
  it changes; rules read them as `actor.traits`.

### Before sign-in, and events a page reports

Before sign-in there is no actor: send the failed logins and the password
resets with the `email` the person typed. openfraud counts stuffing per
address and network and names the account the address belongs to in
`matched_actor`.

Anyone can type someone else's address, so such an event is evidence about
the sender, never about the account it matches. An event without an actor:

- never counts under a key that names one account: `actor`, `cluster`,
  `email`, `email_alias`, `phone` (counters keyed on the IP, the network,
  the device, the email domain or the country keep counting);
- never writes such a key on a list (`list.add` on a list keyed by
  `actor`, `email` or `phone` is skipped);
- never carries an action, a status change, a case or a trusted device for
  the matched account. `matched_actor` and `matched` are information only:
  a rule may weigh them in the answer to this request, nothing more.

When your page or app sends an event straight to your backend, which only
passes it on, mark it `"reported_by": "client"` (the default is
`"server"`: your backend saw it happen and knows who is signed in). A
client-reported event is treated like one without an actor: its
`actor_id`, `tenant_id` and `owner_id` are dropped, since a page can claim
any of them. A `challenge.succeeded` must come from your server, never from
the page: only then does it trust the device. Rules and counter conditions
read `event.reported_by` to weigh or exclude such events
(`when = 'event.reported_by == "server"'`).

The guard covers the built-in keys. A counter or a list of your own keyed on
an attribute that names one account (an `attrs.<name>` such as a username,
an account number or an API key id, or an entry of `[privacy] id_attrs`)
needs it written out, or a page could raise it for someone else:

```toml
[counters.exports_per_account_key_1h]
events = ["resource.exported"]
by = "attrs.account_key"
when = 'event.reported_by == "server" && has(event.actor)'
window = "1h"
```

The shipped packs do this for `attrs.key_id` and `attrs.referrer_id`.

After a `step_up`, send what happened: `challenge.requested`, then
`challenge.succeeded` or `challenge.failed`, with the actor and the device.
A passed challenge trusts the device for the account for 14 days.

## Sandbox

An instance started with `[server] sandbox = true` (for tests and staging,
never production) reads a mock device token and answers from it:
`device_token = "test|device:d1|verdict:deny|score:80|ip:BE"`. `device` is
the device id, `verdict` a decision (`allow`, `challenge` as `step_up`,
`deny` as `block`, or any decision name), `score` 0 to 1,000 (or `risk` 0 to
1), `ip` a country for the event. The answer carries the rule
`sandbox_mock`, which acts. Your tests drive every branch of your code
without writing a rule. Elsewhere a `test|` token is `invalid`; `GET /health`
says `sandbox: true` on a sandbox.

## Handling the answer

The `decision` and the `actions` of the answer, and the webhooks, tell you
what to do. The vocabulary is fixed ([api.md](api.md#actions-webhooks)):

| Action / decision | What your application does |
|---|---|
| `allow` | proceed |
| `review` | proceed. A person looks later |
| `step_up` | ask for proof before continuing (MFA, 3-D Secure, a CAPTCHA, an email check) |
| `hold` | do not complete the action. Keep it pending. If `hold_until` (Unix seconds) is set, it can proceed after that time if nobody objects; otherwise wait for the release |
| `block` | refuse this request, nothing more |
| `quarantine` | refuse, and restrict the account: no sending, payouts or new resources, until `release` |
| `suspend_feature:<name>` | turn that one feature off for the target (for example `suspend_feature:email`) |
| `limit:<quota>` | lower that quota to the free level (`limit:trial`) |
| `throttle:<duration>` | nothing to store: openfraud refuses the same action type from this account until the time is up and answers `block` with `retry_after`; answer HTTP 429 with a `Retry-After` header |
| `revoke_sessions` | end every session and refresh token of the account, so it signs in again (with step-up if you have it) |
| `release` | lift a quarantine, hold, suspension or limit |

Rules:

- Each action has a `target` (`actor` or `tenant`) and an `id`. Apply it to
  that object.
- Make handlers idempotent and keep a local flag (`restricted_by_openfraud`,
  the feature or quota affected). Actions can arrive twice, in the decision
  and in a webhook.
- A decision's `actions` covers the synchronous path. Changes made later (a
  person releasing a quarantine, a label) come as webhooks: subscribe to at
  least `actor.status_changed` (its `actions` say `quarantine` or `release`),
  `tenant.status_changed` and `decision.quarantine`.
- `hold_until` is not signalled when it passes; your application compares
  the time. A person releasing a hold earlier arrives as a status change.
- After a successful `step_up`, let the action proceed. openfraud has no
  "proof passed" event; calling `decide` again for the same action would
  evaluate the same rules again.
- A trusted actor (`trust` at or above `[trust] act_below`) never gets a
  `block` or `quarantine` automatically: the answer is a `hold` with
  `protected: true`.
- During shadow rollout (below) ignore `decision` and log
  `shadow.decision`.

### Verifying webhooks

Set `[webhooks] url` and optionally `events`. Deliveries are
[Standard Webhooks](https://www.standardwebhooks.com): three headers
`webhook-id`, `webhook-timestamp`, `webhook-signature`, the signature being
`v1,` and the base64 HMAC-SHA256 of `<id>.<timestamp>.<raw body>` under the
secret (`whsec_...`, the base64 key after the prefix). The secret is
`webhook_secret` in the state file ([deploy.md](deploy.md)).

- Verify against the **raw body**, before any JSON parsing, and reject a
  timestamp more than five minutes from your clock.
- Answer 2xx quickly and do the work asynchronously. A non-2xx (or a
  timeout of 5 s) is retried with growing delays, 12 attempts over about two
  days (`[webhooks] max_attempts`); a 410 stops the retries.
- Deliveries are at least once and not ordered. `webhook-id` is stable
  across retries: use it to deduplicate. Order by the `timestamp` in the
  body.
- Any Standard Webhooks library works. The SDKs ship a verifier (below).

## Statement of reasons and appeals

When a restriction carries actions for the user, the answer has a
`statement_id` and a `case_id`. Show the user their statement and an appeal
path ([compliance.md](compliance.md)):

1. `GET /v1/statements/{statement_id}`: render `facts` (the reasons),
   `restriction.scope` and `.duration`, `ground` and `redress`.
2. Offer an appeal. Forward it with `POST /v1/cases/{case_id}/appeal`
   `{"message": "..."}`. Keep the `case_id` from the decision, or read it
   from `GET /v1/actors/{id}` (`open_case`).
3. A person resolves the case in the admin interface; you learn the result
   from the `case.resolved` and `actor.status_changed` webhooks.

Keep your own copy of the user's message: the case stores up to 4,000
characters.

## Labelling

Labels are how openfraud learns what was really fraud, and what the replay
measures rules against ([safety.md](safety.md)). Send them from your support
and finance tools: `POST /v1/actors/{id}/label`, with `{"label": ..., "note": ...}`:

- `fraud`: a confirmed abuser, a lost dispute, a chargeback. The account is
  quarantined and the other members of its cluster get a review case.
- `legit`: a verified good customer. It becomes trusted.
- `false_positive`: openfraud was wrong about a real customer. Trusted, and
  counted against the precision of the rules that hit it.

Label good accounts too: without `legit` labels precision cannot be
computed. Never write personal data in `note`.

### Snoozing a rule for one account

Some customers trip a rule for a good reason: a school that signs up forty
accounts from one address, a reseller that adds many cards. Rather than
switch the rule off for everyone, snooze it for that account:
`POST /v1/actors/{id}/snoozes` with `{"rule": ..., "for": "90d"}`, or resolve
its case as `false_positive` with `"snooze": "30d"`, which snoozes every rule
that opened the case. The rule still fires for every other account, the
answers list it in `snoozed`, and the snooze ends on its own. Snoozes are
audited, exported with the account and erased with it. A block of the core
(`core_blocked_actor`, `core_blocked_ip` ...) is never snoozed: take the
account or the address out of its list.

## The SDKs

Under `sdk/`, each with a README; none has dependencies.

| SDK | Install | Highlights |
|---|---|---|
| `sdk/typescript` | `npm install openfraud` (or copy the folder) | Node 18+, Deno, Bun, edge runtimes. `new Client({baseUrl, apiKey})`, `decide`, `track`, `trackBatch`, `verifyWebhook` |
| `sdk/python` | `pip install ./sdk/python` | Python 3.9+, standard library only. `Client(base_url, api_key)`, `decide`, `track`, `track_batch`, `verify_webhook` |
| `sdk/go` | `go get github.com/regisandre/openfraud-rs/sdk/go` | `NewClient(Options{...})`, `Decide`, `Track`, `TrackBatch`, `VerifyWebhook` |
| `sdk/device` | copy `device.js`; Swift and Kotlin snippets in the README | a random 128-bit device id kept in first-party storage. No fingerprinting. Check ePrivacy for your legal basis, and offer `forgetDevice()` if you rely on consent |

What the three clients share: a 300 ms timeout; on a timeout, a network
error, a 429 or a 5xx, two retries (50 ms, 150 ms) with the same
`Idempotency-Key` and event id; then a **failover** decision
`allow` (flagged `failover`) so an outage never blocks users, or `hold` with
the fail-closed option. A 4xx raises an `OpenFraudError`/`APIError`. `track`
never throws on transport errors: it returns `accepted: false`. Always call
openfraud from your **server**: the API key must never reach a browser or an
app; the browser sends its `device` id to your backend, which puts it in the
event.

```js
const d = await of.decide({ id: requestId, type: "payout.requested", actor_id: user.id,
  tenant_id: store.id, owner_id: store.ownerId, ip, device, attrs: { amount: 12000 } },
  { failClosed: true });
if (d.decision === "hold" || d.decision === "block" || d.decision === "quarantine") return pending();
```

## A staged rollout

Do not start by letting rules act.

1. **Core only, collecting.** Run openfraud with no pack. Create an API key,
   send events from the places above (`track`, or `decide` and ignore the
   answer), always with actor, ip, device and country. Core blocklists act
   (a list you fill by hand), trust is earned by paid invoices, account
   takeover runs in shadow. This stage builds the history that replays need:
   a rule can only be approved after `replay_days` (30) of events exist.
   If your product already has users, send `actor_created_at` with their
   events (the account's real creation date), or every existing account
   looks a few minutes old.
2. **Packs in shadow.** Turn on the packs that match your product
   (`packs = [...]`, [packs.md](packs.md)); every rule ships in shadow. Call
   `decide` in the request path but still ignore `decision`; log
   `shadow.decision` (`would`) and `shadow.reasons`. Check
   `openfraud validate`, watch the admin Rules page, open cases, and label
   them. Use `?dry_run=true` for tests.
3. **Handle the actions, before anything acts.** Implement the action table
   above, the webhook receiver, the statement page and the appeal form.
   Test them with a scenario and with the admin playground, and by setting a
   test account's status through the status route.
4. **Promote rules after a replay.** Once 30 days of history exist, read each
   rule's hits, precision and recall and its `changed` events from
   `openfraud replay` or the Rules page, then promote one rule at a time
   ([safety.md](safety.md)): lowest volume and highest precision first. A
   rule that changed logic goes back to shadow and needs a new replay.
5. **Operate.** Set `[[alerts]]` and the brake thresholds, keep labelling,
   back up the state file and the database ([deploy.md](deploy.md)), and
   revisit shadow rules monthly. If a rule misbehaves, demote it
   (`[overrides.<id>] mode = "shadow"`) before releasing the brake.
