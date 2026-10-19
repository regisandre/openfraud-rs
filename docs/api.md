> Status: shipped in 0.1, matches src/server.rs
> Last checked: 2026-10-19

# HTTP API

Two listeners. The API (`[server] bind`, default `127.0.0.1:8092`) is for your
backend and needs an API key. The admin interface (`[admin] bind`, default
`127.0.0.1:8093`) is for people and needs the admin token. See
[deploy.md](deploy.md) for keys and tokens.

Authentication: `Authorization: Bearer <key>` or `X-Api-Key: <key>`. With
`[server] allow_unauthenticated = true` the API checks nothing (tests only).

Bodies are JSON and need `Content-Type: application/json`. The default body
limit is `[server] max_body_bytes` (65,536); the admin listener allows 1 MiB.
Unknown fields in a body are refused (`bad_request`). There is no rate
limiting.

Every refusal has one envelope:

```json
{"error": {"type": "invalid_event", "message": "the `type` `Foo` must be lowercase words joined by dots, such as account.created"}}
```

| Status | `type` | When |
|---|---|---|
| 400 | `bad_request` | the body is not the JSON expected, an unknown field, a bad label or status, a bad `Idempotency-Key`, a batch over 100 events, a bad Stripe signature |
| 400 | `invalid_event` | the event breaks a rule of the event model, or its type is unknown |
| 401 | `unauthorized` | no key, or a wrong one |
| 404 | `not_found` | no such route, account, tenant, case, statement or list |
| 413 | `body_too_large` | over `[server] max_body_bytes` |
| 415 | `unsupported_media` | not `Content-Type: application/json` |
| 422 | `invalid_config` | (admin) a configuration that does not compile; the envelope also carries `problems: [...]` |
| 500 | `internal` | see the server log |

`GET /health` needs no key: `{"status": "ok", "version", "packs", "workflows",
"brake", "modules": {"ai", "stripe"}}`.

## The event

```json
{
  "id": "evt_01J...",
  "type": "message.send_requested",
  "at": "2026-10-19T12:47:00Z",
  "actor_id": "u_123",
  "tenant_id": "ws_9",
  "owner_id": "u_100",
  "email": "someone@example.com",
  "phone": "+32470123456",
  "ip": "203.0.113.50",
  "device": "dev_8f2c...",
  "country": "BE",
  "subject": {"type": "campaign", "id": "c_77"},
  "attrs": {"channel": "email", "recipients": ["a@example.org", "b@example.net"]}
}
```

The full model, the vocabulary and the normalization are in
[events.md](events.md). In short:

- `id`: unique per event, up to 128 characters. A retry with the same id gets
  the first answer (`duplicate: true`) and counts nothing, so at-least-once
  delivery is safe. Generated when absent.
- `type`: one of the vocabulary, or a custom type declared in `[events] custom`.
- `at`: RFC 3339 or Unix seconds; now when absent. A time more than 5
  minutes ahead of the server's clock is refused (400): a date in the future
  would corrupt the counters.
- `actor_id`: who acts (`user` is accepted as an alias). `tenant_id`,
  `owner_id`: the workspace, team, organisation or store the actor acts on,
  and its owner. All optional, up to 256 characters.
- `email`, `phone`, `ip`, `device`: replaced by keyed pseudonyms before any
  rule sees them; the raw values are never stored.
- `attrs`: a JSON object. Attributes listed in `[privacy] contact_attrs` and
  `id_attrs` are pseudonymized too.
- `schema` is accepted and ignored.

`?dry_run=true` on `/v1/decide`, `/v1/events` and `/v1/events/batch` decides
without remembering anything (no counters, cases, statements or webhooks).

## Decide: `POST /v1/decide`

Call it before a sensitive action and wait for the answer. The optional
`Idempotency-Key` header (1 to 200 characters) overrides the event `id` as
the dedupe key; the SDKs send it on every retry.

Latency budget: p99 under 50 ms on a 2-vCPU server with every pack on (see
the README's Performance section for the measured numbers). Clients must
time out (the SDKs use 300 ms) and **fail open**: on a timeout or a 5xx,
proceed as `allow` and send the event again later through `/v1/events`.
Fail closed only where a false allow costs money you cannot get back
(payouts), and say so in your code. See [integration.md](integration.md).

Request: an event with `"type": "message.send_requested"` and so on. Answer,
for a promoted `msg_inbox_probe` rule (workflow `msg_sending`, `hold_at = 60`):

```json
{
  "event_id": "evt_01J...",
  "decision": "hold",
  "score": 70,
  "reasons": [
    {"rule": "msg_inbox_probe", "workflow": "msg_sending", "score": 70,
     "reason": "A handful of addresses, one per big mailbox provider: an inbox placement probe",
     "mode": "act", "pending_approval": false}
  ],
  "actions": [
    {"action": "hold", "target": "actor", "id": "u_123"}
  ],
  "case_id": 42,
  "tenant_case_id": null,
  "statement_id": "st_3f9a1c07d2b84e55",
  "hold_until": null,
  "shadow": {"decision": "hold", "reasons": []},
  "protected": false,
  "brake": false,
  "duplicate": false,
  "dry_run": false,
  "took_us": 412
}
```

- `decision`: the strictest decision of the rules that act. Decisions, from
  the mildest:

| Decision | Your application |
|---|---|
| `allow` | proceeds |
| `step_up` | asks for proof first: MFA, 3-D Secure, a CAPTCHA, an email check |
| `review` | proceeds; a person looks at the case |
| `hold` | pauses this action until a person releases it, or until `hold_until` |
| `block` | refuses this action |
| `quarantine` | refuses, and restricts the account until a person releases it |

- `reasons`: the rules that fired in `act` mode. `shadow.reasons`: the rules
  that fired in shadow mode, including those that ask to act but wait for an
  approved replay (`pending_approval: true`). `shadow.decision` is the
  decision with all of them counted (`would` in `openfraud simulate`).
- `actions`: what your application is asked to do, each with a `target`
  (`actor` or `tenant`) and an `id`. See below.
- `case_id`: the actor's case, when the decision is `review` or stricter.
  `tenant_case_id`: the tenant's, when a tenant is reviewed or restricted.
- `statement_id`: the statement of reasons ([compliance.md](compliance.md)),
  written when a restriction carries actions for the actor or the account
  becomes quarantined. Fetch it with `GET /v1/statements/{id}`.
- `hold_until`: Unix seconds, for a `hold` whose rule has `hold_for`.
- `protected`: a block or quarantine was turned into a hold because the
  actor is trusted.
- `brake`: the safety brake turned a restriction into a review
  ([safety.md](safety.md)).
- `duplicate`: the id was seen before; everything else is the first answer.
- `took_us`: microseconds spent deciding.

Rules that could not be evaluated (for example an attribute that is missing)
do not fire; they are listed in `errors` in the admin playground
(`POST /admin/api/test`) and in `openfraud simulate`, not in this answer.

## Ingest: `POST /v1/events` and `POST /v1/events/batch`

The same event through the same pipeline (rules run, cases open, accounts can
be quarantined), answered without the decision details:
`{"event_id": "...", "accepted": true, "duplicate": false, "decision": "allow"}`.
Use it for events that report what happened (`message.delivered`,
`payment.succeeded`) and to replay events after a failed `decide`.

A batch holds at most 100 events: `{"events": [...]}`. The answer is
`{"results": [...]}`, one entry per event in order, either
`{"event_id": ..., "accepted": true, "duplicate": false, "decision": ...}` or
`{"accepted": false, "error": "..."}`. A bad event does not stop the others.
`Idempotency-Key` is not read here; use the event `id`.

## Actions (webhooks)

openfraud never acts on your systems itself (except the optional Stripe
module). It tells your application what to do, in the `actions` of a
decision and in signed webhooks. The action vocabulary is fixed:

| Action | Meaning | Undo |
|---|---|---|
| `quarantine` | restrict the account: no sending, no payout, no new resource | `release` |
| `release` | lift a quarantine or a hold | |
| `hold` | pause the action the event asked for | `release` |
| `suspend_feature:<name>` | turn one feature off for the target | `release` |
| `step_up` | require proof at the next sensitive action | |
| `review` | nothing to do now; a person looks | |
| `limit:<quota>` | lower one quota to the free level | `release` |

`stripe.cancel_subscriptions`, `stripe.block_cards` and
`stripe.detach_payment_methods` are carried out by the Stripe module, not by
you ([stripe.md](stripe.md)).

Every action has a `target` (`actor` or `tenant`) and an `id`. A tenant's
owner is never the target of an automatic action for what another member
did: the tenant gets a review case instead.

Configure delivery with `[webhooks]`: `url`, `events` (default all types
below), `timeout_ms` (5000), `max_attempts` (12). Each webhook is a POST of

```json
{"type": "decision.hold", "timestamp": "2026-10-19T12:47:00Z", "data": {...}}
```

signed with the Standard Webhooks scheme (`webhook-id`, `webhook-timestamp`,
`webhook-signature`; the `whsec_` secret is in the state file). A 2xx is
delivered, a 410 stops retries, anything else is retried with growing delays
(5 s, 30 s, 2 min ... up to a day; 12 attempts take about two days).
Deliveries are at least once and not ordered; `webhook-id` is stable across
retries.

| Type | `data` |
|---|---|
| `decision.step_up`, `.review`, `.hold`, `.block`, `.quarantine` | the full decision record of the event (like the answer, plus `rules` with every rule that fired, `errors`, `workflows`, `actor`, `tenant`) |
| `case.opened`, `case.updated` | `{case_id, subject: {kind, id}}` |
| `case.resolved` | `{case_id, subject, label, by}` |
| `case.appealed` | `{case_id, subject}` |
| `actor.status_changed`, `tenant.status_changed` | `{subject, from, to, by, actions}` where `actions` is `["quarantine"]` or `["release"]` |
| `brake.engaged` | `{since, reason}` |
| `brake.released` | `{by}` |

## Accounts, tenants, cases

Served on both listeners (on the admin listener under the same paths, with
the admin token). Except where noted, these need an API key.

| Route | |
|---|---|
| `GET /v1/actors/{id}` | `{actor, recent, links, open_case}`: the actor (status, trust, label, first and last seen ...), its 50 latest events with decision, score, `case_id`, `statement_id` and the rules, the identifier kinds it shares with other accounts, and its open case id |
| `GET /v1/actors/{id}/cluster` | `{cluster: {root, size, flagged, fraud, legit, members, joined_by}}`, up to 200 members ([graph.md](graph.md)) |
| `POST /v1/actors/{id}/label` | `{"label": "fraud" \| "legit" \| "false_positive", "note": "..."}` answers `{actor}`. `fraud` quarantines, the other two trust it |
| `POST /v1/actors/{id}/status` | `{"status": "normal" \| "review" \| "quarantined" \| "trusted", "trust": 1, "note": "..."}` answers `{actor}`. Releasing a quarantine goes through here |
| `GET /v1/tenants/{id}` | `{tenant, recent, open_case}`: the same for a tenant |
| `POST /v1/tenants/{id}/status` | the same body as for an actor; answers `{tenant}` |
| `GET /v1/cases?status=open\|all&limit=50&offset=0` | `{cases}`, newest activity first; `open` means not resolved (open or appealed); `limit` up to 500 |
| `GET /v1/cases/{id}` | `{case}`: status `open`, `appealed` or `resolved`, rules, events, summary, appeal |
| `POST /v1/cases/{id}/resolve` | `{"label": "...", "note": "..."}`: the reviewer's decision; answers `{subject}` |
| `POST /v1/cases/{id}/appeal` | `{"message": "..."}`: the user's appeal, forwarded by you (API listener only; the message is cut at 4,000 characters); answers `{case}`. A case is appealed once: a second appeal answers 409 `conflict` |
| `GET /v1/statements/{id}` | `{statement}`: the statement of reasons to show the user (API listener only) |
| `GET /v1/subjects/{actor_id}/export` | every record about an account (GDPR art. 15); audited |
| `DELETE /v1/subjects/{actor_id}` | erase them (GDPR art. 17); answers `{erased: <rows>}` |
| `GET /v1/lists` | `{lists: [{name, kind, items, description, url}]}` |
| `GET /v1/lists/{name}/items` | `{items}`: only those added at run time |
| `POST /v1/lists/{name}/items` | `{"items": [...], "note": "..."}`, at most 10,000; answers `{added}` |
| `DELETE /v1/lists/{name}/items?item=...` | answers `{removed}` |

Labelling, status changes and resolving are recorded in the audit log with
the caller (`api` or `admin`).

## The Stripe module

`POST /v1/stripe/webhook`, no API key: the `Stripe-Signature` header is the
authentication. 404 when the module is off. See [stripe.md](stripe.md).

## Admin API

On the admin listener only, behind the admin token. It serves the web
interface (`/`, `/app.js`, `/app.css`) and:

| Route | |
|---|---|
| `GET /admin/api/overview` | counts, workflows, counters, brake, modules |
| `GET /admin/api/config`, `PUT /admin/api/config` | read the configuration text; replace it with `{"text": "..."}` after it compiles (422 `invalid_config` otherwise) |
| `POST /admin/api/test` | `{"event": {...}}`: decide without storing, with the full record |
| `GET /admin/api/rules` | every rule: origin, mode, `may_act`, hits over 30 days, precision and recall |
| `POST /admin/api/rules/{id}/promote` | replay, approve and write `[overrides.<id>] mode = "act"` ([safety.md](safety.md)) |
| `POST /admin/api/replay` | `{"text": "<candidate config>", "days": 30}` (days up to 366); the running configuration when `text` is absent |
| `GET /admin/api/brake`, `POST /admin/api/brake/release` | the brake and its thresholds; release it |
| `GET /admin/api/keys`, `POST /admin/api/keys`, `DELETE /admin/api/keys/{id}` | API keys: `{"name": "..."}` answers the key once |
| `GET /admin/api/audit`, `GET /admin/api/outbox` | the 200 latest audit entries, the 100 latest deliveries |
| `POST /admin/api/cases/{id}/summary`, `POST /admin/api/ai/suggest` | the AI assistant ([ai.md](ai.md)) |
| `PUT /admin/api/rotate` | a new admin token; the old one stops working |
| `GET /admin/api/session` | `{"ok": true}`, to check a token |
