> Status: shipped in 0.1, matches src/engine.rs, src/event.rs, src/store.rs and src/keys.rs
> Last checked: 2026-10-20

# Compliance: statements of reasons, appeals, GDPR, retention

openfraud gives you the records these obligations need. Whether a rule of the
DSA or the GDPR applies to you, and on which legal basis, is for you and your
counsel to decide; this page says what the software does. It is not legal
advice.

## Statements of reasons (DSA art. 17)

When openfraud restricts an account, it writes a **statement of reasons** you
can show to the user. Fetch it with `GET /v1/statements/{id}`; the id is in
the `statement_id` of the decision answer (and in `recent` of
`GET /v1/actors/{id}`). The answer is `{"statement": {...}}`:

| Field | Content |
|---|---|
| `id` | `st_` and 16 hex digits |
| `subject` | `{kind, id}`: the actor or the tenant restricted |
| `created_at` | RFC 3339 |
| `case_id` | the case opened for it, or null |
| `restriction.decision` | `hold`, `block` or `quarantine` |
| `restriction.actions` | the actions asked of the application |
| `restriction.scope` | the same in words: "the account", "the action asked for", "the feature `email`", "the quota `contacts`" |
| `restriction.duration` | "until <time>" for a hold with `hold_for`, "this request only" for a block, else "until a person reviews it" |
| `facts` | the `reason` of every rule that acted: write them for the user ([rules.md](rules.md)) |
| `rules` | the ids of those rules |
| `automated_detection`, `automated_decision` | `true` when the engine decided, `false` when a person did |
| `ground` | `[compliance] ground`: the clause of your terms the restriction rests on |
| `redress` | `[compliance] redress`: how to ask for a new look |
| `appeal_url` | `[compliance] appeal_url`, if you set one |

```toml
[compliance]
ground = "Terms of service, section 7 (fraud and abuse)"
redress = "Reply to the notice or use the appeal link: a person reviews every appeal."
appeal_url = "https://app.example.com/appeal"
```

### When one is written

- when a decision of `hold`, `block` or `quarantine` carries at least one
  action for the actor (a `hold` and a `quarantine` always do; a plain
  `block` implies none, so it gets a statement only if a rule or workflow
  adds an action to it);
- when the account becomes quarantined, by the engine or by a person (the
  label `fraud` or the status route; then `automated_decision` is false);
- when a tenant is restricted.

Reviews and step-ups do not get one: nothing is taken away. Statements are
kept until you erase the account.

## Appeals

Show the statement, offer an appeal, and forward it:
`POST /v1/cases/{case_id}/appeal` with `{"message": "..."}` (cut at 4,000
characters). The case moves to `appealed`, a `case.appealed` webhook is sent,
an info alert goes out, and the appeal is audited. Nothing is lifted
automatically: a person decides in the admin interface, or through
`POST /v1/cases/{id}/resolve`. `legit` or `false_positive` trusts the account
and releases it (an `actor.status_changed` webhook asks your application to
`release`); `fraud` confirms the quarantine.

## GDPR access and erasure

`GET /v1/subjects/{actor_id}/export` returns everything held about an
account (art. 15): the subject record, every stored event with its outcome
(up to 100,000), the identifier kinds with their pseudonymized values, its
cluster root, its cases, its statements and the audit entries about it. The
export is itself audited.

`DELETE /v1/subjects/{actor_id}` erases it (art. 17) and answers
`{"erased": <rows>}`. It deletes:

- the account's events and outcomes, its subject record, its links and
  cluster membership;
- its cases and statements;
- its throttles;
- every outbox row (webhook or alert) that names it, sent or not;
- its links to external ids (a Stripe customer, [stripe.md](stripe.md)).

A workspace it owned stays, but no longer names it as its owner.

The **audit log** keeps its entries about the account, renamed to the
anonymous marker `erased:<hash>` and stripped of their free text (the note a
person typed). Other accounts' records that merely mention it (a `related` id in an attribute,
cluster counters in memory until restart) are not rewritten.

### Keeping a fraud flag after erasure

```toml
[compliance]
keep_fraud_flag_after_erasure = false   # default
```

Off by default. When on, erasing an account that a person labelled `fraud`
leaves one anonymous marker: a quarantined subject `erased:<hash of the id>`
and the hashed strong identifiers of the account (those in `[graph] link_on`),
so the same card, device or mailbox is recognized if it returns
(`links.<kind>.flagged`). That is personal data kept after an erasure
request. It needs a legal basis of your own (fraud prevention as a legitimate
interest, documented with a balancing test) and a retention limit you set;
leave it off until you have one. The marker is flagged, so retention never
purges its links: it stays until you switch the setting off and erase it (`DELETE
/v1/subjects/erased:<hash>`; with the setting on, erasing a marker leaves a new one).

## Pseudonymized storage

- Email addresses, phone numbers, IP addresses and devices are replaced by
  keyed hashes (HMAC-SHA256 under a 32-byte random key, one hash namespace
  per kind) **before** any rule sees them and before anything is stored.
  See [events.md](events.md) for exactly what is kept: the email domain, the
  phone prefix, the IP /24 (/48) network, and a few numbers measured on the
  address (its length, how many digits, whether it has a `+tag`), never its
  local part.
- The raw IP address lives in memory only for the list lookup and is never
  serialized.
- Plain attributes (`attrs`) are stored as sent. Do not send personal data
  there; use `contact_attrs` and `id_attrs`.
- Pseudonymized data is still personal data under the GDPR: it can be linked
  back by whoever holds the key or the original value. The export and
  erasure routes above exist for that reason.
- The key is in the **state file** (`[server] state_file`, `pseudonym_key`),
  in clear, next to the digests of the API keys and the admin token. Keep the
  file private (mode 0600 on Unix) and back it up. Lose it, or change it, and
  every hash of an account that returns is different: nothing is linked any
  more. Do not restore an old database with another state file.

## Retention

```toml
[server]
retention_days = 90   # 0 keeps everything
```

Every minute the server deletes throttles that have ended (whatever
`retention_days` says), events and their outcomes older than
`retention_days`; delivered or failed outbox rows older than that; and the
identifier links of accounts not flagged that were last seen before it.
Flagged accounts (quarantined or labelled fraud) keep their links, so a
returning offender is still recognized.

Account and tenant records last seen before the limit go too, with their
cases, statements, links and cluster membership, unless they are
quarantined, labelled, or have a case still open: those are kept so a return
is recognized and an appeal can be answered. A cluster whose root was
forgotten takes its smallest remaining member as root.

Not purged by retention: rule approvals and the audit log. Counter windows
longer than `retention_days` (some packs use 365 days) can only be rebuilt
after a restart from the events still stored; `openfraud validate` warns
about each one. Idempotency also lasts only as long as the event is stored.

## The audit log

Every act of a person or of the API that changes state is recorded with a
time, the caller (`api`, `admin`, `user` for an appeal, `stripe`, `openfraud`
for itself), an action and a target: labels, status changes, case
resolutions, appeals, rule approvals, list edits, configuration saves, API
key creation and revocation, admin token rotation, brake release, exports
and erasures, and the Stripe actions carried out. The API caller is recorded
as `api` whichever key was used. Read it in the admin interface (the latest
200) or in an export.

## No third-party calls by default

A fresh install makes no outbound request:

- `[server] fetch_lists = false`: lists with a `url` are not downloaded;
- `[ai] enabled = false` ([ai.md](ai.md));
- `[stripe] enabled = false` ([stripe.md](stripe.md));
- `[webhooks]` and `[[alerts]]` are absent until you add them
  ([alerts.md](alerts.md)).

Each of these sends only what is described on its page. With the AI on,
pseudonymized events (never raw emails or IPs) go to the model endpoint you
configure.
