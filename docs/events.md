> Status: shipped in 0.1, matches src/event.rs
> Last checked: 2026-10-20

# The event model

An event is one thing your application reports: an account was created, a
card was added, a campaign was sent. openfraud checks it, replaces personal
data by keyed pseudonyms, and only then do rules see it. The normalized form
is what is stored, so a replay sees exactly what the live decision saw.

The schema is `openfraud.event/v1` (the `schema` field is accepted and
ignored). Routes and answers are in [api.md](api.md).

## Fields

| Field | Type | Rules |
|---|---|---|
| `id` | string | 1 to 128 characters; generated (`evt_` and 24 hex digits) when absent. Same id twice: the first answer, nothing counted twice |
| `type` | string | required; lowercase words of letters, digits and `_`, joined by dots, each starting with a letter, at most 64 characters |
| `at` | RFC 3339 or Unix seconds | now when absent; fractions of a second are dropped |
| `actor_id` (alias `user`) | string | 1 to 256 characters; the account that acts |
| `actor_created_at` | RFC 3339 or Unix seconds | when the account was created, for accounts that existed before openfraud saw them; used only while no `account.created` and no earlier claim gave a date; a date after `at` counts as `at` |
| `tenant_id` | string | the workspace, team, organisation or store acted on |
| `owner_id` | string | the tenant's owner |
| `email` | string | any text; see below |
| `phone` | string | international (`+` and 8 to 15 digits; spaces, dashes, dots and brackets allowed), else 400 |
| `ip` | string | IPv4 or IPv6, else 400 |
| `device` | string | an opaque id from your app (see `sdk/device`) |
| `country` | string | two letters (ISO 3166 alpha-2), upper-cased; from a CDN header for example |
| `subject` | `{type, id}` | what the event is about: a page, an order, a campaign; both 1 to 128 characters |
| `attrs` | object | free; must be an object when present |

Unknown top-level fields are refused. A type outside the vocabulary and
`[events] custom` is refused with `invalid_event`.

## What normalization keeps

Rules read the normalized event as `event` (see [rules.md](rules.md)). Its
field names differ from the input: `actor`, `tenant`, `owner`.

| Input | Stored and read as |
|---|---|
| `email` | `event.email` = `<12 hex>.<8 hex>@domain`; `event.email_domain` = `domain`; `event.email_shape` (measured on the address as typed, see below); `event.email_alias` (8 hex: the address as typed, tag included) |
| `phone` | `event.phone_prefix` = `+` and the first six digits; the number itself only as a hash in `event.ids.phone` |
| `ip` | `event.ip_hash` (16 hex), `event.ip_prefix` (`203.0.113.0/24`, or `/48` for IPv6), `event.ip_lists` (names of the IP lists the address was on) |
| `device` | `event.device` = 16 hex digits of a keyed hash |
| `country` | `event.country` |
| everything else | as sent (`event.attrs`, `event.subject`, `event.at`, `event.type`, `event.id`) |

The raw IP address stays in memory for the list lookup and is never
serialized or stored. All hashes are HMAC-SHA256 under the pseudonym key of
the state file ([compliance.md](compliance.md)).

### Email pseudonyms

`someone+tag@Gmail.com` is first read the way the provider reads it: lower
case, the `+tag` dropped, and for Gmail the dots dropped and `googlemail.com`
read as `gmail.com`. The pseudonym has two hashes:

- the first (12 hex digits) identifies the mailbox. It is the identifier
  `event.ids.email`, and what links two accounts with the same address;
- the second (8 hex digits) identifies the stem, the letters of the local
  part, so `openai7623@x.com` and `open.ai@y.org` share a stem.

The domain stays in clear. An address that cannot be read (no `@`, no dot in
the domain, spaces) becomes `<hash>.<hash>@invalid`.

### Email shape

Before the address is hashed, openfraud measures it and keeps only the
numbers, as `event.email_shape` (absent for an address that cannot be read):

| Key | Meaning |
|---|---|
| `tagged` | the address has a `+tag` |
| `length` | characters in the local part, tag included |
| `digits` | digits in the local part (tag excluded) |
| `digit_run` | the longest run of consecutive digits (`1990` is 4) |
| `numeric` | the local part is digits only |
| `no_vowels` | letters and no vowel (`y` counts as one) |
| `role` | a function mailbox (`admin`, `info`, `noreply` ... the same 24 names as list shapes) |
| `generated` | looks typed by a script: five consonants in a row, vowels under 15% of six letters or more, or letters and digits alternating six times or more |

`event.email_alias` is a short keyed hash of the address exactly as typed
(lower case, tag kept): `ann+1@x.com` and `ann+2@x.com` share `event.email`
(the mailbox) but not the alias, so a counter `by = "email"` with
`distinct = "email_alias"` counts how many spellings of one mailbox signed
up. The counter key `email_stem` is the stem hash of `event.email`, the same
for `john1@` and `john2@`.

### Identifier kinds (`event.ids`)

Values that can link two accounts are gathered in `event.ids`: `email`,
`phone`, `ip`, `ip_prefix`, `device`, plus one entry per attribute named in
`[privacy] id_attrs`. These feed counters (`distinct`), the link graph
([graph.md](graph.md)) and `links.<kind>`.

### Contact attributes (`[privacy] contact_attrs`)

Default: `recipients`, `billing_email`, `to`. An attribute with one of these
names holds a text or a list of texts, each an email address or a phone
number. Each item is replaced before rules run:

- an address becomes its email pseudonym (domain kept);
- an international number becomes `<+first six digits>~<10 hex>` (country and
  operator range kept).

For a **list**, openfraud first measures it and stores the result next to it
as `<attr>_shape` (for `recipients`: `recipients_shape`):

| Key | Meaning |
|---|---|
| `count` | number of items |
| `roles` | addresses whose local part is a function mailbox (`admin`, `info`, `noreply`, `support`, `sales`, `postmaster` ... 24 names; a `+tag` is ignored) |
| `invalid` | items that are neither a plausible address nor a phone number (or not text) |
| `prefixes` | distinct country-and-operator prefixes among the phone numbers |
| `longest_run` | longest run of consecutive phone numbers (`...101`, `...102`, `...103`), the mark of a generated list; 0 without numbers |

A single contact (not a list) gets no shape. The shape is only as good as the
sample you send: send the list itself, up to the body size limit.

### Identifier attributes (`[privacy] id_attrs`)

Default: `card_fingerprint`, `payout_destination`, `custom_domain`. A text
or number attribute with one of these names is replaced by `HMAC(name,
value)` (16 hex digits), which is also recorded in `event.ids.<name>`. Other
attributes are stored as sent: never put an email address, a name or a
document number in a plain attribute. Names in these lists must be lowercase
words and cannot be a built-in key (`actor`, `ip`, `email` ...).

## Custom types

Add your own types to the configuration, or let a pack do it:

```toml
[events]
custom = ["x.game_won", "x.level_up"]
```

The same rule as above applies (lowercase words joined by dots). Workflows
and counters may then list them in `events`. The `x.` prefix is a
convention, not a requirement.

## Vocabulary

52 types in nine families. "Attrs" are those read by the shipped rules; every
type accepts any other attribute. "Pack" names the pack that reads it
([packs.md](packs.md)); the account takeover core reads `session.*` and a few
others through `device`, `country` and `ip` ([account-takeover.md](account-takeover.md)).

### account

| Type | Meaning | Attrs read |
|---|---|---|
| `account.created` | a new account | `email`, `ip`, `device` (fields), `attrs.username` |
| `account.updated` | profile data changed | none |
| `account.verified` | email or phone verified | none |
| `account.email_changed` | the login email changed (a credential change) | none |
| `account.phone_changed` | the phone changed (a credential change) | none |
| `account.referred` | the account came from a referral | `attrs.referrer_id` (read as `related.referrer_id`) |
| `account.deleted` | the account was closed | none |

### session

| Type | Meaning | Attrs read |
|---|---|---|
| `session.login` | a successful sign-in | `ip`, `device`, `country` (fields) |
| `session.login_failed` | a failed sign-in | `ip` |
| `session.logout` | a sign-out | none |
| `session.password_reset` | the password was reset (a credential change) | none |
| `session.mfa_changed` | two-factor settings changed (a credential change) | `device` |

### payment

| Type | Meaning | Attrs read |
|---|---|---|
| `payment.method_added` | a card or other method was attached | `card_fingerprint`, `card_country`, `card_funding`, `cvc_check`, `address_check`, `billing_name_matches`, `billing_email` |
| `payment.attempted` | a charge was tried | `card_fingerprint`, `amount` (minor units), `card_funding`, `card_country`, `cvc_check`, `address_check`, `risk_level` |
| `payment.succeeded` | a charge succeeded (for a marketplace: a sale, seller as tenant, buyer as actor) | the same as `payment.attempted`; `amount` is summed per store |
| `payment.failed` | a charge was declined | the same as `payment.attempted` |
| `payment.refunded` | a refund | `card_fingerprint`; `tenant_id` |
| `payment.disputed` | a chargeback | `tenant_id` |
| `payment.fraud_warning` | an early fraud warning from the processor | none |
| `payment.promo_redeemed` | a promo code was used | none (counted per cluster and per network; buyer `device`, `ip`) |

`cvc_check` and `address_check` are `fail` when the check failed;
`risk_level` is `highest` for the processor's top risk.

### subscription

| Type | Meaning | Attrs read |
|---|---|---|
| `subscription.trial_started` | a trial began | `card_fingerprint`, `card_country`, `billing_name_matches` (bool), `billing_email`, `country` |
| `subscription.created` | a paid subscription began | none |
| `subscription.upgraded` | a plan upgrade | none (order and timing count) |
| `subscription.downgraded` | a plan downgrade | none |
| `subscription.canceled` | a cancellation | none (order and timing count) |
| `subscription.invoice_paid` | an invoice was paid; the core raises the trust of the actor, and of the tenant when the event names one, to 1 | `attrs.amount` in minor units: an invoice of 0 (a trial's first invoice, a full discount) earns no trust; without `amount` the event is taken at its word |

### resource

| Type | Meaning | Attrs read |
|---|---|---|
| `resource.created` | the account created something (a page, a store, a project); also the "early event" that dates a new tenant | none (counted per actor) |
| `resource.updated` | it changed one | none |
| `resource.deleted` | it deleted one | none |
| `resource.exported` | it exported data (a sensitive action for account takeover) | none |
| `resource.feature_enabled` | it turned a feature on | none |
| `resource.apikey_created` | it created an API key | none (account age and trust are read) |
| `resource.webhook_created` | it created a webhook | none |
| `resource.domain_added` | it attached a domain | `attrs.domain` |

### message

| Type | Meaning | Attrs read |
|---|---|---|
| `message.send_requested` | the account asks to send email, SMS or push (call `/v1/decide`) | `attrs.recipients` (list), `attrs.channel`, `attrs.recipients_count`, `attrs.subject`, `attrs.link_domains` (host names of the links in the message); `email` of the sender |
| `message.test_requested` | a test send | the same |
| `message.contacts_imported` | a contact list was uploaded | `attrs.recipients`, `attrs.count`, `attrs.recipients_count`, `attrs.recipients_shape` (computed), `attrs.bounced_before` |
| `message.delivered` | a message was delivered | `tenant_id` (the sender), `subject` (the campaign), `attrs.count` |
| `message.bounced` | a message bounced | the same |
| `message.complained` | the recipient reported spam | the same |
| `message.otp_requested` | a one-time code was requested by SMS | `phone`, `ip` |

### payout

| Type | Meaning | Attrs read |
|---|---|---|
| `payout.destination_changed` | the bank account or wallet changed | `attrs.payout_destination` (hashed and linked) |
| `payout.requested` | a seller asks to be paid (call `/v1/decide`) | `attrs.fulfilment_at` (Unix seconds, when orders are delivered); `tenant_id`, `actor_id` |
| `payout.sent` | the payout went out | none |

### usage

| Type | Meaning | Attrs read |
|---|---|---|
| `usage.recorded` | metered consumption | `attrs.key_id`, `attrs.units`, `attrs.plan_units_per_day`, `attrs.end_user`, `attrs.duration_s`, `attrs.gpu_pct`, `attrs.cpu_pct`; `ip`, `country` |
| `usage.quota_exceeded` | a quota was hit | none (a pack workflow listens; no rule reads it yet) |
| `usage.credit_granted` | free credit was granted | none (counted per cluster) |

`end_user` is a plain attribute: send an opaque id, never an address, or add
it to `id_attrs` to hash it.

### content

| Type | Meaning | Attrs read |
|---|---|---|
| `content.published` | a page or post went live | `attrs.title` (or any short text), `attrs.has_password_form` (bool), `attrs.link_count` |
| `content.uploaded` | a file was uploaded | `attrs.sha256` (lower-case hex) |
| `content.moderated` | an outside moderation verdict | `attrs.verdict` (`allow`, `review`, `reject`) |
| `content.reported` | a user reported content | `subject` (the content), `actor_id` (the reporter) |
| `content.removed` | content was taken down | none |

## Tips

- Send `actor_id`, `ip` and `device` on every event: counters, links and the
  cluster depend on them. Events without an actor still run the rules that
  do not need one (an IP-based card rule works on a guest checkout).
- Send an early event for each new tenant (`resource.created`): a tenant's age
  is the time since the first event that carries its `tenant_id`.
- Events are cheap to retry: reuse the same `id`.
