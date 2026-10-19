> Status: shipped in 0.1, optional and off by default; matches src/stripe.rs
> Last checked: 2026-10-19

# The Stripe module

An optional module that does two things for products billed through Stripe:

- **in**: it receives Stripe webhooks and turns them into openfraud events,
  so the card, trial and payment rules work without you sending those events
  yourself;
- **out**: it carries out `stripe.*` actions (cancel subscriptions, block
  cards, detach payment methods) when a rule asks for them.

It is **off by default** and makes no call to Stripe unless enabled.
Everything else in openfraud works without it.

## Configuration

```toml
[stripe]
enabled = true
webhook_secret_env = "STRIPE_WEBHOOK_SECRET"   # default
api_key_env = "STRIPE_API_KEY"                 # default
api_base = "https://api.stripe.com"            # default; a proxy or a test double
user_metadata_key = "user_id"                  # default
actions = false                                # default
# radar_value_list = "rsl_..."
```

| Key | Meaning |
|---|---|
| `enabled` | turns the module and the route on. The server refuses to start if the webhook secret variable is not set |
| `webhook_secret_env` | name of the environment variable holding the endpoint signing secret (`whsec_...` from the Stripe dashboard). Secrets are never in the file |
| `api_key_env` | name of the variable holding a Stripe API key. Optional for receiving; needed to fetch missing card data and for any action |
| `api_base` | the Stripe API base URL |
| `user_metadata_key` | the metadata key on Stripe objects that holds **your** actor id |
| `actions` | let openfraud call Stripe for the `stripe.*` actions. Off: they appear in decisions and nothing is done |
| `radar_value_list` | id of a Radar value list of type `card_fingerprint`, for `stripe.block_cards` |

## The webhook endpoint

`POST /v1/stripe/webhook` on the API listener. It needs no API key: the
`Stripe-Signature` header is the authentication. openfraud checks the `t=`
timestamp (five minutes of tolerance) and a `v1=` signature, which is the
HMAC-SHA256 of `<t>.<raw body>` under the endpoint secret. A bad or missing
signature answers 400 `bad_request`; with the module off the route answers
404. In the Stripe dashboard, point a webhook endpoint at your public URL and
select the events below. The Stripe event id becomes the openfraud event id,
so Stripe's retries count once. The answer is the decision record, or
`{"received": true, "ignored": true}` for an event type not used.

Stripe's webhooks reach this route over the Internet, so expose it through a
reverse proxy that forwards only `/v1/stripe/webhook` and keep the rest of
the API private ([deploy.md](deploy.md)).

## Event mapping

| Stripe event | openfraud event | Attributes |
|---|---|---|
| `payment_method.attached` | `payment.method_added` | `card_fingerprint`, `card_country`, `card_funding`, `card_brand`, `cvc_check`, `address_check`, `wallet`, `billing_email` |
| `customer.subscription.created` | `subscription.trial_started` if the status is `trialing`, else `subscription.created` | `plan` (price lookup key or id), `subscription_status`; with an API key, the default payment method's card data |
| `charge.failed` | `payment.failed` | card data, `amount`, `currency`, `decline_code`, `risk_level`, `billing_email` |
| `charge.succeeded` | `payment.succeeded` | the same |
| `invoice.paid` (amount paid above 0; a trial's zero invoice is skipped) | `subscription.invoice_paid` | `amount`, `currency` |
| `charge.dispute.created` | `payment.disputed` | `amount`, `currency`, `dispute_reason`, `stripe_charge` |
| `radar.early_fraud_warning.created` | `payment.fraud_warning` | `fraud_type`, `stripe_charge` |

Every mapped event also carries `stripe_customer` when there is one. Other
Stripe events are ignored. The event time is Stripe's `created`. Stripe does
not give the customer's IP address or device, so rules that need them
(card testing by IP) work on events you send yourself; send
`payment.attempted` from your checkout for those.

## Linking customers to actors

openfraud needs to know which of your accounts a Stripe object belongs to.
Put your actor id in the metadata of the Stripe objects you create, under
`user_metadata_key` (default `user_id`): on the Customer, and preferably on
the subscription and payment method. The module reads
`data.object.metadata.<key>`; when it finds both a customer and an actor on
an event, it remembers the pair. Later events that carry only the customer
(an invoice, a charge) are attributed to the same actor. For a dispute or a
fraud warning, which carry only a charge, an API key lets the module fetch
the charge to find its customer and metadata. An event whose actor cannot be
found is still processed, without an actor.

## Actions

Add the actions to the rule or to the workflow's `on_<decision>`:

```toml
[workflows.trial_start]
on_quarantine = { actions = ["suspend_feature:trial", "stripe.block_cards", "stripe.cancel_subscriptions"] }
```

With `actions = true` and an API key, each `stripe.*` action in a decision
(for the actor) is queued and carried out in the background, for every Stripe
customer linked to that actor, with retries (8 attempts):

| Action | What it does |
|---|---|
| `stripe.cancel_subscriptions` | a trial or an unpaid subscription (`trialing`, `incomplete`, `past_due`, `unpaid`) is canceled now, without invoice or proration; an `active` one is set to end at the end of its period, so a mistake can be undone |
| `stripe.block_cards` | adds the fingerprint of each card of the customer to `radar_value_list` (required) |
| `stripe.detach_payment_methods` | detaches each card of the customer |

Each carried-out action is recorded in the audit log with the caller
`stripe`. An actor with no linked customer is a silent no-op. Keep the
decision shadow-first like any rule: a `stripe.*` action on a rule that has
not been promoted does nothing, since a shadow rule asks for no action.
