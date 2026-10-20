> Status: shipped in shadow mode, opt-in
> Last checked: 2026-10-20

# card-and-payments

## What it covers

Card testing (many cards, many small authorizations, many declines from one
address, device or account), risky cards (prepaid, foreign, failed security
code or address check, highest processor risk), cards of quarantined accounts,
refund-then-rebuy loops, disputes and early fraud warnings.

## Events it needs

| Event | Attrs read |
|---|---|
| `payment.method_added`, `payment.attempted`, `payment.succeeded`, `payment.failed` | `attrs.card_fingerprint` (hashed and linked), `attrs.amount` in minor units, `attrs.card_funding` (`prepaid`...), `attrs.card_country`, `attrs.cvc_check` (`fail`), `attrs.address_check` (`fail`), `attrs.risk_level` (`highest`), `attrs.webdriver`, plus `ip`, `device`, `user_agent` and `country` |
| `payment.refunded` | `attrs.card_fingerprint` |
| `payment.disputed` | none (counted per actor) |
| `payment.fraud_warning` | none |

Guest checkouts without `actor_id` still work for the IP-based rules.

## Rules

All rules ship in `mode = "shadow"`. One workflow, `card_payments`, with bands:
step-up at 40, review at 60, block at 80, quarantine at 120.

| Rule | Catches | Score or decision |
|---|---|---|
| `card_automation` | a card added or charged by an automated browser or an HTTP library (`event.agent`), or with `attrs.webdriver` true | 40 |
| `card_testing_ip` | more than 3 distinct cards from one IP in an hour | 60 |
| `card_testing_device` | more than 3 distinct cards from one device in an hour | 60 |
| `card_declines_ip` | more than 3 declines from one IP in an hour | 50 |
| `card_declines_actor` | more than 3 declines on one account in a day | 50 |
| `card_small_attempts` | more than 5 authorizations of 200 or less (minor units) from one IP in an hour | 40 |
| `card_prepaid` | `card_funding` is `prepaid` | 25 |
| `card_foreign` | `card_country` differs from the connection country | 15 |
| `card_cvc_fail` | security code check failed | 60 |
| `card_address_fail_foreign` | address check failed on a foreign card | 40 |
| `card_processor_risk` | processor rated the payment `highest` | 60 |
| `card_flagged` | the card is on a quarantined or fraudulent account | decision `block` |
| `card_refund_rebuy` | a purchase on a card refunded twice in 30 days | 40 |
| `card_dispute` | a dispute | 60 |
| `card_repeat_disputes` | a second dispute in 90 days | 40 |
| `card_fraud_warning` | the card network reported a payment as fraudulent | decision `quarantine` |

## Counters and lists

Counters: `card_cards_per_ip_1h`, `card_cards_per_device_1h`,
`card_failed_per_ip_1h`, `card_failed_per_actor_1d`,
`card_small_attempts_per_ip_1h`, `card_refunds_per_card_30d`,
`card_disputes_per_actor_90d`.

Lists: none. Card rules need `card_fingerprint` in `[privacy] id_attrs` and
`[graph] link_on` (the defaults in the sample `openfraud.toml`), so that a card
is hashed and linked across accounts. Send the processor's fingerprint, never
the card number.

## Turn it on

```toml
packs = ["card-and-payments"]
```

## Tune

```toml
[overrides.card_prepaid]
score = 10

[overrides.card_foreign]
enabled = false
```

Rules cannot be edited in place, and thresholds such as the 200 minor units of
`card_small_attempts` are part of the rule. Disable a rule to replace it.

## Promote a rule from shadow to act

Run in shadow, open the Rules page of the admin interface, review the 30-day
replay of the rule, then promote it. `card_flagged` and `card_fraud_warning`
are decisions, not scores: replay them first, as they block or quarantine alone.

## Known false positives

- A shared office or school IP buying several cards: `card_testing_ip`,
  `card_declines_ip`, `card_small_attempts`.
- A customer swapping cards after a decline, on one device: `card_testing_device`.
- Travellers, expatriates and online shoppers with foreign cards: `card_foreign`,
  `card_address_fail_foreign`.
- Prepaid cards are common with teenagers and gift buyers: `card_prepaid` (25
  points alone never reaches step-up).
- Mistyped security codes: `card_cvc_fail` is 60 on one attempt.
- A genuine customer disputing once: `card_dispute` leads to review.
- Product with many small cheap payments: `card_small_attempts`.
- The safety brake turns restrictions into reviews when they spike.

## Scenarios

- `examples/scenarios/pack-card-and-payments.jsonl`: the first 15 rules in five stories and a control.
- `examples/scenarios/core-agents.jsonl`: `card_automation`, a payment from a headless browser.
- `examples/scenarios/pack-card-and-payments-shadow.jsonl`: shadow behaviour (`allow`, `would` block).
- `examples/scenarios/card-testing.jsonl`: guest card testing.

Run them with `cargo test --test scenarios`.
