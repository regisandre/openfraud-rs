> Status: shipped in shadow mode, opt-in
> Last checked: 2026-10-29

# marketplace-and-payouts

## What it covers

Marketplaces and platforms that pay sellers: exit scams by new sellers, payout
destination hijacks, stores with high refund or dispute rates, buyers that are
really one person (bulk buys, promo farming) and sellers buying from themselves.

## Model

The seller is the tenant (a store), its owner the seller's account. A sale is a
`payment.succeeded` event with the store as `tenant_id` and the buyer as
`actor_id`; add `owner_id` (the store's owner) so that `buyer_is_seller` can
compare it with the buyer. A payout is a `payout.requested` event with the
store as `tenant_id` and the seller as `actor_id`.

## Events it needs

| Event | Attrs read |
|---|---|
| `payout.requested` | `attrs.fulfilment_at` (Unix seconds; the time the orders are delivered), `tenant_id`, `actor_id` |
| `payout.destination_changed` | `attrs.payout_destination` (hashed and linked); only the time of the last such event is read |
| `payment.succeeded` | `attrs.amount` (summed per store), `tenant_id`, `owner_id`, the buyer's `device` and `ip` |
| `payment.refunded`, `payment.disputed` | `tenant_id` |
| `payment.promo_redeemed` | buyer's `device`, `ip` |

The store's age is the time since the first event that carries its `tenant_id`.
Send an early event for each new store (for example `resource.created`).

## Rules

All rules ship in `mode = "shadow"`.

### Workflow `market_payout` (on `payout.requested`)

Bands: review at 40, hold at 60, block at 100.

| Rule | Catches | Score or decision |
|---|---|---|
| `payout_new_seller` | store under 7 days old | `hold` for 7 days |
| `payout_before_fulfilment` | `fulfilment_at` is in the future | `hold` |
| `payout_destination_recent` | destination changed less than 3 days ago | 60 |
| `payout_sales_spike` | store under 30 days old whose sales in one day exceed 5 days of its 30-day total | 40 |
| `payout_refund_rate` | 10 or more sales in 90 days and 10 percent or more refunded | 40 |
| `payout_dispute_rate` | 20 or more sales in 90 days and 1.5 percent or more disputed | 50 |
| `payout_risky_seller` | the seller's account already scored 50 or more | 30 |

### Workflow `market_buyer` (on `payment.succeeded`, `payment.promo_redeemed`)

Bands: review at 40, hold at 60.

| Rule | Catches | Score |
|---|---|---|
| `buyer_cluster_bulk` | a cluster of more than 2 linked accounts where more than 5 distinct accounts bought in a day | 40 |
| `buyer_cluster_promos` | linked accounts redeemed promo codes more than twice in 30 days | 60 |
| `buyer_is_seller` | the buyer owns the store | 40 |

## Counters and lists

Counters: `market_sales_amount_per_tenant_1d`, `market_sales_amount_per_tenant_30d`,
`market_sales_per_tenant_90d`, `market_refunds_per_tenant_90d`,
`market_disputes_per_tenant_90d`, `market_buys_per_cluster_1d`,
`market_promos_per_cluster_30d`.

Lists: none. `payout_destination` must be in `[privacy] id_attrs` and in
`[graph] link_on` (the defaults in the sample `openfraud.toml`), so that two
sellers paid to the same account are linked.

## Turn it on

```toml
packs = ["marketplace-and-payouts"]
```

## Tune

```toml
[overrides.payout_new_seller]
enabled = false

[overrides.payout_sales_spike]
score = 20
```

Rules cannot be edited in place. A rule that holds by decision
(`payout_new_seller`, `payout_before_fulfilment`) has no score: disable it to
replace it with your own.

## From shadow to act

Every rule of this pack acts by itself after 30 days in shadow. Use those
days: read each rule's replay on the Rules page of the admin interface. Stop
a rule with `[overrides.<rule id>] mode = "shadow"`. Check `payout_new_seller` first: it holds every first payout for 7 days.

## Known false positives

- Honest new sellers all trip `payout_new_seller` once, by design. Decide
  whether 7 days fits your business.
- A seasonal rush (a festival, a launch) trips `payout_sales_spike`.
- Categories with real return rates (clothing) trip `payout_refund_rate`.
- Dropshipping stores delivering after the payout date: `payout_before_fulfilment`.
- Friends and families buying from one phone or one office network:
  `buyer_cluster_bulk`, `buyer_cluster_promos`.
- A seller buying their own product to test checkout: `buyer_is_seller`.
- A seller changing their bank because they changed banks: `payout_destination_recent`.
- The safety brake turns restrictions into reviews when they spike.

## Scenarios

- `examples/scenarios/pack-marketplace-and-payouts.jsonl`: all 10 rules, plus an established store as control.
- `examples/scenarios/pack-marketplace-and-payouts-shadow.jsonl`: shadow behaviour.

Run them with `cargo test --test it scenarios`.
