> Status: shipped in shadow mode, opt-in
> Last checked: 2026-10-20

# free-tier-and-trial

## What it covers

Abuse of free plans and trials: sign-up farms, throwaway mailboxes, one card or
one person behind many trials, trial cycles (start, cancel, start again),
upgrade-use-cancel, self-referrals and promo-code farming.

## Events it needs

| Event | Attrs read |
|---|---|
| `account.created` | `email` (event field), `ip`, `device`, `attrs.username` |
| `account.referred` | `attrs.referrer_id` (a related attribute, resolved as `related.referrer_id`) |
| `subscription.trial_started` | `attrs.card_fingerprint` (hashed and linked), `attrs.card_country`, `attrs.billing_name_matches` (bool), `attrs.billing_email`, `country` |
| `payment.method_added` | `attrs.card_fingerprint`, `attrs.card_country`, `attrs.billing_name_matches`, `attrs.billing_email` |
| `subscription.upgraded`, `subscription.canceled` | none (the order and timing of the two is what counts) |
| `usage.recorded` | `attrs.units` (summed per actor over 3 days) |
| `payment.promo_redeemed` | none (counted per cluster and per network) |

Send `actor_id`, `ip` and `device` on every event: the cluster rules depend on
them.

## Rules

All rules ship in `mode = "shadow"`.

### Workflow `trial_signup` (on `account.created`)

Bands: review at 50, hold at 70, quarantine at 100. A review asks for step-up.

| Rule | Catches | Score |
|---|---|---|
| `signup_ip_burst` | more than 3 accounts from one IP in an hour | 50 |
| `signup_ip_day` | more than 10 accounts from one IP in a day | 40 |
| `signup_device_reuse` | more than 2 accounts from one device in a day | 50 |
| `signup_disposable_email` | email domain on the `disposable_domains` list | 60 |
| `signup_generated_email` | an address that looks typed by a script (`event.email_shape.generated`: five consonants in a row, almost no vowels, letters and digits shuffled) | 20 |
| `signup_numeric_email` | an address of digits only, except at Chinese providers (QQ numbers) | 15 |
| `signup_email_aliases` | one mailbox signed up under more than 2 spellings (plus tags, Gmail dots) in 30 days | 30 |
| `signup_stem_burst` | more than 3 sign-ups in a day from numbered addresses with the same name of 4 letters or more (`marketing01`, `marketing02` ...) | 30 |
| `signup_flagged_mailbox` | the same mailbox as a quarantined or fraudulent account | 100 |
| `signup_flagged_device` | a device used by a quarantined or fraudulent account | 60 |
| `signup_flagged_cluster` | linked to a quarantined or fraudulent account | 50 |
| `signup_brand_name` | `attrs.username` contains an `impersonated_brands` item | 10 |

### Workflow `trial_start` (on `subscription.trial_started`, `payment.method_added`)

Bands: review at 50, hold at 70, quarantine at 100. Review and hold put the
account in status `review` and ask for `limit:trial`; quarantine asks for
`suspend_feature:trial`.

| Rule | Catches | Score |
|---|---|---|
| `trial_fresh_account` | trial started less than an hour after sign-up | 30 |
| `trial_card_reused` | this card already started a trial on another account | 60 |
| `trial_cluster_reused` | an account linked to this one already had a trial | 50 |
| `trial_card_shared` | this card is on another account | 30 |
| `trial_card_flagged` | this card is on a quarantined or fraudulent account | decision `quarantine` |
| `trial_cycles` | linked accounts canceled trials twice or more, then started another | 40 |
| `trial_billing_name` | `billing_name_matches` is false | 10 |
| `trial_billing_email` | the billing email does not look like the account email | 10 |
| `trial_card_country` | `card_country` differs from the connection country | 15 |

### Workflow `trial_cancel` (on `subscription.canceled`)

Review at 40.

| Rule | Catches | Score |
|---|---|---|
| `trial_upgrade_use_cancel` | canceled within 3 days of an upgrade, after using the unlocked quota | 40 |

### Workflow `trial_promo` (on `account.referred`, `payment.promo_redeemed`)

Review at 40, hold at 60 (hold asks for `limit:promo`).

| Rule | Catches | Score |
|---|---|---|
| `referral_same_cluster` | referrer and new account are linked: a self-referral | 70 |
| `referral_burst` | more than 10 referrals by one account in a day | 30 |
| `promo_cluster_farming` | linked accounts redeemed promo codes more than twice in 30 days | 60 |
| `promo_network_farming` | more than 3 accounts redeemed promo codes from one /24 in a day | 40 |

## Counters and lists

Counters: `trial_accounts_per_ip_1h`, `trial_accounts_per_ip_1d`,
`trial_accounts_per_device_1d`, `trial_accounts_per_card` (365 days),
`trial_accounts_per_cluster` (365 days), `trial_cancels_per_cluster`,
`trial_usage_per_actor_3d`, `trial_promos_per_cluster_30d`,
`trial_promos_per_code_ip_1d`, `trial_referrals_per_referrer_1d`.

Lists:

- `disposable_domains` (domain): downloaded from a public list only with
  `[server] fetch_lists = true`. Until then it is empty and `signup_disposable_email`
  stays silent. Add domains by hand in the admin interface if you prefer.
- `impersonated_brands` (value): ships with a short list of brand names. Edit it
  to fit your market.

Card and cluster rules need `card_fingerprint` in `[privacy] id_attrs` and in
`[graph] link_on` (both are the defaults in the sample `openfraud.toml`).

## Turn it on

```toml
packs = ["free-tier-and-trial"]
```

## Tune

Rules cannot be edited in place. Override them:

```toml
[overrides.signup_ip_burst]
score = 30

[overrides.signup_brand_name]
enabled = false
```

## Promote a rule from shadow to act

Run the pack in shadow first. In the admin interface, open the Rules page,
review the 30-day replay of the rule, then promote it. Nothing acts before that.

## Known false positives

- Offices, schools, co-working spaces and mobile carriers share an IP:
  `signup_ip_burst`, `signup_ip_day` and `promo_network_farming`. A shared
  address that links more than `[graph] max_shared` accounts links nobody.
- Families and flatmates share a device or a card: `signup_device_reuse`,
  `trial_card_reused`, `trial_card_shared`, `promo_cluster_farming`.
- A real referral between two people on the same device or network:
  `referral_same_cluster`.
- A customer on a card issued abroad, or a company card in a colleague's name:
  `trial_card_country`, `trial_billing_name`, `trial_billing_email`.
- A customer who starts a trial minutes after sign-up: `trial_fresh_account`
  (30 points alone never reaches review).
- The safety brake turns restrictions into reviews when they spike.

## Scenarios

- `examples/scenarios/pack-free-tier-and-trial-signup.jsonl`
- `examples/scenarios/pack-free-tier-and-trial-trial.jsonl`
- `examples/scenarios/pack-free-tier-and-trial-promo.jsonl`
- `examples/scenarios/pack-free-tier-and-trial-shadow.jsonl` (shadow behaviour)

Together they make all 22 rules fire, with legitimate controls that stay allowed.
Older end-to-end stories using this pack: `trial-farming.jsonl`,
`signup-farm.jsonl`, `trial-probe.jsonl`, `trial-probe-shadow.jsonl`.
Run them with `cargo test --test scenarios`.
