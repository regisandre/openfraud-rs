> Status: shipped in shadow mode, opt-in
> Last checked: 2026-10-29

# hosting-and-content

## What it covers

Platforms that host pages, files or domains for users: phishing and brand
impersonation pages, known-malicious uploads, link and SEO spam, mass creation
by young accounts, and verdicts from an outside moderation service or from
user reports.

## Events it needs

| Event | Attrs read |
|---|---|
| `content.published` | `attrs.title` (or any short text of the page), `attrs.has_password_form` (bool), `attrs.link_count`, `attrs.external_domains` (not read yet) |
| `content.uploaded` | `attrs.sha256` (lower case hex) |
| `content.moderated` | `attrs.verdict` (`allow`, `review`, `reject`), `attrs.categories` (not read yet) |
| `content.reported` | `subject` (the content), `actor_id` (the person reporting) |
| `resource.created` | none (counted per actor) |
| `resource.domain_added` | `attrs.domain` |

`attrs.domain` is a plain attribute. A `custom_domain` attribute, if you also
send one, is hashed and linked across accounts (see `[privacy] id_attrs`).

## Rules

All rules ship in `mode = "shadow"`. One workflow, `content`, with bands: review
at 40, hold at 60, block at 80, quarantine at 120. A hold asks for
`suspend_feature:publishing`.

| Rule | Catches | Score or decision |
|---|---|---|
| `content_phishing_page` | a password form on a page whose title names a brand or a phishing phrase | 80 |
| `content_brand_domain` | a custom domain containing an `impersonated_brands` item | 60 |
| `content_known_bad_file` | `sha256` is on the `malware_hashes` list | decision `quarantine` |
| `content_link_spam` | a page with 20 or more links from an account under 7 days old | 40 |
| `content_link_flood` | more than 200 links published in a day | 40 |
| `content_mass_creation` | more than 20 pages or resources in a day from an account under 7 days old | 50 |
| `content_moderation_reject` | the moderation service rejected the content | 60 |
| `content_moderation_review` | the moderation service asked for a review | 40 |
| `content_reported` | 3 or more distinct people reported the same content in a day | review, on the tenant |

`content_reported` runs on the reporter's event but targets the tenant the
content belongs to: send the author's account or workspace as `tenant_id`
(and `owner_id`) on `content.reported`. The reporter is never the owner, so
the tenant gets a review case and nothing is restricted: reports alone,
however many, never suspend anyone. The reporter's own account is not
scored.

## Counters and lists

Counters: `content_resources_per_actor_1d`, `content_links_per_actor_1d`,
`content_reports_per_subject_1d`.

Lists:

- `impersonated_brands` (value): ships with a short list of brand names. Edit it
  to fit your market.
- `phishing_words` (value): ships with phrases such as "verify your account".
- `malware_hashes` (value): empty. Fill it from a hash list you are allowed to
  use, in the admin interface or through the API. No list is
  downloaded for it, even with `[server] fetch_lists = true`, and
  `content_known_bad_file` stays silent until you do.

## Turn it on

```toml
packs = ["hosting-and-content"]
```

## Tune

```toml
[overrides.content_link_spam]
score = 25

[overrides.content_reported]
enabled = false
```

Rules cannot be edited in place; thresholds and the word lists' use are part of
the rule. Edit the lists to adapt them.

## From shadow to act

Every rule of this pack acts by itself after 30 days in shadow. Use those
days: read each rule's replay on the Rules page of the admin interface. Stop
a rule with `[overrides.<rule id>] mode = "shadow"`. `content_known_bad_file` quarantines by decision: fill your hash list before the 30 days end, or pin it in shadow.

## Known false positives

- Real login pages of your own customers' businesses (a bank's customer portal
  named after the bank): `content_phishing_page`, `content_brand_domain`.
- Fan sites, resellers and agencies with a brand name in the domain:
  `content_brand_domain`.
- Link directories, link-in-bio pages and event listings with many links:
  `content_link_spam`, `content_link_flood`.
- Bulk imports by a new customer migrating from another platform:
  `content_mass_creation`.
- Brigading: three people reporting content they dislike: `content_reported`.
- A moderation service with a high review rate: `content_moderation_review`.
- The safety brake turns restrictions into reviews when they spike.

## Scenarios

- `examples/scenarios/pack-hosting-and-content.jsonl`: all 9 rules in five stories and an ordinary account as control.
- `examples/scenarios/pack-hosting-and-content-shadow.jsonl`: shadow behaviour.

Run them with `cargo test --test it scenarios`.
