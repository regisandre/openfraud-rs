> Status: shipped in 0.1, matches src/engine.rs, src/store.rs and src/config.rs
> Last checked: 2026-10-19

# The link graph

Fraud is rarely one account. openfraud remembers which pseudonymized
identifiers each account was seen with, joins accounts that share a strong
identifier into a **cluster**, and lets rules count and decide on the cluster
instead of the single account. A person's fraud label on one account then
alerts reviewers to the others, never an automatic ban.

## Configuration

```toml
[graph]
link_on = ["card_fingerprint", "payout_destination", "device", "email", "phone", "custom_domain"]
ip_prefix_window = "1h"
max_shared = 50
max_cluster = 200
related_attrs = ["referrer_id", "inviter_id"]
```

| Key | Meaning |
|---|---|
| `link_on` | identifier kinds that join two accounts: `email`, `phone`, `device`, `ip`, or any `[privacy] id_attrs` name ([events.md](events.md)). Default as above; the exact `ip` is not in it |
| `ip_prefix_window` | two accounts on one IP /24 (/48 for IPv6) are joined only if the other was seen there within this window (`1h`); empty turns network links off |
| `max_shared` | an identifier shared by more than this many other accounts (an office, a school, a carrier NAT) joins nobody (50) |
| `max_cluster` | a cluster never grows past this many accounts (200) |
| `related_attrs` | attributes that name another account (`referrer_id`); rules read `related.<attr>` |

### Why `max_cluster` exists

Weak links chain. One shared office network joins two staff, one of whom
shares a device with a customer, who shares a phone with another ... and a
few hops later the whole user base is one cluster, so one fraud label would
open hundreds of cases and a cluster counter would count everybody. The cap
stops joining at 200 accounts: the link is still recorded (and still shows
in `links.<kind>`), but the two clusters are not merged. It also bounds the
cost of merging counters and of the cluster API. Raise it only if your real
fraud rings are bigger than that.

## How accounts are linked

For every event that has an `actor_id`, each identifier of `event.ids` (`email`,
`phone`, `ip`, `ip_prefix`, `device`, and the `id_attrs`) is stored against the
actor with the time last seen. Then, for each identifier kind:

- `links.<kind>.users` is the number of **other** accounts that share the
  value (counted up to 1,000), and `links.<kind>.flagged` how many of them
  are flagged (quarantined or labelled `fraud`). Rules read these for every
  kind present on the event, whether or not it is in `link_on`.
- If the kind is in `link_on` (or is `ip_prefix` with a window), and the
  number of others is between 1 and `max_shared`, the actor joins their
  clusters, as long as the merged size stays within `max_cluster`.

Joining is permanent: a cluster is never split, and the smaller cluster takes
the root of the larger. An actor with no link is a cluster of one. If an
account is erased, another member becomes the root.

The `email` identifier is the mailbox part of the pseudonym, so
`john.smith+a@gmail.com` and `johnsmith@gmail.com` are one email. The
`device`, `phone` and `ip` values are keyed hashes: the same value gives the
same hash, so the graph works without storing the raw values. **Never change
the pseudonym key** (in the state file): every link would be lost
([compliance.md](compliance.md)).

Links of accounts that are not flagged are deleted after `retention_days`
without activity; flagged accounts keep theirs, so a returning offender is
recognized.

## Cluster facts and counters

| Fact | Content |
|---|---|
| `links.cluster.size` | accounts in the cluster the event puts the actor in (the clusters it would join, summed) |
| `links.cluster.flagged` | of those, quarantined or labelled fraud |
| `links.cluster.fraud`, `.legit` | of those, labelled `fraud`; labelled `legit` or `false_positive` |

The decision sees the cluster as it will be after this event, so the
event that links a fresh account to a known offender already sees
`links.cluster.flagged > 0`.

A counter with `by = "cluster"` is keyed by the root of the largest cluster
involved. When two clusters merge, their counter series are added up, so
"trials started by this ring" keeps counting across the merge:

```toml
[counters.trial_accounts_per_cluster]
events = ["subscription.trial_started"]
by = "cluster"
window = "365d"
```

Shipped examples: `signup_flagged_cluster` (`links.cluster.flagged > 0`),
`trial_cluster_reused`, `referral_same_cluster`
([packs.md](packs.md)).

### Related accounts

If an event carries an attribute named in `related_attrs` with another
actor's id, rules read `related.<attr>.same_cluster` (the two are in one
cluster, or this event joins them), `.status`, `.flagged` and `.id`. Used
against self-referral:
`event.type == "account.referred" && has(related.referrer_id) && related.referrer_id.same_cluster`.
The attribute is a plain attribute (the id is yours, not personal data).

## Label propagation

`POST /v1/actors/{id}/label` with `fraud` (or resolving a case as fraud)
quarantines that account and then, for every other member of its cluster:

- if it is already flagged or trusted: nothing;
- otherwise: a **review case** with the reason `cluster_fraud` (or the reason
  is added to its open case). The case raises the usual `case.opened` webhook
  and alert.

Nothing is restricted automatically. A reviewer looks at each member and
labels it `fraud` or `legit`. A `legit` account is trusted: later
propagations skip it, and automatic blocks on it become holds (trust
protection, [rules.md](rules.md)).

## The cluster API

`GET /v1/actors/{id}/cluster` (also in the admin interface):

```json
{"cluster": {
  "root": "u_1", "size": 3, "flagged": 1, "fraud": 1, "legit": 0,
  "members": [{"id": "u_1", "status": "quarantined", "label": "fraud", "trust": 0}],
  "joined_by": [{"kind": "device", "shared_values": 1}]
}}
```

`members` lists up to 200 accounts. `joined_by` gives, per identifier kind,
how many values are shared by more than one member. An actor that is in no
cluster yet answers `{"root": null, "size": 1, "members": [], "joined_by": []}`.
`GET /v1/actors/{id}` shows, for each identifier kind, how many other
accounts share it and how many of those are flagged.
