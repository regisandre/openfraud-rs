> Status: shipped in 0.4, matches src/networks.rs and core/networks.toml
> Last checked: 2026-10-27

# Networks: who announces an address, and what kind of network it is

Two optional sources tell rules more about the IP address of an event,
without calling anyone at decision time:

- the **network table** (`[networks]`, off by default): the autonomous
  system (AS) that announces the address, its operator's name and the
  country the operator is registered in;
- the **network lists** (core, on by default, empty until downloaded): Tor
  exit relays, hosting providers and data centres, commercial VPNs.

Both are looked up in memory when the event arrives, like the other IP
lists. The raw address is still never stored.

## The network table

```toml
[networks]
enabled = true
# url = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"   # the default
# file = "ip2asn-combined.tsv.gz"   # a copy of your own instead of the download
# file = "networks.bin"             # or one compiled with `openfraud networks compile`
```

With `file` unset, openfraud downloads the dataset when `[server]
fetch_lists = true`, keeps it next to the database as
`openfraud-networks.tsv.gz`, and downloads it again every
`lists_refresh_hours`. A failed download keeps the cached copy. With
`fetch_lists = false` and no `file`, the table stays off and the log says
why.

A host that runs many instances can serve the files itself: with `[server]
lists_mirror = "http://mirror.internal/files"`, every list with a `url` is
downloaded from `<mirror>/<list name>.txt` and the dataset from
`<mirror>/ip2asn-combined.tsv.gz`, so the instances need no access to the
internet.

A download never reaches the private network unless you point it there:
a list or dataset served from the internet is fetched from internet
addresses only, whatever its DNS answers, and its redirects are followed
only to https (at most 5). A `url` or `lists_mirror` on your own network
(`http://mirror.internal`, `10.0.0.5`, a single-label name) is fetched as
configured. Turning `enabled` on or off in the configuration file takes effect
within a minute, without a restart.

The data is the [IPtoASN](https://iptoasn.com) dataset (public domain,
PDDL), IPv4 and IPv6, about 580,000 announced ranges.

Rules then read:

| Fact | Meaning |
|---|---|
| `event.ip_asn` | the AS number, for example `15169` |
| `event.ip_org` | the operator, as registered: `GOOGLE`, `OVH`, `ORANGE` |
| `event.ip_country` | the country the **operator** is registered in, not where the user is: a cloud provider registered in the US answers `US` for its servers in Frankfurt. Send `country` from your CDN for the user's country |
| `session.new_asn` | the account connects through an operator it never used before (false for its first one) |

The counter key `ip_asn` counts per operator. These facts are absent when
the table is off or the address is not announced: guard them with
`has(event.ip_asn)`.

### One table for many instances

The table can be compiled ahead of time into a file that openfraud maps
instead of reading:

```sh
openfraud networks compile ip2asn-combined.tsv.gz /srv/openfraud/networks.bin
```

```toml
[networks]
enabled = true
file = "/srv/openfraud/networks.bin"
```

A mapped file is not copied into the process: the operating system keeps
one copy of it in its page cache, shared by every instance on the host
that points at the same file (mount it read-only into each container).
The pages are clean, so under memory pressure the kernel drops them and
reads them again from the file instead of killing a process.

To refresh it, download the dataset again and run the same command: it
writes a new file and renames it over the old one. Each instance notices
the new file within a minute and maps it; the old copy is released once no
instance uses it. Never edit or truncate the compiled file in place, which
could stop the instances that have it mapped.

A file that is not compiled (TSV, gzipped or not) is still read and held in
memory by each instance.

### Memory

Measured on Windows 11 with the dataset of 2026-10-25 (582,326 ranges), as
memory private to the process:

| | Private memory |
|---|---|
| openfraud, core only | 4 MB |
| with the network table, from the TSV | 20 MB (about 16 MB for the table; up to 72 MB resident while it loads) |
| with the network table, from a compiled file | 4 MB, plus one 17 MB copy in the page cache for the whole host |

A lookup takes about half a microsecond. The SQLite page cache comes on
top and grows with the database, up to 64 MiB.

## The network lists

`core/networks.toml` defines four IP lists, downloaded only with
`fetch_lists = true` (you can also fill them by hand or through
`POST /v1/lists/{name}/items`):

| List | Source | Size |
|---|---|---|
| `tor_exits` | the Tor Project's [bulk exit list](https://check.torproject.org/torbulkexitlist) | about 1,200 addresses |
| `datacenter_ips` | [X4BNet lists_vpn](https://github.com/X4BNet/lists_vpn), `output/datacenter` (MIT): hosting, data centres and VPNs, anything that is not a home or mobile connection | about 45,000 ranges |
| `vpn_providers` | the same project, `output/vpn`: commercial VPNs only | about 11,000 ranges |
| `abuse_ips` | [FireHOL abusers_1d](https://iplists.firehol.org/?ipset=firehol_abusers_1d): addresses reported in the last day by StopForumSpam, CleanTalk, BotScout and others for abusing forms and sign-ups | tens of thousands of addresses, refreshed daily |

Rules read them as `"tor_exits" in event.ip_lists`, in rules and in counter
conditions alike. Switch them off with `[core] networks = false`.

`GET /v1/ips/{ip}` answers what openfraud knows of one address (AS number,
operator, country, lists), and `POST /v1/ips/query` of up to 1,000
([api.md](api.md)).

## Rules that use them

All in shadow until promoted ([safety.md](safety.md)).

| Rule | Where | Fires on | Score |
|---|---|---|---|
| `ato_new_device_and_network` | account takeover core | a login from a new device through a new operator | 30 |
| `ato_tor_login` | account takeover core | a login through Tor | 30 |
| `ato_impossible_travel` | account takeover core | no longer judged from `vpn_ips`, `vpn_providers`, `datacenter_ips` or `tor_exits` | 40 |
| `signup_tor_ip` | free-tier-and-trial | a sign-up through Tor | 40 |
| `signup_hosting_ip` | free-tier-and-trial | a sign-up from a server or a VPN | 15 |
| `signup_hosting_burst` | free-tier-and-trial | more than 5 sign-ups in an hour from one hosting operator's servers (a script renting servers changes address, not provider) | 40 |

A VPN or a server is not fraud by itself: many people use a VPN at work or
for privacy. That is why these rules weigh little alone and add to the
other signals.

## Testing with scenarios

A scenario adds ranges to the table with a directive, one line of the
dataset each, before the first event:

```text
# network: 198.51.100.0 198.51.100.255 64500 BE EXAMPLE-ISP Example Telecom
# list: tor_exits 192.0.2.66
```

See `examples/scenarios/core-networks.jsonl`.
