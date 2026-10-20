> Status: shipped in 0.1, matches src/main.rs, src/run.rs, src/keys.rs and the Dockerfile
> Last checked: 2026-10-20

# Running openfraud

One static binary, one SQLite file, one TOML file. No other service to run.

```sh
cargo build --release          # Rust 1.92 or newer; produces target/release/openfraud
openfraud serve                # API on 127.0.0.1:8092, admin on 127.0.0.1:8093
```

Command line (`-c`/`--config` or `OPENFRAUD_CONFIG`, default `openfraud.toml`,
applies to every command):

| Command | |
|---|---|
| `openfraud serve` | start both listeners and the background work |
| `openfraud validate` | check the configuration with the core and packs merged in |
| `openfraud packs` | list the built-in packs |
| `openfraud simulate <file>` | run a scenario ([rules.md](rules.md)) |
| `openfraud replay [--candidate <file>] [--days 30]` | replay stored events ([safety.md](safety.md)) |
| `openfraud admin-token` | print a new admin token; the old one stops working |
| `openfraud key add <name>` / `list` / `revoke <id>` | manage API keys |

Logs go to stderr, `openfraud=info,warn` by default; set `RUST_LOG` to change
it. Ctrl-C or SIGTERM stops the listeners gracefully.

## First start

If the configuration file does not exist, `serve` writes the default one
(the `openfraud.toml` of the repository: core on, no pack, every module off).
It then creates the **state file** and prints the admin token once on stderr:

```text
admin token (shown once, keep it): ofa_...
```

Only a digest of the token is kept. If you lose it, run `openfraud
admin-token` for a new one.

A host that starts many instances can give the token instead: set
`OPENFRAUD_ADMIN_TOKEN` (at least 24 characters) and each start makes it the
admin token, without printing anything. The state file keeps its digest
only. While it is set, the interface's "rotate" answers `409 conflict`:
change the variable and restart instead.

Such a host can give the webhook signing secret too: `OPENFRAUD_WEBHOOK_SECRET`
(`whsec_` and the base64 of at least 16 bytes) replaces the one the state
file made, at each start, so the host checks every instance's webhooks with
a secret it knows. Next, create an API key for your backend
(below), then point your SDK at `http://127.0.0.1:8092`.

`GET /health` answers without a key (`status`, `version`, packs, brake,
modules): use it for load balancer and container health checks.

## Files

All relative paths in the configuration are relative to the configuration
file.

| File | Setting | Holds |
|---|---|---|
| `openfraud.toml` | `--config` | the configuration. The admin editor and the promote button rewrite it atomically (a temporary file next to it, then a rename), so its **directory must be writable** by the service |
| `openfraud-state.toml` | `[server] state_file` | the pseudonym key, the webhook signing secret, and SHA-256 digests of the admin token and of managed API keys. Mode 0600 on Unix |
| `openfraud.db` | `[server] database` | events, accounts, links, cases, statements, approvals, the outbox and the audit log |
| `openfraud-networks.tsv.gz` | next to the database | the downloaded network table, when `[networks]` is on ([networks.md](networks.md)); safe to delete, it is downloaded again |

**Back up the state file together with the database.** The pseudonym key in
it is what makes a returning account recognizable; a database with another
key links nothing, and the webhook secret in it is what your receiver
verifies. Never regenerate it on a live system.

### The database

SQLite in WAL mode, `synchronous = NORMAL`. The engine never checkpoints the
log itself (that would stall a decision for tens of milliseconds): a
background thread does it every second. You will see `openfraud.db-wal` and
`openfraud.db-shm` next to the file. To back up a live instance use SQLite's
online backup rather than copying files:

```sh
sqlite3 /var/lib/openfraud/openfraud.db ".backup '/backups/openfraud-$(date +%F).db'"
cp /var/lib/openfraud/openfraud-state.toml /backups/
```

Restoring is the reverse with the service stopped. Size is set mostly by
`retention_days` ([compliance.md](compliance.md)); counters are kept in memory
and rebuilt at start from the stored events.

### Editing the configuration

Saving from the admin editor validates and applies the change at once, with
no restart. A running server also notices an edit made by hand within a few
seconds and applies it; a file that does not validate is reported in the log
and the running configuration stays (run `openfraud validate` first). The
listen addresses are read at start only. API keys created with `openfraud
key` are picked up by a running server on the next request.

## API keys

The API accepts a key from three sources, combined:

1. `OPENFRAUD_API_KEYS`: comma-separated, in the environment;
2. `[server] api_keys_file`: one key per line, `#` comments (read at start);
3. keys managed in the state file, through `openfraud key` or the admin
   interface.

External keys (1 and 2) must be at least 24 characters. Generate keys with
`openfraud key add <name>` (`of_` and 48 hex digits, printed once on stdout;
the state keeps a digest, an id and the first characters):

```sh
openfraud key add backend            # prints the key
openfraud key add web --scope events # a key that may only send events
openfraud key list                   # id, first characters, date, scope, name
openfraud key revoke 3fa91c0b2d4e    # by id
```

A key is `full` by default: it sends events and also acts on accounts,
cases, lists and personal data (status, labels, export, erasure). A key made
with `--scope events` (or "Events only" in the admin interface) may only call
`/v1/decide`, `/v1/events`, `/v1/events/batch`, appeals and statements; any
other route answers 403. Give the events key to a service that only reports
what users do, and keep a full key where people act on accounts. Keys from
`OPENFRAUD_API_KEYS` and `api_keys_file` are full.

With no key at all, every call gets 401 (unless
`[server] allow_unauthenticated = true`, for tests only). Use one key per
integration so you can revoke one. All calls are logged in the audit log as
`api`, whichever key was used.

## Exposing the listeners

- **The API listener** (`8092`) is for your backend: keep it on loopback or a
  private network. It has no TLS and no rate limiting. If it must cross a
  network you do not trust, put a TLS reverse proxy in front.
- **The admin listener** (`8093`) is for people, with the admin token. Keep
  it on `127.0.0.1` and reach it by an SSH tunnel:

  ```sh
  ssh -L 8093:127.0.0.1:8093 you@fraud-host   # then open http://127.0.0.1:8093
  ```

  or behind an HTTPS reverse proxy with its own access control, for example

  ```text
  admin.example.com {
      reverse_proxy 127.0.0.1:8093
  }
  ```

  The token travels in a header on every call, so never expose the admin port
  over plain HTTP outside a tunnel. Set `[admin] enabled = false` to run
  without it (rules can then not be approved, so they stay in shadow
  unless you set `[safety] require_replay = false`: see [safety.md](safety.md)).
- If you use the Stripe module, forward only `/v1/stripe/webhook` publicly
  ([stripe.md](stripe.md)).

`OPENFRAUD_BIND` and `OPENFRAUD_ADMIN_BIND` override the two bind addresses
without editing the file (that is how the container listens on every
interface).

## Next to CrowdSec and Fail2Ban

openfraud sees accounts, not raw traffic, and the API has no rate
limiting. On the same server, run [CrowdSec](https://www.crowdsec.net) (log
analysis, a firewall or reverse-proxy bouncer, a community blocklist) and
[Fail2Ban](https://github.com/fail2ban/fail2ban) (bans after repeated
failures in a log, SSH first). Addresses they ban can also be added to
openfraud's `blocked_ips` list through `POST /v1/lists/blocked_ips/items`.

## Docker

The repository has a `Dockerfile` at its root: a two-stage build (Rust, then
a slim Debian with the CA certificates) that runs as an unprivileged user.

```sh
docker build -t openfraud .
docker run -d --name openfraud -v openfraud-data:/data \
  -e OPENFRAUD_API_KEYS="$(openssl rand -hex 24)" \
  -p 127.0.0.1:8092:8092 -p 127.0.0.1:8093:8093 openfraud
docker logs openfraud          # the admin token, at the first start
docker exec openfraud openfraud key add backend
```

- `/data` is the volume. The configuration is `/data/openfraud.toml` (the
  first start writes the default one there), and with the default relative
  paths the state file and the database are in `/data` too. Back up the
  volume.
- The image sets `OPENFRAUD_CONFIG=/data/openfraud.toml`,
  `OPENFRAUD_BIND=0.0.0.0:8092` and `OPENFRAUD_ADMIN_BIND=0.0.0.0:8093`: the
  listeners take every interface **inside** the container. Publish the admin
  port on the host's loopback only, as above, or not at all.
- To use your own configuration, put it in the volume as `openfraud.toml`
  before the first start, or edit it in the admin interface.
- Secrets for the optional modules (`STRIPE_API_KEY`, `OPENFRAUD_AI_API_KEY`,
  `OPENFRAUD_TELEGRAM_TOKEN`, SMTP credentials) are environment variables:
  pass them with `-e` or an env file.

## systemd

```ini
# /etc/systemd/system/openfraud.service
[Unit]
Description=openfraud
After=network.target

[Service]
User=openfraud
Group=openfraud
EnvironmentFile=/etc/openfraud/env
ExecStart=/usr/local/bin/openfraud --config /etc/openfraud/openfraud.toml serve
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/etc/openfraud /var/lib/openfraud

[Install]
WantedBy=multi-user.target
```

with, in `/etc/openfraud/openfraud.toml`:

```toml
[server]
state_file = "/var/lib/openfraud/openfraud-state.toml"
database = "/var/lib/openfraud/openfraud.db"
```

`/etc/openfraud/env` holds `OPENFRAUD_API_KEYS=...` and the module secrets
(mode 0600). The first start prints the admin token to the journal:
`journalctl -u openfraud | grep "admin token"`, or run `openfraud admin-token`
as the service user.

## Upgrading

1. Back up the database and the state file.
2. Install the new binary (or image) and run `openfraud validate` with it
   against your configuration: unknown keys are errors, so a renamed option
   shows up here, not in production.
3. Restart. The database creates missing tables on start; this release has
   no separate migration step, so read the release notes first.
4. Check `/health` for the version.

The packs are built into the binary, so an upgrade can change a pack rule. A
rule whose logic changed is no longer covered by its approval and goes back
to shadow until you promote it again ([safety.md](safety.md)); your
`[overrides]` stay. Replay a candidate before restarting if you want to see
the effect first.

## Performance notes

- One engine lock: decisions are processed **one at a time**. Each is a
  short in-memory evaluation plus one SQLite transaction, and the answer
  carries `took_us`. Reads (`GET /v1/actors/...`, cases, the admin pages) take
  the same lock briefly.
- Webhook, alert, Stripe and AI deliveries run on a background thread
  outside the lock; a slow receiver does not slow decisions.
- Heavy admin operations (a replay over a long window, the Rules page over
  30 days) read many stored events; run a 30-day replay at a quiet hour on a
  big database.
- Memory grows with the counters you keep: windows of a year over many keys
  (the trial and referral counters of some packs) are the largest.
- The measured latencies (p50/p95/p99 with every pack on) and the benchmark
  to reproduce them (`cargo run --release --example bench`) are in the
  README's Performance section. Clients should still time out at 300 ms and
  fail open ([integration.md](integration.md)).
