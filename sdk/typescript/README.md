> Status: 0.1, matches docs/api.md
> Last checked: 2026-10-19

# openfraud for JavaScript and TypeScript

No dependencies. Uses `fetch`, `crypto.subtle` and `AbortController`: Node 18+, Deno, Bun, edge runtimes.

```sh
npm install openfraud   # or copy this folder until it is published
```

## Decide before a sensitive action

```js
import { Client } from "openfraud";

const of = new Client({ baseUrl: "http://127.0.0.1:8090", apiKey: process.env.OPENFRAUD_KEY });

const d = await of.decide({ type: "message.send_requested", actor_id: user.id, ip, device });
if (d.decision === "block" || d.decision === "quarantine") return refuse();
if (d.decision === "step_up") return askForMfa();
send(); // allow, review (a person looks later), and hold if you handle it
```

Fail open: on a timeout (300 ms), a network error, a 429 or a 5xx, `decide` retries twice
(50 ms, 150 ms, same `Idempotency-Key` and event id) and then returns
`{decision: "allow", failover: true, reasons: []}` so an outage never blocks your users.
Where a false allow costs money (payouts), pass `{failClosed: true}` to get `hold` instead.
A 4xx throws `OpenFraudError` (`status`, `type`, `message`): it is a bug in your call.

`track(event)` and `trackBatch(events)` send events without waiting for a decision and
return `{accepted: false, error}` instead of throwing on transport errors.

## Verify a webhook

```js
import { verifyWebhook } from "openfraud";

// rawBody: the body string exactly as received, before any JSON parsing
const event = await verifyWebhook(process.env.OPENFRAUD_WEBHOOK_SECRET, req.headers, rawBody);
// throws WebhookError on a bad signature or a timestamp older than 5 minutes
```

## Tests

```sh
npm test
```
