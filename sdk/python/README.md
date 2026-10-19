> Status: 0.1, matches docs/api.md
> Last checked: 2026-10-19

# openfraud for Python

Standard library only. Python 3.9+.

```sh
pip install ./sdk/python   # from a checkout, until it is published
```

## Decide before a sensitive action

```python
import os
from openfraud import Client

of = Client("http://127.0.0.1:8092", os.environ["OPENFRAUD_KEY"])

d = of.decide({"type": "message.send_requested", "actor_id": user.id, "ip": ip, "device": device})
if d["decision"] in ("block", "quarantine"):
    refuse()
elif d["decision"] == "step_up":
    ask_for_mfa()
else:
    send()  # allow, review (a person looks later), hold if you handle it
```

Fail open: on a timeout (300 ms), a network error, a 429 or a 5xx, `decide` retries twice
(50 ms, 150 ms, same `Idempotency-Key` and event id) and then returns
`{"decision": "allow", "failover": True, "reasons": []}` so an outage never blocks your users.
Where a false allow costs money (payouts), pass `fail_closed=True` to get `hold` instead.
A 4xx raises `OpenFraudError` (`status`, `type`, `message`): it is a bug in your call.

`track(event)` and `track_batch(events)` send events without waiting for a decision and
return `{"accepted": False, "error": ...}` instead of raising on transport errors.

## Verify a webhook

```python
from openfraud import verify_webhook, WebhookError

# raw_body: the body exactly as received, before any JSON parsing
try:
    event = verify_webhook(os.environ["OPENFRAUD_WEBHOOK_SECRET"], request.headers, raw_body)
except WebhookError:
    return 400  # bad signature, or a timestamp older than 5 minutes
```

## Tests

```sh
python -m unittest discover -s sdk/python/tests
```
