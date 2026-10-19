"""openfraud client: standard library only. Fails open by default."""
from __future__ import annotations

import json
import os
import random
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from .webhook import WebhookError, verify_webhook

__all__ = ["Client", "OpenFraudError", "WebhookError", "verify_webhook", "DECISIONS", "Event", "Decision"]

DECISIONS = ("allow", "step_up", "review", "hold", "block", "quarantine")

# Typed models: plain dicts that follow docs/api.md (TypedDict needs 3.8+, fine on 3.9).
try:
    from typing import TypedDict

    class Event(TypedDict, total=False):
        id: str
        type: str
        at: Any
        actor_id: str
        actor_created_at: Any
        tenant_id: str
        owner_id: str
        email: str
        phone: str
        ip: str
        device: str
        country: str
        subject: Dict[str, str]
        attrs: Dict[str, Any]

    class Decision(TypedDict, total=False):
        event_id: str
        decision: str
        score: int
        reasons: List[Dict[str, Any]]
        actions: List[Dict[str, Any]]
        case_id: Optional[int]
        statement_id: Optional[str]
        hold_until: Optional[int]
        retry_after: Optional[int]
        shadow: Dict[str, Any]
        brake: bool
        duplicate: bool
        took_us: int
        failover: bool
        error: str
except ImportError:  # pragma: no cover
    Event = Decision = dict  # type: ignore


class OpenFraudError(Exception):
    """A 4xx answer: a bug in the caller. Carries the server's type and message."""

    def __init__(self, status: int, type_: str, message: str):
        super().__init__(message)
        self.status = status
        self.type = type_
        self.message = message


def _event_id() -> str:
    return "evt_" + os.urandom(16).hex()


class Client:
    def __init__(self, base_url: str, api_key: str, timeout_ms: int = 300, retries: int = 2,
                 backoff_ms=(50, 150)):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout_ms = timeout_ms
        self.retries = retries
        self.backoff_ms = tuple(backoff_ms)

    def _post(self, path: str, payload: dict, idem_key: str):
        """Return (body, None) on 2xx, (None, error) after retries on transport/429/5xx.
        Raise OpenFraudError on any other 4xx."""
        data = json.dumps(payload).encode()
        error = "unknown"
        for attempt in range(self.retries + 1):
            if attempt:
                base = self.backoff_ms[min(attempt - 1, len(self.backoff_ms) - 1)]
                time.sleep(base * (0.5 + random.random() * 0.5) / 1000)  # jitter
            req = urllib.request.Request(
                self.base_url + path, data=data, method="POST",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + self.api_key,
                    "Idempotency-Key": idem_key,
                },
            )
            try:
                with urllib.request.urlopen(req, timeout=self.timeout_ms / 1000) as res:
                    return json.loads(res.read() or b"{}"), None
            except urllib.error.HTTPError as e:
                text = e.read().decode("utf-8", "replace")
                if e.code == 429 or e.code >= 500:
                    error = "http %d" % e.code
                    continue
                try:
                    err = json.loads(text).get("error", {})
                except (ValueError, AttributeError):
                    err = {}
                raise OpenFraudError(e.code, err.get("type", "http_error"), err.get("message", text)) from None
            except (urllib.error.URLError, OSError, ValueError) as e:
                error = "timeout" if "timed out" in str(e) else str(e)
        return None, error

    def decide(self, event: dict, idempotency_key: Optional[str] = None, fail_closed: bool = False) -> dict:
        """Ask for a decision before a sensitive action.

        Fails open (allow) on timeout, network error, 429 or 5xx; fail_closed=True gives
        hold instead. Raises OpenFraudError on 4xx."""
        ev = dict(event)
        ev.setdefault("id", _event_id())
        body, error = self._post("/v1/decide", ev, idempotency_key or ev["id"])
        if body is not None:
            return body
        return {
            "event_id": ev["id"],
            "decision": "hold" if fail_closed else "allow",
            "score": 0,
            "reasons": [],
            "actions": [],
            "failover": True,
            "error": error,
        }

    def track(self, event: dict) -> dict:
        """Send one event. Never raises on transport errors."""
        ev = dict(event)
        ev.setdefault("id", _event_id())
        body, error = self._post("/v1/events", ev, ev["id"])
        return body if body is not None else {"event_id": ev["id"], "accepted": False, "error": error}

    def track_batch(self, events: List[dict]) -> dict:
        """Send up to 100 events. Never raises on transport errors."""
        evs = []
        for e in events:
            e = dict(e)
            e.setdefault("id", _event_id())
            evs.append(e)
        body, error = self._post("/v1/events/batch", {"events": evs}, "batch_" + os.urandom(16).hex())
        return body if body is not None else {"accepted": False, "error": error}
