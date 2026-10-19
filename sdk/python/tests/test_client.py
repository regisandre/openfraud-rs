import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from openfraud import Client, OpenFraudError, WebhookError, verify_webhook  # noqa: E402

OK = {"event_id": "e", "decision": "block", "score": 9, "reasons": [], "actions": []}
EV = {"type": "message.send_requested", "actor_id": "u1"}


def reply(status, obj):
    return ("reply", status, obj)


HANG = ("hang",)


class Fake:
    """Local HTTP server answering from `script` in order (the last entry repeats)."""

    def __init__(self, script):
        self.seen = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(n) or b"{}")
                outer.seen.append({"path": self.path, "headers": self.headers, "body": body})
                step = script[min(len(outer.seen) - 1, len(script) - 1)]
                if step[0] == "hang":
                    outer.release.wait(2)
                    return
                data = json.dumps(step[2]).encode()
                self.send_response(step[1])
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        self.release = threading.Event()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.daemon_threads = True
        self.url = "http://127.0.0.1:%d" % self.server.server_port
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()


def mk(url):
    return Client(url, "k", timeout_ms=100, backoff_ms=(5, 10))


DEAD = "http://127.0.0.1:1"


class ClientTests(unittest.TestCase):
    def test_fail_open_or_hold_on_transport_and_5xx(self):
        cases = [
            ("timeout", [HANG]),
            ("503 after retries", [reply(503, {"error": {"type": "internal", "message": "x"}})]),
            ("connection refused", None),
        ]
        for name, script in cases:
            with self.subTest(name):
                fake = Fake(script) if script else None
                c = mk(fake.url if fake else DEAD)
                open_ = c.decide(EV)
                self.assertEqual(open_["decision"], "allow", name)
                self.assertTrue(open_["failover"], name)
                self.assertEqual(open_["reasons"], [], name)
                closed = c.decide(EV, fail_closed=True)
                self.assertEqual(closed["decision"], "hold", name)
                self.assertTrue(closed["failover"], name)
                if fake:
                    self.assertEqual(len(fake.seen), 6, name + ": 3 attempts per call")
                    fake.close()

    def test_4xx_raises_with_server_message_and_is_not_retried(self):
        for status, type_, msg in [(400, "invalid_event", "bad type"), (401, "unauthorized", "no key")]:
            with self.subTest(status):
                fake = Fake([reply(status, {"error": {"type": type_, "message": msg}})])
                with self.assertRaises(OpenFraudError) as cm:
                    mk(fake.url).decide(EV)
                e = cm.exception
                self.assertEqual((e.status, e.type, e.message), (status, type_, msg), str(status))
                self.assertEqual(len(fake.seen), 1, "%d: one attempt" % status)
                fake.close()

    def test_retries_reuse_idempotency_key_and_event_id(self):
        cases = [
            ("generated id", EV, None),
            ("caller id", dict(EV, id="evt_mine"), None),
            ("explicit key", EV, "key-1"),
        ]
        for name, ev, key in cases:
            with self.subTest(name):
                fake = Fake([reply(503, {}), reply(429, {}), reply(200, OK)])
                d = mk(fake.url).decide(ev, idempotency_key=key)
                self.assertEqual(d["decision"], "block", name)
                self.assertEqual(len(fake.seen), 3, name)
                keys = {r["headers"]["Idempotency-Key"] for r in fake.seen}
                ids = {r["body"]["id"] for r in fake.seen}
                self.assertEqual(len(keys), 1, name + ": one key")
                self.assertEqual(len(ids), 1, name + ": one event id")
                if "id" in ev:
                    self.assertEqual(ids, {ev["id"]}, name + ": id kept")
                if key:
                    self.assertEqual(keys, {key}, name + ": key kept")
                self.assertEqual(fake.seen[0]["headers"]["Authorization"], "Bearer k", name)
                fake.close()

    def test_track_and_batch_routes_retry_and_never_raise(self):
        fake = Fake([reply(503, {}), reply(200, {"event_id": "e", "accepted": True})])
        self.assertTrue(mk(fake.url).track(EV)["accepted"], "track retried then ok")
        self.assertEqual(fake.seen[0]["path"], "/v1/events", "track route")
        self.assertEqual(fake.seen[0]["body"]["id"], fake.seen[1]["body"]["id"], "track same id")
        fake.close()

        fake = Fake([reply(200, {"results": []})])
        mk(fake.url).track_batch([EV, EV])
        self.assertEqual(fake.seen[0]["path"], "/v1/events/batch", "batch route")
        self.assertTrue(all(e["id"] for e in fake.seen[0]["body"]["events"]), "batch ids")
        fake.close()

        dead = mk(DEAD)
        self.assertFalse(dead.track(EV)["accepted"], "track refused")
        self.assertFalse(dead.track_batch([EV])["accepted"], "batch refused")


SECRET = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"  # gitleaks:allow (the public Standard Webhooks test vector)
H = {
    "webhook-id": "msg_p5jXN8AQM9LWM0D4loKWxJek",
    "webhook-timestamp": "1614265330",
    "webhook-signature": "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=",
}
BODY = '{"test": 2432232314}'
T = 1614265330
# The body above signed with an empty key: what a forger sends when the
# receiver's secret is unset.
EMPTY_KEY_SIG = "v1,woH/1mJtZGSMCmpFTxRYbStS24eLLD/oXIYr4PYyZ7g="


class WebhookTests(unittest.TestCase):
    def test_accepts_valid_signatures(self):
        cases = [
            ("test vector", H),
            ("several signatures", dict(H, **{"webhook-signature": "v1,AAAA " + H["webhook-signature"]})),
            ("mixed-case headers", {k.title(): v for k, v in H.items()}),
        ]
        for name, headers in cases:
            with self.subTest(name):
                self.assertEqual(verify_webhook(SECRET, headers, BODY, now=T), {"test": 2432232314}, name)
        self.assertEqual(verify_webhook(SECRET, H, BODY.encode(), now=T), {"test": 2432232314}, "bytes body")

    def test_rejects_bad_requests(self):
        other = "whsec_" + "YW5vdGhlciBzZWNyZXQga2V5IDEyMzQ1Njc4OTAxMg=="
        cases = [
            ("tampered body", SECRET, H, '{"test": 2432232315}', T),
            ("wrong secret", other, H, BODY, T),
            ("old timestamp", SECRET, H, BODY, T + 301),
            ("future timestamp", SECRET, H, BODY, T - 301),
            ("missing headers", SECRET, {}, BODY, T),
            ("wrong version", SECRET, dict(H, **{"webhook-signature": H["webhook-signature"].replace("v1", "v2")}), BODY, T),
            ("an empty secret", "", dict(H, **{"webhook-signature": EMPTY_KEY_SIG}), BODY, T),
            ("an empty secret with its prefix", "whsec_", dict(H, **{"webhook-signature": EMPTY_KEY_SIG}), BODY, T),
        ]
        for name, secret, headers, body, now in cases:
            with self.subTest(name):
                with self.assertRaises(WebhookError, msg=name):
                    verify_webhook(secret, headers, body, now=now)


if __name__ == "__main__":
    unittest.main()
