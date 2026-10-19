import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { Client, OpenFraudError, verifyWebhook, WebhookError } from "../src/index.js";

// Fake server: `script` is a list of handlers used in order (the last one repeats).
async function fake(script) {
  const seen = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      seen.push({ url: req.url, headers: req.headers, body: JSON.parse(body || "{}") });
      script[Math.min(seen.length - 1, script.length - 1)](req, res);
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    seen,
    close: () => {
      server.closeAllConnections();
      server.close();
    },
  };
}
const json = (status, obj) => (_q, res) => {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(obj));
};
const hang = () => {};
const OK = { event_id: "e", decision: "block", score: 9, reasons: [], actions: [] };
const mk = (url, o = {}) => new Client({ baseUrl: url, apiKey: "k", timeoutMs: 80, backoffMs: [5, 10], ...o });
const EV = { type: "message.send_requested", actor_id: "u1" };

test("fail open (or hold when failClosed) on transport and 5xx errors", async () => {
  const cases = [
    ["timeout", [hang]],
    ["503 after retries", [json(503, { error: { type: "internal", message: "x" } })]],
    ["connection refused", null],
  ];
  for (const [name, script] of cases) {
    const s = script ? await fake(script) : { url: "http://127.0.0.1:1", seen: [], close() {} };
    const c = mk(s.url);
    const open = await c.decide(EV);
    assert.equal(open.decision, "allow", `${name}: allow`);
    assert.equal(open.failover, true, `${name}: failover flag`);
    assert.deepEqual(open.reasons, [], `${name}: no reasons`);
    const closed = await c.decide(EV, { failClosed: true });
    assert.equal(closed.decision, "hold", `${name}: failClosed hold`);
    assert.equal(closed.failover, true, `${name}: failClosed flag`);
    if (script) assert.equal(s.seen.length, 6, `${name}: 3 attempts per call`);
    s.close();
  }
});

test("4xx raises with the server's type and message and is never retried", async () => {
  const cases = [
    [400, "invalid_event", "bad type"],
    [401, "unauthorized", "no key"],
  ];
  for (const [status, type, message] of cases) {
    const s = await fake([json(status, { error: { type, message } })]);
    await assert.rejects(
      () => mk(s.url).decide(EV),
      (e) => e instanceof OpenFraudError && e.status === status && e.type === type && e.message === message,
      `${status}: raises`,
    );
    assert.equal(s.seen.length, 1, `${status}: one attempt`);
    s.close();
  }
});

test("retries reuse the idempotency key and the event id; success is returned", async () => {
  const cases = [
    ["generated id", EV, undefined],
    ["caller id", { ...EV, id: "evt_mine" }, undefined],
    ["explicit key", EV, "key-1"],
  ];
  for (const [name, ev, key] of cases) {
    const s = await fake([json(503, {}), json(429, {}), json(200, OK)]);
    const d = await mk(s.url).decide(ev, { idempotencyKey: key });
    assert.equal(d.decision, "block", `${name}: final answer`);
    assert.equal(s.seen.length, 3, `${name}: attempts`);
    const keys = new Set(s.seen.map((r) => r.headers["idempotency-key"]));
    const ids = new Set(s.seen.map((r) => r.body.id));
    assert.equal(keys.size, 1, `${name}: one key`);
    assert.equal(ids.size, 1, `${name}: one event id`);
    assert.ok([...ids][0], `${name}: id present`);
    if (ev.id) assert.equal([...ids][0], ev.id, `${name}: id kept`);
    if (key) assert.equal([...keys][0], key, `${name}: key kept`);
    assert.equal(s.seen[0].headers.authorization, "Bearer k", `${name}: auth`);
    s.close();
  }
});

test("track and trackBatch use their routes, retry, and never throw on transport errors", async () => {
  const s = await fake([json(503, {}), json(200, { event_id: "e", accepted: true })]);
  const r = await mk(s.url).track(EV);
  assert.equal(r.accepted, true, "track retried then ok");
  assert.equal(s.seen[0].url, "/v1/events", "track route");
  assert.equal(s.seen[0].body.id, s.seen[1].body.id, "track same id");
  s.close();

  const b = await fake([json(200, { results: [{ event_id: "e", accepted: true }] })]);
  await mk(b.url).trackBatch([EV, EV]);
  assert.equal(b.seen[0].url, "/v1/events/batch", "batch route");
  assert.ok(b.seen[0].body.events.every((e) => e.id), "batch ids");
  b.close();

  const dead = mk("http://127.0.0.1:1");
  assert.equal((await dead.track(EV)).accepted, false, "track refused");
  assert.equal((await dead.trackBatch([EV])).accepted, false, "batch refused");
});

const SECRET = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"; // gitleaks:allow (the public Standard Webhooks test vector)
const H = {
  "webhook-id": "msg_p5jXN8AQM9LWM0D4loKWxJek",
  "webhook-timestamp": "1614265330",
  "webhook-signature": "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=",
};
const BODY = '{"test": 2432232314}';
const T = 1614265330;

test("webhook verification", async () => {
  const good = [
    ["test vector", H, {}],
    ["several signatures", { ...H, "webhook-signature": "v1,AAAA " + H["webhook-signature"] }, {}],
    ["Headers object", new Headers(H), {}],
  ];
  for (const [name, headers] of good) {
    const out = await verifyWebhook(SECRET, headers, BODY, { now: T });
    assert.deepEqual(out, { test: 2432232314 }, name);
  }

  const bad = [
    ["tampered body", SECRET, H, '{"test": 2432232315}', T],
    ["wrong secret", "whsec_" + btoa("another secret key 123456789012"), H, BODY, T],
    ["old timestamp", SECRET, H, BODY, T + 301],
    ["future timestamp", SECRET, H, BODY, T - 301],
    ["missing headers", SECRET, {}, BODY, T],
    ["wrong version", SECRET, { ...H, "webhook-signature": H["webhook-signature"].replace("v1", "v2") }, BODY, T],
  ];
  for (const [name, secret, headers, body, now] of bad) {
    await assert.rejects(() => verifyWebhook(secret, headers, body, { now }), WebhookError, name);
  }
});
