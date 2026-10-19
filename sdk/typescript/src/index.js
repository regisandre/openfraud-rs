// openfraud client: fetch + WebCrypto only. Fails open by default.
export { verifyWebhook, WebhookError } from "./webhook.js";

export class OpenFraudError extends Error {
  /** @param {number} status @param {string} type @param {string} message */
  constructor(status, type, message) {
    super(message);
    this.name = "OpenFraudError";
    this.status = status;
    this.type = type;
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function randomId(prefix) {
  const b = crypto.getRandomValues(new Uint8Array(16));
  return prefix + Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

export class Client {
  /**
   * @param {{baseUrl: string, apiKey: string, timeoutMs?: number, retries?: number, backoffMs?: number[]}} o
   */
  constructor({ baseUrl, apiKey, timeoutMs = 300, retries = 2, backoffMs = [50, 150] }) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.apiKey = apiKey;
    this.timeoutMs = timeoutMs;
    this.retries = retries;
    this.backoffMs = backoffMs;
  }

  // POST with retries. Returns {body} on 2xx, {error} on transport/5xx/429 exhaustion.
  // Throws OpenFraudError on other 4xx.
  async #post(path, payload, idemKey) {
    const body = JSON.stringify(payload);
    let error = "unknown";
    for (let attempt = 0; attempt <= this.retries; attempt++) {
      if (attempt > 0) {
        const base = this.backoffMs[Math.min(attempt - 1, this.backoffMs.length - 1)];
        await sleep(base * (0.5 + Math.random() * 0.5)); // jitter
      }
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), this.timeoutMs);
      try {
        const res = await fetch(this.baseUrl + path, {
          method: "POST",
          signal: ctl.signal,
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${this.apiKey}`,
            "idempotency-key": idemKey,
          },
          body,
        });
        const text = await res.text();
        let json = null;
        try {
          json = JSON.parse(text);
        } catch {}
        if (res.ok) return { body: json ?? {} };
        if (res.status === 429 || res.status >= 500) {
          error = `http ${res.status}`;
          continue;
        }
        const e = json?.error ?? {};
        throw new OpenFraudError(res.status, e.type ?? "http_error", e.message ?? text);
      } catch (e) {
        if (e instanceof OpenFraudError) throw e;
        error = e?.name === "AbortError" ? "timeout" : String(e?.message ?? e);
      } finally {
        clearTimeout(timer);
      }
    }
    return { error };
  }

  /**
   * Ask for a decision before a sensitive action.
   * Fail open on timeout, network error, 429 or 5xx; `failClosed` returns `hold` instead.
   * Throws OpenFraudError on 4xx.
   */
  async decide(event, { idempotencyKey, failClosed = false } = {}) {
    const ev = { ...event, id: event.id ?? randomId("evt_") };
    const r = await this.#post("/v1/decide", ev, idempotencyKey ?? ev.id);
    if (r.body) return r.body;
    return {
      event_id: ev.id,
      decision: failClosed ? "hold" : "allow",
      score: 0,
      reasons: [],
      actions: [],
      failover: true,
      error: r.error,
    };
  }

  /** Send one event without waiting for a decision. Never throws on transport errors. */
  async track(event) {
    const ev = { ...event, id: event.id ?? randomId("evt_") };
    const r = await this.#post("/v1/events", ev, ev.id);
    return r.body ?? { event_id: ev.id, accepted: false, error: r.error };
  }

  /** Send up to 100 events. Never throws on transport errors. */
  async trackBatch(events) {
    const evs = events.map((e) => ({ ...e, id: e.id ?? randomId("evt_") }));
    const r = await this.#post("/v1/events/batch", { events: evs }, randomId("batch_"));
    return r.body ?? { accepted: false, error: r.error };
  }
}
