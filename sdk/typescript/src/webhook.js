// Standard Webhooks verification, WebCrypto only (Node 18+, edge runtimes).

export class WebhookError extends Error {
  constructor(message) {
    super(message);
    this.name = "WebhookError";
  }
}

const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

function header(headers, name) {
  if (typeof headers.get === "function") return headers.get(name);
  for (const k of Object.keys(headers)) if (k.toLowerCase() === name) return headers[k];
  return null;
}

/**
 * Verify a webhook and return the parsed JSON body. Throws WebhookError otherwise.
 * @param {string} secret `whsec_` + base64 key
 * @param {Record<string,string>|Headers} headers
 * @param {string} rawBody the body exactly as received
 * @param {{toleranceSec?: number, now?: number}} [opts] `now` in Unix seconds
 */
export async function verifyWebhook(secret, headers, rawBody, opts = {}) {
  const { toleranceSec = 300, now = Math.floor(Date.now() / 1000) } = opts;
  const id = header(headers, "webhook-id");
  const ts = header(headers, "webhook-timestamp");
  const sigs = header(headers, "webhook-signature");
  if (!id || !ts || !sigs) throw new WebhookError("missing webhook headers");
  const t = Number(ts);
  if (!Number.isInteger(t)) throw new WebhookError("invalid timestamp");
  if (Math.abs(now - t) > toleranceSec) throw new WebhookError("timestamp outside tolerance");

  let key;
  try {
    const raw = b64(secret.startsWith("whsec_") ? secret.slice(6) : secret);
    key = await crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  } catch {
    throw new WebhookError("invalid secret");
  }
  const data = new TextEncoder().encode(`${id}.${ts}.${rawBody}`);
  for (const part of sigs.split(" ")) {
    const [version, sig] = part.split(",");
    if (version !== "v1" || !sig) continue;
    let bytes;
    try {
      bytes = b64(sig);
    } catch {
      continue;
    }
    // subtle.verify compares in constant time
    if (await crypto.subtle.verify("HMAC", key, bytes, data)) {
      try {
        return JSON.parse(rawBody);
      } catch {
        throw new WebhookError("body is not JSON");
      }
    }
  }
  throw new WebhookError("no matching signature");
}
