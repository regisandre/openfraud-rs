// openfraud device id: a random 128-bit id, generated once, kept in first-party
// localStorage. No fingerprinting: nothing is read from canvas, fonts, audio or hardware.
// Storing it is subject to ePrivacy Art. 5(3) in the EU: see README.md.
const KEY = "openfraud_device";

function randomHex() {
  const bytes = crypto.getRandomValues(new Uint8Array(16)); // 128 bits
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Returns the device id, creating it on first call. Null when storage is blocked. */
export function deviceId() {
  try {
    let id = localStorage.getItem(KEY);
    if (!id) {
      id = "dev_" + randomHex();
      localStorage.setItem(KEY, id);
    }
    return id;
  } catch {
    return null; // storage blocked: send no device rather than a guess
  }
}

/** Forget the id, for example when the user withdraws consent. */
export function forgetDevice() {
  try {
    localStorage.removeItem(KEY);
  } catch {}
}

/** Whether the browser says it is under remote control (navigator.webdriver,
 * set by Selenium, Puppeteer and Playwright). A standard flag, not a fingerprint. */
export function automated() {
  try {
    return navigator.webdriver === true;
  } catch {
    return false;
  }
}

/** A device token for one request: the device id, a random nonce, the time,
 * the time zone, the platform, whether the screen takes touch, and the webdriver
 * flag. openfraud reads it once per kind of event and for two minutes, and checks
 * it against the request: no secret is in it, and no fingerprint. Make a new one
 * for each form you submit. */
export function deviceToken() {
  const read = (f, fallback) => {
    try {
      return f();
    } catch {
      return fallback;
    }
  };
  const body = {
    v: 1,
    n: randomHex(),
    t: Math.floor(Date.now() / 1000),
    tz: read(() => Intl.DateTimeFormat().resolvedOptions().timeZone || "", ""),
    p: read(() => String(navigator.platform || "").slice(0, 64), ""),
    touch: read(() => (navigator.maxTouchPoints || 0) > 0, false),
    wd: automated(),
  };
  const id = deviceId();
  if (id) body.id = id;
  const bytes = new TextEncoder().encode(JSON.stringify(body));
  let text = "";
  for (const b of bytes) text += String.fromCharCode(b);
  return "of1." + btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Send it with your event: { type: "session.login", actor_id, device_token: deviceToken() }
// (or, without the token, device: deviceId() and attrs: { webdriver: automated() }).
