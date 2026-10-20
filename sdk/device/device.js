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

// Send it with your event: { type: "auth.login", actor_id, device: deviceId(),
//   attrs: { webdriver: automated() } }
