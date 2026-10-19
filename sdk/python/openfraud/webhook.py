"""Standard Webhooks verification."""
import base64
import binascii
import hashlib
import hmac
import json
import time


class WebhookError(Exception):
    pass


def _header(headers, name):
    for k, v in headers.items():
        if k.lower() == name:
            return v
    return None


def verify_webhook(secret, headers, raw_body, tolerance_sec=300, now=None):
    """Return the parsed JSON body, or raise WebhookError.

    secret: "whsec_" + base64 key. raw_body: str or bytes, exactly as received."""
    now = time.time() if now is None else now
    wid = _header(headers, "webhook-id")
    ts = _header(headers, "webhook-timestamp")
    sigs = _header(headers, "webhook-signature")
    if not (wid and ts and sigs):
        raise WebhookError("missing webhook headers")
    try:
        t = int(ts)
    except ValueError:
        raise WebhookError("invalid timestamp") from None
    if abs(now - t) > tolerance_sec:
        raise WebhookError("timestamp outside tolerance")
    try:
        key = base64.b64decode(secret[6:] if secret.startswith("whsec_") else secret)
    except (binascii.Error, ValueError):
        raise WebhookError("invalid secret") from None
    if not key:
        # An empty key would accept a signature anyone can compute.
        raise WebhookError("invalid secret")
    body = raw_body if isinstance(raw_body, bytes) else raw_body.encode()
    signed = ("%s.%s." % (wid, ts)).encode() + body
    expected = hmac.new(key, signed, hashlib.sha256).digest()
    for part in sigs.split(" "):
        version, _, sig = part.partition(",")
        if version != "v1" or not sig:
            continue
        try:
            got = base64.b64decode(sig)
        except (binascii.Error, ValueError):
            continue
        if hmac.compare_digest(expected, got):
            try:
                return json.loads(body)
            except ValueError:
                raise WebhookError("body is not JSON") from None
    raise WebhookError("no matching signature")
