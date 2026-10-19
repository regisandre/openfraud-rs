package openfraud

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ErrWebhook is wrapped by every verification failure.
var ErrWebhook = errors.New("openfraud: invalid webhook")

// WebhookOptions tunes VerifyWebhook. The zero value means 5 minutes and time.Now.
type WebhookOptions struct {
	Tolerance time.Duration
	Now       time.Time
}

func fail(msg string) error { return fmt.Errorf("%w: %s", ErrWebhook, msg) }

// VerifyWebhook checks a Standard Webhooks request. secret is "whsec_" + base64
// key; body is the raw body exactly as received. It returns nil when valid.
func VerifyWebhook(secret string, h http.Header, body []byte, o WebhookOptions) error {
	if o.Tolerance <= 0 {
		o.Tolerance = 5 * time.Minute
	}
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	id, ts, sigs := h.Get("webhook-id"), h.Get("webhook-timestamp"), h.Get("webhook-signature")
	if id == "" || ts == "" || sigs == "" {
		return fail("missing headers")
	}
	t, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return fail("invalid timestamp")
	}
	diff := o.Now.Sub(time.Unix(t, 0))
	if diff < 0 {
		diff = -diff
	}
	if diff > o.Tolerance {
		return fail("timestamp outside tolerance")
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	if err != nil || len(key) == 0 {
		// An empty key would accept a signature anyone can compute.
		return fail("invalid secret")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id + "." + ts + "."))
	mac.Write(body)
	expected := mac.Sum(nil)
	for _, part := range strings.Split(sigs, " ") {
		version, sig, ok := strings.Cut(part, ",")
		if !ok || version != "v1" {
			continue
		}
		got, err := base64.StdEncoding.DecodeString(sig)
		if err != nil {
			continue
		}
		if hmac.Equal(expected, got) {
			return nil
		}
	}
	return fail("no matching signature")
}
