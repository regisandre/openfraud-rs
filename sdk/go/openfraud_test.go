package openfraud

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type seenReq struct {
	path string
	hdr  http.Header
	body map[string]any
}

// fake answers from steps in order (the last one repeats). A step with
// status 0 hangs until the request is cancelled.
type step struct {
	status int
	body   string
}

type fake struct {
	*httptest.Server
	mu   sync.Mutex
	seen []seenReq
}

func newFake(steps []step) *fake {
	f := &fake{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var b map[string]any
		_ = json.Unmarshal(raw, &b)
		f.mu.Lock()
		f.seen = append(f.seen, seenReq{r.URL.Path, r.Header.Clone(), b})
		n := len(f.seen) - 1
		f.mu.Unlock()
		if n >= len(steps) {
			n = len(steps) - 1
		}
		s := steps[n]
		if s.status == 0 {
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(s.status)
		_, _ = w.Write([]byte(s.body))
	}))
	return f
}

func client(url string) *Client {
	return NewClient(Options{
		BaseURL: url, APIKey: "k", Timeout: 80 * time.Millisecond,
		Backoff: []time.Duration{5 * time.Millisecond, 10 * time.Millisecond},
	})
}

var ev = Event{Type: "message.send_requested", ActorID: "u1"}

const okBody = `{"event_id":"e","decision":"block","score":9,"reasons":[],"actions":[]}`

func TestFailOpenOrHold(t *testing.T) {
	cases := []struct {
		name  string
		steps []step // nil = connection refused
	}{
		{"timeout", []step{{0, ""}}},
		{"503 after retries", []step{{503, `{"error":{"type":"internal","message":"x"}}`}}},
		{"connection refused", nil},
	}
	for _, c := range cases {
		url := "http://127.0.0.1:1"
		var f *fake
		if c.steps != nil {
			f = newFake(c.steps)
			defer f.Close()
			url = f.URL
		}
		cl := client(url)
		open, err := cl.Decide(context.Background(), ev, DecideOptions{})
		if err != nil || open.Decision != Allow || !open.Failover || len(open.Reasons) != 0 {
			t.Errorf("%s: want failover allow, got %+v err=%v", c.name, open, err)
		}
		closed, err := cl.Decide(context.Background(), ev, DecideOptions{FailClosed: true})
		if err != nil || closed.Decision != Hold || !closed.Failover {
			t.Errorf("%s: want failover hold, got %+v err=%v", c.name, closed, err)
		}
		if f != nil && len(f.seen) != 6 {
			t.Errorf("%s: want 6 attempts (3 per call), got %d", c.name, len(f.seen))
		}
	}
}

func TestClientErrorsRaiseAndAreNotRetried(t *testing.T) {
	cases := []struct {
		status   int
		typ, msg string
	}{
		{400, "invalid_event", "bad type"},
		{401, "unauthorized", "no key"},
	}
	for _, c := range cases {
		f := newFake([]step{{c.status, `{"error":{"type":"` + c.typ + `","message":"` + c.msg + `"}}`}})
		_, err := client(f.URL).Decide(context.Background(), ev, DecideOptions{})
		var ae *APIError
		if !errors.As(err, &ae) || ae.Status != c.status || ae.Type != c.typ || ae.Message != c.msg {
			t.Errorf("%d: want APIError, got %v", c.status, err)
		}
		if len(f.seen) != 1 {
			t.Errorf("%d: want 1 attempt, got %d", c.status, len(f.seen))
		}
		f.Close()
	}
}

func TestRetriesReuseKeyAndEventID(t *testing.T) {
	withID := ev
	withID.ID = "evt_mine"
	cases := []struct {
		name string
		ev   Event
		key  string
	}{
		{"generated id", ev, ""},
		{"caller id", withID, ""},
		{"explicit key", ev, "key-1"},
	}
	for _, c := range cases {
		f := newFake([]step{{503, `{}`}, {429, `{}`}, {200, okBody}})
		d, err := client(f.URL).Decide(context.Background(), c.ev, DecideOptions{IdempotencyKey: c.key})
		if err != nil || d.Decision != Block || d.Failover {
			t.Errorf("%s: want the server decision, got %+v err=%v", c.name, d, err)
		}
		if len(f.seen) != 3 {
			t.Fatalf("%s: want 3 attempts, got %d", c.name, len(f.seen))
		}
		first := f.seen[0]
		for i, r := range f.seen {
			if r.hdr.Get("Idempotency-Key") != first.hdr.Get("Idempotency-Key") {
				t.Errorf("%s: attempt %d changed the idempotency key", c.name, i)
			}
			if r.body["id"] != first.body["id"] || r.body["id"] == "" {
				t.Errorf("%s: attempt %d changed the event id", c.name, i)
			}
			if r.hdr.Get("Authorization") != "Bearer k" {
				t.Errorf("%s: missing bearer", c.name)
			}
		}
		if c.ev.ID != "" && first.body["id"] != c.ev.ID {
			t.Errorf("%s: caller id not kept", c.name)
		}
		if c.key != "" && first.hdr.Get("Idempotency-Key") != c.key {
			t.Errorf("%s: explicit key not kept", c.name)
		}
		f.Close()
	}
}

func TestTrackRoutesRetryAndNoTransportError(t *testing.T) {
	f := newFake([]step{{503, `{}`}, {200, `{"event_id":"e","accepted":true}`}})
	defer f.Close()
	r, err := client(f.URL).Track(context.Background(), ev)
	if err != nil || !r.Accepted || f.seen[0].path != "/v1/events" || f.seen[0].body["id"] != f.seen[1].body["id"] {
		t.Errorf("track: got %+v err=%v seen=%v", r, err, f.seen)
	}

	b := newFake([]step{{200, `{"results":[{"event_id":"e","accepted":true}]}`}})
	defer b.Close()
	br, err := client(b.URL).TrackBatch(context.Background(), []Event{ev, ev})
	evs, _ := b.seen[0].body["events"].([]any)
	if err != nil || !br.Accepted || b.seen[0].path != "/v1/events/batch" || len(evs) != 2 {
		t.Errorf("batch: got %+v err=%v", br, err)
	}

	dead := client("http://127.0.0.1:1")
	if tr, err := dead.Track(context.Background(), ev); err != nil || tr.Accepted {
		t.Errorf("track refused: got %+v err=%v", tr, err)
	}
	if br, err := dead.TrackBatch(context.Background(), []Event{ev}); err != nil || br.Accepted {
		t.Errorf("batch refused: got %+v err=%v", br, err)
	}
}

const (
	secret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw" // gitleaks:allow (the public Standard Webhooks test vector)
	body   = `{"test": 2432232314}`
	sig    = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="
	ts     = 1614265330
)

func hdr(sigs string) http.Header {
	h := http.Header{}
	h.Set("webhook-id", "msg_p5jXN8AQM9LWM0D4loKWxJek")
	h.Set("webhook-timestamp", "1614265330")
	h.Set("webhook-signature", sigs)
	return h
}

func TestVerifyWebhook(t *testing.T) {
	at := func(d time.Duration) time.Time { return time.Unix(ts, 0).Add(d) }
	other := "whsec_" + base64.StdEncoding.EncodeToString([]byte("another secret key 123456789012"))
	cases := []struct {
		name   string
		secret string
		h      http.Header
		body   string
		now    time.Time
		valid  bool
	}{
		{"test vector", secret, hdr(sig), body, at(0), true},
		{"several signatures", secret, hdr("v1,AAAA " + sig), body, at(0), true},
		{"tampered body", secret, hdr(sig), `{"test": 2432232315}`, at(0), false},
		{"wrong secret", other, hdr(sig), body, at(0), false},
		{"old timestamp", secret, hdr(sig), body, at(301 * time.Second), false},
		{"future timestamp", secret, hdr(sig), body, at(-301 * time.Second), false},
		{"missing headers", secret, http.Header{}, body, at(0), false},
		{"wrong version", secret, hdr("v2" + sig[2:]), body, at(0), false},
	}
	for _, c := range cases {
		err := VerifyWebhook(c.secret, c.h, []byte(c.body), WebhookOptions{Now: c.now})
		if (err == nil) != c.valid {
			t.Errorf("%s: valid=%v but err=%v", c.name, c.valid, err)
		}
	}
}
