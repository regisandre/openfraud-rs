// Package openfraud is the client of the openfraud fraud and abuse engine.
// Standard library only. Decide fails open by default.
package openfraud

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// Decision values.
const (
	Allow      = "allow"
	StepUp     = "step_up"
	Review     = "review"
	Hold       = "hold"
	Block      = "block"
	Quarantine = "quarantine"
)

// Subject is the object an event acts on.
type Subject struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Event is the event model of docs/api.md. Empty fields are not sent.
type Event struct {
	ID       string         `json:"id,omitempty"`
	Type     string         `json:"type"`
	At       string         `json:"at,omitempty"` // RFC 3339
	ActorID  string         `json:"actor_id,omitempty"`
	TenantID string         `json:"tenant_id,omitempty"`
	OwnerID  string         `json:"owner_id,omitempty"`
	Email    string         `json:"email,omitempty"`
	Phone    string         `json:"phone,omitempty"`
	IP       string         `json:"ip,omitempty"`
	Device   string         `json:"device,omitempty"`
	Country  string         `json:"country,omitempty"`
	Subject  *Subject       `json:"subject,omitempty"`
	Attrs    map[string]any `json:"attrs,omitempty"`
}

// Reason is one rule that fired.
type Reason struct {
	Rule     string `json:"rule"`
	Workflow string `json:"workflow"`
	Score    int    `json:"score"`
	Reason   string `json:"reason"`
	Mode     string `json:"mode"`
}

// Action is something the application should do.
type Action struct {
	Action string `json:"action"`
	Target string `json:"target"`
	ID     string `json:"id"`
}

// Shadow is what the shadow rules would have decided.
type Shadow struct {
	Decision string   `json:"decision"`
	Reasons  []Reason `json:"reasons"`
}

// DecisionResult is the answer of /v1/decide.
type DecisionResult struct {
	EventID     string   `json:"event_id"`
	Decision    string   `json:"decision"`
	Score       int      `json:"score"`
	Reasons     []Reason `json:"reasons"`
	Actions     []Action `json:"actions"`
	CaseID      *int64   `json:"case_id,omitempty"`
	StatementID *string  `json:"statement_id,omitempty"`
	HoldUntil   *string  `json:"hold_until,omitempty"`
	Shadow      *Shadow  `json:"shadow,omitempty"`
	Brake       bool     `json:"brake"`
	Duplicate   bool     `json:"duplicate"`
	TookUs      int64    `json:"took_us"`

	// Failover is true when the SDK made this decision because the server
	// could not be reached. Error then says why.
	Failover bool   `json:"-"`
	Error    string `json:"-"`
}

// TrackResult is the answer of /v1/events, or a failure note.
type TrackResult struct {
	EventID   string `json:"event_id"`
	Accepted  bool   `json:"accepted"`
	Duplicate bool   `json:"duplicate"`
	Error     string `json:"-"`
}

// BatchItem is one entry of a batch answer.
type BatchItem struct {
	EventID  string `json:"event_id"`
	Accepted bool   `json:"accepted"`
	Error    string `json:"error"`
}

// BatchResult is the answer of /v1/events/batch, or a failure note.
type BatchResult struct {
	Results  []BatchItem `json:"results"`
	Accepted bool        `json:"-"` // false when the whole call failed
	Error    string      `json:"-"`
}

// APIError is a 4xx answer: a bug in the caller. It is never retried.
type APIError struct {
	Status  int
	Type    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("openfraud: %d %s: %s", e.Status, e.Type, e.Message)
}

// Options configures a Client.
type Options struct {
	BaseURL string
	APIKey  string
	Timeout time.Duration // per attempt, default 300ms
	Retries int           // default 2 when 0; a negative value means no retry
	Backoff []time.Duration
	HTTP    *http.Client
}

// DecideOptions are the per-call options of Decide.
type DecideOptions struct {
	IdempotencyKey string
	// FailClosed returns "hold" instead of "allow" when the server is unreachable.
	FailClosed bool
}

// Client talks to one openfraud server.
type Client struct {
	base    string
	key     string
	timeout time.Duration
	retries int
	backoff []time.Duration
	http    *http.Client
}

// NewClient applies the defaults: 300 ms timeout, 2 retries, 50 ms then 150 ms backoff.
func NewClient(o Options) *Client {
	c := &Client{
		base:    strings.TrimRight(o.BaseURL, "/"),
		key:     o.APIKey,
		timeout: o.Timeout,
		retries: o.Retries,
		backoff: o.Backoff,
		http:    o.HTTP,
	}
	if c.timeout <= 0 {
		c.timeout = 300 * time.Millisecond
	}
	if c.retries == 0 {
		c.retries = 2
	} else if c.retries < 0 {
		c.retries = 0
	}
	if len(c.backoff) == 0 {
		c.backoff = []time.Duration{50 * time.Millisecond, 150 * time.Millisecond}
	}
	if c.http == nil {
		c.http = &http.Client{}
	}
	return c
}

func randomID(prefix string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

func jitter(d time.Duration) time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(d)/2+1))
	if err != nil {
		return d
	}
	return d/2 + time.Duration(n.Int64())
}

// post sends the body with retries. It returns the 2xx body, or a note
// describing the last transport/429/5xx failure. Other 4xx give an *APIError.
func (c *Client) post(ctx context.Context, path string, payload any, idemKey string) ([]byte, string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, "", err
	}
	note := "unknown"
	for attempt := 0; attempt <= c.retries; attempt++ {
		if attempt > 0 {
			i := attempt - 1
			if i >= len(c.backoff) {
				i = len(c.backoff) - 1
			}
			select {
			case <-time.After(jitter(c.backoff[i])):
			case <-ctx.Done():
				return nil, ctx.Err().Error(), nil
			}
		}
		actx, cancel := context.WithTimeout(ctx, c.timeout)
		req, err := http.NewRequestWithContext(actx, http.MethodPost, c.base+path, bytes.NewReader(body))
		if err != nil {
			cancel()
			return nil, "", err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+c.key)
		req.Header.Set("Idempotency-Key", idemKey)
		res, err := c.http.Do(req)
		if err != nil {
			cancel()
			if errors.Is(err, context.DeadlineExceeded) {
				note = "timeout"
			} else {
				note = err.Error()
			}
			continue
		}
		data, rerr := io.ReadAll(res.Body)
		res.Body.Close()
		cancel()
		switch {
		case rerr != nil:
			note = rerr.Error()
		case res.StatusCode >= 200 && res.StatusCode < 300:
			return data, "", nil
		case res.StatusCode == 429 || res.StatusCode >= 500:
			note = fmt.Sprintf("http %d", res.StatusCode)
		default:
			var env struct {
				Error struct {
					Type    string `json:"type"`
					Message string `json:"message"`
				} `json:"error"`
			}
			_ = json.Unmarshal(data, &env)
			t, m := env.Error.Type, env.Error.Message
			if t == "" {
				t = "http_error"
			}
			if m == "" {
				m = string(data)
			}
			return nil, "", &APIError{Status: res.StatusCode, Type: t, Message: m}
		}
	}
	return nil, note, nil
}

// Decide asks for a decision before a sensitive action. On timeout, network
// error, 429 or 5xx (after retries) it fails open: a synthetic "allow" with
// Failover set (or "hold" with FailClosed). It returns an *APIError on 4xx.
func (c *Client) Decide(ctx context.Context, ev Event, o DecideOptions) (*DecisionResult, error) {
	if ev.ID == "" {
		ev.ID = randomID("evt_")
	}
	key := o.IdempotencyKey
	if key == "" {
		key = ev.ID
	}
	data, note, err := c.post(ctx, "/v1/decide", ev, key)
	if err != nil {
		return nil, err
	}
	if data != nil {
		var d DecisionResult
		if jerr := json.Unmarshal(data, &d); jerr == nil {
			return &d, nil
		}
		note = "invalid response"
	}
	decision := Allow
	if o.FailClosed {
		decision = Hold
	}
	return &DecisionResult{
		EventID: ev.ID, Decision: decision,
		Reasons: []Reason{}, Actions: []Action{},
		Failover: true, Error: note,
	}, nil
}

// Track sends one event. Transport errors give Accepted=false, not an error;
// a 4xx gives an *APIError.
func (c *Client) Track(ctx context.Context, ev Event) (*TrackResult, error) {
	if ev.ID == "" {
		ev.ID = randomID("evt_")
	}
	data, note, err := c.post(ctx, "/v1/events", ev, ev.ID)
	if err != nil {
		return nil, err
	}
	var r TrackResult
	if data != nil && json.Unmarshal(data, &r) == nil {
		return &r, nil
	}
	if note == "" {
		note = "invalid response"
	}
	return &TrackResult{EventID: ev.ID, Accepted: false, Error: note}, nil
}

// TrackBatch sends up to 100 events. Same error rules as Track.
func (c *Client) TrackBatch(ctx context.Context, events []Event) (*BatchResult, error) {
	evs := make([]Event, len(events))
	copy(evs, events)
	for i := range evs {
		if evs[i].ID == "" {
			evs[i].ID = randomID("evt_")
		}
	}
	data, note, err := c.post(ctx, "/v1/events/batch", map[string]any{"events": evs}, randomID("batch_"))
	if err != nil {
		return nil, err
	}
	var r BatchResult
	if data != nil && json.Unmarshal(data, &r) == nil {
		r.Accepted = true
		return &r, nil
	}
	if note == "" {
		note = "invalid response"
	}
	return &BatchResult{Accepted: false, Error: note}, nil
}
