> Status: 0.1, matches docs/api.md
> Last checked: 2026-10-19

# openfraud for Go

Standard library only.

```sh
go get github.com/regisandre/openfraud-rs/sdk/go
```

## Decide before a sensitive action

```go
of := openfraud.NewClient(openfraud.Options{
	BaseURL: "http://127.0.0.1:8092", APIKey: os.Getenv("OPENFRAUD_KEY"),
})

d, err := of.Decide(ctx, openfraud.Event{Type: "message.send_requested", ActorID: user.ID, IP: ip}, openfraud.DecideOptions{})
if err != nil { // *openfraud.APIError: a 4xx, a bug in your call
	return err
}
switch d.Decision {
case openfraud.Block, openfraud.Quarantine:
	return errRefused
case openfraud.StepUp:
	return askForMFA()
}
send() // allow, review (a person looks later), hold if you handle it
```

Fail open: on a timeout (300 ms), a network error, a 429 or a 5xx, `Decide` retries twice
(50 ms, 150 ms, same `Idempotency-Key` and event id) and then returns
`Decision: "allow", Failover: true` with a nil error, so an outage never blocks your users.
Where a false allow costs money (payouts), set `DecideOptions{FailClosed: true}` to get `hold`.

`Track` and `TrackBatch` send events without waiting for a decision; on transport errors
they return `Accepted: false` and a nil error.

## Verify a webhook

```go
body, _ := io.ReadAll(r.Body) // the raw body, before any JSON parsing
if err := openfraud.VerifyWebhook(os.Getenv("OPENFRAUD_WEBHOOK_SECRET"), r.Header, body, openfraud.WebhookOptions{}); err != nil {
	http.Error(w, "bad signature", http.StatusBadRequest) // also: timestamp older than 5 minutes
	return
}
```

## Tests

```sh
cd sdk/go && go test ./...
```
