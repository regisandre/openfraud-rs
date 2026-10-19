package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	openfraud "github.com/regisandre/openfraud-rs/sdk/go"
)

func main() {
	key, secret, hookFile := os.Args[1], os.Args[2], os.Args[3]
	ctx := context.Background()
	of := openfraud.NewClient(openfraud.Options{BaseURL: "http://127.0.0.1:18092", APIKey: key})
	probe := openfraud.Event{Type: "message.test_requested", ActorID: "go_probe", Email: "go.probe@gmail.com",
		Attrs: map[string]any{"recipients": []string{"a3@gmail.com", "b3@yahoo.com", "c3@outlook.com", "d3@icloud.com"}}}
	d, err := of.Decide(ctx, probe, openfraud.DecideOptions{})
	if err != nil || d.Decision != "quarantine" || d.Failover {
		panic(fmt.Sprintf("decide: %v %+v", err, d))
	}
	t, err := of.Track(ctx, openfraud.Event{Type: "account.created", ActorID: "go_other"})
	if err != nil || !t.Accepted {
		panic(fmt.Sprintf("track: %v %+v", err, t))
	}
	time.Sleep(4 * time.Second)
	raw, _ := os.ReadFile(hookFile)
	var hook struct {
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
	}
	if err := json.Unmarshal(raw, &hook); err != nil {
		panic(err)
	}
	h := http.Header{}
	for k, v := range hook.Headers {
		h.Set(k, v)
	}
	if err := openfraud.VerifyWebhook(secret, h, []byte(hook.Body), openfraud.WebhookOptions{}); err != nil {
		panic(err)
	}
	down := openfraud.NewClient(openfraud.Options{BaseURL: "http://127.0.0.1:1", APIKey: key})
	f, err := down.Decide(ctx, probe, openfraud.DecideOptions{})
	if err != nil || f.Decision != "allow" || !f.Failover {
		panic(fmt.Sprintf("fail open: %v %+v", err, f))
	}
	fmt.Println("go ok")
}
