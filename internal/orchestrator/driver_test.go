package orchestrator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDriverCollideCallsInitiatorTrigger(t *testing.T) {
	var gotBody map[string]string
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/trigger/greet" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]any{"greetId": "gX", "reply": "hi", "accepted": true})
	}))
	defer stub.Close()

	r := Roster{Agents: []Agent{
		{Name: "Noah", Role: "greeter-open", Policy: "open", Addr: stub.Listener.Addr().String()},
		{Name: "Ada", Role: "greeter-open", Policy: "open", Addr: "127.0.0.1:1"},
	}}
	d := NewDriver(r)

	greetID, err := d.Collide(context.Background(), "Noah", "Ada")
	if err != nil {
		t.Fatalf("Collide: %v", err)
	}
	if greetID != "gX" {
		t.Fatalf("greetID = %q", greetID)
	}
	if gotBody["toRole"] != "greeter-open" || gotBody["toName"] != "Ada" {
		t.Fatalf("trigger body = %+v", gotBody)
	}
}

func TestDriverCollideRejectsAuthorityTarget(t *testing.T) {
	r := Roster{Agents: []Agent{
		{Name: "Noah", Role: "greeter-open", Policy: "open", Addr: "127.0.0.1:1"},
		{Name: "authority-1", Role: "authority", Policy: "authority", Addr: "127.0.0.1:2"},
	}}
	if _, err := NewDriver(r).Collide(context.Background(), "Noah", "authority-1"); err == nil {
		t.Fatal("greeting the authority should error")
	}
}
