package orchestrator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func bookWith(agents ...Agent) *AgentBook {
	return NewAgentBook(Roster{Agents: agents}, 18300)
}

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

	b := bookWith(
		Agent{Name: "Noah", Role: "greeter-open", Policy: "open", Addr: stub.Listener.Addr().String()},
		Agent{Name: "Ada", Role: "greeter-open", Policy: "open", Addr: "127.0.0.1:1"},
	)
	greetID, err := NewDriver(b).Collide(context.Background(), "Noah", "Ada")
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
	b := bookWith(
		Agent{Name: "Noah", Role: "greeter-open", Policy: "open", Addr: "127.0.0.1:1"},
		Agent{Name: "authority-1", Role: "authority", Policy: "authority", Addr: "127.0.0.1:2"},
	)
	if _, err := NewDriver(b).Collide(context.Background(), "Noah", "authority-1"); err == nil {
		t.Fatal("greeting the authority should error")
	}
}

func TestCollideRoutesSellerToBuy(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]string{"greetId": "g1"})
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	roster := Roster{Agents: []Agent{
		{Name: "Ada", Role: "greeter-open", Policy: "open", Type: "simple", Addr: addr},
		{Name: "shop-acp", Role: "seller", Policy: "acp", Type: "acp", Addr: "127.0.0.1:1"},
	}}
	book := NewAgentBook(roster, 19999)
	d := NewDriver(book)
	if _, err := d.Collide(context.Background(), "Ada", "shop-acp"); err != nil {
		t.Fatalf("collide: %v", err)
	}
	if gotPath != "/trigger/buy" {
		t.Fatalf("path = %q, want /trigger/buy", gotPath)
	}
}

func TestCollideRoutesUCPSellerToBuy(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]string{"greetId": "g1"})
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	roster := Roster{Agents: []Agent{
		{Name: "Ada", Role: "greeter-open", Policy: "open", Type: "simple", Addr: addr},
		{Name: "shop-ucp", Role: "seller", Policy: "ucp", Type: "ucp", Addr: "127.0.0.1:1"},
	}}
	book := NewAgentBook(roster, 19998)
	d := NewDriver(book)
	if _, err := d.Collide(context.Background(), "Ada", "shop-ucp"); err != nil {
		t.Fatalf("collide: %v", err)
	}
	if gotPath != "/trigger/buy" {
		t.Fatalf("path = %q, want /trigger/buy", gotPath)
	}
}
