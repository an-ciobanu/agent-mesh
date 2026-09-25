package a2a

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
)

func TestNewMuxServesCardWithDynamicURLAndA2A(t *testing.T) {
	self := domain.LocalANSName("greeter-open")
	svc := NewGreetService(self, policy.Open{}, zerolog.Nop())
	card := Card{Name: "greeter-open", Version: "0.1.0", Security: []map[string][]string{}}

	ts := httptest.NewServer(NewMux(card, svc, zerolog.Nop()))
	defer ts.Close()

	// Card is served and its url points at this host's /a2a (not a baked value).
	resp, err := http.Get(ts.URL + "/.well-known/agent-card.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got Card
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.URL != ts.URL+"/a2a" {
		t.Fatalf("card url = %q, want %q", got.URL, ts.URL+"/a2a")
	}

	// The /a2a route exists (a bare GET is the wrong method -> 405, not 404).
	resp2, err := http.Get(ts.URL + "/a2a")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode == http.StatusNotFound {
		t.Fatal("/a2a route not registered")
	}
}
