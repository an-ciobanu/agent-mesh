package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/discovery"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/registry"
)

func TestP0_RegisterDiscoverAndFetchCard(t *testing.T) {
	reg := httptest.NewServer(registry.New(zerolog.Nop()).Handler())
	defer reg.Close()

	card := a2a.Card{Name: "greeter-open", Version: "0.1.0", Security: []map[string][]string{}}
	agent := httptest.NewServer(a2a.CardHandler(card, zerolog.Nop()))
	defer agent.Close()

	disco := discovery.New(reg.URL)
	ctx := context.Background()

	info := domain.AgentInfo{
		Name:    "greeter-open",
		Role:    "greeter",
		BaseURL: agent.URL,
		CardURL: agent.URL + "/.well-known/agent-card.json",
	}
	if err := disco.Register(ctx, info); err != nil {
		t.Fatalf("register: %v", err)
	}

	peers, err := disco.Search(ctx, "greeter")
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(peers) != 1 {
		t.Fatalf("want 1 peer, got %d", len(peers))
	}

	resp, err := http.Get(peers[0].CardURL)
	if err != nil {
		t.Fatalf("fetch card: %v", err)
	}
	defer resp.Body.Close()

	var got a2a.Card
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode card: %v", err)
	}
	if got.Name != "greeter-open" {
		t.Fatalf("card name = %q, want greeter-open", got.Name)
	}
}
