package integration

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/discovery"
	"github.com/an-ciobanu/agent-mesh/internal/comms/resolver"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/greet"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
	"github.com/an-ciobanu/agent-mesh/internal/registry"
)

func TestP1_SimpleGreetEndToEnd(t *testing.T) {
	reg := httptest.NewServer(registry.New(zerolog.Nop()).Handler())
	defer reg.Close()

	const name = "greeter-open"
	self := domain.LocalANSName(name)
	svc := a2a.NewGreetService(self, policy.Open{}, zerolog.Nop())
	agent := httptest.NewServer(a2a.NewMux(
		a2a.Card{Name: name, Version: "0.1.0", Security: []map[string][]string{}}, svc, zerolog.Nop()))
	defer agent.Close()

	disco := discovery.New(reg.URL)
	ctx := context.Background()
	if err := disco.Register(ctx, domain.AgentInfo{
		Name: name, Role: "greeter", BaseURL: agent.URL,
		CardURL: agent.URL + "/.well-known/agent-card.json",
	}); err != nil {
		t.Fatal(err)
	}

	priv, _ := crypto.GenerateEd25519()
	caller := domain.LocalANSName("visitor")
	reply, _, peer, err := greet.Initiate(ctx, disco, resolver.New(), a2a.NewClient(), priv, caller, "greeter", "hello there")
	if err != nil {
		t.Fatalf("greet: %v", err)
	}
	if peer.Name != name {
		t.Fatalf("peer = %q, want %q", peer.Name, name)
	}
	if !strings.Contains(reply, caller) || !strings.Contains(reply, self) {
		t.Fatalf("reply %q must contain caller %q and self %q", reply, caller, self)
	}
}
