package greet

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
	"github.com/an-ciobanu/agent-mesh/internal/policy"
	"github.com/an-ciobanu/agent-mesh/internal/registry"
)

func TestInitiateGreetsDiscoveredOpenPeer(t *testing.T) {
	reg := httptest.NewServer(registry.New(zerolog.Nop()).Handler())
	defer reg.Close()

	const name = "greeter-open"
	self := domain.LocalANSName(name)
	svc := a2a.NewGreetService(self, policy.Open{}, zerolog.Nop())
	agent := httptest.NewServer(a2a.NewMux(a2a.Card{Name: name, Version: "0.1.0"}, svc, zerolog.Nop()))
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
	reply, peer, err := Initiate(ctx, disco, resolver.New(), a2a.NewClient(), priv, caller, "greeter", "hello there")
	if err != nil {
		t.Fatal(err)
	}
	if peer.Name != name {
		t.Fatalf("peer.Name = %q", peer.Name)
	}
	if !strings.Contains(reply, caller) || !strings.Contains(reply, self) {
		t.Fatalf("reply missing identities: %q", reply)
	}
}

func TestInitiateErrorsWhenNoPeer(t *testing.T) {
	reg := httptest.NewServer(registry.New(zerolog.Nop()).Handler())
	defer reg.Close()

	priv, _ := crypto.GenerateEd25519()
	_, _, err := Initiate(context.Background(), discovery.New(reg.URL), resolver.New(), a2a.NewClient(),
		priv, domain.LocalANSName("visitor"), "greeter", "hi")
	if err == nil {
		t.Fatal("expected error when no agent of the role exists")
	}
}
