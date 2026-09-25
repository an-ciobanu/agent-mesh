package greet

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/discovery"
	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
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
	reply, _, peer, err := Initiate(ctx, disco, resolver.New(), a2a.NewClient(), mcp.NewClient(), priv, caller, "greeter", "hello there")
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

func TestInitiateErrorsWhenPeerRequiresAuth(t *testing.T) {
	reg := httptest.NewServer(registry.New(zerolog.Nop()).Handler())
	defer reg.Close()

	// A peer whose card declares a non-empty security requirement — P1 has no
	// way to satisfy that, so Initiate must refuse rather than greet blindly.
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"secure-greeter","url":"http://example.invalid/a2a","version":"0.1.0","security":[{"oauth2":[]}]}`))
	}))
	defer agent.Close()

	disco := discovery.New(reg.URL)
	ctx := context.Background()
	if err := disco.Register(ctx, domain.AgentInfo{
		Name: "secure-greeter", Role: "greeter", BaseURL: agent.URL,
		CardURL: agent.URL + "/.well-known/agent-card.json",
	}); err != nil {
		t.Fatal(err)
	}

	priv, _ := crypto.GenerateEd25519()
	_, _, _, err := Initiate(ctx, disco, resolver.New(), a2a.NewClient(), mcp.NewClient(),
		priv, domain.LocalANSName("visitor"), "greeter", "hi")
	if err == nil {
		t.Fatal("expected error when the peer requires authentication")
	}
	if !strings.Contains(err.Error(), "requires unsupported authentication") {
		t.Fatalf("error = %q, want it to mention unsupported authentication", err.Error())
	}
}

func TestInitiateErrorsWhenNoPeer(t *testing.T) {
	reg := httptest.NewServer(registry.New(zerolog.Nop()).Handler())
	defer reg.Close()

	priv, _ := crypto.GenerateEd25519()
	_, _, _, err := Initiate(context.Background(), discovery.New(reg.URL), resolver.New(), a2a.NewClient(), mcp.NewClient(),
		priv, domain.LocalANSName("visitor"), "greeter", "hi")
	if err == nil {
		t.Fatal("expected error when no agent of the role exists")
	}
}
