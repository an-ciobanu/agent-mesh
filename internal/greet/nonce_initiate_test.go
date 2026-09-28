package greet

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/discovery"
	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
	"github.com/an-ciobanu/agent-mesh/internal/comms/resolver"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/nonce"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
	"github.com/an-ciobanu/agent-mesh/internal/registry"
)

func nonceCard(name string) a2a.Card {
	return a2a.Card{
		Name: name, Version: "0.1.0",
		Security: []map[string][]string{{"dpop": {}}},
		Capabilities: &a2a.Capabilities{Extensions: []a2a.Extension{{
			URI: a2a.ExtNonceURI, Required: true,
		}}},
	}
}

func TestInitiateNonceHappyPath(t *testing.T) {
	ctx := context.Background()
	reg := httptest.NewServer(registry.New(zerolog.Nop()).Handler())
	defer reg.Close()
	disco := discovery.New(reg.URL)

	const gname = "greeter-nonce"
	self := domain.LocalANSName(gname)
	store := nonce.NewStore(time.Minute)
	guard := policy.NewNonce(self, store, zerolog.Nop())

	mux := a2a.NewMux(nonceCard(gname), a2a.NewGreetService(self, guard, zerolog.Nop()), zerolog.Nop())
	mcpSrv := mcp.NewServer(zerolog.Nop())
	mcpSrv.Register("get_nonce", store.MCPTool())
	mux.Handle("/mcp", mcpSrv.Handler())
	greeter := httptest.NewServer(mux)
	defer greeter.Close()

	if err := disco.Register(ctx, domain.AgentInfo{Name: gname, Role: "greeter-nonce", BaseURL: greeter.URL, CardURL: greeter.URL + "/.well-known/agent-card.json"}); err != nil {
		t.Fatal(err)
	}

	visitorPriv, _ := crypto.GenerateEd25519()
	reply, _, _, peer, err := Initiate(ctx, disco, resolver.New(), a2a.NewClient(), mcp.NewClient(),
		visitorPriv, domain.LocalANSName("visitor"), "greeter-nonce", "hello")
	if err != nil {
		t.Fatalf("nonce greet failed: %v", err)
	}
	if peer.Name != gname || reply == "" {
		t.Fatalf("unexpected result: peer=%s reply=%q", peer.Name, reply)
	}
}

func TestInitiateNonceNoGetNonce(t *testing.T) {
	ctx := context.Background()
	reg := httptest.NewServer(registry.New(zerolog.Nop()).Handler())
	defer reg.Close()
	disco := discovery.New(reg.URL)

	const gname = "greeter-nonce"
	self := domain.LocalANSName(gname)
	// Greeter advertises the nonce extension but serves NO /mcp get_nonce.
	greeter := httptest.NewServer(a2a.NewMux(nonceCard(gname), a2a.NewGreetService(self, policy.Open{}, zerolog.Nop()), zerolog.Nop()))
	defer greeter.Close()
	if err := disco.Register(ctx, domain.AgentInfo{Name: gname, Role: "greeter-nonce", BaseURL: greeter.URL, CardURL: greeter.URL + "/.well-known/agent-card.json"}); err != nil {
		t.Fatal(err)
	}

	visitorPriv, _ := crypto.GenerateEd25519()
	if _, _, _, _, err := Initiate(ctx, disco, resolver.New(), a2a.NewClient(), mcp.NewClient(),
		visitorPriv, domain.LocalANSName("visitor"), "greeter-nonce", "hi"); err == nil {
		t.Fatal("expected error when the greeter has no get_nonce endpoint")
	}
}
