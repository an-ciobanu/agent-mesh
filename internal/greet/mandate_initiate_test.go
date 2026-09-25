package greet

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/authority"
	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/discovery"
	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
	"github.com/an-ciobanu/agent-mesh/internal/comms/resolver"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
	"github.com/an-ciobanu/agent-mesh/internal/registry"
)

func mandateCard(name string) a2a.Card {
	return a2a.Card{
		Name: name, Version: "0.1.0",
		Security: []map[string][]string{{"mandate": {}}},
		Capabilities: &a2a.Capabilities{Extensions: []a2a.Extension{{
			URI: a2a.ExtMandateURI, Required: true,
			Params: map[string]any{"authorityRole": "authority", "scope": "greet"},
		}}},
	}
}

func TestInitiateMandateHappyPath(t *testing.T) {
	ctx := context.Background()
	reg := httptest.NewServer(registry.New(zerolog.Nop()).Handler())
	defer reg.Close()
	disco := discovery.New(reg.URL)

	authPriv, _ := crypto.GenerateEd25519()
	authAns := domain.LocalANSName("authority-1")
	auth := authority.New(authAns, authPriv, time.Hour, zerolog.Nop())
	mcpSrv := mcp.NewServer(zerolog.Nop())
	mcpSrv.Register("issue_mandate", auth.MCPTool())
	amux := http.NewServeMux()
	amux.Handle("/mcp", mcpSrv.Handler())
	authTS := httptest.NewServer(amux)
	defer authTS.Close()
	if err := disco.Register(ctx, domain.AgentInfo{Name: "authority-1", Role: "authority", BaseURL: authTS.URL, CardURL: authTS.URL + "/pubkey"}); err != nil {
		t.Fatal(err)
	}

	const gname = "greeter-mandate"
	self := domain.LocalANSName(gname)
	guard := policy.NewMandate(self, authAns, authPriv.Public().(ed25519.PublicKey), "greet", zerolog.Nop())
	greeterTS := httptest.NewServer(a2a.NewMux(mandateCard(gname), a2a.NewGreetService(self, guard, zerolog.Nop()), zerolog.Nop()))
	defer greeterTS.Close()
	if err := disco.Register(ctx, domain.AgentInfo{Name: gname, Role: "greeter-mandate", BaseURL: greeterTS.URL, CardURL: greeterTS.URL + "/.well-known/agent-card.json"}); err != nil {
		t.Fatal(err)
	}

	visitorPriv, _ := crypto.GenerateEd25519()
	reply, _, peer, err := Initiate(ctx, disco, resolver.New(), a2a.NewClient(), mcp.NewClient(),
		visitorPriv, domain.LocalANSName("visitor"), "greeter-mandate", "hello")
	if err != nil {
		t.Fatalf("mandate greet failed: %v", err)
	}
	if peer.Name != gname || reply == "" {
		t.Fatalf("unexpected result: peer=%s reply=%q", peer.Name, reply)
	}
}

func TestInitiateNoAuthorityFound(t *testing.T) {
	ctx := context.Background()
	reg := httptest.NewServer(registry.New(zerolog.Nop()).Handler())
	defer reg.Close()
	disco := discovery.New(reg.URL)

	const gname = "greeter-mandate"
	greeterTS := httptest.NewServer(a2a.NewMux(mandateCard(gname), a2a.NewGreetService(domain.LocalANSName(gname), policy.Open{}, zerolog.Nop()), zerolog.Nop()))
	defer greeterTS.Close()
	// Register the greeter but NOT any authority.
	if err := disco.Register(ctx, domain.AgentInfo{Name: gname, Role: "greeter-mandate", BaseURL: greeterTS.URL, CardURL: greeterTS.URL + "/.well-known/agent-card.json"}); err != nil {
		t.Fatal(err)
	}

	visitorPriv, _ := crypto.GenerateEd25519()
	if _, _, _, err := Initiate(ctx, disco, resolver.New(), a2a.NewClient(), mcp.NewClient(),
		visitorPriv, domain.LocalANSName("visitor"), "greeter-mandate", "hi"); err == nil {
		t.Fatal("expected error when no authority is registered")
	}
}

func TestInitiateEmptyMandate(t *testing.T) {
	ctx := context.Background()
	reg := httptest.NewServer(registry.New(zerolog.Nop()).Handler())
	defer reg.Close()
	disco := discovery.New(reg.URL)

	// Authority whose issue_mandate returns an empty mandate.
	mcpSrv := mcp.NewServer(zerolog.Nop())
	mcpSrv.Register("issue_mandate", func(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
		return []byte(`{"mandateCose":""}`), nil
	})
	amux := http.NewServeMux()
	amux.Handle("/mcp", mcpSrv.Handler())
	authTS := httptest.NewServer(amux)
	defer authTS.Close()
	if err := disco.Register(ctx, domain.AgentInfo{Name: "authority-1", Role: "authority", BaseURL: authTS.URL, CardURL: authTS.URL + "/pubkey"}); err != nil {
		t.Fatal(err)
	}

	const gname = "greeter-mandate"
	greeterTS := httptest.NewServer(a2a.NewMux(mandateCard(gname), a2a.NewGreetService(domain.LocalANSName(gname), policy.Open{}, zerolog.Nop()), zerolog.Nop()))
	defer greeterTS.Close()
	if err := disco.Register(ctx, domain.AgentInfo{Name: gname, Role: "greeter-mandate", BaseURL: greeterTS.URL, CardURL: greeterTS.URL + "/.well-known/agent-card.json"}); err != nil {
		t.Fatal(err)
	}

	visitorPriv, _ := crypto.GenerateEd25519()
	if _, _, _, err := Initiate(ctx, disco, resolver.New(), a2a.NewClient(), mcp.NewClient(),
		visitorPriv, domain.LocalANSName("visitor"), "greeter-mandate", "hi"); err == nil {
		t.Fatal("expected error for an empty mandate")
	}
}
