package integration

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
	"github.com/an-ciobanu/agent-mesh/internal/comms/authclient"
	"github.com/an-ciobanu/agent-mesh/internal/comms/discovery"
	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
	"github.com/an-ciobanu/agent-mesh/internal/comms/resolver"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/greet"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
	"github.com/an-ciobanu/agent-mesh/internal/registry"
)

func TestP3B_MandateGreetEndToEnd(t *testing.T) {
	ctx := context.Background()
	reg := httptest.NewServer(registry.New(zerolog.Nop()).Handler())
	defer reg.Close()
	disco := discovery.New(reg.URL)

	// Authority: serves issue_mandate over MCP and its /pubkey.
	authPriv, _ := crypto.GenerateEd25519()
	authAns := domain.LocalANSName("authority-1")
	auth := authority.New(authAns, authPriv, time.Hour, zerolog.Nop())
	mcpSrv := mcp.NewServer(zerolog.Nop())
	mcpSrv.Register("issue_mandate", auth.MCPTool())
	authMux := http.NewServeMux()
	authMux.Handle("/mcp", mcpSrv.Handler())
	authMux.HandleFunc("GET /pubkey", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(crypto.PublicJWK(authPriv.Public().(ed25519.PublicKey)))
	})
	authSrv := httptest.NewServer(authMux)
	defer authSrv.Close()
	if err := disco.Register(ctx, domain.AgentInfo{
		Name: "authority-1", Role: "authority", BaseURL: authSrv.URL, CardURL: authSrv.URL + "/.well-known/agent-card.json",
	}); err != nil {
		t.Fatal(err)
	}

	// Mandate greeter: pins the authority key and advertises the extension.
	const gname = "greeter-mandate"
	self := domain.LocalANSName(gname)
	authPub, err := authclient.New().FetchPubKey(ctx, authSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	guard := policy.NewMandate(self, authAns, authPub, "greet", zerolog.Nop())
	svc := a2a.NewGreetService(self, guard, zerolog.Nop())
	card := a2a.Card{
		Name: gname, Version: "0.1.0",
		Security: []map[string][]string{{"mandate": {}}},
		Capabilities: &a2a.Capabilities{Extensions: []a2a.Extension{{
			URI: a2a.ExtMandateURI, Required: true,
			Params: map[string]any{"authorityRole": "authority", "scope": "greet"},
		}}},
	}
	greeter := httptest.NewServer(a2a.NewMux(card, svc, zerolog.Nop()))
	defer greeter.Close()
	if err := disco.Register(ctx, domain.AgentInfo{
		Name: gname, Role: "greeter-mandate", BaseURL: greeter.URL, CardURL: greeter.URL + "/.well-known/agent-card.json",
	}); err != nil {
		t.Fatal(err)
	}

	visitorPriv, _ := crypto.GenerateEd25519()
	visitorAns := domain.LocalANSName("visitor")

	// Happy path: the initiator discovers the requirement, gets a mandate, greets.
	reply, _, peer, err := greet.Initiate(ctx, disco, resolver.New(), a2a.NewClient(), mcp.NewClient(),
		visitorPriv, visitorAns, "greeter-mandate", "hello")
	if err != nil {
		t.Fatalf("mandate greet failed: %v", err)
	}
	if peer.Name != gname || reply == "" {
		t.Fatalf("unexpected greet result: peer=%s reply=%q", peer.Name, reply)
	}

	greetEndpoint := greeter.URL + "/a2a"

	// Negative 1: a direct greet with NO mandate is rejected (fail closed).
	if _, _, err := a2a.NewClient().SendGreet(ctx, greetEndpoint, visitorPriv, a2a.GreetPayload{
		CallerAns: visitorAns, AudienceAns: self, Greeting: "sneak in",
	}); err == nil {
		t.Fatal("expected rejection: no mandate presented")
	}

	// Negative 2: a mandate forged by a non-authority key is rejected.
	forgerPriv, _ := crypto.GenerateEd25519()
	forger := authority.New(authAns, forgerPriv, time.Hour, zerolog.Nop())
	forged, err := forger.IssueMandate(visitorAns, self, "greet")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a2a.NewClient().SendGreet(ctx, greetEndpoint, visitorPriv, a2a.GreetPayload{
		CallerAns: visitorAns, AudienceAns: self, Greeting: "forged",
	}, a2a.WithMandate(forged)); err == nil {
		t.Fatal("expected rejection: mandate not signed by the trusted authority")
	}
}
