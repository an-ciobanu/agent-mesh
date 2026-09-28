package integration

import (
	"context"
	"encoding/json"
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
	"github.com/an-ciobanu/agent-mesh/internal/greet"
	"github.com/an-ciobanu/agent-mesh/internal/nonce"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
	"github.com/an-ciobanu/agent-mesh/internal/registry"
)

func TestP4B_NonceGreetEndToEnd(t *testing.T) {
	ctx := context.Background()
	reg := httptest.NewServer(registry.New(zerolog.Nop()).Handler())
	defer reg.Close()
	disco := discovery.New(reg.URL)

	const gname = "greeter-nonce"
	self := domain.LocalANSName(gname)
	store := nonce.NewStore(time.Minute)
	guard := policy.NewNonce(self, store, zerolog.Nop())

	mux := a2a.NewMux(a2a.Card{
		Name: gname, Version: "0.1.0",
		Security:     []map[string][]string{{"dpop": {}}},
		Capabilities: &a2a.Capabilities{Extensions: []a2a.Extension{{URI: a2a.ExtNonceURI, Required: true}}},
	}, a2a.NewGreetService(self, guard, zerolog.Nop()), zerolog.Nop())
	mcpSrv := mcp.NewServer(zerolog.Nop())
	mcpSrv.Register("get_nonce", store.MCPTool())
	mux.Handle("/mcp", mcpSrv.Handler())
	greeter := httptest.NewServer(mux)
	defer greeter.Close()
	if err := disco.Register(ctx, domain.AgentInfo{Name: gname, Role: "greeter-nonce", BaseURL: greeter.URL, CardURL: greeter.URL + "/.well-known/agent-card.json"}); err != nil {
		t.Fatal(err)
	}

	visitorPriv, _ := crypto.GenerateEd25519()
	visitorAns := domain.LocalANSName("visitor")
	greetEndpoint := greeter.URL + "/a2a"
	htu := greetEndpoint // card.URL resolves to this same host+/a2a

	// Happy path: initiator discovers the requirement, gets a nonce, proves, greets.
	reply, _, _, peer, err := greet.Initiate(ctx, disco, resolver.New(), a2a.NewClient(), mcp.NewClient(),
		visitorPriv, visitorAns, "greeter-nonce", "hello")
	if err != nil {
		t.Fatalf("nonce greet failed: %v", err)
	}
	if peer.Name != gname || reply == "" {
		t.Fatalf("unexpected greet result: peer=%s reply=%q", peer.Name, reply)
	}

	// Negative 1: a greet with NO DPoP proof is rejected.
	if _, _, err := a2a.NewClient().SendGreet(ctx, greetEndpoint, visitorPriv, a2a.GreetPayload{
		CallerAns: visitorAns, AudienceAns: self, Greeting: "sneak",
	}); err == nil {
		t.Fatal("expected rejection: no DPoP proof")
	}

	// Negative 2: a replayed nonce is rejected (consume once).
	nonceCli := mcp.NewClient()
	raw, err := nonceCli.Call(ctx, greeter.URL+"/mcp", "get_nonce", map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	key, _ := crypto.GenerateDPoPKey()
	mkProof := func(n string) string {
		p, perr := crypto.CreateDPoPProof(key, crypto.DPoPClaims{HTM: "POST", HTU: htu, IAT: time.Now().Unix(), JTI: "j", Nonce: n})
		if perr != nil {
			t.Fatal(perr)
		}
		return p
	}
	if _, _, err := a2a.NewClient().SendGreet(ctx, greetEndpoint, visitorPriv, a2a.GreetPayload{
		CallerAns: visitorAns, AudienceAns: self, Greeting: "first",
	}, a2a.WithDPoP(mkProof(got.Nonce))); err != nil {
		t.Fatalf("first use of nonce should succeed: %v", err)
	}
	if _, _, err := a2a.NewClient().SendGreet(ctx, greetEndpoint, visitorPriv, a2a.GreetPayload{
		CallerAns: visitorAns, AudienceAns: self, Greeting: "replay",
	}, a2a.WithDPoP(mkProof(got.Nonce))); err == nil {
		t.Fatal("expected rejection: replayed (already-consumed) nonce")
	}

	// Negative 3: a proof bound to the wrong htu is rejected.
	raw2, _ := nonceCli.Call(ctx, greeter.URL+"/mcp", "get_nonce", map[string]string{})
	var got2 struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(raw2, &got2); err != nil {
		t.Fatal(err)
	}
	badHTU, _ := crypto.CreateDPoPProof(key, crypto.DPoPClaims{HTM: "POST", HTU: "http://evil.example/a2a", IAT: time.Now().Unix(), JTI: "j2", Nonce: got2.Nonce})
	if _, _, err := a2a.NewClient().SendGreet(ctx, greetEndpoint, visitorPriv, a2a.GreetPayload{
		CallerAns: visitorAns, AudienceAns: self, Greeting: "wrong-htu",
	}, a2a.WithDPoP(badHTU)); err == nil {
		t.Fatal("expected rejection: DPoP htu mismatch")
	}
}
