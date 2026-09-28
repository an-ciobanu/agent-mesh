package acp_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/commerce"
	"github.com/an-ciobanu/agent-mesh/internal/commerce/acp"
	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
)

type stubDiscovery struct{ byRole map[string][]domain.AgentInfo }

func (s stubDiscovery) Register(context.Context, domain.AgentInfo) error { return nil }
func (s stubDiscovery) Search(_ context.Context, role string) ([]domain.AgentInfo, error) {
	return s.byRole[role], nil
}

func TestBuyPeerHappyPath(t *testing.T) {
	authPriv, _ := crypto.GenerateEd25519()
	authAns := domain.LocalANSName("authority-1")
	authMCP := mcp.NewServer(zerolog.Nop())
	authMCP.Register("issue_spend_mandate", func(_ context.Context, args json.RawMessage) (json.RawMessage, error) {
		return newAuthorityTool(t, authPriv, authAns)(context.Background(), args)
	})
	authSrv := httptest.NewServer(authMCP.Handler())
	defer authSrv.Close()

	guard := policy.NewSpend(domain.LocalANSName("shop-acp"), authAns, authPriv.Public().(ed25519.PublicKey), zerolog.Nop())
	seller := acp.NewSeller(acp.SellerConfig{
		SelfAns: domain.LocalANSName("shop-acp"), AgentName: "shop-acp", Currency: "usd",
		Catalog: commerce.DefaultCatalog("usd"), Guard: guard, Payment: commerce.FakePayment{}, Log: zerolog.Nop(),
	})
	sMux := http.NewServeMux()
	seller.Mount(sMux)
	sellerSrv := httptest.NewServer(sMux)
	defer sellerSrv.Close()

	disco := stubDiscovery{byRole: map[string][]domain.AgentInfo{
		"authority": {{Name: "authority-1", Role: "authority", BaseURL: authSrv.URL, CardURL: authSrv.URL + "/.well-known/agent-card.json"}},
	}}
	peer := domain.AgentInfo{Name: "shop-acp", Role: "seller", BaseURL: sellerSrv.URL, CardURL: sellerSrv.URL + "/.well-known/agent-card.json"}
	card := a2a.Card{Name: "shop-acp", Capabilities: &a2a.Capabilities{Extensions: []a2a.Extension{{
		URI: a2a.ExtACPURI, Params: map[string]any{
			"catalogPath": "/acp/catalog", "checkoutPath": "/acp/checkout_sessions",
			"authorityRole": "authority", "authorityAns": authAns, "currency": "usd",
		},
	}}}}

	res, err := acp.BuyPeer(context.Background(), http.DefaultClient, mcp.NewClient(), disco, domain.LocalANSName("Ada"), peer, card)
	if err != nil {
		t.Fatalf("buy: %v", err)
	}
	if res.Status != "completed" || res.PaymentRef == "" {
		t.Fatalf("unexpected buy result: %+v", res)
	}
}
