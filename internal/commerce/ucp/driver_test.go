package ucp_test

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/commerce"
	"github.com/an-ciobanu/agent-mesh/internal/commerce/ucp"
	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
)

type stubDisco struct{ byRole map[string][]domain.AgentInfo }

func (s stubDisco) Register(context.Context, domain.AgentInfo) error { return nil }
func (s stubDisco) Search(_ context.Context, role string) ([]domain.AgentInfo, error) {
	return s.byRole[role], nil
}

func TestUCPBuyPeerHappyPath(t *testing.T) {
	authPriv, _ := crypto.GenerateEd25519()
	authAns := domain.LocalANSName("authority-1")
	authMCP := mcp.NewServer(zerolog.Nop())
	authMCP.Register("issue_checkout_mandate", newCheckoutTool(t, authPriv, authAns))
	authMCP.Register("issue_payment_mandate", newPaymentTool(t, authPriv, authAns))
	authSrv := httptest.NewServer(authMCP.Handler())
	defer authSrv.Close()

	sellerPriv, _ := crypto.GenerateEd25519()
	guard := policy.NewUCP(domain.LocalANSName("shop-ucp"), authAns, authPriv.Public().(ed25519.PublicKey), zerolog.Nop())
	seller := ucp.NewSeller(ucp.SellerConfig{
		SelfAns: domain.LocalANSName("shop-ucp"), AgentName: "shop-ucp", Currency: "usd",
		Catalog: commerce.DefaultCatalog("usd"), Guard: guard, Payment: commerce.FakePayment{},
		SignKey: sellerPriv, AuthorityRole: "authority", AuthorityAns: authAns, Log: zerolog.Nop(),
	})
	sMux := http.NewServeMux()
	seller.Mount(sMux)
	sellerSrv := httptest.NewServer(sMux)
	defer sellerSrv.Close()

	disco := stubDisco{byRole: map[string][]domain.AgentInfo{
		"authority": {{Name: "authority-1", Role: "authority", BaseURL: authSrv.URL}},
	}}
	peer := domain.AgentInfo{Name: "shop-ucp", Role: "seller", BaseURL: sellerSrv.URL, CardURL: sellerSrv.URL + "/.well-known/agent-card.json"}
	card := a2a.Card{Name: "shop-ucp", Capabilities: &a2a.Capabilities{Extensions: []a2a.Extension{{
		URI: a2a.ExtUCPURI, Params: map[string]any{"profilePath": "/.well-known/ucp"},
	}}}}

	res, err := ucp.BuyPeer(context.Background(), http.DefaultClient, mcp.NewClient(), disco, domain.LocalANSName("Ada"), peer, card)
	if err != nil {
		t.Fatalf("buy: %v", err)
	}
	if res.Status != "completed" || res.PaymentRef == "" {
		t.Fatalf("unexpected result: %+v", res)
	}
}
