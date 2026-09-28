package ucp_test

// Negative-path coverage for BuyPeer (the UCP buyer driver): a fully scriptable
// fake seller lets each stage of the purchase pipeline be made to fail in turn,
// proving BuyPeer surfaces (rather than swallows) every failure mode.

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/commerce/ucp"
	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

type fakeSellerCfg struct {
	noHandlers       bool
	badSigningKey    bool
	catalogStatus    int
	emptyCatalog     bool
	createStatus     int
	createBadSig     bool
	updateStatus     int
	updateBadSig     bool
	tokenizeStatus   int
	tokenizeEmptyTok bool
	completeStatus   int
}

func writeFakeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func signFakeTerms(t *testing.T, priv ed25519.PrivateKey, checkoutID, itemID string, amount int64, currency string) []byte {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"checkoutId": checkoutID, "itemId": itemID, "amount": amount, "currency": currency})
	cose, err := crypto.SignCOSE1(priv, b)
	if err != nil {
		t.Fatalf("sign fake terms: %v", err)
	}
	return cose
}

// newFakeSeller builds a UCP seller surface whose behavior at every stage is
// driven by cfg, so a single failure can be injected at a time. Fields left at
// their zero value behave like a normal, successful seller.
func newFakeSeller(t *testing.T, priv ed25519.PrivateKey, authorityAns string, cfg fakeSellerCfg) *httptest.Server {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	mux := http.NewServeMux()

	mux.HandleFunc("GET /.well-known/ucp", func(w http.ResponseWriter, r *http.Request) {
		var handlers []map[string]any
		if !cfg.noHandlers {
			handlers = []map[string]any{{"id": "stripe_payments", "type": "com.stripe.payments", "tokenizePath": "/ucp/tokenize"}}
		}
		var signingKey any = crypto.PublicJWK(pub)
		if cfg.badSigningKey {
			signingKey = map[string]any{"kty": "bogus", "crv": "bogus", "x": "!!!not-base64url!!!"}
		}
		writeFakeJSON(w, http.StatusOK, map[string]any{
			"handlers":   handlers,
			"checkout":   map[string]string{"catalogPath": "/ucp/catalog", "sessionsPath": "/ucp/checkout_sessions"},
			"ap2":        map[string]any{"authorityRole": "authority", "authorityAns": authorityAns},
			"signingKey": signingKey,
		})
	})

	mux.HandleFunc("GET /ucp/catalog", func(w http.ResponseWriter, r *http.Request) {
		if cfg.catalogStatus != 0 {
			w.WriteHeader(cfg.catalogStatus)
			return
		}
		var items []map[string]any
		if !cfg.emptyCatalog {
			items = []map[string]any{{"id": "sticker", "name": "Mesh Sticker", "amount": 500, "currency": "usd"}}
		}
		writeFakeJSON(w, http.StatusOK, map[string]any{"items": items})
	})

	mux.HandleFunc("POST /ucp/checkout_sessions", func(w http.ResponseWriter, r *http.Request) {
		if cfg.createStatus != 0 {
			w.WriteHeader(cfg.createStatus)
			return
		}
		signer := priv
		if cfg.createBadSig {
			other, _ := crypto.GenerateEd25519()
			signer = other
		}
		sig := signFakeTerms(t, signer, "cs_1", "sticker", 500, "usd")
		writeFakeJSON(w, http.StatusOK, map[string]any{"checkoutId": "cs_1", "itemId": "sticker", "amount": 500, "currency": "usd", "checkoutSignature": sig})
	})

	mux.HandleFunc("POST /ucp/checkout_sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
		if cfg.updateStatus != 0 {
			w.WriteHeader(cfg.updateStatus)
			return
		}
		signer := priv
		if cfg.updateBadSig {
			other, _ := crypto.GenerateEd25519()
			signer = other
		}
		sig := signFakeTerms(t, signer, "cs_1", "sticker", 800, "usd")
		writeFakeJSON(w, http.StatusOK, map[string]any{"checkoutId": "cs_1", "itemId": "sticker", "amount": 800, "currency": "usd", "checkoutSignature": sig})
	})

	mux.HandleFunc("POST /ucp/tokenize", func(w http.ResponseWriter, r *http.Request) {
		if cfg.tokenizeStatus != 0 {
			w.WriteHeader(cfg.tokenizeStatus)
			return
		}
		token := "utok_fake"
		if cfg.tokenizeEmptyTok {
			token = ""
		}
		writeFakeJSON(w, http.StatusOK, map[string]any{"token": token, "expiresAt": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	})

	mux.HandleFunc("POST /ucp/checkout_sessions/{id}/complete", func(w http.ResponseWriter, r *http.Request) {
		if cfg.completeStatus != 0 {
			w.WriteHeader(cfg.completeStatus)
			return
		}
		writeFakeJSON(w, http.StatusOK, map[string]any{"status": "completed", "provider": "fake", "paymentRef": "ref_1", "itemId": "sticker", "amount": 800, "currency": "usd"})
	})

	return httptest.NewServer(mux)
}

// buyPeerHarness wires a fake seller advertising the UCP extension, plus (when
// needed) a real authority MCP server, and invokes BuyPeer against them.
type buyPeerHarness struct {
	authAns string
	disco   domain.Discovery
	mcpCli  *mcp.Client
}

func newBuyPeerHarness(t *testing.T, authoritySrv *httptest.Server) buyPeerHarness {
	t.Helper()
	authAns := domain.LocalANSName("authority-1")
	disco := stubDisco{byRole: map[string][]domain.AgentInfo{}}
	if authoritySrv != nil {
		disco = stubDisco{byRole: map[string][]domain.AgentInfo{
			"authority": {{Name: "authority-1", Role: "authority", BaseURL: authoritySrv.URL}},
		}}
	}
	return buyPeerHarness{authAns: authAns, disco: disco, mcpCli: mcp.NewClient()}
}

func fullAuthorityServer(t *testing.T, authPriv ed25519.PrivateKey, authAns string, withCheckout, withPayment bool) *httptest.Server {
	t.Helper()
	srv := mcp.NewServer(zerolog.Nop())
	if withCheckout {
		srv.Register("issue_checkout_mandate", newCheckoutTool(t, authPriv, authAns))
	}
	if withPayment {
		srv.Register("issue_payment_mandate", newPaymentTool(t, authPriv, authAns))
	}
	return httptest.NewServer(srv.Handler())
}

func ucpCard() a2a.Card {
	return a2a.Card{Name: "shop-ucp", Capabilities: &a2a.Capabilities{Extensions: []a2a.Extension{{
		URI: a2a.ExtUCPURI, Params: map[string]any{"profilePath": "/.well-known/ucp"},
	}}}}
}

func runBuyPeer(t *testing.T, h buyPeerHarness, sellerSrv *httptest.Server) (commerceBuyResult, error) {
	t.Helper()
	peer := domain.AgentInfo{Name: "shop-ucp", Role: "seller", BaseURL: sellerSrv.URL, CardURL: sellerSrv.URL + "/.well-known/agent-card.json"}
	res, err := ucp.BuyPeer(context.Background(), http.DefaultClient, h.mcpCli, h.disco, domain.LocalANSName("Ada"), peer, ucpCard())
	return commerceBuyResult{res.Status, res.PaymentRef}, err
}

type commerceBuyResult struct {
	Status     string
	PaymentRef string
}

func TestBuyPeerRejectsCardWithoutUCPExtension(t *testing.T) {
	sellerSrv := httptest.NewServer(http.NewServeMux())
	defer sellerSrv.Close()
	peer := domain.AgentInfo{Name: "shop-ucp", BaseURL: sellerSrv.URL}
	disco := stubDisco{}
	_, err := ucp.BuyPeer(context.Background(), http.DefaultClient, mcp.NewClient(), disco, domain.LocalANSName("Ada"), peer, a2a.Card{})
	if err == nil {
		t.Fatal("expected rejection: card does not advertise UCP")
	}
}

func TestBuyPeerRejectsProfileFetchFailure(t *testing.T) {
	// No routes registered at all: GET /.well-known/ucp 404s.
	sellerSrv := httptest.NewServer(http.NewServeMux())
	defer sellerSrv.Close()
	h := newBuyPeerHarness(t, nil)
	if _, err := runBuyPeer(t, h, sellerSrv); err == nil {
		t.Fatal("expected rejection: profile fetch failure")
	}
}

func TestBuyPeerRejectsProfileWithNoHandlers(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	h := newBuyPeerHarness(t, nil)
	sellerSrv := newFakeSeller(t, priv, h.authAns, fakeSellerCfg{noHandlers: true})
	defer sellerSrv.Close()
	if _, err := runBuyPeer(t, h, sellerSrv); err == nil {
		t.Fatal("expected rejection: profile advertises no handlers")
	}
}

func TestBuyPeerRejectsBadSigningKey(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	h := newBuyPeerHarness(t, nil)
	sellerSrv := newFakeSeller(t, priv, h.authAns, fakeSellerCfg{badSigningKey: true})
	defer sellerSrv.Close()
	if _, err := runBuyPeer(t, h, sellerSrv); err == nil {
		t.Fatal("expected rejection: unparsable seller signing key")
	}
}

func TestBuyPeerRejectsCatalogFetchFailure(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	h := newBuyPeerHarness(t, nil)
	sellerSrv := newFakeSeller(t, priv, h.authAns, fakeSellerCfg{catalogStatus: http.StatusInternalServerError})
	defer sellerSrv.Close()
	if _, err := runBuyPeer(t, h, sellerSrv); err == nil {
		t.Fatal("expected rejection: catalog fetch failure")
	}
}

func TestBuyPeerRejectsEmptyCatalog(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	h := newBuyPeerHarness(t, nil)
	sellerSrv := newFakeSeller(t, priv, h.authAns, fakeSellerCfg{emptyCatalog: true})
	defer sellerSrv.Close()
	if _, err := runBuyPeer(t, h, sellerSrv); err == nil {
		t.Fatal("expected rejection: empty catalog")
	}
}

func TestBuyPeerRejectsSessionCreateFailure(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	h := newBuyPeerHarness(t, nil)
	sellerSrv := newFakeSeller(t, priv, h.authAns, fakeSellerCfg{createStatus: http.StatusInternalServerError})
	defer sellerSrv.Close()
	if _, err := runBuyPeer(t, h, sellerSrv); err == nil {
		t.Fatal("expected rejection: session create failure")
	}
}

func TestBuyPeerRejectsBadCheckoutSignature(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	h := newBuyPeerHarness(t, nil)
	sellerSrv := newFakeSeller(t, priv, h.authAns, fakeSellerCfg{createBadSig: true})
	defer sellerSrv.Close()
	if _, err := runBuyPeer(t, h, sellerSrv); err == nil {
		t.Fatal("expected rejection: checkout terms signed by an untrusted key")
	}
}

func TestBuyPeerRejectsSessionUpdateFailure(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	h := newBuyPeerHarness(t, nil)
	sellerSrv := newFakeSeller(t, priv, h.authAns, fakeSellerCfg{updateStatus: http.StatusInternalServerError})
	defer sellerSrv.Close()
	if _, err := runBuyPeer(t, h, sellerSrv); err == nil {
		t.Fatal("expected rejection: session update failure")
	}
}

func TestBuyPeerRejectsBadUpdateSignature(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	h := newBuyPeerHarness(t, nil)
	sellerSrv := newFakeSeller(t, priv, h.authAns, fakeSellerCfg{updateBadSig: true})
	defer sellerSrv.Close()
	if _, err := runBuyPeer(t, h, sellerSrv); err == nil {
		t.Fatal("expected rejection: updated terms signed by an untrusted key")
	}
}

func TestBuyPeerRejectsNoAuthorityFound(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	h := newBuyPeerHarness(t, nil) // no authority registered under the "authority" role
	sellerSrv := newFakeSeller(t, priv, h.authAns, fakeSellerCfg{})
	defer sellerSrv.Close()
	if _, err := runBuyPeer(t, h, sellerSrv); err == nil {
		t.Fatal("expected rejection: no authority found")
	}
}

type erroringDisco struct{}

func (erroringDisco) Register(context.Context, domain.AgentInfo) error { return nil }
func (erroringDisco) Search(context.Context, string) ([]domain.AgentInfo, error) {
	return nil, errDiscoUnavailable
}

var errDiscoUnavailable = &discoErr{"discovery unavailable"}

type discoErr struct{ s string }

func (e *discoErr) Error() string { return e.s }

func TestBuyPeerPropagatesDiscoveryError(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	authAns := domain.LocalANSName("authority-1")
	sellerSrv := newFakeSeller(t, priv, authAns, fakeSellerCfg{})
	defer sellerSrv.Close()
	h := buyPeerHarness{authAns: authAns, disco: erroringDisco{}, mcpCli: mcp.NewClient()}
	if _, err := runBuyPeer(t, h, sellerSrv); err == nil {
		t.Fatal("expected rejection: discovery error")
	}
}

func TestBuyPeerRejectsCheckoutMandateAcquireFailure(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	authPriv, _ := crypto.GenerateEd25519()
	authoritySrv := fullAuthorityServer(t, authPriv, domain.LocalANSName("authority-1"), false /* no checkout tool */, true)
	defer authoritySrv.Close()
	h := newBuyPeerHarness(t, authoritySrv)
	sellerSrv := newFakeSeller(t, priv, h.authAns, fakeSellerCfg{})
	defer sellerSrv.Close()
	if _, err := runBuyPeer(t, h, sellerSrv); err == nil {
		t.Fatal("expected rejection: checkout mandate acquisition failure")
	}
}

func TestBuyPeerRejectsPaymentMandateAcquireFailure(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	authPriv, _ := crypto.GenerateEd25519()
	authoritySrv := fullAuthorityServer(t, authPriv, domain.LocalANSName("authority-1"), true, false /* no payment tool */)
	defer authoritySrv.Close()
	h := newBuyPeerHarness(t, authoritySrv)
	sellerSrv := newFakeSeller(t, priv, h.authAns, fakeSellerCfg{})
	defer sellerSrv.Close()
	if _, err := runBuyPeer(t, h, sellerSrv); err == nil {
		t.Fatal("expected rejection: payment mandate acquisition failure")
	}
}

func TestBuyPeerRejectsTokenizeFailure(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	authPriv, _ := crypto.GenerateEd25519()
	authoritySrv := fullAuthorityServer(t, authPriv, domain.LocalANSName("authority-1"), true, true)
	defer authoritySrv.Close()
	h := newBuyPeerHarness(t, authoritySrv)
	sellerSrv := newFakeSeller(t, priv, h.authAns, fakeSellerCfg{tokenizeStatus: http.StatusInternalServerError})
	defer sellerSrv.Close()
	if _, err := runBuyPeer(t, h, sellerSrv); err == nil {
		t.Fatal("expected rejection: tokenize failure")
	}
}

func TestBuyPeerRejectsEmptyToken(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	authPriv, _ := crypto.GenerateEd25519()
	authoritySrv := fullAuthorityServer(t, authPriv, domain.LocalANSName("authority-1"), true, true)
	defer authoritySrv.Close()
	h := newBuyPeerHarness(t, authoritySrv)
	sellerSrv := newFakeSeller(t, priv, h.authAns, fakeSellerCfg{tokenizeEmptyTok: true})
	defer sellerSrv.Close()
	if _, err := runBuyPeer(t, h, sellerSrv); err == nil {
		t.Fatal("expected rejection: empty token from handler")
	}
}

func TestBuyPeerRejectsCompleteFailure(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	authPriv, _ := crypto.GenerateEd25519()
	authoritySrv := fullAuthorityServer(t, authPriv, domain.LocalANSName("authority-1"), true, true)
	defer authoritySrv.Close()
	h := newBuyPeerHarness(t, authoritySrv)
	sellerSrv := newFakeSeller(t, priv, h.authAns, fakeSellerCfg{completeStatus: http.StatusForbidden})
	defer sellerSrv.Close()
	if _, err := runBuyPeer(t, h, sellerSrv); err == nil {
		t.Fatal("expected rejection: complete failure")
	}
}
