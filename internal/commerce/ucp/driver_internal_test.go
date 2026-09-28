package ucp

// Internal (white-box) tests for driver.go's unexported helpers: BuyPeer itself
// is covered end-to-end by TestUCPBuyPeerHappyPath in driver_test.go (package
// ucp_test); these tests target the helper functions' fail-closed and edge
// branches directly, since they aren't reachable from outside the package.

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

func TestUcpExtension(t *testing.T) {
	if _, ok := ucpExtension(a2a.Card{}); ok {
		t.Fatal("card with no capabilities should not advertise UCP")
	}
	noMatch := a2a.Card{Capabilities: &a2a.Capabilities{Extensions: []a2a.Extension{{URI: "other://ext"}}}}
	if _, ok := ucpExtension(noMatch); ok {
		t.Fatal("card without the UCP extension URI should not match")
	}
	match := a2a.Card{Capabilities: &a2a.Capabilities{Extensions: []a2a.Extension{{URI: a2a.ExtUCPURI, Params: map[string]any{"profilePath": "/x"}}}}}
	ext, ok := ucpExtension(match)
	if !ok || ext.Params["profilePath"] != "/x" {
		t.Fatalf("expected UCP extension match, got %+v ok=%v", ext, ok)
	}
}

func TestVerifyTerms(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	pub := priv.Public().(ed25519.PublicKey)
	other, _ := crypto.GenerateEd25519()

	if err := verifyTerms(nil, pub, "cs_1", 100); err == nil {
		t.Fatal("expected rejection: missing signature")
	}
	if err := verifyTerms([]byte("not-a-cose-message"), pub, "cs_1", 100); err == nil {
		t.Fatal("expected rejection: invalid COSE")
	}
	goodSig, _ := crypto.SignCOSE1(priv, mustJSON(t, checkoutTerms{CheckoutID: "cs_1", ItemID: "mug", Amount: 100, Currency: "usd"}))
	if err := verifyTerms(goodSig, other.Public().(ed25519.PublicKey), "cs_1", 100); err == nil {
		t.Fatal("expected rejection: signer is not the advertised seller key")
	}
	malformed, _ := crypto.SignCOSE1(priv, []byte("not-json"))
	if err := verifyTerms(malformed, pub, "cs_1", 100); err == nil {
		t.Fatal("expected rejection: malformed signed terms")
	}
	mismatch, _ := crypto.SignCOSE1(priv, mustJSON(t, checkoutTerms{CheckoutID: "cs_other", ItemID: "mug", Amount: 100, Currency: "usd"}))
	if err := verifyTerms(mismatch, pub, "cs_1", 100); err == nil {
		t.Fatal("expected rejection: checkoutId mismatch")
	}
	amountMismatch, _ := crypto.SignCOSE1(priv, mustJSON(t, checkoutTerms{CheckoutID: "cs_1", ItemID: "mug", Amount: 999, Currency: "usd"}))
	if err := verifyTerms(amountMismatch, pub, "cs_1", 100); err == nil {
		t.Fatal("expected rejection: amount mismatch")
	}
	if err := verifyTerms(goodSig, pub, "cs_1", 100); err != nil {
		t.Fatalf("valid terms rejected: %v", err)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

type errDisco struct{}

func (errDisco) Register(context.Context, domain.AgentInfo) error { return nil }
func (errDisco) Search(context.Context, string) ([]domain.AgentInfo, error) {
	return nil, errors.New("discovery unavailable")
}

type stubDiscoLocal struct{ byRole map[string][]domain.AgentInfo }

func (s stubDiscoLocal) Register(context.Context, domain.AgentInfo) error { return nil }
func (s stubDiscoLocal) Search(_ context.Context, role string) ([]domain.AgentInfo, error) {
	return s.byRole[role], nil
}

func TestPickAuthority(t *testing.T) {
	if _, _, err := pickAuthority(context.Background(), errDisco{}, "authority", ""); err == nil {
		t.Fatal("expected discovery error to propagate")
	}
	empty := stubDiscoLocal{byRole: map[string][]domain.AgentInfo{}}
	if _, ok, err := pickAuthority(context.Background(), empty, "authority", ""); err != nil || ok {
		t.Fatalf("expected ok=false for no peers under role, got ok=%v err=%v", ok, err)
	}
	disco := stubDiscoLocal{byRole: map[string][]domain.AgentInfo{
		"authority": {{Name: "authority-1"}, {Name: "authority-2"}},
	}}
	a, ok, err := pickAuthority(context.Background(), disco, "authority", "")
	if err != nil || !ok || a.Name != "authority-1" {
		t.Fatalf("expected first peer when wantAns is empty, got %+v ok=%v err=%v", a, ok, err)
	}
	a, ok, err = pickAuthority(context.Background(), disco, "authority", domain.LocalANSName("authority-2"))
	if err != nil || !ok || a.Name != "authority-2" {
		t.Fatalf("expected named authority match, got %+v ok=%v err=%v", a, ok, err)
	}
	_, ok, err = pickAuthority(context.Background(), disco, "authority", domain.LocalANSName("authority-nope"))
	if err != nil || ok {
		t.Fatalf("expected ok=false for unmatched wantAns, got ok=%v err=%v", ok, err)
	}
}

func TestStrParam(t *testing.T) {
	if v := strParam(nil, "k", "def"); v != "def" {
		t.Fatalf("nil params: want def, got %q", v)
	}
	if v := strParam(map[string]any{}, "k", "def"); v != "def" {
		t.Fatalf("missing key: want def, got %q", v)
	}
	if v := strParam(map[string]any{"k": 5}, "k", "def"); v != "def" {
		t.Fatalf("wrong type: want def, got %q", v)
	}
	if v := strParam(map[string]any{"k": ""}, "k", "def"); v != "def" {
		t.Fatalf("empty string value: want def, got %q", v)
	}
	if v := strParam(map[string]any{"k": "v"}, "k", "def"); v != "v" {
		t.Fatalf("present key: want v, got %q", v)
	}
}

func TestSetGreet(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://x", nil)
	setGreet(req, "")
	if req.Header.Get("X-ANS-Greet-Id") != "" {
		t.Fatal("empty greetID should not set the header")
	}
	setGreet(req, "g-1")
	if req.Header.Get("X-ANS-Greet-Id") != "g-1" {
		t.Fatal("non-empty greetID should set the header")
	}
}

func TestGetJSON(t *testing.T) {
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"a": "b"})
	}))
	defer okSrv.Close()
	var out map[string]string
	if err := getJSON(context.Background(), http.DefaultClient, "", okSrv.URL, &out); err != nil || out["a"] != "b" {
		t.Fatalf("expected successful decode, got out=%+v err=%v", out, err)
	}

	errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer errSrv.Close()
	if err := getJSON(context.Background(), http.DefaultClient, "", errSrv.URL, &out); err == nil {
		t.Fatal("expected error for non-200 status")
	}

	if err := getJSON(context.Background(), http.DefaultClient, "", "http://127.0.0.1:0/nope", &out); err == nil {
		t.Fatal("expected error for unreachable host")
	}
}

func TestPostJSONExpect(t *testing.T) {
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"a": "b"})
	}))
	defer okSrv.Close()
	var out map[string]string
	if err := postJSON(context.Background(), http.DefaultClient, "g-1", okSrv.URL, map[string]string{}, &out); err != nil || out["a"] != "b" {
		t.Fatalf("expected successful decode, got out=%+v err=%v", out, err)
	}

	withErrMsg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "not authorized"})
	}))
	defer withErrMsg.Close()
	err := postJSONExpect(context.Background(), http.DefaultClient, "", withErrMsg.URL, map[string]string{}, &out)
	if err == nil || err.Error() != "not authorized" {
		t.Fatalf("expected the server's error message to surface, got %v", err)
	}

	noErrMsg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer noErrMsg.Close()
	if err := postJSONExpect(context.Background(), http.DefaultClient, "", noErrMsg.URL, map[string]string{}, &out); err == nil {
		t.Fatal("expected a generic status error when the body has no error field")
	}

	if err := postJSONExpect(context.Background(), http.DefaultClient, "", "http://127.0.0.1:0/nope", map[string]string{}, &out); err == nil {
		t.Fatal("expected error for unreachable host")
	}
}

func TestAcquireMandate(t *testing.T) {
	// Unreachable authority -> mcp.Client.Call fails -> wrapped error.
	if _, _, err := acquireMandate(context.Background(), mcp.NewClient(), "http://127.0.0.1:0/mcp", "issue_checkout_mandate", map[string]any{}); err == nil {
		t.Fatal("expected error for unreachable authority")
	}

	emptySrv := mcp.NewServer(zerolog.Nop())
	emptySrv.Register("issue_checkout_mandate", func(context.Context, json.RawMessage) (json.RawMessage, error) {
		return json.Marshal(map[string]any{"mandateCose": []byte{}})
	})
	httpSrv := httptest.NewServer(emptySrv.Handler())
	defer httpSrv.Close()
	if _, _, err := acquireMandate(context.Background(), mcp.NewClient(), httpSrv.URL, "issue_checkout_mandate", map[string]any{}); err == nil {
		t.Fatal("expected error for empty mandate from authority")
	}
}
