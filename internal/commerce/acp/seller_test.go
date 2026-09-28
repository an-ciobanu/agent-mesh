package acp_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/commerce"
	"github.com/an-ciobanu/agent-mesh/internal/commerce/acp"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/events"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
)

func newSellerServer(t *testing.T) (*httptest.Server, ed25519.PrivateKey) {
	t.Helper()
	authPriv, _ := crypto.GenerateEd25519()
	guard := policy.NewSpend(
		domain.LocalANSName("shop-acp"),
		domain.LocalANSName("authority-1"),
		authPriv.Public().(ed25519.PublicKey),
		zerolog.Nop(),
	)
	seller := acp.NewSeller(acp.SellerConfig{
		SelfAns:   domain.LocalANSName("shop-acp"),
		AgentName: "shop-acp",
		Currency:  "usd",
		Catalog:   commerce.DefaultCatalog("usd"),
		Guard:     guard,
		Payment:   commerce.FakePayment{},
		Events:    events.Nop{},
		Log:       zerolog.Nop(),
	})
	mux := http.NewServeMux()
	seller.Mount(mux)
	return httptest.NewServer(mux), authPriv
}

func spendMandateFor(t *testing.T, authPriv ed25519.PrivateKey, itemID string, maxAmount int64) []byte {
	t.Helper()
	now := time.Now().UTC()
	c := domain.SpendMandateClaims{
		MandateID: "spend-x", SubjectAns: domain.LocalANSName("Ada"),
		AudienceAns: domain.LocalANSName("shop-acp"), ItemID: itemID, MaxAmount: maxAmount,
		Currency: "usd", Scope: domain.ScopePurchase,
		NotBefore: now.Add(-time.Minute).Format(time.RFC3339), NotAfter: now.Add(time.Hour).Format(time.RFC3339),
		AuthorityAns: domain.LocalANSName("authority-1"),
	}
	b, _ := json.Marshal(c)
	cose, err := crypto.SignCOSE1(authPriv, b)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return cose
}

func postJSON(t *testing.T, url string, body any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(commerce.HeaderGreetID, "greet-test")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post %s: %v", url, err)
	}
	return resp
}

func TestSellerCatalog(t *testing.T) {
	srv, _ := newSellerServer(t)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/acp/catalog")
	if err != nil {
		t.Fatalf("get catalog: %v", err)
	}
	defer resp.Body.Close()
	var out struct {
		Items []commerce.Item `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Items) == 0 {
		t.Fatal("empty catalog")
	}
}

func TestSellerCheckoutHappyPath(t *testing.T) {
	srv, authPriv := newSellerServer(t)
	defer srv.Close()

	resp := postJSON(t, srv.URL+"/acp/checkout_sessions", map[string]string{"itemId": "sticker"})
	var sess struct {
		SessionID string `json:"sessionId"`
		Amount    int64  `json:"amount"`
		Currency  string `json:"currency"`
		Status    string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&sess); err != nil {
		t.Fatalf("decode session: %v", err)
	}
	resp.Body.Close()
	if sess.SessionID == "" || sess.Amount != 500 || sess.Status != "ready_for_payment" {
		t.Fatalf("unexpected session: %+v", sess)
	}

	m := spendMandateFor(t, authPriv, "sticker", 500)
	resp = postJSON(t, srv.URL+"/acp/checkout_sessions/"+sess.SessionID+"/complete",
		map[string]any{"callerAns": domain.LocalANSName("Ada"), "spendMandate": m})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("complete status = %d", resp.StatusCode)
	}
	var rec struct {
		Status     string `json:"status"`
		Provider   string `json:"provider"`
		PaymentRef string `json:"paymentRef"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rec); err != nil {
		t.Fatalf("decode receipt: %v", err)
	}
	resp.Body.Close()
	if rec.Status != "completed" || rec.PaymentRef == "" || rec.Provider != "fake" {
		t.Fatalf("unexpected receipt: %+v", rec)
	}
}

func TestSellerCompleteRejectsBadMandate(t *testing.T) {
	srv, authPriv := newSellerServer(t)
	defer srv.Close()
	resp := postJSON(t, srv.URL+"/acp/checkout_sessions", map[string]string{"itemId": "mug"})
	var sess struct {
		SessionID string `json:"sessionId"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&sess)
	resp.Body.Close()

	m := spendMandateFor(t, authPriv, "sticker", 5000) // wrong item
	resp = postJSON(t, srv.URL+"/acp/checkout_sessions/"+sess.SessionID+"/complete",
		map[string]any{"callerAns": domain.LocalANSName("Ada"), "spendMandate": m})
	if resp.StatusCode == http.StatusOK {
		t.Fatal("expected non-200 for item-mismatch mandate")
	}
	resp.Body.Close()
}
