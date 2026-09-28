package ucp_test

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
	"github.com/an-ciobanu/agent-mesh/internal/commerce/ucp"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/events"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
)

func newUCPSeller(t *testing.T) (*httptest.Server, ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	authPriv, _ := crypto.GenerateEd25519()
	sellerPriv, _ := crypto.GenerateEd25519()
	guard := policy.NewUCP(domain.LocalANSName("shop-ucp"), domain.LocalANSName("authority-1"), authPriv.Public().(ed25519.PublicKey), zerolog.Nop())
	seller := ucp.NewSeller(ucp.SellerConfig{
		SelfAns: domain.LocalANSName("shop-ucp"), AgentName: "shop-ucp", Currency: "usd",
		Catalog: commerce.DefaultCatalog("usd"), Guard: guard, Payment: commerce.FakePayment{},
		SignKey: sellerPriv, AuthorityRole: "authority", AuthorityAns: domain.LocalANSName("authority-1"),
		Events: events.Nop{}, Log: zerolog.Nop(),
	})
	mux := http.NewServeMux()
	seller.Mount(mux)
	return httptest.NewServer(mux), authPriv, sellerPriv.Public().(ed25519.PublicKey)
}

func post(t *testing.T, url string, body any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(commerce.HeaderGreetID, "g-test")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post %s: %v", url, err)
	}
	return resp
}

func mint(t *testing.T, authPriv ed25519.PrivateKey, v any) []byte {
	t.Helper()
	b, _ := json.Marshal(v)
	c, err := crypto.SignCOSE1(authPriv, b)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return c
}

func TestUCPProfileAdvertisesHandlerAndKey(t *testing.T) {
	srv, _, sellerPub := newUCPSeller(t)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/.well-known/ucp")
	if err != nil {
		t.Fatalf("get profile: %v", err)
	}
	defer resp.Body.Close()
	var prof struct {
		Handlers []struct {
			ID           string `json:"id"`
			TokenizePath string `json:"tokenizePath"`
		} `json:"handlers"`
		AP2 struct {
			AuthorityAns string `json:"authorityAns"`
		} `json:"ap2"`
		SigningKey crypto.JWK `json:"signingKey"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&prof); err != nil {
		t.Fatalf("decode profile: %v", err)
	}
	if len(prof.Handlers) == 0 || prof.Handlers[0].TokenizePath == "" || prof.AP2.AuthorityAns == "" {
		t.Fatalf("profile incomplete: %+v", prof)
	}
	got, err := crypto.PublicKeyFromJWK(prof.SigningKey)
	if err != nil || !got.Equal(sellerPub) {
		t.Fatalf("profile signingKey mismatch: %v", err)
	}
}

func TestUCPHappyPath(t *testing.T) {
	srv, authPriv, sellerPub := newUCPSeller(t)
	defer srv.Close()

	resp := post(t, srv.URL+"/ucp/checkout_sessions", map[string]string{"itemId": "sticker"})
	var sess struct {
		CheckoutID        string `json:"checkoutId"`
		ItemID            string `json:"itemId"`
		Amount            int64  `json:"amount"`
		Currency          string `json:"currency"`
		CheckoutSignature []byte `json:"checkoutSignature"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&sess)
	resp.Body.Close()
	if sess.CheckoutID == "" || sess.Amount != 500 || len(sess.CheckoutSignature) == 0 {
		t.Fatalf("bad session: %+v", sess)
	}
	payload, signer, err := crypto.VerifyCOSE1(sess.CheckoutSignature)
	if err != nil || !signer.Equal(sellerPub) {
		t.Fatalf("checkout signature not from seller: %v", err)
	}
	var terms struct {
		CheckoutID string `json:"checkoutId"`
		Amount     int64  `json:"amount"`
	}
	_ = json.Unmarshal(payload, &terms)
	if terms.CheckoutID != sess.CheckoutID || terms.Amount != sess.Amount {
		t.Fatalf("signed terms mismatch: %+v", terms)
	}

	resp = post(t, srv.URL+"/ucp/checkout_sessions/"+sess.CheckoutID, map[string]any{})
	var upd struct {
		Amount            int64  `json:"amount"`
		CheckoutSignature []byte `json:"checkoutSignature"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&upd)
	resp.Body.Close()
	if upd.Amount <= sess.Amount || len(upd.CheckoutSignature) == 0 {
		t.Fatalf("update did not raise amount / re-sign: %+v", upd)
	}

	resp = post(t, srv.URL+"/ucp/tokenize", map[string]any{
		"binding":    map[string]string{"checkoutId": sess.CheckoutID},
		"allowance":  map[string]any{"maxAmount": upd.Amount, "currency": "usd"},
		"credential": map[string]string{"type": "card"},
	})
	var tok struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&tok)
	resp.Body.Close()
	if tok.Token == "" {
		t.Fatal("no token issued")
	}

	now := time.Now().UTC()
	cm := mint(t, authPriv, domain.CheckoutMandateClaims{
		MandateID: "c", SubjectAns: domain.LocalANSName("Ada"), AudienceAns: domain.LocalANSName("shop-ucp"),
		CheckoutID: sess.CheckoutID, ItemID: "sticker", Amount: upd.Amount, Currency: "usd", Scope: domain.ScopeCheckout,
		NotBefore: now.Add(-time.Minute).Format(time.RFC3339), NotAfter: now.Add(time.Hour).Format(time.RFC3339), AuthorityAns: domain.LocalANSName("authority-1"),
	})
	pm := mint(t, authPriv, domain.PaymentMandateClaims{
		MandateID: "p", SubjectAns: domain.LocalANSName("Ada"), AudienceAns: domain.LocalANSName("shop-ucp"),
		Amount: upd.Amount, Currency: "usd", Scope: domain.ScopePayment,
		NotBefore: now.Add(-time.Minute).Format(time.RFC3339), NotAfter: now.Add(time.Hour).Format(time.RFC3339), AuthorityAns: domain.LocalANSName("authority-1"),
	})

	resp = post(t, srv.URL+"/ucp/checkout_sessions/"+sess.CheckoutID+"/complete", map[string]any{
		"callerAns": domain.LocalANSName("Ada"), "checkoutMandate": cm, "paymentMandate": pm, "paymentToken": tok.Token,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("complete status=%d", resp.StatusCode)
	}
	var rec struct {
		Status     string `json:"status"`
		PaymentRef string `json:"paymentRef"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&rec)
	resp.Body.Close()
	if rec.Status != "completed" || rec.PaymentRef == "" {
		t.Fatalf("bad receipt: %+v", rec)
	}
}

func TestUCPCompleteRejectsBadMandate(t *testing.T) {
	srv, authPriv, _ := newUCPSeller(t)
	defer srv.Close()
	resp := post(t, srv.URL+"/ucp/checkout_sessions", map[string]string{"itemId": "mug"})
	var sess struct {
		CheckoutID string `json:"checkoutId"`
		Amount     int64  `json:"amount"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&sess)
	resp.Body.Close()
	resp = post(t, srv.URL+"/ucp/tokenize", map[string]any{"binding": map[string]string{"checkoutId": sess.CheckoutID}, "allowance": map[string]any{"maxAmount": sess.Amount, "currency": "usd"}, "credential": map[string]string{"type": "card"}})
	var tok struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&tok)
	resp.Body.Close()
	now := time.Now().UTC()
	cm := mint(t, authPriv, domain.CheckoutMandateClaims{MandateID: "c", SubjectAns: domain.LocalANSName("Ada"), AudienceAns: domain.LocalANSName("shop-ucp"), CheckoutID: "cs_wrong", ItemID: "mug", Amount: sess.Amount, Currency: "usd", Scope: domain.ScopeCheckout, NotBefore: now.Add(-time.Minute).Format(time.RFC3339), NotAfter: now.Add(time.Hour).Format(time.RFC3339), AuthorityAns: domain.LocalANSName("authority-1")})
	pm := mint(t, authPriv, domain.PaymentMandateClaims{MandateID: "p", SubjectAns: domain.LocalANSName("Ada"), AudienceAns: domain.LocalANSName("shop-ucp"), Amount: sess.Amount, Currency: "usd", Scope: domain.ScopePayment, NotBefore: now.Add(-time.Minute).Format(time.RFC3339), NotAfter: now.Add(time.Hour).Format(time.RFC3339), AuthorityAns: domain.LocalANSName("authority-1")})
	resp = post(t, srv.URL+"/ucp/checkout_sessions/"+sess.CheckoutID+"/complete", map[string]any{"callerAns": domain.LocalANSName("Ada"), "checkoutMandate": cm, "paymentMandate": pm, "paymentToken": tok.Token})
	if resp.StatusCode == http.StatusOK {
		t.Fatal("expected non-200 for checkoutId-mismatch mandate")
	}
	resp.Body.Close()
}
