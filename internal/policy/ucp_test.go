package policy_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
)

func signJSON(t *testing.T, priv ed25519.PrivateKey, v any) []byte {
	t.Helper()
	b, _ := json.Marshal(v)
	cose, err := crypto.SignCOSE1(priv, b)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return cose
}

func ucpGuard(t *testing.T) (*policy.UCP, ed25519.PrivateKey) {
	t.Helper()
	authPriv, _ := crypto.GenerateEd25519()
	g := policy.NewUCP(domain.LocalANSName("shop-ucp"), domain.LocalANSName("authority-1"), authPriv.Public().(ed25519.PublicKey), zerolog.Nop())
	return g, authPriv
}

func goodCheckout(now time.Time) domain.CheckoutMandateClaims {
	return domain.CheckoutMandateClaims{
		MandateID: "c", SubjectAns: domain.LocalANSName("Ada"), AudienceAns: domain.LocalANSName("shop-ucp"),
		CheckoutID: "cs_1", ItemID: "mug", Amount: 1200, Currency: "usd", Scope: domain.ScopeCheckout,
		NotBefore: now.Add(-time.Minute).Format(time.RFC3339), NotAfter: now.Add(time.Hour).Format(time.RFC3339), AuthorityAns: domain.LocalANSName("authority-1"),
	}
}
func goodPayment(now time.Time) domain.PaymentMandateClaims {
	return domain.PaymentMandateClaims{
		MandateID: "p", SubjectAns: domain.LocalANSName("Ada"), AudienceAns: domain.LocalANSName("shop-ucp"),
		Amount: 1200, Currency: "usd", Scope: domain.ScopePayment,
		NotBefore: now.Add(-time.Minute).Format(time.RFC3339), NotAfter: now.Add(time.Hour).Format(time.RFC3339), AuthorityAns: domain.LocalANSName("authority-1"),
	}
}
func completion(cm, pm []byte) domain.UCPCompletion {
	return domain.UCPCompletion{CallerAns: domain.LocalANSName("Ada"), CheckoutID: "cs_1", ItemID: "mug", Amount: 1200, Currency: "usd", CheckoutMandate: cm, PaymentMandate: pm}
}

func TestUCPAcceptsValidPair(t *testing.T) {
	g, ap := ucpGuard(t)
	now := time.Now().UTC()
	if err := g.Verify(context.Background(), completion(signJSON(t, ap, goodCheckout(now)), signJSON(t, ap, goodPayment(now)))); err != nil {
		t.Fatalf("valid pair rejected: %v", err)
	}
}

func TestUCPRejectsWrongAuthorityKey(t *testing.T) {
	g, _ := ucpGuard(t)
	other, _ := crypto.GenerateEd25519()
	now := time.Now().UTC()
	if err := g.Verify(context.Background(), completion(signJSON(t, other, goodCheckout(now)), signJSON(t, other, goodPayment(now)))); err == nil {
		t.Fatal("expected rejection: untrusted issuer")
	}
}

func TestUCPRejectsCheckoutIDMismatch(t *testing.T) {
	g, ap := ucpGuard(t)
	now := time.Now().UTC()
	c := goodCheckout(now)
	c.CheckoutID = "cs_other"
	if err := g.Verify(context.Background(), completion(signJSON(t, ap, c), signJSON(t, ap, goodPayment(now)))); err == nil {
		t.Fatal("expected rejection: checkoutId mismatch")
	}
}

func TestUCPRejectsPaymentUnderAmount(t *testing.T) {
	g, ap := ucpGuard(t)
	now := time.Now().UTC()
	p := goodPayment(now)
	p.Amount = 1000
	if err := g.Verify(context.Background(), completion(signJSON(t, ap, goodCheckout(now)), signJSON(t, ap, p))); err == nil {
		t.Fatal("expected rejection: payment authorizes less than amount")
	}
}

func TestUCPRejectsWrongPaymentScope(t *testing.T) {
	g, ap := ucpGuard(t)
	now := time.Now().UTC()
	if err := g.Verify(context.Background(), completion(signJSON(t, ap, goodCheckout(now)), signJSON(t, ap, goodCheckout(now)))); err == nil {
		t.Fatal("expected rejection: payment mandate has wrong scope")
	}
}

func TestUCPRejectsMissingMandates(t *testing.T) {
	g, _ := ucpGuard(t)
	if err := g.Verify(context.Background(), completion(nil, nil)); err == nil {
		t.Fatal("expected rejection: missing mandates")
	}
}
