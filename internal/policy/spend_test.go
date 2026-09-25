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

func signSpend(t *testing.T, priv ed25519.PrivateKey, c domain.SpendMandateClaims) []byte {
	t.Helper()
	b, _ := json.Marshal(c)
	cose, err := crypto.SignCOSE1(priv, b)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return cose
}

func validClaims(now time.Time) domain.SpendMandateClaims {
	return domain.SpendMandateClaims{
		MandateID:    "spend-1",
		SubjectAns:   domain.LocalANSName("Ada"),
		AudienceAns:  domain.LocalANSName("shop-acp"),
		ItemID:       "widget",
		MaxAmount:    1500,
		Currency:     "usd",
		Scope:        domain.ScopePurchase,
		NotBefore:    now.Add(-time.Minute).Format(time.RFC3339),
		NotAfter:     now.Add(time.Hour).Format(time.RFC3339),
		AuthorityAns: domain.LocalANSName("authority-1"),
	}
}

func newGuard(t *testing.T) (*policy.Spend, ed25519.PrivateKey) {
	t.Helper()
	authPriv, _ := crypto.GenerateEd25519()
	g := policy.NewSpend(
		domain.LocalANSName("shop-acp"),
		domain.LocalANSName("authority-1"),
		authPriv.Public().(ed25519.PublicKey),
		zerolog.Nop(),
	)
	return g, authPriv
}

func req(mandate []byte) domain.PurchaseRequest {
	return domain.PurchaseRequest{
		CallerAns: domain.LocalANSName("Ada"), ItemID: "widget",
		Amount: 1200, Currency: "usd", SpendMandate: mandate,
	}
}

func TestSpendAcceptsValidMandate(t *testing.T) {
	g, authPriv := newGuard(t)
	m := signSpend(t, authPriv, validClaims(time.Now().UTC()))
	if err := g.Verify(context.Background(), req(m)); err != nil {
		t.Fatalf("valid mandate rejected: %v", err)
	}
}

func TestSpendRejectsMissingMandate(t *testing.T) {
	g, _ := newGuard(t)
	if err := g.Verify(context.Background(), req(nil)); err == nil {
		t.Fatal("expected rejection for missing mandate")
	}
}

func TestSpendRejectsWrongAuthorityKey(t *testing.T) {
	g, _ := newGuard(t)
	other, _ := crypto.GenerateEd25519()
	m := signSpend(t, other, validClaims(time.Now().UTC()))
	if err := g.Verify(context.Background(), req(m)); err == nil {
		t.Fatal("expected rejection: mandate signed by untrusted key")
	}
}

func TestSpendRejectsItemMismatch(t *testing.T) {
	g, authPriv := newGuard(t)
	c := validClaims(time.Now().UTC())
	c.ItemID = "gadget"
	m := signSpend(t, authPriv, c)
	if err := g.Verify(context.Background(), req(m)); err == nil {
		t.Fatal("expected rejection: item mismatch")
	}
}

func TestSpendRejectsAmountOverMax(t *testing.T) {
	g, authPriv := newGuard(t)
	c := validClaims(time.Now().UTC())
	c.MaxAmount = 1000 // request Amount is 1200
	m := signSpend(t, authPriv, c)
	if err := g.Verify(context.Background(), req(m)); err == nil {
		t.Fatal("expected rejection: amount exceeds maxAmount")
	}
}

func TestSpendRejectsWrongAudience(t *testing.T) {
	g, authPriv := newGuard(t)
	c := validClaims(time.Now().UTC())
	c.AudienceAns = domain.LocalANSName("someone-else")
	m := signSpend(t, authPriv, c)
	if err := g.Verify(context.Background(), req(m)); err == nil {
		t.Fatal("expected rejection: audience mismatch")
	}
}

func TestSpendRejectsExpired(t *testing.T) {
	g, authPriv := newGuard(t)
	c := validClaims(time.Now().UTC())
	c.NotAfter = time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339)
	m := signSpend(t, authPriv, c)
	if err := g.Verify(context.Background(), req(m)); err == nil {
		t.Fatal("expected rejection: expired mandate")
	}
}
