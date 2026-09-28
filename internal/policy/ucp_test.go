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

// signRaw signs arbitrary (possibly non-JSON) bytes as a COSE_Sign1, to exercise
// the "claims malformed" unmarshal-failure branches.
func signRaw(t *testing.T, priv ed25519.PrivateKey, b []byte) []byte {
	t.Helper()
	cose, err := crypto.SignCOSE1(priv, b)
	if err != nil {
		t.Fatalf("sign raw: %v", err)
	}
	return cose
}

// TestUCPFlipsOneFieldAtATime covers Verify's fail-closed branches by mutating
// exactly one aspect of an otherwise-valid mandate pair and asserting rejection.
func TestUCPFlipsOneFieldAtATime(t *testing.T) {
	cases := []struct {
		name  string
		build func(now time.Time, ap ed25519.PrivateKey) (cm, pm []byte)
	}{
		{
			name: "checkout audience mismatch",
			build: func(now time.Time, ap ed25519.PrivateKey) ([]byte, []byte) {
				c := goodCheckout(now)
				c.AudienceAns = domain.LocalANSName("someone-else")
				return signJSON(t, ap, c), signJSON(t, ap, goodPayment(now))
			},
		},
		{
			name: "checkout subject mismatch",
			build: func(now time.Time, ap ed25519.PrivateKey) ([]byte, []byte) {
				c := goodCheckout(now)
				c.SubjectAns = domain.LocalANSName("someone-else")
				return signJSON(t, ap, c), signJSON(t, ap, goodPayment(now))
			},
		},
		{
			name: "checkout itemId mismatch",
			build: func(now time.Time, ap ed25519.PrivateKey) ([]byte, []byte) {
				c := goodCheckout(now)
				c.ItemID = "other-item"
				return signJSON(t, ap, c), signJSON(t, ap, goodPayment(now))
			},
		},
		{
			name: "checkout currency mismatch",
			build: func(now time.Time, ap ed25519.PrivateKey) ([]byte, []byte) {
				c := goodCheckout(now)
				c.Currency = "eur"
				return signJSON(t, ap, c), signJSON(t, ap, goodPayment(now))
			},
		},
		{
			name: "checkout amount over authorized limit",
			build: func(now time.Time, ap ed25519.PrivateKey) ([]byte, []byte) {
				c := goodCheckout(now)
				c.Amount = 1000 // completion() charges 1200
				return signJSON(t, ap, c), signJSON(t, ap, goodPayment(now))
			},
		},
		{
			name: "checkout window expired",
			build: func(now time.Time, ap ed25519.PrivateKey) ([]byte, []byte) {
				c := goodCheckout(now)
				c.NotAfter = now.Add(-10 * time.Minute).Format(time.RFC3339)
				return signJSON(t, ap, c), signJSON(t, ap, goodPayment(now))
			},
		},
		{
			name: "checkout window not yet valid",
			build: func(now time.Time, ap ed25519.PrivateKey) ([]byte, []byte) {
				c := goodCheckout(now)
				c.NotBefore = now.Add(10 * time.Minute).Format(time.RFC3339)
				return signJSON(t, ap, c), signJSON(t, ap, goodPayment(now))
			},
		},
		{
			name: "checkout claims malformed",
			build: func(now time.Time, ap ed25519.PrivateKey) ([]byte, []byte) {
				return signRaw(t, ap, []byte("not-json")), signJSON(t, ap, goodPayment(now))
			},
		},
		{
			name: "payment subject mismatch",
			build: func(now time.Time, ap ed25519.PrivateKey) ([]byte, []byte) {
				p := goodPayment(now)
				p.SubjectAns = domain.LocalANSName("someone-else")
				return signJSON(t, ap, goodCheckout(now)), signJSON(t, ap, p)
			},
		},
		{
			name: "payment audience mismatch",
			build: func(now time.Time, ap ed25519.PrivateKey) ([]byte, []byte) {
				p := goodPayment(now)
				p.AudienceAns = domain.LocalANSName("someone-else")
				return signJSON(t, ap, goodCheckout(now)), signJSON(t, ap, p)
			},
		},
		{
			name: "payment currency mismatch",
			build: func(now time.Time, ap ed25519.PrivateKey) ([]byte, []byte) {
				p := goodPayment(now)
				p.Currency = "eur"
				return signJSON(t, ap, goodCheckout(now)), signJSON(t, ap, p)
			},
		},
		{
			name: "payment window expired",
			build: func(now time.Time, ap ed25519.PrivateKey) ([]byte, []byte) {
				p := goodPayment(now)
				p.NotAfter = now.Add(-10 * time.Minute).Format(time.RFC3339)
				return signJSON(t, ap, goodCheckout(now)), signJSON(t, ap, p)
			},
		},
		{
			name: "payment window not yet valid",
			build: func(now time.Time, ap ed25519.PrivateKey) ([]byte, []byte) {
				p := goodPayment(now)
				p.NotBefore = now.Add(10 * time.Minute).Format(time.RFC3339)
				return signJSON(t, ap, goodCheckout(now)), signJSON(t, ap, p)
			},
		},
		{
			name: "payment claims malformed",
			build: func(now time.Time, ap ed25519.PrivateKey) ([]byte, []byte) {
				return signJSON(t, ap, goodCheckout(now)), signRaw(t, ap, []byte("not-json"))
			},
		},
		{
			// Scope confusion, vice versa of TestUCPRejectsWrongPaymentScope: a
			// payment-scoped mandate supplied in the checkout slot.
			name: "scope confusion: payment mandate in checkout slot",
			build: func(now time.Time, ap ed25519.PrivateKey) ([]byte, []byte) {
				return signJSON(t, ap, goodPayment(now)), signJSON(t, ap, goodPayment(now))
			},
		},
		{
			name: "checkout mandate not a valid COSE_Sign1",
			build: func(now time.Time, ap ed25519.PrivateKey) ([]byte, []byte) {
				return []byte("not-a-cose-message"), signJSON(t, ap, goodPayment(now))
			},
		},
		{
			name: "payment mandate not a valid COSE_Sign1",
			build: func(now time.Time, ap ed25519.PrivateKey) ([]byte, []byte) {
				return signJSON(t, ap, goodCheckout(now)), []byte("not-a-cose-message")
			},
		},
		{
			name: "payment signed by untrusted key (checkout signer still trusted)",
			build: func(now time.Time, ap ed25519.PrivateKey) ([]byte, []byte) {
				other, _ := crypto.GenerateEd25519()
				return signJSON(t, ap, goodCheckout(now)), signJSON(t, other, goodPayment(now))
			},
		},
		{
			name: "checkout authority claim not trusted",
			build: func(now time.Time, ap ed25519.PrivateKey) ([]byte, []byte) {
				c := goodCheckout(now)
				c.AuthorityAns = domain.LocalANSName("authority-2")
				return signJSON(t, ap, c), signJSON(t, ap, goodPayment(now))
			},
		},
		{
			name: "payment authority claim not trusted",
			build: func(now time.Time, ap ed25519.PrivateKey) ([]byte, []byte) {
				p := goodPayment(now)
				p.AuthorityAns = domain.LocalANSName("authority-2")
				return signJSON(t, ap, goodCheckout(now)), signJSON(t, ap, p)
			},
		},
		{
			name: "checkout notBefore unparsable",
			build: func(now time.Time, ap ed25519.PrivateKey) ([]byte, []byte) {
				c := goodCheckout(now)
				c.NotBefore = "not-a-timestamp"
				return signJSON(t, ap, c), signJSON(t, ap, goodPayment(now))
			},
		},
		{
			name: "checkout notAfter unparsable",
			build: func(now time.Time, ap ed25519.PrivateKey) ([]byte, []byte) {
				c := goodCheckout(now)
				c.NotAfter = "not-a-timestamp"
				return signJSON(t, ap, c), signJSON(t, ap, goodPayment(now))
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, ap := ucpGuard(t)
			now := time.Now().UTC()
			cm, pm := tc.build(now, ap)
			if err := g.Verify(context.Background(), completion(cm, pm)); err == nil {
				t.Fatalf("expected rejection for %q", tc.name)
			}
		})
	}
}
