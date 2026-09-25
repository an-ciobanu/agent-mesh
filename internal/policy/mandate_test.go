package policy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

func mustKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// signMandate builds a COSE_Sign1 mandate over claims, signed by priv.
func signMandate(t *testing.T, priv ed25519.PrivateKey, claims domain.MandateClaims) []byte {
	t.Helper()
	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	cose, err := crypto.SignCOSE1(priv, b)
	if err != nil {
		t.Fatal(err)
	}
	return cose
}

// fixture returns a guard trusting authPriv's key, plus a valid claims template.
func fixture(t *testing.T) (*Mandate, ed25519.PrivateKey, domain.MandateClaims) {
	t.Helper()
	authPriv := mustKey(t)
	self := domain.LocalANSName("greeter-mandate")
	authAns := domain.LocalANSName("authority-1")
	g := NewMandate(self, authAns, authPriv.Public().(ed25519.PublicKey), "greet", zerolog.Nop())
	now := time.Now().UTC()
	claims := domain.MandateClaims{
		MandateID:    "mandate-test",
		SubjectAns:   domain.LocalANSName("visitor"),
		AudienceAns:  self,
		Scope:        "greet",
		NotBefore:    now.Add(-time.Minute).Format(time.RFC3339),
		NotAfter:     now.Add(time.Hour).Format(time.RFC3339),
		AuthorityAns: authAns,
	}
	return g, authPriv, claims
}

func req(caller string, mandate []byte) domain.GreetRequest {
	return domain.GreetRequest{CallerAns: domain.LocalANSName(caller), AudienceAns: domain.LocalANSName("greeter-mandate"), Mandate: mandate}
}

func TestMandateHappyPath(t *testing.T) {
	g, authPriv, claims := fixture(t)
	if err := g.Authorize(context.Background(), req("visitor", signMandate(t, authPriv, claims))); err != nil {
		t.Fatalf("valid mandate rejected: %v", err)
	}
}

func TestMandateMissing(t *testing.T) {
	g, _, _ := fixture(t)
	if err := g.Authorize(context.Background(), req("visitor", nil)); err == nil {
		t.Fatal("expected rejection when no mandate is presented")
	}
}

func TestMandateForgedAuthorityRejected(t *testing.T) {
	g, _, claims := fixture(t)
	// Attacker signs a well-formed mandate with THEIR OWN key. Self-verifying
	// COSE would "verify" — the pinned-key check must reject it.
	attacker := mustKey(t)
	if err := g.Authorize(context.Background(), req("visitor", signMandate(t, attacker, claims))); err == nil {
		t.Fatal("expected rejection: mandate not signed by the trusted authority")
	}
}

func TestMandateAuthorityAnsMismatch(t *testing.T) {
	g, authPriv, claims := fixture(t)
	claims.AuthorityAns = domain.LocalANSName("rogue-authority")
	if err := g.Authorize(context.Background(), req("visitor", signMandate(t, authPriv, claims))); err == nil {
		t.Fatal("expected rejection when claims.AuthorityAns is not the trusted authority")
	}
}

func TestMandateAudienceMismatch(t *testing.T) {
	g, authPriv, claims := fixture(t)
	claims.AudienceAns = domain.LocalANSName("some-other-greeter")
	if err := g.Authorize(context.Background(), req("visitor", signMandate(t, authPriv, claims))); err == nil {
		t.Fatal("expected rejection on audience mismatch")
	}
}

func TestMandateSubjectMismatch(t *testing.T) {
	g, authPriv, claims := fixture(t)
	// Mandate was issued for "visitor" but "intruder" presents it.
	if err := g.Authorize(context.Background(), req("intruder", signMandate(t, authPriv, claims))); err == nil {
		t.Fatal("expected rejection when caller is not the mandate subject")
	}
}

func TestMandateScopeMismatch(t *testing.T) {
	g, authPriv, claims := fixture(t)
	claims.Scope = "administer"
	if err := g.Authorize(context.Background(), req("visitor", signMandate(t, authPriv, claims))); err == nil {
		t.Fatal("expected rejection on scope mismatch")
	}
}

func TestMandateExpired(t *testing.T) {
	g, authPriv, claims := fixture(t)
	past := time.Now().UTC().Add(-2 * time.Hour)
	claims.NotBefore = past.Add(-time.Hour).Format(time.RFC3339)
	claims.NotAfter = past.Format(time.RFC3339)
	if err := g.Authorize(context.Background(), req("visitor", signMandate(t, authPriv, claims))); err == nil {
		t.Fatal("expected rejection for an expired mandate")
	}
}

func TestMandateNotYetValid(t *testing.T) {
	g, authPriv, claims := fixture(t)
	future := time.Now().UTC().Add(2 * time.Hour)
	claims.NotBefore = future.Format(time.RFC3339)
	claims.NotAfter = future.Add(time.Hour).Format(time.RFC3339)
	if err := g.Authorize(context.Background(), req("visitor", signMandate(t, authPriv, claims))); err == nil {
		t.Fatal("expected rejection for a not-yet-valid mandate")
	}
}

func TestMandateMalformedCOSE(t *testing.T) {
	g, _, _ := fixture(t)
	if err := g.Authorize(context.Background(), req("visitor", []byte("not a cose object"))); err == nil {
		t.Fatal("expected rejection for a malformed mandate")
	}
}

func TestMandateMalformedClaims(t *testing.T) {
	g, authPriv, _ := fixture(t)
	// Valid COSE signed by the trusted authority, but payload is not MandateClaims.
	bad, err := crypto.SignCOSE1(authPriv, []byte("[1,2,3]"))
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Authorize(context.Background(), req("visitor", bad)); err == nil {
		t.Fatal("expected rejection for malformed claims")
	}
}

func TestMandateMalformedNotBefore(t *testing.T) {
	g, authPriv, claims := fixture(t)
	claims.NotBefore = "not-a-timestamp"
	if err := g.Authorize(context.Background(), req("visitor", signMandate(t, authPriv, claims))); err == nil {
		t.Fatal("expected rejection for malformed notBefore")
	}
}

func TestMandateMalformedNotAfter(t *testing.T) {
	g, authPriv, claims := fixture(t)
	claims.NotAfter = "not-a-timestamp"
	if err := g.Authorize(context.Background(), req("visitor", signMandate(t, authPriv, claims))); err == nil {
		t.Fatal("expected rejection for malformed notAfter")
	}
}

func TestMandateUsesInjectedClock(t *testing.T) {
	g, authPriv, claims := fixture(t)
	// Freeze the clock far in the future so the fixture's 1h window is expired.
	g.now = func() time.Time { return time.Now().UTC().Add(48 * time.Hour) }
	if err := g.Authorize(context.Background(), req("visitor", signMandate(t, authPriv, claims))); err == nil {
		t.Fatal("expected expiry using the injected clock")
	}
}
