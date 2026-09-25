package policy

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/events"
	"github.com/an-ciobanu/agent-mesh/internal/nonce"
)

const testHTU = "http://greeter.example/a2a"

func nonceFixture(t *testing.T) (*Nonce, *nonce.Store) {
	t.Helper()
	store := nonce.NewStore(time.Minute)
	g := NewNonce(domain.LocalANSName("greeter-nonce"), store, zerolog.Nop())
	return g, store
}

func TestNonceHappyPath(t *testing.T) {
	g, store := nonceFixture(t)
	priv, _ := crypto.GenerateDPoPKey()
	n := store.Issue()
	proof, err := crypto.CreateDPoPProof(priv, crypto.DPoPClaims{
		HTM: "POST", HTU: testHTU, IAT: time.Now().Unix(), JTI: "j1", Nonce: n,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := domain.GreetRequest{CallerAns: domain.LocalANSName("visitor"), DPoPProof: proof, HTTPMethod: "POST", HTTPURL: testHTU}
	if err := g.Authorize(context.Background(), req); err != nil {
		t.Fatalf("valid proof rejected: %v", err)
	}
	// Single-use: the same proof/nonce cannot be replayed.
	if err := g.Authorize(context.Background(), req); err == nil {
		t.Fatal("expected replay (same nonce) to be rejected")
	}
}

func TestNonceMissingProof(t *testing.T) {
	g, _ := nonceFixture(t)
	if err := g.Authorize(context.Background(), domain.GreetRequest{HTTPMethod: "POST", HTTPURL: testHTU}); err == nil {
		t.Fatal("expected rejection when no DPoP proof is presented")
	}
}

func TestNonceUnknownNonce(t *testing.T) {
	g, _ := nonceFixture(t)
	priv, _ := crypto.GenerateDPoPKey()
	proof, _ := crypto.CreateDPoPProof(priv, crypto.DPoPClaims{HTM: "POST", HTU: testHTU, IAT: time.Now().Unix(), JTI: "j", Nonce: "never-issued"})
	req := domain.GreetRequest{DPoPProof: proof, HTTPMethod: "POST", HTTPURL: testHTU}
	if err := g.Authorize(context.Background(), req); err == nil {
		t.Fatal("expected rejection for a nonce the greeter never issued")
	}
}

func TestNonceHTMMismatch(t *testing.T) {
	g, store := nonceFixture(t)
	priv, _ := crypto.GenerateDPoPKey()
	n := store.Issue()
	proof, _ := crypto.CreateDPoPProof(priv, crypto.DPoPClaims{HTM: "GET", HTU: testHTU, IAT: time.Now().Unix(), JTI: "j", Nonce: n})
	req := domain.GreetRequest{DPoPProof: proof, HTTPMethod: "POST", HTTPURL: testHTU}
	if err := g.Authorize(context.Background(), req); err == nil {
		t.Fatal("expected rejection on htm mismatch")
	}
}

func TestNonceHTUMismatch(t *testing.T) {
	g, store := nonceFixture(t)
	priv, _ := crypto.GenerateDPoPKey()
	n := store.Issue()
	proof, _ := crypto.CreateDPoPProof(priv, crypto.DPoPClaims{HTM: "POST", HTU: "http://evil.example/a2a", IAT: time.Now().Unix(), JTI: "j", Nonce: n})
	req := domain.GreetRequest{DPoPProof: proof, HTTPMethod: "POST", HTTPURL: testHTU}
	if err := g.Authorize(context.Background(), req); err == nil {
		t.Fatal("expected rejection on htu mismatch")
	}
}

func TestNonceStaleProof(t *testing.T) {
	g, store := nonceFixture(t)
	priv, _ := crypto.GenerateDPoPKey()
	n := store.Issue()
	proof, _ := crypto.CreateDPoPProof(priv, crypto.DPoPClaims{HTM: "POST", HTU: testHTU, IAT: time.Now().Add(-10 * time.Minute).Unix(), JTI: "j", Nonce: n})
	req := domain.GreetRequest{DPoPProof: proof, HTTPMethod: "POST", HTTPURL: testHTU}
	if err := g.Authorize(context.Background(), req); err == nil {
		t.Fatal("expected rejection for a stale proof (old iat)")
	}
}

func TestNonceFutureProof(t *testing.T) {
	g, store := nonceFixture(t)
	priv, _ := crypto.GenerateDPoPKey()
	n := store.Issue()
	proof, _ := crypto.CreateDPoPProof(priv, crypto.DPoPClaims{HTM: "POST", HTU: testHTU, IAT: time.Now().Add(10 * time.Minute).Unix(), JTI: "j", Nonce: n})
	req := domain.GreetRequest{DPoPProof: proof, HTTPMethod: "POST", HTTPURL: testHTU}
	if err := g.Authorize(context.Background(), req); err == nil {
		t.Fatal("expected rejection for a proof with iat far in the future")
	}
}

func TestNonceEmitsChecks(t *testing.T) {
	g, store := nonceFixture(t)
	priv, _ := crypto.GenerateDPoPKey()
	n := store.Issue()
	proof, err := crypto.CreateDPoPProof(priv, crypto.DPoPClaims{
		HTM: "POST", HTU: testHTU, IAT: time.Now().Unix(), JTI: "j1", Nonce: n,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := domain.GreetRequest{CallerAns: domain.LocalANSName("visitor"), DPoPProof: proof, HTTPMethod: "POST", HTTPURL: testHTU}

	var buf bytes.Buffer
	ctx := events.WithScope(context.Background(), events.NewJSONEmitter(&buf), "g1", "ema", events.RoleResponder)
	if err := g.Authorize(ctx, req); err != nil {
		t.Fatalf("expected accept, got %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, `"step":"dpop.verify"`) || !strings.Contains(got, `"step":"nonce.consume"`) {
		t.Fatalf("missing check events: %s", got)
	}
}

func TestNonceMalformedProof(t *testing.T) {
	g, _ := nonceFixture(t)
	req := domain.GreetRequest{DPoPProof: "not-a-jws", HTTPMethod: "POST", HTTPURL: testHTU}
	if err := g.Authorize(context.Background(), req); err == nil {
		t.Fatal("expected rejection for a malformed proof")
	}
}
