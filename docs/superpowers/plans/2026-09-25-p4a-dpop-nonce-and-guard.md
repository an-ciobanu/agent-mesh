# agent-mesh P4a — DPoP + Nonce Primitives + Guard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the proof-of-possession primitives for the third agent type (the nonce greeter): P-256/ES256 DPoP proof crypto, a single-use nonce store exposed via a `get_nonce` MCP tool, and a `policy.Nonce` guard that verifies a DPoP proof over a fresh, single-use nonce — proven in isolation with unit tests.

**Architecture:** Follows the P3 pattern. `crypto/dpop.go` adds RFC 9449-style DPoP proofs: an ES256 compact JWS whose header embeds the signer's P-256 public JWK (self-verifying, like our other primitives), carrying `htm`/`htu`/`iat`/`jti`/`nonce` claims. `internal/nonce` holds a `Store` that issues random single-use nonces (with a TTL) and exposes them through a `get_nonce` MCP tool; the greeter consumes a nonce exactly once. `policy.Nonce` is a `GreetPolicy` that verifies the DPoP proof's signature (via the embedded key), binds `htm`/`htu` to the request, checks `iat` freshness, and consumes the nonce from the store. `domain.GreetRequest` gains `DPoPProof`/`HTTPMethod`/`HTTPURL` fields so the guard receives what it needs. The guard and store are pure (no network), so they are fully unit-testable.

**Tech Stack:** Go 1.23 stdlib crypto (`crypto/ecdsa`, `crypto/elliptic`, `crypto/sha256`), existing deps (`rs/zerolog`); no new third-party dependencies.

**Scope:** P4a is primitives + guard only. The `X-ANS-DPoP` transport, the nonce-aware initiator (card extension → `get_nonce` → build proof → present), `cmd/agent --policy nonce` wiring, the end-to-end integration test, and the demo are **P4b** (next plan). The nonce greeter's challenge is delivered via a `get_nonce` MCP tool (decided). Retrofitting DPoP-binding onto P3 mandates (mandate `jkt`) remains a separate future item.

**Baseline:** P0–P3b merged on `master`. Reuse: `crypto.{JWK,PublicJWK,Thumbprint}` patterns (dpop.go mirrors `jws.go`'s compact-JWS style); `mcp.ToolFunc`; `domain.{GreetRequest,GreetPolicy,LocalANSName}`; `policy.Open`/`policy.Mandate` (for style). Do all work on a branch off `master` (e.g. `p4a-dpop-nonce`).

---

## File structure (this plan)

```
internal/domain/greet.go            # MODIFY: add DPoPProof/HTTPMethod/HTTPURL to GreetRequest
internal/crypto/dpop.go             # NEW: P-256/ES256 DPoP proof create + verify, thumbprint
internal/crypto/dpop_test.go        # NEW: round-trip, tamper, malformed
internal/nonce/store.go             # NEW: single-use nonce Store + get_nonce MCP tool
internal/nonce/store_test.go        # NEW
internal/policy/nonce.go            # NEW: the Nonce guard
internal/policy/nonce_test.go       # NEW: comprehensive guard tests
```

Conventions unchanged: hexagonal Go; injected `zerolog.Logger` tagged `component`; no `fmt.Println`/`log` in library code; crypto targets 100%; `gofmt`/`go vet` clean before every commit; **no AI `Co-Authored-By:` trailer**, no `git commit -s`.

---

## Task 1: domain — carry a DPoP proof on the greet request

**Files:**
- Modify: `internal/domain/greet.go`

- [ ] **Step 1: Add the fields**

In `GreetRequest`, after the `Mandate []byte` field, add:

```go
	// DPoPProof is the caller-presented RFC 9449 proof-of-possession (an ES256
	// compact JWS over a fresh nonce), or "" if none. A nonce-gated GreetPolicy
	// verifies it; other policies ignore it.
	DPoPProof string

	// HTTPMethod and HTTPURL are the request's method and URL (scheme+host+path),
	// used to bind a DPoP proof's htm/htu claims to this request. Empty for
	// non-HTTP callers.
	HTTPMethod string
	HTTPURL    string
```

- [ ] **Step 2: Verify it compiles**

Run: `go build ./...`
Expected: exits 0 (fields unused for now — fine).

- [ ] **Step 3: Commit**

```bash
git add internal/domain/greet.go
git commit -m "feat(domain): carry an optional DPoP proof + request binding on GreetRequest"
```

---

## Task 2: crypto — P-256/ES256 DPoP proofs

**Files:**
- Create: `internal/crypto/dpop.go`
- Test: `internal/crypto/dpop_test.go`

- [ ] **Step 1: Write the failing test**

```go
package crypto

import (
	"strings"
	"testing"
	"time"
)

func sampleClaims() DPoPClaims {
	return DPoPClaims{
		HTM:   "POST",
		HTU:   "http://127.0.0.1:9/a2a",
		IAT:   time.Now().Unix(),
		JTI:   "jti-123",
		Nonce: "nonce-abc",
	}
}

func TestDPoPProofRoundTrip(t *testing.T) {
	priv, err := GenerateDPoPKey()
	if err != nil {
		t.Fatal(err)
	}
	in := sampleClaims()
	proof, err := CreateDPoPProof(priv, in)
	if err != nil {
		t.Fatal(err)
	}
	got, thumb, err := VerifyDPoPProof(proof)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got != in {
		t.Fatalf("claims mismatch: %+v vs %+v", got, in)
	}
	if thumb == "" {
		t.Fatal("empty thumbprint")
	}
	// The thumbprint is stable for the same key.
	if thumb != DPoPThumbprint(&priv.PublicKey) {
		t.Fatal("thumbprint not stable")
	}
}

func TestDPoPProofRejectsTamperedClaims(t *testing.T) {
	priv, _ := GenerateDPoPKey()
	proof, _ := CreateDPoPProof(priv, sampleClaims())
	parts := strings.Split(proof, ".")
	// Corrupt the claims segment.
	parts[1] = parts[1][:len(parts[1])-2] + "AA"
	if _, _, err := VerifyDPoPProof(strings.Join(parts, ".")); err == nil {
		t.Fatal("expected verification failure on tampered claims")
	}
}

func TestDPoPProofRejectsWrongKey(t *testing.T) {
	priv, _ := GenerateDPoPKey()
	other, _ := GenerateDPoPKey()
	proof, _ := CreateDPoPProof(priv, sampleClaims())
	// Splice the other key's header in — signature no longer matches.
	otherProof, _ := CreateDPoPProof(other, sampleClaims())
	spliced := strings.Split(otherProof, ".")[0] + "." + strings.SplitN(proof, ".", 2)[1]
	if _, _, err := VerifyDPoPProof(spliced); err == nil {
		t.Fatal("expected verification failure when header key does not match signature")
	}
}

func TestDPoPProofRejectsMalformed(t *testing.T) {
	for _, bad := range []string{"", "a.b", "a.b.c.d", "!!!.!!!.!!!"} {
		if _, _, err := VerifyDPoPProof(bad); err == nil {
			t.Fatalf("expected error for malformed proof %q", bad)
		}
	}
}

func TestDPoPThumbprintDistinctKeys(t *testing.T) {
	a, _ := GenerateDPoPKey()
	b, _ := GenerateDPoPKey()
	if DPoPThumbprint(&a.PublicKey) == DPoPThumbprint(&b.PublicKey) {
		t.Fatal("distinct keys must have distinct thumbprints")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/crypto/ -run DPoP -v`
Expected: FAIL — `undefined: GenerateDPoPKey`, etc.

- [ ] **Step 3: Write `internal/crypto/dpop.go`**

```go
package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// DPoPClaims are the RFC 9449 DPoP proof claims agent-mesh uses.
type DPoPClaims struct {
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	IAT   int64  `json:"iat"`
	JTI   string `json:"jti"`
	Nonce string `json:"nonce"`
}

// ecJWK is a P-256 public key in JWK form.
type ecJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type dpopHeader struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	JWK ecJWK  `json:"jwk"`
}

// GenerateDPoPKey returns a fresh P-256 key for DPoP proofs.
func GenerateDPoPKey() (*ecdsa.PrivateKey, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate dpop key: %w", err)
	}
	return k, nil
}

// coord32 left-pads a coordinate to the 32-byte P-256 field size.
func coord32(v *big.Int) []byte {
	b := v.Bytes()
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func ecPublicJWK(pub *ecdsa.PublicKey) ecJWK {
	return ecJWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(coord32(pub.X)),
		Y:   base64.RawURLEncoding.EncodeToString(coord32(pub.Y)),
	}
}

// DPoPThumbprint returns the RFC 7638 JWK thumbprint of a P-256 public key.
func DPoPThumbprint(pub *ecdsa.PublicKey) string {
	j := ecPublicJWK(pub)
	canonical := fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q,"y":%q}`, j.Crv, j.Kty, j.X, j.Y)
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// CreateDPoPProof builds a compact ES256 JWS DPoP proof over claims, embedding
// the signer's P-256 public key in the header (self-verifying).
func CreateDPoPProof(priv *ecdsa.PrivateKey, claims DPoPClaims) (string, error) {
	hb, err := json.Marshal(dpopHeader{Typ: "dpop+jwt", Alg: "ES256", JWK: ecPublicJWK(&priv.PublicKey)})
	if err != nil {
		return "", fmt.Errorf("marshal dpop header: %w", err)
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal dpop claims: %w", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign dpop proof: %w", err)
	}
	sig := append(coord32(r), coord32(s)...)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyDPoPProof verifies a compact ES256 DPoP proof against its embedded key
// and returns the claims plus the RFC 7638 thumbprint of that key. It verifies
// the signature and structural validity only; freshness, htm/htu and nonce are
// the caller's (policy's) responsibility.
func VerifyDPoPProof(compact string) (DPoPClaims, string, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return DPoPClaims{}, "", errors.New("dpop: malformed proof")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return DPoPClaims{}, "", fmt.Errorf("dpop: decode header: %w", err)
	}
	var hdr dpopHeader
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return DPoPClaims{}, "", fmt.Errorf("dpop: parse header: %w", err)
	}
	if hdr.Typ != "dpop+jwt" || hdr.Alg != "ES256" {
		return DPoPClaims{}, "", errors.New("dpop: unexpected header typ/alg")
	}
	pub, err := ecPublicKeyFromJWK(hdr.JWK)
	if err != nil {
		return DPoPClaims{}, "", err
	}
	cb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return DPoPClaims{}, "", fmt.Errorf("dpop: decode claims: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return DPoPClaims{}, "", fmt.Errorf("dpop: decode signature: %w", err)
	}
	if len(sig) != 64 {
		return DPoPClaims{}, "", errors.New("dpop: bad signature length")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return DPoPClaims{}, "", errors.New("dpop: signature verification failed")
	}
	var claims DPoPClaims
	if err := json.Unmarshal(cb, &claims); err != nil {
		return DPoPClaims{}, "", fmt.Errorf("dpop: parse claims: %w", err)
	}
	return claims, DPoPThumbprint(pub), nil
}

// ecPublicKeyFromJWK reconstructs a P-256 public key from its JWK. ecdsa.Verify
// safely rejects an off-curve or invalid point (returns false), so no explicit
// on-curve check is needed here.
func ecPublicKeyFromJWK(j ecJWK) (*ecdsa.PublicKey, error) {
	if j.Kty != "EC" || j.Crv != "P-256" {
		return nil, errors.New("dpop: not a P-256 EC key")
	}
	x, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, fmt.Errorf("dpop: decode x: %w", err)
	}
	y, err := base64.RawURLEncoding.DecodeString(j.Y)
	if err != nil {
		return nil, fmt.Errorf("dpop: decode y: %w", err)
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/crypto/ -run DPoP -v` (PASS), then `go test ./internal/crypto/ -cover` — report the number. The DPoP functions should be at/near 100%; if a specific error branch is uncovered, add a small case (e.g. a proof whose header carries a non-P-256 `crv` → `ecPublicKeyFromJWK` error).

- [ ] **Step 5: Format/vet**

Run: `gofmt -l internal/crypto/` (clean), `go vet ./internal/crypto/...` (clean), `go build ./...` (exit 0).

- [ ] **Step 6: Commit**

```bash
git add internal/crypto/dpop.go internal/crypto/dpop_test.go
git commit -m "feat(crypto): P-256/ES256 DPoP proof create, verify, thumbprint"
```

---

## Task 3: nonce — single-use store + get_nonce MCP tool

**Files:**
- Create: `internal/nonce/store.go`
- Test: `internal/nonce/store_test.go`

- [ ] **Step 1: Write the failing test**

```go
package nonce

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestIssueThenConsumeOnce(t *testing.T) {
	s := NewStore(time.Minute)
	n := s.Issue()
	if n == "" {
		t.Fatal("empty nonce")
	}
	if !s.Consume(n) {
		t.Fatal("first consume should succeed")
	}
	if s.Consume(n) {
		t.Fatal("second consume must fail (single-use)")
	}
}

func TestConsumeUnknownFails(t *testing.T) {
	s := NewStore(time.Minute)
	if s.Consume("never-issued") {
		t.Fatal("consuming an unknown nonce must fail")
	}
}

func TestConsumeExpiredFails(t *testing.T) {
	s := NewStore(time.Minute)
	base := time.Now()
	s.now = func() time.Time { return base }
	n := s.Issue()
	// Jump past the TTL.
	s.now = func() time.Time { return base.Add(2 * time.Minute) }
	if s.Consume(n) {
		t.Fatal("expired nonce must not be consumable")
	}
}

func TestIssueDistinct(t *testing.T) {
	s := NewStore(time.Minute)
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		n := s.Issue()
		if seen[n] {
			t.Fatal("duplicate nonce issued")
		}
		seen[n] = true
	}
}

func TestGetNonceMCPTool(t *testing.T) {
	s := NewStore(time.Minute)
	out, err := s.MCPTool()(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var res struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatal(err)
	}
	if res.Nonce == "" {
		t.Fatal("get_nonce returned empty nonce")
	}
	if !s.Consume(res.Nonce) {
		t.Fatal("nonce from get_nonce should be consumable")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/nonce/ -v`
Expected: FAIL — package/`NewStore` undefined.

- [ ] **Step 3: Write `internal/nonce/store.go`**

```go
// Package nonce issues and single-use-tracks challenge nonces for DPoP
// proof-of-possession.
package nonce

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"sync"
	"time"

	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
)

// Store issues random single-use nonces, each valid for a bounded TTL.
type Store struct {
	mu     sync.Mutex
	issued map[string]time.Time // nonce -> expiry
	ttl    time.Duration
	now    func() time.Time
}

// NewStore returns a nonce store whose nonces expire after ttl.
func NewStore(ttl time.Duration) *Store {
	return &Store{issued: make(map[string]time.Time), ttl: ttl, now: time.Now}
}

// Issue creates, records, and returns a fresh single-use nonce.
func (s *Store) Issue() string {
	b := make([]byte, 32)
	// rand.Read never returns an error on supported platforms; the nonce's
	// unpredictability comes from crypto/rand.
	_, _ = rand.Read(b)
	n := base64.RawURLEncoding.EncodeToString(b)
	s.mu.Lock()
	s.issued[n] = s.now().Add(s.ttl)
	s.mu.Unlock()
	return n
}

// Consume returns true exactly once for a nonce that was issued and has not
// expired, removing it (single-use); it returns false otherwise.
func (s *Store) Consume(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.issued[nonce]
	if !ok {
		return false
	}
	delete(s.issued, nonce)
	return s.now().Before(exp)
}

type nonceResult struct {
	Nonce string `json:"nonce"`
}

// MCPTool returns the get_nonce MCP tool handler: each call issues a fresh nonce.
func (s *Store) MCPTool() mcp.ToolFunc {
	return func(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
		return json.Marshal(nonceResult{Nonce: s.Issue()})
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/nonce/ -v` (PASS), `go test ./internal/nonce/ -cover` (report; expect ≥90%). `gofmt -l internal/nonce/` clean, `go vet ./internal/nonce/...` clean.

- [ ] **Step 5: Commit**

```bash
git add internal/nonce/store.go internal/nonce/store_test.go
git commit -m "feat(nonce): single-use nonce store with get_nonce MCP tool"
```

---

## Task 4: policy — the Nonce guard

**Files:**
- Create: `internal/policy/nonce.go`
- Test: `internal/policy/nonce_test.go`

The guard verifies a DPoP proof over a fresh, single-use nonce and binds it to the request (`htm`/`htu`, freshness). It is pure: the nonce store is injected; no network.

- [ ] **Step 1: Write the failing test**

```go
package policy

import (
	"context"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/nonce"
)

const testHTU = "http://greeter.example/a2a"

// nonceFixture returns a guard, its store, and a P-256 key for building proofs.
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

func TestNonceMalformedProof(t *testing.T) {
	g, _ := nonceFixture(t)
	req := domain.GreetRequest{DPoPProof: "not-a-jws", HTTPMethod: "POST", HTTPURL: testHTU}
	if err := g.Authorize(context.Background(), req); err == nil {
		t.Fatal("expected rejection for a malformed proof")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/ -run Nonce -v`
Expected: FAIL — `undefined: NewNonce`, `undefined: Nonce`.

- [ ] **Step 3: Write `internal/policy/nonce.go`**

```go
package policy

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/nonce"
)

// Nonce is a GreetPolicy that admits a caller only if it presents a valid DPoP
// proof-of-possession (RFC 9449, ES256) over a fresh, single-use nonce this
// greeter issued: the proof's signature must verify against its embedded key,
// its htm/htu must match this request, its iat must be fresh, and its nonce must
// be one the greeter issued and has not yet consumed.
type Nonce struct {
	selfAns string
	store   *nonce.Store
	leeway  time.Duration
	now     func() time.Time
	log     zerolog.Logger
}

// NewNonce builds a nonce-gated policy for greeter selfAns backed by store.
func NewNonce(selfAns string, store *nonce.Store, log zerolog.Logger) *Nonce {
	return &Nonce{
		selfAns: selfAns,
		store:   store,
		leeway:  60 * time.Second,
		now:     time.Now,
		log:     log.With().Str("component", "policy").Logger(),
	}
}

// Authorize enforces the DPoP proof. Every failure returns an error (fail closed).
func (n *Nonce) Authorize(_ context.Context, req domain.GreetRequest) error {
	if req.DPoPProof == "" {
		return fmt.Errorf("DPoP proof required")
	}
	claims, thumb, err := crypto.VerifyDPoPProof(req.DPoPProof)
	if err != nil {
		return fmt.Errorf("DPoP proof invalid: %w", err)
	}
	if claims.HTM != req.HTTPMethod {
		return fmt.Errorf("DPoP htm %q does not match request method %q", claims.HTM, req.HTTPMethod)
	}
	if claims.HTU != req.HTTPURL {
		return fmt.Errorf("DPoP htu %q does not match request URL %q", claims.HTU, req.HTTPURL)
	}
	iat := time.Unix(claims.IAT, 0)
	now := n.now()
	if iat.After(now.Add(n.leeway)) || now.Sub(iat) > n.leeway {
		return fmt.Errorf("DPoP proof stale or not yet valid")
	}
	// Consuming the nonce enforces single use and freshness (the greeter issued
	// it, within the store's TTL).
	if !n.store.Consume(claims.Nonce) {
		return fmt.Errorf("DPoP nonce not recognized or already used")
	}
	n.log.Info().Str("callerAns", req.CallerAns).Str("dpopThumbprint", thumb).Msg("nonce proof accepted")
	return nil
}

var _ domain.GreetPolicy = (*Nonce)(nil)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/policy/ -run Nonce -v` (PASS), then `go test ./internal/policy/ -v` (all policy tests: Open, Mandate, Nonce), `go test ./internal/policy/ -cover` (report; expect ≥90%).

- [ ] **Step 5: Format/vet**

Run: `gofmt -l internal/policy/` (clean), `go vet ./internal/policy/...` (clean), `go build ./...` (exit 0).

- [ ] **Step 6: Commit**

```bash
git add internal/policy/nonce.go internal/policy/nonce_test.go
git commit -m "feat(policy): nonce guard verifying a single-use DPoP proof-of-possession"
```

---

## Task 5: gate + branch verification

**Files:** none (verification only).

- [ ] **Step 1: Full gate**

Run:
```bash
gofmt -l .          # expect no output
go vet ./...        # expect clean
go build ./...      # expect exit 0
go test ./...       # expect all pass
go mod tidy && git diff --exit-code go.mod go.sum   # expect no changes
```

- [ ] **Step 2: Hygiene**

Run:
```bash
git log master..HEAD --format='%b' | grep -i "co-authored-by" && echo FOUND || echo NONE   # expect NONE
git status --porcelain   # expect empty
```

- [ ] **Step 3: (No demo in P4a.)** The end-to-end nonce greet demo lands in P4b. This phase is proven by unit tests: DPoP proofs round-trip and reject tampering/wrong keys; the nonce store is single-use with a TTL; the guard rejects missing/malformed proofs, htm/htu mismatch, stale `iat`, and replayed/unknown nonces, and accepts a valid fresh proof exactly once.

---

## Self-review

**Spec coverage (P4a scope):**
- P-256/ES256 DPoP proof create + verify + thumbprint (RFC 9449 / RFC 7638) → Task 2. ✓
- `get_nonce` capability + single-use nonce with TTL → Task 3 (store + MCP tool). ✓
- `policy.Nonce` guard: DPoP signature (embedded key), htm/htu binding, iat freshness, single-use nonce consume, fail-closed → Task 4. ✓
- Carry the proof + request binding to the guard → Task 1 (`GreetRequest.DPoPProof/HTTPMethod/HTTPURL`). ✓
- Deferred correctly (absent): `X-ANS-DPoP` transport, nonce-aware initiator, `cmd/agent --policy nonce`, integration + demo (all P4b); mandate DPoP-binding (future). Noted in Scope.

**Placeholder scan:** none — every step has concrete code or an exact command with expected output.

**Type consistency check:**
- `crypto.DPoPClaims{HTM,HTU,IAT,JTI,Nonce}`, `crypto.GenerateDPoPKey() (*ecdsa.PrivateKey, error)`, `crypto.CreateDPoPProof(priv *ecdsa.PrivateKey, claims DPoPClaims) (string, error)`, `crypto.VerifyDPoPProof(compact string) (DPoPClaims, string, error)`, `crypto.DPoPThumbprint(*ecdsa.PublicKey) string` — defined Task 2; used by the guard (Task 4) and its tests, and (in P4b) by the initiator. ✓
- `nonce.NewStore(ttl) *Store`, `(*Store).Issue() string`, `(*Store).Consume(string) bool`, `(*Store).MCPTool() mcp.ToolFunc` — defined Task 3; the store is injected into the guard (Task 4) and wired to the greeter's `/mcp` in P4b. `MCPTool` returns `mcp.ToolFunc` (matches P3a's mcp signature). ✓
- `policy.NewNonce(selfAns string, store *nonce.Store, log zerolog.Logger) *Nonce` implementing `domain.GreetPolicy` — defined Task 4; wired in `cmd/agent` in P4b. ✓
- `domain.GreetRequest.{DPoPProof string, HTTPMethod string, HTTPURL string}` — added Task 1; populated by the a2a handler in P4b, read by the guard (Task 4). ✓
- No import cycles: `nonce` imports `comms/mcp` (which imports only zerolog); `policy` imports `crypto`, `domain`, `nonce`; none import `policy`. ✓
- The guard is pure (injected store + injected `now`), so its tests need no network; the HTTP wiring that fills `HTTPMethod`/`HTTPURL` and the `get_nonce` serving are explicitly P4b. ✓
