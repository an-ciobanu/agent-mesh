# agent-mesh P3b-1 — Mandate Transport + Guard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Carry a caller-presented mandate through the generic comms module and enforce it with a `Mandate` GreetPolicy that authenticates the issuer by **pinning the trusted authority's key** — proving in isolation that a mandate-gated greeter admits only callers holding a valid mandate from its trusted authority.

**Architecture:** Extends P3a. The A2A Agent Card gains a `capabilities.extensions` field so a greeter can advertise "mandate required" and point callers to the authority (by role). The A2A greet transport gains an optional `X-ANS-Mandate` header (client attaches, server extracts) so a mandate rides alongside the existing identity JWS. `domain.GreetRequest` gains a `Mandate []byte` field. A new `policy.Mandate` guard verifies the mandate's COSE signature, **pins it to the authority's Ed25519 key** (self-verifying COSE proves only that *some* key signed — the pinned-key check authenticates *which* authority), and checks audience=self, subject=caller, scope, and the validity window. The guard takes a pinned key at construction and does no network I/O, so it is fully unit-testable.

**Tech Stack:** Go 1.23, existing deps (`veraison/go-cose` via `internal/crypto`, `rs/zerolog`); no new dependencies.

**Scope:** P3b-1 is transport + guard only. The authority-pubkey client, the mandate-aware initiator (which follows the card extension, discovers the authority, and calls `issue_mandate`), `cmd/agent`/`meshctl` wiring, the end-to-end integration test, and the demo are **P3b-2** (next plan). This phase does NOT yet run a full mandate greet as processes — it proves each mechanism with unit tests. DPoP sender-constraint (binding the mandate to the caller's key) remains **P4**.

**Baseline:** P0–P3a merged on `master`. Reuse: `crypto.VerifyCOSE1(data) ([]byte, ed25519.PublicKey, error)` and `crypto.SignCOSE1(priv, payload) ([]byte, error)` (`internal/crypto/cose.go`); `domain.{GreetRequest,GreetPolicy,MandateClaims,LocalANSName}`; `a2a.{Card,GreetService,GreetPayload,HandleMessageSend,Client,SendGreet}`; `policy.Open`. Do all work on a branch off `master` (e.g. `p3b1-mandate-guard`).

---

## File structure (this plan)

```
internal/domain/greet.go               # MODIFY: add Mandate []byte to GreetRequest
internal/comms/a2a/card.go             # MODIFY: add Capabilities/Extension types + Card field + ExtMandateURI const
internal/comms/a2a/card_test.go        # NEW (or extend): card+capabilities JSON/serve round-trip
internal/comms/a2a/message.go          # MODIFY: HeaderMandate const; extract mandate header into GreetRequest
internal/comms/a2a/client.go           # MODIFY: SendOption + WithMandate; SendGreet variadic
internal/comms/a2a/mandate_transport_test.go  # NEW: header carries mandate to policy; bad encoding fails closed
internal/policy/mandate.go             # NEW: the Mandate guard (pins authority key)
internal/policy/mandate_test.go        # NEW: comprehensive guard tests (the security heart)
```

Conventions unchanged: hexagonal Go; injected `zerolog.Logger` tagged `component`; no `fmt.Println`/`log` in library code; tests verify real behavior; `gofmt`/`go vet` clean before every commit; **no AI `Co-Authored-By:` trailer**, no `git commit -s`.

---

## Task 1: domain — carry a mandate on the greet request

**Files:**
- Modify: `internal/domain/greet.go`

- [ ] **Step 1: Add the field**

In `internal/domain/greet.go`, add a `Mandate` field to `GreetRequest` (place it after `CallerKeyThumbprint`):

```go
	// Mandate is the caller-presented authorization: a COSE_Sign1 over
	// domain.MandateClaims, or nil if none was presented. A mandate-gated
	// GreetPolicy verifies and pins it to a trusted authority; an open policy
	// ignores it.
	Mandate []byte
```

The struct becomes:
```go
type GreetRequest struct {
	CallerAns   string
	AudienceAns string
	Greeting    string

	// CallerKeyThumbprint is the RFC 7638 JWK thumbprint of the key that signed
	// the greet — proof that the caller possesses that key. It does NOT prove
	// CallerAns belongs to that key: in P1, CallerAns is self-asserted by the
	// caller. Binding CallerAns to a registered key is deferred to P2/P3.
	CallerKeyThumbprint string

	// Mandate is the caller-presented authorization: a COSE_Sign1 over
	// domain.MandateClaims, or nil if none was presented. A mandate-gated
	// GreetPolicy verifies and pins it to a trusted authority; an open policy
	// ignores it.
	Mandate []byte
}
```

- [ ] **Step 2: Verify it compiles**

Run: `go build ./internal/domain/` and `go build ./...`
Expected: exits 0 (the new field is unused for now; that is fine).

- [ ] **Step 3: Commit**

```bash
git add internal/domain/greet.go
git commit -m "feat(domain): carry an optional mandate on GreetRequest"
```

---

## Task 2: A2A Card — capabilities extensions

**Files:**
- Modify: `internal/comms/a2a/card.go`
- Test: `internal/comms/a2a/card_test.go` (create if absent; otherwise append)

- [ ] **Step 1: Write the failing test**

Create `internal/comms/a2a/card_test.go` (if a card test file already exists, append these two functions to it and skip the `package`/import lines it already has):

```go
package a2a

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
)

func TestCardCapabilitiesRoundTrip(t *testing.T) {
	in := Card{
		Name:    "greeter-mandate",
		Version: "0.1.0",
		Security: []map[string][]string{{"mandate": {}}},
		Capabilities: &Capabilities{Extensions: []Extension{{
			URI:         ExtMandateURI,
			Description: "present a mandate from the authority",
			Required:    true,
			Params:      map[string]any{"authorityRole": "authority", "scope": "greet"},
		}}},
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Card
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.Capabilities == nil || len(out.Capabilities.Extensions) != 1 {
		t.Fatalf("capabilities lost in round trip: %+v", out.Capabilities)
	}
	ext := out.Capabilities.Extensions[0]
	if ext.URI != ExtMandateURI || !ext.Required || ext.Params["scope"] != "greet" {
		t.Fatalf("extension round trip wrong: %+v", ext)
	}
}

func TestServeCardIncludesCapabilities(t *testing.T) {
	card := Card{
		Name:         "greeter-mandate",
		Version:      "0.1.0",
		Security:     []map[string][]string{{"mandate": {}}},
		Capabilities: &Capabilities{Extensions: []Extension{{URI: ExtMandateURI, Required: true}}},
	}
	ts := httptest.NewServer(CardHandler(card, zerolog.Nop()))
	defer ts.Close()

	resp, err := ts.Client().Get(ts.URL + "/.well-known/agent-card.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got Card
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Capabilities == nil || len(got.Capabilities.Extensions) != 1 || got.Capabilities.Extensions[0].URI != ExtMandateURI {
		t.Fatalf("served card dropped capabilities: %+v", got.Capabilities)
	}
	if got.URL == "" {
		t.Fatal("served card should still set URL dynamically")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/comms/a2a/ -run 'Card|Capabilities' -v`
Expected: FAIL — `undefined: Capabilities`, `undefined: Extension`, `undefined: ExtMandateURI`, and no `Capabilities` field on `Card`.

- [ ] **Step 3: Add the types, constant, and field in `internal/comms/a2a/card.go`**

Add the constant and types (near the top, after the imports):

```go
// ExtMandateURI identifies the agent-mesh "mandate required" A2A capabilities
// extension. A greeter that advertises it requires callers to present a mandate.
const ExtMandateURI = "https://agent-mesh.local/ext/mandate/v1"

// Extension is an A2A capabilities extension: a URI naming the extension plus
// optional parameters. The mandate-gated greeter uses one to tell callers they
// must present a mandate and by which role to discover the issuing authority.
type Extension struct {
	URI         string         `json:"uri"`
	Description string         `json:"description,omitempty"`
	Required    bool           `json:"required,omitempty"`
	Params      map[string]any `json:"params,omitempty"`
}

// Capabilities is the A2A capabilities object; only extensions are modeled here.
type Capabilities struct {
	Extensions []Extension `json:"extensions,omitempty"`
}
```

Add the `Capabilities` field to `Card` (between `Version` and `Security`):

```go
type Card struct {
	Name         string                `json:"name"`
	Description  string                `json:"description,omitempty"`
	URL          string                `json:"url"`
	Version      string                `json:"version"`
	Capabilities *Capabilities         `json:"capabilities,omitempty"`
	Security     []map[string][]string `json:"security"`
}
```

(`serveCard` copies the card by value and only overwrites `URL`, so `Capabilities` is served as-is — no change needed there.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/comms/a2a/ -run 'Card|Capabilities' -v`
Expected: PASS. Also run the whole package: `go test ./internal/comms/a2a/` — all existing tests still pass.

- [ ] **Step 5: Commit**

```bash
git add internal/comms/a2a/card.go internal/comms/a2a/card_test.go
git commit -m "feat(a2a): Agent Card capabilities extensions (mandate advertisement)"
```

---

## Task 3: A2A transport — carry the mandate over the wire

**Files:**
- Modify: `internal/comms/a2a/message.go`
- Modify: `internal/comms/a2a/client.go`
- Test: `internal/comms/a2a/mandate_transport_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/comms/a2a/mandate_transport_test.go`:

```go
package a2a

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

// capturePolicy records the GreetRequest it was asked to authorize.
type capturePolicy struct{ last domain.GreetRequest }

func (c *capturePolicy) Authorize(_ context.Context, req domain.GreetRequest) error {
	c.last = req
	return nil
}

func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func TestMandateHeaderReachesPolicy(t *testing.T) {
	pol := &capturePolicy{}
	svc := NewGreetService(domain.LocalANSName("greeter-mandate"), pol, zerolog.Nop())
	ts := httptest.NewServer(http.HandlerFunc(svc.HandleMessageSend))
	defer ts.Close()

	priv := testKey(t)
	mandate := []byte("pretend-cose-mandate-bytes")
	_, _, err := NewClient().SendGreet(context.Background(), ts.URL, priv, GreetPayload{
		CallerAns:   domain.LocalANSName("visitor"),
		AudienceAns: domain.LocalANSName("greeter-mandate"),
		Greeting:    "hi",
	}, WithMandate(mandate))
	if err != nil {
		t.Fatal(err)
	}
	if string(pol.last.Mandate) != string(mandate) {
		t.Fatalf("policy did not receive the mandate: got %q", pol.last.Mandate)
	}
}

func TestNoMandateHeaderMeansNilMandate(t *testing.T) {
	pol := &capturePolicy{}
	svc := NewGreetService(domain.LocalANSName("greeter"), pol, zerolog.Nop())
	ts := httptest.NewServer(http.HandlerFunc(svc.HandleMessageSend))
	defer ts.Close()

	priv := testKey(t)
	if _, _, err := NewClient().SendGreet(context.Background(), ts.URL, priv, GreetPayload{
		CallerAns:   domain.LocalANSName("visitor"),
		AudienceAns: domain.LocalANSName("greeter"),
		Greeting:    "hi",
	}); err != nil {
		t.Fatal(err)
	}
	if pol.last.Mandate != nil {
		t.Fatalf("expected nil mandate, got %q", pol.last.Mandate)
	}
}

func TestBadMandateEncodingFailsClosed(t *testing.T) {
	svc := NewGreetService(domain.LocalANSName("greeter"), &capturePolicy{}, zerolog.Nop())
	ts := httptest.NewServer(http.HandlerFunc(svc.HandleMessageSend))
	defer ts.Close()

	priv := testKey(t)
	// Send a well-formed greet but a corrupt (non-base64) mandate header.
	_, _, err := NewClient().SendGreet(context.Background(), ts.URL, priv, GreetPayload{
		CallerAns:   domain.LocalANSName("visitor"),
		AudienceAns: domain.LocalANSName("greeter"),
		Greeting:    "hi",
	}, func(r *http.Request) { r.Header.Set(HeaderMandate, "!!!not base64!!!") })
	if err == nil {
		t.Fatal("expected the greet to be rejected for an invalid mandate encoding")
	}
}

// keep base64 import used even if the compiler would otherwise drop it in edits
var _ = base64.StdEncoding
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/comms/a2a/ -run Mandate -v`
Expected: FAIL — `undefined: WithMandate`, `undefined: HeaderMandate`, and `SendGreet` does not accept a variadic option.

- [ ] **Step 3: Add the header constant and extraction in `internal/comms/a2a/message.go`**

Add `"encoding/base64"` to the imports. Add the constant to the existing `const (...)` block:

```go
	// HeaderMandate carries the caller's presented mandate (a COSE_Sign1 over
	// domain.MandateClaims), base64-std encoded. Optional; a mandate-gated
	// policy requires it.
	HeaderMandate = "X-ANS-Mandate"
```

In `HandleMessageSend`, after the audience check (right before the `g.policy.Authorize(...)` call) extract the mandate header:

```go
	var mandate []byte
	if mh := r.Header.Get(HeaderMandate); mh != "" {
		decoded, derr := base64.StdEncoding.DecodeString(mh)
		if derr != nil {
			g.log.Warn().Err(derr).Msg("greet: invalid mandate encoding")
			g.writeError(w, req.ID, -32602, "invalid mandate encoding")
			return
		}
		mandate = decoded
	}
```

Then pass it into the policy call by adding the `Mandate` field:

```go
	if err := g.policy.Authorize(r.Context(), domain.GreetRequest{
		CallerAns:           gp.CallerAns,
		AudienceAns:         gp.AudienceAns,
		Greeting:            gp.Greeting,
		CallerKeyThumbprint: thumb,
		Mandate:             mandate,
	}); err != nil {
```

- [ ] **Step 4: Add the send option in `internal/comms/a2a/client.go`**

Add `"encoding/base64"` to the imports. Add the option type and constructor:

```go
// SendOption customizes an outbound greet request before it is sent.
type SendOption func(*http.Request)

// WithMandate attaches a mandate (COSE_Sign1 bytes) to the greet via the
// X-ANS-Mandate header, base64-std encoded.
func WithMandate(mandate []byte) SendOption {
	return func(r *http.Request) {
		r.Header.Set(HeaderMandate, base64.StdEncoding.EncodeToString(mandate))
	}
}
```

Change `SendGreet` to accept variadic options and apply them after the standard headers are set:

```go
func (c *Client) SendGreet(ctx context.Context, endpoint string, priv ed25519.PrivateKey, payload GreetPayload, opts ...SendOption) (string, *domain.EvidenceBundle, error) {
```

and, after the two existing `req.Header.Set(...)` lines:

```go
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderRequestJWS, jws)
	for _, opt := range opts {
		opt(req)
	}
```

(Existing callers pass no options and are unaffected.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/comms/a2a/ -run Mandate -v`
Expected: PASS. Then the whole package: `go test ./internal/comms/a2a/` — all pass (existing greet tests still work since options are variadic).

- [ ] **Step 6: Commit**

```bash
git add internal/comms/a2a/message.go internal/comms/a2a/client.go internal/comms/a2a/mandate_transport_test.go
git commit -m "feat(a2a): carry a mandate via X-ANS-Mandate header (client + server)"
```

---

## Task 4: the Mandate guard (pins the trusted authority key)

**Files:**
- Create: `internal/policy/mandate.go`
- Test: `internal/policy/mandate_test.go`

This is the security heart of the phase. Self-verifying COSE proves only that *some* key signed the mandate; the guard must **pin** the trusted authority's key, or any party could mint a mandate with its own key. The guard also binds audience→self, subject→caller, scope, and the validity window.

- [ ] **Step 1: Write the failing test**

Create `internal/policy/mandate_test.go`:

```go
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
	// Valid COSE signed by the trusted authority, but the payload is not
	// MandateClaims JSON.
	bad, err := crypto.SignCOSE1(authPriv, []byte("[1,2,3]"))
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Authorize(context.Background(), req("visitor", bad)); err == nil {
		t.Fatal("expected rejection for malformed claims")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/ -run Mandate -v`
Expected: FAIL — `undefined: NewMandate`, `undefined: Mandate`.

- [ ] **Step 3: Write `internal/policy/mandate.go`**

```go
package policy

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

// Mandate is a GreetPolicy that admits a caller only if it presents a valid
// mandate: a COSE_Sign1 over domain.MandateClaims, signed by the specific
// authority this greeter trusts (its Ed25519 key pinned at construction), naming
// this greeter as the audience, the caller as the subject, the required scope,
// and a currently-valid window.
//
// Self-verifying COSE proves only that SOME key signed the mandate; pinning the
// authority's key is what authenticates the issuer. Without it, any party could
// mint a mandate signed with its own key and pass.
type Mandate struct {
	selfAns      string
	authorityAns string
	authorityPub ed25519.PublicKey
	scope        string
	leeway       time.Duration
	now          func() time.Time
	log          zerolog.Logger
}

// NewMandate builds a mandate-gated policy for greeter selfAns that trusts only
// mandates signed by authorityPub (the authority named authorityAns), granting
// scope. A small clock-skew leeway is applied to the validity window.
func NewMandate(selfAns, authorityAns string, authorityPub ed25519.PublicKey, scope string, log zerolog.Logger) *Mandate {
	return &Mandate{
		selfAns:      selfAns,
		authorityAns: authorityAns,
		authorityPub: authorityPub,
		scope:        scope,
		leeway:       60 * time.Second,
		now:          time.Now,
		log:          log.With().Str("component", "policy").Logger(),
	}
}

// Authorize enforces the mandate. Every failure returns an error (fail closed).
func (m *Mandate) Authorize(_ context.Context, req domain.GreetRequest) error {
	if len(req.Mandate) == 0 {
		return fmt.Errorf("mandate required")
	}
	payload, signer, err := crypto.VerifyCOSE1(req.Mandate)
	if err != nil {
		return fmt.Errorf("mandate signature invalid: %w", err)
	}
	if !signer.Equal(m.authorityPub) {
		return fmt.Errorf("mandate not signed by the trusted authority")
	}
	var claims domain.MandateClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return fmt.Errorf("mandate claims malformed: %w", err)
	}
	if claims.AuthorityAns != m.authorityAns {
		return fmt.Errorf("mandate authority %q is not the trusted authority %q", claims.AuthorityAns, m.authorityAns)
	}
	if claims.AudienceAns != m.selfAns {
		return fmt.Errorf("mandate audience %q is not this greeter %q", claims.AudienceAns, m.selfAns)
	}
	if claims.SubjectAns != req.CallerAns {
		return fmt.Errorf("mandate subject %q does not match caller %q", claims.SubjectAns, req.CallerAns)
	}
	if claims.Scope != m.scope {
		return fmt.Errorf("mandate scope %q is not %q", claims.Scope, m.scope)
	}
	now := m.now()
	nb, err := time.Parse(time.RFC3339, claims.NotBefore)
	if err != nil {
		return fmt.Errorf("mandate notBefore invalid: %w", err)
	}
	na, err := time.Parse(time.RFC3339, claims.NotAfter)
	if err != nil {
		return fmt.Errorf("mandate notAfter invalid: %w", err)
	}
	if now.Before(nb.Add(-m.leeway)) {
		return fmt.Errorf("mandate not yet valid")
	}
	if now.After(na.Add(m.leeway)) {
		return fmt.Errorf("mandate expired")
	}

	m.log.Info().Str("mandateId", claims.MandateID).Str("callerAns", req.CallerAns).Msg("mandate accepted")
	return nil
}

var _ domain.GreetPolicy = (*Mandate)(nil)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/policy/ -v`
Expected: PASS (all mandate cases plus the existing `Open` tests).

- [ ] **Step 5: Check coverage**

Run: `go test ./internal/policy/ -cover`
Expected: ≥90% (the guard's branches are all exercised). If below, add the missing negative case; the malformed-`NotAfter` branch is covered by combining a valid `NotBefore` with a non-RFC3339 `NotAfter` — add such a case only if coverage requires it.

- [ ] **Step 6: Commit**

```bash
git add internal/policy/mandate.go internal/policy/mandate_test.go
git commit -m "feat(policy): mandate guard pinning the trusted authority key"
```

---

## Task 5: gate + branch verification

**Files:** none (verification only).

- [ ] **Step 1: Format, vet, build, test the whole repo**

Run:
```bash
gofmt -l .           # expect no output
go vet ./...         # expect clean
go build ./...       # expect exit 0
go test ./...        # expect all packages pass
```

- [ ] **Step 2: Confirm module + hygiene**

Run:
```bash
go mod tidy && git diff --exit-code go.mod go.sum   # expect no changes
git log master..HEAD --format='%b' | grep -i "co-authored-by" && echo FOUND || echo NONE  # expect NONE
git status --porcelain   # expect empty (data/ and bin/ gitignored)
```

- [ ] **Step 3: (No demo in P3b-1.)** The end-to-end mandate greet demo lands in P3b-2. This phase is proven by the unit tests: the guard rejects a forged-authority mandate and enforces audience/subject/scope/time, and the transport carries a mandate to the policy and fails closed on bad encoding.

---

## Self-review

**Spec coverage (P3b-1 scope):**
- Carry a mandate on the request → Task 1 (`GreetRequest.Mandate`). ✓
- Advertise the requirement on the Agent Card → Task 2 (`capabilities.extensions` + `ExtMandateURI`). ✓
- Transport the mandate client→server → Task 3 (`X-ANS-Mandate` header, `WithMandate`, server extract, fail-closed on bad encoding). ✓
- Enforce it with authority-key pinning → Task 4 (`policy.Mandate`), the carried-forward P3a requirement: forged-authority mandate rejected, plus audience/subject/scope/time checks. ✓
- Deferred correctly (absent): authority-pubkey client, mandate-aware initiator, `cmd`/`meshctl` wiring, end-to-end integration + demo (all P3b-2); DPoP mandate→caller-key binding (P4). Noted in Scope.

**Placeholder scan:** none — every step has concrete code or an exact command with expected output.

**Type consistency check:**
- `domain.GreetRequest.Mandate []byte` — added Task 1; populated by `a2a.HandleMessageSend` (Task 3) and read by `policy.Mandate.Authorize` (Task 4) and the `capturePolicy` test (Task 3). ✓
- `a2a.Card.Capabilities *Capabilities`, `a2a.Capabilities{Extensions []Extension}`, `a2a.Extension{URI,Description,Required,Params}`, `a2a.ExtMandateURI` — defined Task 2; used in Task 2 tests (and by P3b-2's initiator + `cmd/agent`). ✓
- `a2a.HeaderMandate` const, `a2a.SendOption`, `a2a.WithMandate([]byte) SendOption`, `SendGreet(..., opts ...SendOption)` — defined Task 3; used by Task 3 tests (and by P3b-2's initiator). Existing `SendGreet` callers unaffected (variadic). ✓
- `policy.NewMandate(selfAns, authorityAns string, authorityPub ed25519.PublicKey, scope string, log zerolog.Logger) *Mandate` implementing `domain.GreetPolicy` — defined Task 4; consumed by Task 4 tests (and wired in P3b-2's `cmd/agent`). ✓
- `crypto.VerifyCOSE1(data) ([]byte, ed25519.PublicKey, error)` and `crypto.SignCOSE1(priv, payload) ([]byte, error)` — existing (P2a); used by the guard (Task 4) and its tests. `signer.Equal(m.authorityPub)` uses `ed25519.PublicKey.Equal`. ✓
- The guard is pure (pinned key + injected `now`), so its tests need no network; the authority-pubkey fetch that supplies the pinned key is explicitly P3b-2. ✓
