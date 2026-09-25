# agent-mesh P1 — Simple Greet (A2A message/send, identity-signed) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An initiator discovers a peer by role, reads its open Agent Card, and sends an identity-signed greet over A2A `message/send`; the peer verifies the caller's Ed25519 signature and greets back.

**Architecture:** Builds on P0. Adds compact Ed25519 JWS sign/verify in `internal/crypto`; a `GreetPolicy` port in `internal/domain` with an `open` implementation in `internal/policy`; the A2A message layer (`message/send` server handler + client) in `internal/comms/a2a`; a requirements resolver in `internal/comms/resolver`; and a greet initiator in `internal/greet`. A new `cmd/meshctl greet` drives it. The caller's identity proof rides in an HTTP header (`X-ANS-Request-JWS`) — the same "proof in a header" shape ANS-6 uses — keeping the A2A JSON-RPC body standard.

**Tech Stack:** Go 1.23, stdlib `net/http` + `crypto/ed25519`, `github.com/rs/zerolog`. No new dependencies.

**Scope:** P1 only. Transparency/SCITT (P2), mandate/OAuth2 (P3), nonce/DPoP (P4), and the UI (P5) are out of scope and planned separately. Replay/freshness hardening is deliberately deferred to P4 — P1 signs *who/to-whom/what* and binds the greet to its audience, nothing more. See `docs/superpowers/specs/2026-09-25-agent-mesh-design.md`.

**Baseline:** P0 is merged on `master`. Existing packages: `internal/domain` (AgentInfo, Discovery), `internal/crypto` (JWK, PublicJWK, Thumbprint, GenerateEd25519, LoadOrCreateEd25519), `internal/registry`, `internal/comms/discovery`, `internal/comms/a2a` (Card, CardHandler), `cmd/agent`, `cmd/registry`. Do all P1 work on a branch off `master` (e.g. `p1-simple-greet`).

---

## File structure (this plan)

```
internal/crypto/jws.go                      # NEW: SignJWS / VerifyJWS (compact EdDSA, jwk in header)
internal/crypto/jws_test.go                 # NEW
internal/domain/greet.go                    # NEW: GreetRequest, GreetPolicy port
internal/domain/identity.go                 # NEW: LocalANSName helper
internal/domain/identity_test.go            # NEW
internal/policy/open.go                      # NEW: Open policy (accept any verified caller)
internal/policy/open_test.go                 # NEW
internal/comms/a2a/message.go                # NEW: A2A message/send types + GreetService handler
internal/comms/a2a/message_test.go           # NEW
internal/comms/a2a/card.go                   # MODIFY: extract serveCard (dynamic url from host)
internal/comms/a2a/server.go                 # NEW: NewMux (card + /a2a routes)
internal/comms/a2a/server_test.go            # NEW
internal/comms/a2a/client.go                 # NEW: SendGreet client
internal/comms/a2a/client_test.go            # NEW
internal/comms/resolver/resolver.go          # NEW: FetchCard
internal/comms/resolver/resolver_test.go     # NEW
internal/greet/initiator.go                  # NEW: Initiate (discover -> resolve -> greet)
internal/greet/initiator_test.go             # NEW
cmd/agent/main.go                            # MODIFY: mount NewMux with Open policy + selfAns
cmd/meshctl/main.go                          # NEW: `greet` subcommand
internal/integration/p1_test.go              # NEW: end-to-end greet
scripts/demo/p1-greet.sh                     # NEW: runnable demo
```

Conventions (unchanged from P0): idiomatic hexagonal Go; injected `zerolog.Logger` tagged with `component`; no `fmt.Println`/`log` in library code (cmd/* may print to stdout for user output); `make check` green before every commit; **no AI `Co-Authored-By:` trailer** on commits.

---

## Task 1: Crypto — compact Ed25519 JWS (sign/verify)

**Files:**
- Create: `internal/crypto/jws.go`
- Test: `internal/crypto/jws_test.go`

- [ ] **Step 1: Write the failing test**

```go
package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

func TestSignVerifyJWSRoundTrip(t *testing.T) {
	priv, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"hello":"world"}`)

	compact, err := SignJWS(priv, payload)
	if err != nil {
		t.Fatal(err)
	}
	got, jwk, err := VerifyJWS(compact)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload = %s, want %s", got, payload)
	}
	if jwk != PublicJWK(priv.Public().(ed25519.PublicKey)) {
		t.Fatal("returned jwk does not match signer")
	}
}

func TestVerifyJWSRejectsTamperedPayload(t *testing.T) {
	priv, _ := GenerateEd25519()
	compact, _ := SignJWS(priv, []byte(`{"a":1}`))

	parts := strings.Split(compact, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"a":2}`))
	tampered := strings.Join(parts, ".")

	if _, _, err := VerifyJWS(tampered); err == nil {
		t.Fatal("expected verification failure on tampered payload")
	}
}

func TestVerifyJWSRejectsMalformed(t *testing.T) {
	if _, _, err := VerifyJWS("only.two"); err == nil {
		t.Fatal("expected error for malformed compact jws")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/crypto/ -run JWS -v`
Expected: FAIL — `undefined: SignJWS`.

- [ ] **Step 3: Write the implementation**

```go
package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type jwsHeader struct {
	Alg string `json:"alg"`
	JWK JWK    `json:"jwk"`
}

// SignJWS returns a compact JWS (EdDSA) over payload, embedding the signer's
// public JWK in the protected header so a verifier is self-contained.
func SignJWS(priv ed25519.PrivateKey, payload []byte) (string, error) {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return "", errors.New("jws: private key is not ed25519")
	}
	hb, err := json.Marshal(jwsHeader{Alg: "EdDSA", JWK: PublicJWK(pub)})
	if err != nil {
		return "", fmt.Errorf("jws: marshal header: %w", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	sig := ed25519.Sign(priv, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyJWS verifies a compact EdDSA JWS whose header carries the public JWK,
// returning the payload and the verifying key. Possession of the key is proven
// by the signature; binding that key to a registered identity is out of scope.
func VerifyJWS(compact string) ([]byte, JWK, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, JWK{}, errors.New("jws: expected 3 parts")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, JWK{}, fmt.Errorf("jws: decode header: %w", err)
	}
	var hdr jwsHeader
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, JWK{}, fmt.Errorf("jws: parse header: %w", err)
	}
	if hdr.Alg != "EdDSA" {
		return nil, JWK{}, fmt.Errorf("jws: unsupported alg %q", hdr.Alg)
	}
	if hdr.JWK.Kty != "OKP" || hdr.JWK.Crv != "Ed25519" {
		return nil, JWK{}, errors.New("jws: header jwk is not an Ed25519 OKP key")
	}
	pub, err := base64.RawURLEncoding.DecodeString(hdr.JWK.X)
	if err != nil {
		return nil, JWK{}, fmt.Errorf("jws: decode jwk x: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, JWK{}, fmt.Errorf("jws: bad public key size %d", len(pub))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, JWK{}, fmt.Errorf("jws: decode payload: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, JWK{}, fmt.Errorf("jws: decode signature: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte(parts[0]+"."+parts[1]), sig) {
		return nil, JWK{}, errors.New("jws: signature verification failed")
	}
	return payload, hdr.JWK, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/crypto/ -v`
Expected: PASS (new JWS tests plus the existing key tests).

- [ ] **Step 5: Commit**

```bash
git add internal/crypto/jws.go internal/crypto/jws_test.go
git commit -m "feat(crypto): compact Ed25519 JWS sign/verify with embedded jwk"
```

---

## Task 2: Domain — GreetPolicy port, GreetRequest, LocalANSName

**Files:**
- Create: `internal/domain/greet.go`
- Create: `internal/domain/identity.go`
- Test: `internal/domain/identity_test.go`

- [ ] **Step 1: Write `internal/domain/greet.go`**

```go
package domain

import "context"

// GreetRequest is the verified content of an inbound greet.
type GreetRequest struct {
	CallerAns   string
	AudienceAns string
	Greeting    string
}

// GreetPolicy decides whether an agent accepts a greet. Implementations are the
// per-type behavior (open, mandate-gated, nonce-gated); the comms layer stays
// identical across them.
type GreetPolicy interface {
	Authorize(ctx context.Context, req GreetRequest) error
}
```

- [ ] **Step 2: Write the failing test for LocalANSName**

```go
package domain

import "testing"

func TestLocalANSName(t *testing.T) {
	got := LocalANSName("greeter-open")
	want := "ans://v1.0.0.greeter-open.mesh.local"
	if got != want {
		t.Fatalf("LocalANSName = %q, want %q", got, want)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/domain/ -v`
Expected: FAIL — `undefined: LocalANSName`.

- [ ] **Step 4: Write `internal/domain/identity.go`**

```go
package domain

// LocalANSName returns the local-development ANS name for an agent instance.
// Online ANS registration (real names, DNS, certs) is deferred; this gives
// agents a stable, verifiable name to sign as during local development.
func LocalANSName(name string) string {
	return "ans://v1.0.0." + name + ".mesh.local"
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/domain/ -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/domain/greet.go internal/domain/identity.go internal/domain/identity_test.go
git commit -m "feat(domain): GreetPolicy port, GreetRequest, LocalANSName"
```

---

## Task 3: Policy — Open

**Files:**
- Create: `internal/policy/open.go`
- Test: `internal/policy/open_test.go`

- [ ] **Step 1: Write the failing test**

```go
package policy

import (
	"context"
	"testing"

	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

func TestOpenAuthorizeAcceptsAnyCaller(t *testing.T) {
	var p domain.GreetPolicy = Open{}
	err := p.Authorize(context.Background(), domain.GreetRequest{
		CallerAns:   "ans://v1.0.0.visitor.mesh.local",
		AudienceAns: "ans://v1.0.0.greeter-open.mesh.local",
		Greeting:    "hello",
	})
	if err != nil {
		t.Fatalf("Open.Authorize returned error: %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/ -v`
Expected: FAIL — `undefined: Open`.

- [ ] **Step 3: Write the implementation**

```go
// Package policy holds the per-type GreetPolicy implementations.
package policy

import (
	"context"

	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

// Open accepts any greet from any identity-verified caller.
type Open struct{}

// Authorize always succeeds — the caller's identity was already verified by the
// transport layer; an open greeter imposes no further requirement.
func (Open) Authorize(_ context.Context, _ domain.GreetRequest) error {
	return nil
}

var _ domain.GreetPolicy = Open{}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/policy/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/policy/open.go internal/policy/open_test.go
git commit -m "feat(policy): Open greet policy"
```

---

## Task 4: A2A — message/send types + GreetService handler

**Files:**
- Create: `internal/comms/a2a/message.go`
- Test: `internal/comms/a2a/message_test.go`

- [ ] **Step 1: Write the failing test**

```go
package a2a

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
)

func signedGreet(t *testing.T, callerAns, audienceAns, greeting string) (body []byte, jws string) {
	t.Helper()
	priv, err := crypto.GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	pb, _ := json.Marshal(GreetPayload{CallerAns: callerAns, AudienceAns: audienceAns, Greeting: greeting})
	jws, err = crypto.SignJWS(priv, pb)
	if err != nil {
		t.Fatal(err)
	}
	rpc := rpcRequest{JSONRPC: "2.0", ID: 1, Method: MethodMessageSend,
		Params: messageParams{Message: Message{Role: "user", Parts: []Part{{Kind: "text", Text: greeting}}}}}
	body, _ = json.Marshal(rpc)
	return body, jws
}

func postGreet(t *testing.T, h http.Handler, body []byte, jws string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/a2a", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if jws != "" {
		req.Header.Set(HeaderRequestJWS, jws)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Result()
}

func TestGreetServiceAcceptsSignedGreet(t *testing.T) {
	self := domain.LocalANSName("greeter-open")
	svc := NewGreetService(self, policy.Open{}, zerolog.Nop())

	body, jws := signedGreet(t, domain.LocalANSName("visitor"), self, "hello there")
	resp := postGreet(t, http.HandlerFunc(svc.HandleMessageSend), body, jws)
	defer resp.Body.Close()

	var out rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Error != nil {
		t.Fatalf("unexpected rpc error: %+v", out.Error)
	}
	if out.Result == nil || len(out.Result.Parts) == 0 {
		t.Fatal("expected a reply message")
	}
	reply := out.Result.Parts[0].Text
	if !strings.Contains(reply, domain.LocalANSName("visitor")) || !strings.Contains(reply, self) {
		t.Fatalf("reply missing identities: %q", reply)
	}
}

func TestGreetServiceRejectsMissingJWS(t *testing.T) {
	self := domain.LocalANSName("greeter-open")
	svc := NewGreetService(self, policy.Open{}, zerolog.Nop())
	body, _ := signedGreet(t, domain.LocalANSName("visitor"), self, "hi")

	resp := postGreet(t, http.HandlerFunc(svc.HandleMessageSend), body, "")
	defer resp.Body.Close()
	var out rpcResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.Error == nil {
		t.Fatal("expected rpc error for missing identity proof")
	}
}

func TestGreetServiceRejectsAudienceMismatch(t *testing.T) {
	self := domain.LocalANSName("greeter-open")
	svc := NewGreetService(self, policy.Open{}, zerolog.Nop())
	// audience is someone else
	body, jws := signedGreet(t, domain.LocalANSName("visitor"), domain.LocalANSName("other"), "hi")

	resp := postGreet(t, http.HandlerFunc(svc.HandleMessageSend), body, jws)
	defer resp.Body.Close()
	var out rpcResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.Error == nil {
		t.Fatal("expected rpc error for audience mismatch")
	}
}

func TestGreetServiceRejectsWrongMethod(t *testing.T) {
	self := domain.LocalANSName("greeter-open")
	svc := NewGreetService(self, policy.Open{}, zerolog.Nop())
	rpc := rpcRequest{JSONRPC: "2.0", ID: 7, Method: "message/stream"}
	body, _ := json.Marshal(rpc)

	resp := postGreet(t, http.HandlerFunc(svc.HandleMessageSend), body, "")
	defer resp.Body.Close()
	var out rpcResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.Error == nil {
		t.Fatal("expected rpc error for wrong method")
	}
}

var _ = context.Background // context used indirectly via handler
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/comms/a2a/ -run GreetService -v`
Expected: FAIL — `undefined: GreetPayload` / `undefined: NewGreetService`.

- [ ] **Step 3: Write the implementation**

```go
package a2a

import (
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

const (
	// HeaderRequestJWS carries the caller's compact identity JWS ("who is asking").
	HeaderRequestJWS = "X-ANS-Request-JWS"
	// MethodMessageSend is the A2A JSON-RPC method for sending a message.
	MethodMessageSend = "message/send"
)

// GreetPayload is the signed body of a greet: who, to whom, and what.
type GreetPayload struct {
	CallerAns   string `json:"callerAns"`
	AudienceAns string `json:"audienceAns"`
	Greeting    string `json:"greeting"`
}

// Part is one A2A message part.
type Part struct {
	Kind string `json:"kind"`
	Text string `json:"text"`
}

// Message is an A2A message.
type Message struct {
	Role  string `json:"role"`
	Parts []Part `json:"parts"`
}

type messageParams struct {
	Message Message `json:"message"`
}

type rpcRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      int           `json:"id"`
	Method  string        `json:"method"`
	Params  messageParams `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      int       `json:"id"`
	Result  *Message  `json:"result,omitempty"`
	Error   *rpcError `json:"error,omitempty"`
}

// GreetService handles inbound A2A greets: verify caller identity, enforce the
// agent's GreetPolicy, and reply.
type GreetService struct {
	selfAns string
	policy  domain.GreetPolicy
	log     zerolog.Logger
}

// NewGreetService builds a greet handler for an agent whose ANS name is selfAns.
func NewGreetService(selfAns string, p domain.GreetPolicy, log zerolog.Logger) *GreetService {
	return &GreetService{selfAns: selfAns, policy: p, log: log.With().Str("component", "a2a").Logger()}
}

// HandleMessageSend implements POST /a2a (A2A message/send) for greets.
func (g *GreetService) HandleMessageSend(w http.ResponseWriter, r *http.Request) {
	var req rpcRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		g.writeError(w, 0, -32700, "parse error")
		return
	}
	if req.Method != MethodMessageSend {
		g.writeError(w, req.ID, -32601, "method not found")
		return
	}

	jws := r.Header.Get(HeaderRequestJWS)
	if jws == "" {
		g.log.Warn().Msg("greet: missing identity proof")
		g.writeError(w, req.ID, -32000, "missing identity proof")
		return
	}
	payload, _, err := crypto.VerifyJWS(jws)
	if err != nil {
		g.log.Warn().Err(err).Msg("greet: identity proof invalid")
		g.writeError(w, req.ID, -32001, "invalid identity proof")
		return
	}
	var gp GreetPayload
	if err := json.Unmarshal(payload, &gp); err != nil {
		g.writeError(w, req.ID, -32602, "invalid greet payload")
		return
	}
	if gp.AudienceAns != g.selfAns {
		g.log.Warn().Str("audienceAns", gp.AudienceAns).Str("selfAns", g.selfAns).Msg("greet: audience mismatch")
		g.writeError(w, req.ID, -32002, "audience mismatch")
		return
	}

	if err := g.policy.Authorize(r.Context(), domain.GreetRequest{
		CallerAns:   gp.CallerAns,
		AudienceAns: gp.AudienceAns,
		Greeting:    gp.Greeting,
	}); err != nil {
		g.log.Warn().Err(err).Str("callerAns", gp.CallerAns).Msg("greet: policy rejected")
		g.writeError(w, req.ID, -32003, "greet not authorized: "+err.Error())
		return
	}

	g.log.Info().Str("callerAns", gp.CallerAns).Str("greeting", gp.Greeting).Msg("greet accepted")
	g.writeResult(w, req.ID, &Message{
		Role:  "agent",
		Parts: []Part{{Kind: "text", Text: "hi " + gp.CallerAns + ", this is " + g.selfAns}},
	})
}

func (g *GreetService) writeResult(w http.ResponseWriter, id int, msg *Message) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(rpcResponse{JSONRPC: "2.0", ID: id, Result: msg}); err != nil {
		g.log.Error().Err(err).Msg("greet: encode result")
	}
}

// writeError emits a JSON-RPC error object (HTTP 200 per JSON-RPC convention).
func (g *GreetService) writeError(w http.ResponseWriter, id, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: message}}); err != nil {
		g.log.Error().Err(err).Msg("greet: encode error")
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/comms/a2a/ -v`
Expected: PASS (new GreetService tests plus existing card tests).

- [ ] **Step 5: Commit**

```bash
git add internal/comms/a2a/message.go internal/comms/a2a/message_test.go
git commit -m "feat(a2a): message/send greet handler with identity verification"
```

---

## Task 5: A2A — dynamic-URL card + NewMux

**Files:**
- Modify: `internal/comms/a2a/card.go`
- Create: `internal/comms/a2a/server.go`
- Test: `internal/comms/a2a/server_test.go`

- [ ] **Step 1: Write the failing test**

```go
package a2a

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
)

func TestNewMuxServesCardWithDynamicURLAndA2A(t *testing.T) {
	self := domain.LocalANSName("greeter-open")
	svc := NewGreetService(self, policy.Open{}, zerolog.Nop())
	card := Card{Name: "greeter-open", Version: "0.1.0", Security: []map[string][]string{}}

	ts := httptest.NewServer(NewMux(card, svc, zerolog.Nop()))
	defer ts.Close()

	// Card is served and its url points at this host's /a2a (not a baked value).
	resp, err := http.Get(ts.URL + "/.well-known/agent-card.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got Card
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.URL != ts.URL+"/a2a" {
		t.Fatalf("card url = %q, want %q", got.URL, ts.URL+"/a2a")
	}

	// The /a2a route exists (a bare GET is the wrong method -> 405, not 404).
	resp2, err := http.Get(ts.URL + "/a2a")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode == http.StatusNotFound {
		t.Fatal("/a2a route not registered")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/comms/a2a/ -run NewMux -v`
Expected: FAIL — `undefined: NewMux`.

- [ ] **Step 3: Modify `internal/comms/a2a/card.go`** — replace its entire contents with:

```go
// Package a2a serves and reads A2A Agent Cards and handles A2A messages.
package a2a

import (
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog"
)

// Card is a minimal A2A Agent Card. Security is an OpenAPI-style list of scheme
// requirement maps; an empty slice means "open" (no auth). URL is filled in
// dynamically at serve time from the request host.
type Card struct {
	Name        string                `json:"name"`
	Description string                `json:"description,omitempty"`
	URL         string                `json:"url"`
	Version     string                `json:"version"`
	Security    []map[string][]string `json:"security"`
}

// serveCard returns a handler that serves card, setting url to this host's /a2a
// endpoint so the value is correct regardless of the bound port.
func serveCard(card Card, log zerolog.Logger) http.HandlerFunc {
	l := log.With().Str("component", "a2a").Logger()
	if card.Security == nil {
		card.Security = []map[string][]string{}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		c := card
		c.URL = "http://" + r.Host + "/a2a"
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(c); err != nil {
			l.Error().Err(err).Msg("encode agent card")
			return
		}
		l.Debug().Str("name", c.Name).Msg("served agent card")
	}
}

// CardHandler serves only the Agent Card at /.well-known/agent-card.json.
func CardHandler(card Card, log zerolog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/agent-card.json", serveCard(card, log))
	return mux
}
```

- [ ] **Step 4: Create `internal/comms/a2a/server.go`**

```go
package a2a

import (
	"net/http"

	"github.com/rs/zerolog"
)

// NewMux serves both the Agent Card and the A2A message/send greet endpoint for
// one agent.
func NewMux(card Card, greet *GreetService, log zerolog.Logger) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/agent-card.json", serveCard(card, log))
	mux.HandleFunc("POST /a2a", greet.HandleMessageSend)
	return mux
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/comms/a2a/ -v`
Expected: PASS (new NewMux test + all existing card/message tests; the P0 `card_test.go` still passes because it never asserts `URL`).

- [ ] **Step 6: Commit**

```bash
git add internal/comms/a2a/card.go internal/comms/a2a/server.go internal/comms/a2a/server_test.go
git commit -m "feat(a2a): dynamic-URL card serving and combined NewMux"
```

---

## Task 6: A2A — greet client

**Files:**
- Create: `internal/comms/a2a/client.go`
- Test: `internal/comms/a2a/client_test.go`

- [ ] **Step 1: Write the failing test**

```go
package a2a

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
)

func TestClientSendGreetRoundTrip(t *testing.T) {
	self := domain.LocalANSName("greeter-open")
	svc := NewGreetService(self, policy.Open{}, zerolog.Nop())
	ts := httptest.NewServer(NewMux(Card{Name: "greeter-open", Version: "0.1.0"}, svc, zerolog.Nop()))
	defer ts.Close()

	priv, _ := crypto.GenerateEd25519()
	reply, err := NewClient().SendGreet(context.Background(), ts.URL+"/a2a", priv, GreetPayload{
		CallerAns:   domain.LocalANSName("visitor"),
		AudienceAns: self,
		Greeting:    "hello there",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reply, self) {
		t.Fatalf("reply = %q, want it to contain %q", reply, self)
	}
}

func TestClientSendGreetSurfacesRPCError(t *testing.T) {
	self := domain.LocalANSName("greeter-open")
	svc := NewGreetService(self, policy.Open{}, zerolog.Nop())
	ts := httptest.NewServer(NewMux(Card{Name: "greeter-open", Version: "0.1.0"}, svc, zerolog.Nop()))
	defer ts.Close()

	priv, _ := crypto.GenerateEd25519()
	// Wrong audience -> handler returns a JSON-RPC error -> client must error.
	_, err := NewClient().SendGreet(context.Background(), ts.URL+"/a2a", priv, GreetPayload{
		CallerAns:   domain.LocalANSName("visitor"),
		AudienceAns: domain.LocalANSName("someone-else"),
		Greeting:    "hi",
	})
	if err == nil {
		t.Fatal("expected an error when the server rejects the greet")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/comms/a2a/ -run Client -v`
Expected: FAIL — `undefined: NewClient`.

- [ ] **Step 3: Write the implementation**

```go
package a2a

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
)

// Client sends A2A greets to peer agents.
type Client struct {
	http *http.Client
}

// NewClient returns an A2A client with a bounded timeout.
func NewClient() *Client {
	return &Client{http: &http.Client{Timeout: 5 * time.Second}}
}

// SendGreet signs payload with priv, sends an A2A message/send to endpoint, and
// returns the peer's reply text.
func (c *Client) SendGreet(ctx context.Context, endpoint string, priv ed25519.PrivateKey, payload GreetPayload) (string, error) {
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal greet payload: %w", err)
	}
	jws, err := crypto.SignJWS(priv, pb)
	if err != nil {
		return "", fmt.Errorf("sign greet: %w", err)
	}

	body, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  MethodMessageSend,
		Params:  messageParams{Message: Message{Role: "user", Parts: []Part{{Kind: "text", Text: payload.Greeting}}}},
	})
	if err != nil {
		return "", fmt.Errorf("marshal rpc request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderRequestJWS, jws)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("send greet: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("greet: unexpected status %d", resp.StatusCode)
	}

	var out rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	if out.Error != nil {
		return "", fmt.Errorf("greet rejected: %s (code %d)", out.Error.Message, out.Error.Code)
	}
	if out.Result == nil || len(out.Result.Parts) == 0 {
		return "", fmt.Errorf("greet: empty reply")
	}
	return out.Result.Parts[0].Text, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/comms/a2a/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/comms/a2a/client.go internal/comms/a2a/client_test.go
git commit -m "feat(a2a): greet client (sign + message/send + parse reply)"
```

---

## Task 7: Resolver — fetch a peer's card

**Files:**
- Create: `internal/comms/resolver/resolver.go`
- Test: `internal/comms/resolver/resolver_test.go`

- [ ] **Step 1: Write the failing test**

```go
package resolver

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
)

func TestFetchCardReturnsPeerCard(t *testing.T) {
	self := domain.LocalANSName("greeter-open")
	svc := a2a.NewGreetService(self, policy.Open{}, zerolog.Nop())
	ts := httptest.NewServer(a2a.NewMux(a2a.Card{Name: "greeter-open", Version: "0.1.0"}, svc, zerolog.Nop()))
	defer ts.Close()

	card, err := New().FetchCard(context.Background(), ts.URL+"/.well-known/agent-card.json")
	if err != nil {
		t.Fatal(err)
	}
	if card.Name != "greeter-open" {
		t.Fatalf("card.Name = %q", card.Name)
	}
	if len(card.Security) != 0 {
		t.Fatalf("expected open card, got security %+v", card.Security)
	}
}

func TestFetchCardErrorsOnNotFound(t *testing.T) {
	ts := httptest.NewServer(a2a.NewMux(a2a.Card{Name: "x", Version: "0.1.0"},
		a2a.NewGreetService("x", policy.Open{}, zerolog.Nop()), zerolog.Nop()))
	defer ts.Close()

	if _, err := New().FetchCard(context.Background(), ts.URL+"/nope"); err == nil {
		t.Fatal("expected error for missing card")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/comms/resolver/ -v`
Expected: FAIL — `undefined: New`.

- [ ] **Step 3: Write the implementation**

```go
// Package resolver reads a peer's Agent Card to learn how to call it.
package resolver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
)

// Resolver fetches and interprets peer Agent Cards.
type Resolver struct {
	http *http.Client
}

// New returns a resolver with a bounded HTTP timeout.
func New() *Resolver {
	return &Resolver{http: &http.Client{Timeout: 5 * time.Second}}
}

// FetchCard retrieves the Agent Card at cardURL.
func (r *Resolver) FetchCard(ctx context.Context, cardURL string) (a2a.Card, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cardURL, nil)
	if err != nil {
		return a2a.Card{}, fmt.Errorf("build card request: %w", err)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return a2a.Card{}, fmt.Errorf("fetch card: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return a2a.Card{}, fmt.Errorf("fetch card: unexpected status %d", resp.StatusCode)
	}
	var card a2a.Card
	if err := json.NewDecoder(resp.Body).Decode(&card); err != nil {
		return a2a.Card{}, fmt.Errorf("decode card: %w", err)
	}
	return card, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/comms/resolver/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/comms/resolver/resolver.go internal/comms/resolver/resolver_test.go
git commit -m "feat(resolver): fetch a peer's Agent Card"
```

---

## Task 8: Greet initiator

**Files:**
- Create: `internal/greet/initiator.go`
- Test: `internal/greet/initiator_test.go`

- [ ] **Step 1: Write the failing test**

```go
package greet

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/discovery"
	"github.com/an-ciobanu/agent-mesh/internal/comms/resolver"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
	"github.com/an-ciobanu/agent-mesh/internal/registry"
)

func TestInitiateGreetsDiscoveredOpenPeer(t *testing.T) {
	reg := httptest.NewServer(registry.New(zerolog.Nop()).Handler())
	defer reg.Close()

	const name = "greeter-open"
	self := domain.LocalANSName(name)
	svc := a2a.NewGreetService(self, policy.Open{}, zerolog.Nop())
	agent := httptest.NewServer(a2a.NewMux(a2a.Card{Name: name, Version: "0.1.0"}, svc, zerolog.Nop()))
	defer agent.Close()

	disco := discovery.New(reg.URL)
	ctx := context.Background()
	if err := disco.Register(ctx, domain.AgentInfo{
		Name: name, Role: "greeter", BaseURL: agent.URL,
		CardURL: agent.URL + "/.well-known/agent-card.json",
	}); err != nil {
		t.Fatal(err)
	}

	priv, _ := crypto.GenerateEd25519()
	caller := domain.LocalANSName("visitor")
	reply, peer, err := Initiate(ctx, disco, resolver.New(), a2a.NewClient(), priv, caller, "greeter", "hello there")
	if err != nil {
		t.Fatal(err)
	}
	if peer.Name != name {
		t.Fatalf("peer.Name = %q", peer.Name)
	}
	if !strings.Contains(reply, caller) || !strings.Contains(reply, self) {
		t.Fatalf("reply missing identities: %q", reply)
	}
}

func TestInitiateErrorsWhenNoPeer(t *testing.T) {
	reg := httptest.NewServer(registry.New(zerolog.Nop()).Handler())
	defer reg.Close()

	priv, _ := crypto.GenerateEd25519()
	_, _, err := Initiate(context.Background(), discovery.New(reg.URL), resolver.New(), a2a.NewClient(),
		priv, domain.LocalANSName("visitor"), "greeter", "hi")
	if err == nil {
		t.Fatal("expected error when no agent of the role exists")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/greet/ -v`
Expected: FAIL — `undefined: Initiate`.

- [ ] **Step 3: Write the implementation**

```go
// Package greet drives an initiator: discover a peer, resolve how to call it,
// and send an identity-signed greet.
package greet

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/resolver"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

// Initiate finds a peer of role toRole, verifies it is open (declares no
// security), and sends it an identity-signed greet, returning the reply and the
// peer it greeted.
func Initiate(
	ctx context.Context,
	disco domain.Discovery,
	res *resolver.Resolver,
	cli *a2a.Client,
	priv ed25519.PrivateKey,
	callerAns, toRole, greeting string,
) (string, domain.AgentInfo, error) {
	peers, err := disco.Search(ctx, toRole)
	if err != nil {
		return "", domain.AgentInfo{}, fmt.Errorf("discover role %q: %w", toRole, err)
	}
	if len(peers) == 0 {
		return "", domain.AgentInfo{}, fmt.Errorf("no agents found for role %q", toRole)
	}
	peer := peers[0]

	card, err := res.FetchCard(ctx, peer.CardURL)
	if err != nil {
		return "", peer, fmt.Errorf("resolve peer card: %w", err)
	}
	if len(card.Security) != 0 {
		return "", peer, fmt.Errorf("peer %q requires authentication not supported in P1", peer.Name)
	}

	reply, err := cli.SendGreet(ctx, card.URL, priv, a2a.GreetPayload{
		CallerAns:   callerAns,
		AudienceAns: domain.LocalANSName(peer.Name),
		Greeting:    greeting,
	})
	if err != nil {
		return "", peer, err
	}
	return reply, peer, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/greet/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/greet/initiator.go internal/greet/initiator_test.go
git commit -m "feat(greet): initiator — discover, resolve, identity-signed greet"
```

---

## Task 9: Wire the greet handler into the agent binary

**Files:**
- Modify: `cmd/agent/main.go`

- [ ] **Step 1: Replace the server-construction section of `cmd/agent/main.go`**

Find the block that builds `card`, `srv`, and starts the server (from `baseURL := "http://" + *addr` through the `go func() { ... }()` server goroutine). Replace that block with:

```go
	baseURL := "http://" + *addr
	selfAns := domain.LocalANSName(*name)
	card := a2a.Card{
		Name:     *name,
		URL:      baseURL + "/a2a",
		Version:  "0.1.0",
		Security: []map[string][]string{}, // open (P1)
	}
	greetSvc := a2a.NewGreetService(selfAns, policy.Open{}, log)
	srv := &http.Server{Addr: *addr, Handler: a2a.NewMux(card, greetSvc, log)}
	go func() {
		log.Info().Str("addr", *addr).Str("ans", selfAns).Msg("agent listening")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("agent server exited")
		}
	}()
```

- [ ] **Step 2: Add the policy import**

In the import block of `cmd/agent/main.go`, add:

```go
	"github.com/an-ciobanu/agent-mesh/internal/policy"
```

(The file already imports `internal/comms/a2a`, `internal/comms/discovery`, `internal/crypto`, and `internal/domain`.)

- [ ] **Step 3: Build and run the existing suite**

Run: `go build ./cmd/agent/ && go test ./... -count=1`
Expected: builds; all tests PASS.

- [ ] **Step 4: Manual smoke — agent serves /a2a and card**

Run:
```bash
go run ./cmd/registry --addr 127.0.0.1:18090 &
REG=$!
sleep 0.5
go run ./cmd/agent --name greeter-open --role greeter --addr 127.0.0.1:18101 --registry http://127.0.0.1:18090 &
AG=$!
sleep 1
curl -s http://127.0.0.1:18101/.well-known/agent-card.json
echo
kill $AG $REG
```
Expected: card JSON with `"url":"http://127.0.0.1:18101/a2a"` and `"security":[]`.

- [ ] **Step 5: Commit**

```bash
git add cmd/agent/main.go
git commit -m "feat(agent): serve A2A message/send with Open greet policy"
```

---

## Task 10: `meshctl greet` command

**Files:**
- Create: `cmd/meshctl/main.go`

- [ ] **Step 1: Write the binary**

```go
// Command meshctl drives the mesh from the terminal. P1 subcommand: greet.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/discovery"
	"github.com/an-ciobanu/agent-mesh/internal/comms/resolver"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/greet"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: meshctl <command> [flags]")
		fmt.Fprintln(os.Stderr, "commands: greet")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "greet":
		runGreet(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		os.Exit(2)
	}
}

func runGreet(args []string) {
	fs := flag.NewFlagSet("greet", flag.ExitOnError)
	registryURL := fs.String("registry", "http://127.0.0.1:18090", "registry base URL")
	from := fs.String("from", "visitor", "initiator name (identity)")
	toRole := fs.String("to-role", "greeter", "role of the agent to greet")
	text := fs.String("text", "hello", "greeting text")
	keyDir := fs.String("keys", "", "identity key directory (default: ./data/<from>)")
	_ = fs.Parse(args)

	log := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()

	dir := *keyDir
	if dir == "" {
		dir = filepath.Join("data", *from)
	}
	priv, err := crypto.LoadOrCreateEd25519(filepath.Join(dir, "id_ed25519.seed"))
	if err != nil {
		log.Fatal().Err(err).Msg("load identity key")
	}
	callerAns := domain.LocalANSName(*from)

	reply, peer, err := greet.Initiate(
		context.Background(),
		discovery.New(*registryURL),
		resolver.New(),
		a2a.NewClient(),
		priv, callerAns, *toRole, *text,
	)
	if err != nil {
		log.Fatal().Err(err).Msg("greet failed")
	}
	log.Info().Str("peer", peer.Name).Str("callerAns", callerAns).Msg("greet sent")
	fmt.Printf("greeted %s (%s)\nreply: %s\n", peer.Name, peer.BaseURL, reply)
}
```

- [ ] **Step 2: Build**

Run: `make build`
Expected: `bin/agent`, `bin/registry`, `bin/meshctl` produced; exits 0.

- [ ] **Step 3: Commit**

```bash
git add cmd/meshctl/main.go
git commit -m "feat(meshctl): greet subcommand (initiator)"
```

---

## Task 11: End-to-end integration test

**Files:**
- Create: `internal/integration/p1_test.go`

- [ ] **Step 1: Write the test**

```go
package integration

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/discovery"
	"github.com/an-ciobanu/agent-mesh/internal/comms/resolver"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/greet"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
	"github.com/an-ciobanu/agent-mesh/internal/registry"
)

func TestP1_SimpleGreetEndToEnd(t *testing.T) {
	reg := httptest.NewServer(registry.New(zerolog.Nop()).Handler())
	defer reg.Close()

	const name = "greeter-open"
	self := domain.LocalANSName(name)
	svc := a2a.NewGreetService(self, policy.Open{}, zerolog.Nop())
	agent := httptest.NewServer(a2a.NewMux(
		a2a.Card{Name: name, Version: "0.1.0", Security: []map[string][]string{}}, svc, zerolog.Nop()))
	defer agent.Close()

	disco := discovery.New(reg.URL)
	ctx := context.Background()
	if err := disco.Register(ctx, domain.AgentInfo{
		Name: name, Role: "greeter", BaseURL: agent.URL,
		CardURL: agent.URL + "/.well-known/agent-card.json",
	}); err != nil {
		t.Fatal(err)
	}

	priv, _ := crypto.GenerateEd25519()
	caller := domain.LocalANSName("visitor")
	reply, peer, err := greet.Initiate(ctx, disco, resolver.New(), a2a.NewClient(), priv, caller, "greeter", "hello there")
	if err != nil {
		t.Fatalf("greet: %v", err)
	}
	if peer.Name != name {
		t.Fatalf("peer = %q, want %q", peer.Name, name)
	}
	if !strings.Contains(reply, caller) || !strings.Contains(reply, self) {
		t.Fatalf("reply %q must contain caller %q and self %q", reply, caller, self)
	}
}
```

- [ ] **Step 2: Run test**

Run: `go test ./internal/integration/ -run P1 -v`
Expected: PASS.

- [ ] **Step 3: Full suite + check**

Run: `make check`
Expected: gofmt/vet clean, all tests PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/integration/p1_test.go
git commit -m "test(integration): P1 simple greet end-to-end"
```

---

## Task 12: Demo script

**Files:**
- Create: `scripts/demo/p1-greet.sh`

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# P1 demo: start the registry, start an open greeter agent, then use meshctl to
# discover it by role and send an identity-signed greet. Proves a signed greet
# flows end-to-end with no agent hardcoding another's address or keys.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

make build

REG_ADDR="127.0.0.1:18090"
pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

./bin/registry --addr "$REG_ADDR" & pids+=("$!")
sleep 0.5

./bin/agent --name greeter-open --role greeter --addr 127.0.0.1:18101 --registry "http://$REG_ADDR" & pids+=("$!")
sleep 1

echo "== meshctl greet (visitor -> role=greeter) =="
OUT=$(./bin/meshctl greet --registry "http://$REG_ADDR" --from visitor --to-role greeter --text "hello there")
echo "$OUT"

echo "$OUT" | grep -q "this is ans://v1.0.0.greeter-open.mesh.local"
echo "P1 demo OK"
```

- [ ] **Step 2: Make executable and run**

Run:
```bash
chmod +x scripts/demo/p1-greet.sh
./scripts/demo/p1-greet.sh
```
Expected: prints `greeted greeter-open ...` and `reply: hi ans://v1.0.0.visitor.mesh.local, this is ans://v1.0.0.greeter-open.mesh.local`, then `P1 demo OK`.

- [ ] **Step 3: Commit**

```bash
git add scripts/demo/p1-greet.sh
git commit -m "chore(demo): P1 identity-signed greet end-to-end script"
```

---

## Self-review

**Spec coverage (P1 scope):**
- Simple greet over A2A `message/send` → Tasks 4, 6, 9. ✓
- Identity-signed (Ed25519 "who is asking") → Tasks 1 (JWS), 4 (verify), 6 (sign). ✓
- Resolver reads peer card, security `[]` (open) → Tasks 5 (dynamic card), 7 (fetch), 8 (open check). ✓
- `GreetPolicy` port + `open` policy (seam for P3/P4) → Tasks 2, 3, 4. ✓
- Registry-based discovery reused (no hardcoding) → Task 8 (search) on P0's discovery. ✓
- Provable: integration test + demo → Tasks 11, 12. ✓
- Deferred correctly (absent): SCITT/transparency (P2), OAuth2 mandate (P3), DPoP/nonce/replay-freshness (P4), UI (P5). Response signing is also deferred (P1 responses are unsigned) — noted, YAGNI for the simple greet.

**Placeholder scan:** none — every step has concrete code or an exact command with expected output.

**Type consistency check:**
- `crypto.SignJWS(ed25519.PrivateKey, []byte) (string, error)` and `crypto.VerifyJWS(string) ([]byte, JWK, error)` — defined Task 1; used in a2a message (verify, Task 4), a2a client (sign, Task 6). ✓
- `domain.GreetRequest{CallerAns, AudienceAns, Greeting}` and `domain.GreetPolicy.Authorize(ctx, GreetRequest) error` — defined Task 2; implemented by `policy.Open` (Task 3); called in `GreetService` (Task 4). ✓
- `domain.LocalANSName(string) string` — defined Task 2; used in a2a tests, greet initiator (Task 8: `LocalANSName(peer.Name)`), cmd/agent (Task 9), cmd/meshctl (Task 10). Audience set by initiator == `selfAns` set by agent, both `LocalANSName(name)` — they match. ✓
- `a2a.GreetPayload{CallerAns, AudienceAns, Greeting}` — defined Task 4; used by client (Task 6), initiator (Task 8). ✓
- `a2a.NewGreetService(selfAns string, domain.GreetPolicy, zerolog.Logger) *GreetService` + `HandleMessageSend` — defined Task 4; used in Tasks 5, 6, 7, 8, 9, 11. ✓
- `a2a.NewMux(Card, *GreetService, zerolog.Logger) *http.ServeMux` — defined Task 5; used in Tasks 6, 7, 8, 9, 11. ✓
- `a2a.serveCard` dynamic URL (`http://<host>/a2a`) — Task 5; the resolver/initiator rely on `card.URL` being the correct `/a2a` endpoint (Tasks 7, 8), which the dynamic URL guarantees regardless of port. ✓
- `a2a.NewClient() *Client` + `SendGreet(ctx, endpoint, priv, GreetPayload) (string, error)` — defined Task 6; used in Tasks 8, 10, 11. ✓
- `resolver.New() *Resolver` + `FetchCard(ctx, cardURL) (a2a.Card, error)` — defined Task 7; used in Tasks 8, 10, 11. ✓
- `greet.Initiate(ctx, domain.Discovery, *resolver.Resolver, *a2a.Client, ed25519.PrivateKey, callerAns, toRole, greeting) (string, domain.AgentInfo, error)` — defined Task 8; used in Tasks 10, 11. ✓
- `HeaderRequestJWS`, `MethodMessageSend` constants — defined Task 4; used in client (Task 6) and tests. ✓
- cmd/agent import addition of `internal/policy` (Task 9) — `policy.Open{}` matches Task 3. ✓
