# agent-mesh P2b — Sealed Greets + Auditor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When a greeter accepts a greet it seals a COSE_Sign1 "greet.completed" statement into the transparency log and returns the evidence (statement + receipt) in its reply; an independent auditor verifies that evidence (statement signature + TL-signed receipt + inclusion proof) and emits a signed verdict.

**Architecture:** Builds on P0/P1/P2a. `a2a.GreetService` gains optional sealing via a functional option (`WithSealing(priv, tp)`); the A2A response carries an optional `EvidenceBundle`. A new `internal/audit` package verifies a bundle against the TL public key and signs a `domain.Verdict`. `greet.Initiate` and `a2a.Client.SendGreet` propagate the evidence to the caller; `meshctl greet --audit` runs the auditor. cmd/agent gets a `--transparency` flag.

**Tech Stack:** Go 1.23, existing deps (`veraison/go-cose`, `rs/zerolog`); no new dependencies.

**Scope:** P2b only. The auditor is exposed here as a library + `meshctl greet --audit` (its MCP-tool exposure is deferred to P3, when the MCP layer is built for the authority). Mandate/OAuth2 (P3), nonce/DPoP (P4), UI (P5) are later. See the design spec and the P2a plan.

**Baseline:** P0+P1+P2a merged on `master`. Existing relevant symbols: `crypto.SignCOSE1/VerifyCOSE1`, `crypto.LeafHash/VerifyInclusion`, `crypto.Thumbprint/PublicJWK`, `crypto.SignJWS/VerifyJWS`; `domain.{GreetRequest,GreetPolicy,Receipt,Transparency,EvidenceBundle,LocalANSName}`; `a2a.{Card,NewMux,NewGreetService,GreetService,HandleMessageSend,Client,NewClient,SendGreet,GreetPayload,Message,Part,HeaderRequestJWS,MethodMessageSend}`; `comms/transparency.{New,Seal,FetchPubKey}`; `greet.Initiate`; `policy.Open`; `cmd/{agent,meshctl,transparency,registry}`. Do all work on a branch off `master` (e.g. `p2b-auditor`).

---

## File structure (this plan)

```
internal/domain/audit.go                     # NEW: Verdict type
internal/audit/auditor.go                     # NEW: Auditor.Verify -> Verdict + signed COSE
internal/audit/auditor_test.go                # NEW
internal/comms/a2a/message.go                 # MODIFY: WithSealing option, seal on accept, Evidence in response
internal/comms/a2a/message_test.go            # MODIFY: add a sealing test (existing tests unchanged)
internal/comms/a2a/client.go                  # MODIFY: SendGreet returns evidence
internal/comms/a2a/client_test.go             # MODIFY: update SendGreet calls; assert evidence when sealing
internal/greet/initiator.go                   # MODIFY: Initiate returns evidence
internal/greet/initiator_test.go              # MODIFY: update Initiate calls
internal/integration/p1_test.go               # MODIFY: update Initiate call to new signature
cmd/meshctl/main.go                           # MODIFY: greet gains --transparency + --audit; runs auditor
cmd/agent/main.go                             # MODIFY: --transparency flag; WithSealing wiring
internal/integration/p2b_test.go              # NEW: greet -> seal -> audit (valid); tamper -> invalid
scripts/demo/p2b-greet-audit.sh               # NEW: runnable demo
```

Conventions unchanged: hexagonal Go; injected `zerolog.Logger` tagged `component`; no `fmt.Println`/`log` in library code (cmd/* stdout is fine); `make check` green before every commit; **no AI `Co-Authored-By:` trailer**.

---

## Task 1: Domain — Verdict

**Files:**
- Create: `internal/domain/audit.go`

- [ ] **Step 1: Write the file**

```go
package domain

// Verdict is an auditor's judgment on an EvidenceBundle.
type Verdict struct {
	Verdict    string   `json:"verdict"` // "valid" or "invalid"
	Checks     []string `json:"checks"`
	AuditorAns string   `json:"auditorAns"`
}
```

- [ ] **Step 2: Verify it compiles**

Run: `go build ./internal/domain/`
Expected: exits 0.

- [ ] **Step 3: Commit**

```bash
git add internal/domain/audit.go
git commit -m "feat(domain): Verdict type"
```

---

## Task 2: Auditor

**Files:**
- Create: `internal/audit/auditor.go`
- Test: `internal/audit/auditor_test.go`

- [ ] **Step 1: Write the failing test**

```go
package audit

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	commstl "github.com/an-ciobanu/agent-mesh/internal/comms/transparency"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/tl"
)

// sealedBundle builds a real evidence bundle by signing a statement and sealing
// it against a live transparency service, returning the bundle and the TL key.
func sealedBundle(t *testing.T) (domain.EvidenceBundle, []byte, *httptest.Server) {
	t.Helper()
	tlPriv, _ := crypto.GenerateEd25519()
	ts := httptest.NewServer(tl.NewService(tlPriv, zerolog.Nop()).Handler())

	greeter, _ := crypto.GenerateEd25519()
	statement, err := crypto.SignCOSE1(greeter, []byte(`{"type":"greet.completed","greeting":"hi"}`))
	if err != nil {
		t.Fatal(err)
	}
	client := commstl.New(ts.URL)
	rec, err := client.Seal(context.Background(), statement)
	if err != nil {
		t.Fatal(err)
	}
	tlPub, err := client.FetchPubKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return domain.EvidenceBundle{Statement: statement, Receipt: rec}, tlPub, ts
}

func TestAuditorVerifiesValidBundle(t *testing.T) {
	bundle, tlPub, ts := sealedBundle(t)
	defer ts.Close()

	priv, _ := crypto.GenerateEd25519()
	a := New(domain.LocalANSName("auditor"), priv, zerolog.Nop())

	verdict, signed, err := a.Verify(context.Background(), bundle, tlPub)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Verdict != "valid" {
		t.Fatalf("verdict = %q, checks=%v", verdict.Verdict, verdict.Checks)
	}
	// The signed verdict is a COSE_Sign1 by the auditor key.
	_, signer, err := crypto.VerifyCOSE1(signed)
	if err != nil {
		t.Fatal(err)
	}
	if !signer.Equal(priv.Public()) {
		t.Fatal("signed verdict not signed by the auditor key")
	}
}

func TestAuditorRejectsTamperedStatement(t *testing.T) {
	bundle, tlPub, ts := sealedBundle(t)
	defer ts.Close()

	bundle.Statement = append([]byte(nil), bundle.Statement...)
	bundle.Statement[len(bundle.Statement)-5] ^= 0xff

	priv, _ := crypto.GenerateEd25519()
	verdict, _, err := New(domain.LocalANSName("auditor"), priv, zerolog.Nop()).Verify(context.Background(), bundle, tlPub)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Verdict != "invalid" {
		t.Fatalf("verdict = %q, want invalid", verdict.Verdict)
	}
}

func TestAuditorRejectsWrongTLKey(t *testing.T) {
	bundle, _, ts := sealedBundle(t)
	defer ts.Close()

	wrongPub, _ := crypto.GenerateEd25519()
	priv, _ := crypto.GenerateEd25519()
	verdict, _, err := New(domain.LocalANSName("auditor"), priv, zerolog.Nop()).
		Verify(context.Background(), bundle, wrongPub.Public().(interface{ ~[]byte })) // placeholder, see note
	_ = verdict
	_ = err
}
```

Note: replace the broken final test with this exact body (the receipt must be checked against a *different* key):

```go
func TestAuditorRejectsWrongTLKey(t *testing.T) {
	bundle, _, ts := sealedBundle(t)
	defer ts.Close()

	other, _ := crypto.GenerateEd25519()
	wrongPub := other.Public().(ed25519.PublicKey)

	priv, _ := crypto.GenerateEd25519()
	verdict, _, err := New(domain.LocalANSName("auditor"), priv, zerolog.Nop()).
		Verify(context.Background(), bundle, wrongPub)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Verdict != "invalid" {
		t.Fatalf("verdict = %q, want invalid (receipt not signed by given TL key)", verdict.Verdict)
	}
}
```

and add `"crypto/ed25519"` to the test imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/audit/ -v`
Expected: FAIL — `undefined: New`.

- [ ] **Step 3: Write the implementation**

```go
// Package audit independently verifies transparency evidence bundles.
package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

// Auditor verifies evidence bundles and signs its verdicts.
type Auditor struct {
	auditorAns string
	priv       ed25519.PrivateKey
	log        zerolog.Logger
}

// New returns an auditor identified by auditorAns that signs verdicts with priv.
func New(auditorAns string, priv ed25519.PrivateKey, log zerolog.Logger) *Auditor {
	return &Auditor{auditorAns: auditorAns, priv: priv, log: log.With().Str("component", "audit").Logger()}
}

type receiptClaims struct {
	EntryIndex int    `json:"entryIndex"`
	TreeSize   int    `json:"treeSize"`
	Root       []byte `json:"root"`
}

// Verify independently checks a bundle against the transparency log's public key
// and returns a verdict plus a COSE-signed copy of it. A verification failure is
// an "invalid" verdict, not a Go error; errors are reserved for internal faults
// (e.g. signing the verdict).
func (a *Auditor) Verify(_ context.Context, bundle domain.EvidenceBundle, tlPub ed25519.PublicKey) (domain.Verdict, []byte, error) {
	v := domain.Verdict{Verdict: "valid", AuditorAns: a.auditorAns}
	fail := func(reason string) (domain.Verdict, []byte, error) {
		v.Verdict = "invalid"
		v.Checks = append(v.Checks, "FAIL: "+reason)
		a.log.Warn().Str("reason", reason).Msg("audit failed")
		signed, err := a.sign(v)
		return v, signed, err
	}

	// 1. Statement issuer signature (self-asserted issuer key; thumbprint recorded).
	_, issuerPub, err := crypto.VerifyCOSE1(bundle.Statement)
	if err != nil {
		return fail("statement signature invalid: " + err.Error())
	}
	v.Checks = append(v.Checks, "OK: statement signed by "+crypto.Thumbprint(crypto.PublicJWK(issuerPub)))

	// 2. Receipt signed by the transparency log.
	claimsBytes, receiptSigner, err := crypto.VerifyCOSE1(bundle.Receipt.COSE)
	if err != nil {
		return fail("receipt signature invalid: " + err.Error())
	}
	if !receiptSigner.Equal(tlPub) {
		return fail("receipt not signed by the expected transparency-log key")
	}
	v.Checks = append(v.Checks, "OK: receipt signed by the transparency log")

	// 3. Receipt COSE claims match the receipt fields.
	var rc receiptClaims
	if err := json.Unmarshal(claimsBytes, &rc); err != nil {
		return fail("receipt claims unparseable: " + err.Error())
	}
	if rc.EntryIndex != bundle.Receipt.EntryIndex || rc.TreeSize != bundle.Receipt.TreeSize || !bytes.Equal(rc.Root, bundle.Receipt.Root) {
		return fail("receipt claims do not match receipt fields")
	}
	v.Checks = append(v.Checks, "OK: receipt claims consistent")

	// 4. Inclusion proof against the receipt root.
	leaf := crypto.LeafHash(bundle.Statement)
	if !crypto.VerifyInclusion(leaf, bundle.Receipt.EntryIndex, bundle.Receipt.TreeSize, bundle.Receipt.Proof, bundle.Receipt.Root) {
		return fail("inclusion proof does not verify")
	}
	v.Checks = append(v.Checks, fmt.Sprintf("OK: included at entry %d of %d", bundle.Receipt.EntryIndex, bundle.Receipt.TreeSize))

	a.log.Info().Str("verdict", v.Verdict).Msg("audit complete")
	signed, err := a.sign(v)
	return v, signed, err
}

func (a *Auditor) sign(v domain.Verdict) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal verdict: %w", err)
	}
	signed, err := crypto.SignCOSE1(a.priv, b)
	if err != nil {
		return nil, fmt.Errorf("sign verdict: %w", err)
	}
	return signed, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/audit/ -v`
Expected: PASS (valid, tampered, wrong-TL-key).

- [ ] **Step 5: Commit**

```bash
git add internal/domain/audit.go internal/audit/auditor.go internal/audit/auditor_test.go
git commit -m "feat(audit): auditor verifies evidence bundle and signs a verdict"
```

(`internal/domain/audit.go` is included here if not already committed in Task 1; if Task 1 committed it, `git add` will simply no-op on it.)

---

## Task 3: A2A — seal on accept, carry evidence in the reply

**Files:**
- Modify: `internal/comms/a2a/message.go` (replace entire file)
- Modify: `internal/comms/a2a/client.go` (replace entire file)
- Modify: `internal/comms/a2a/message_test.go` (add one test; existing tests unchanged)
- Modify: `internal/comms/a2a/client_test.go` (update SendGreet calls; add an evidence test)

- [ ] **Step 1: Replace `internal/comms/a2a/message.go` with:**

```go
package a2a

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"time"

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
	JSONRPC  string                 `json:"jsonrpc"`
	ID       int                    `json:"id"`
	Result   *Message               `json:"result,omitempty"`
	Evidence *domain.EvidenceBundle `json:"evidence,omitempty"` // sealed greet.completed evidence (P2)
	Error    *rpcError              `json:"error,omitempty"`
}

// greetEvent is the canonical "greet.completed" statement payload that is
// COSE-signed and sealed into the transparency log.
type greetEvent struct {
	Type                string `json:"type"`
	CallerAns           string `json:"callerAns"`
	AudienceAns         string `json:"audienceAns"`
	Greeting            string `json:"greeting"`
	CallerKeyThumbprint string `json:"callerKeyThumbprint"`
	At                  string `json:"at"`
}

// GreetService handles inbound A2A greets: verify caller identity, enforce the
// agent's GreetPolicy, optionally seal the completed greet, and reply.
type GreetService struct {
	selfAns string
	policy  domain.GreetPolicy
	priv    ed25519.PrivateKey  // greeter identity key; signs sealed statements
	tp      domain.Transparency // nil => sealing disabled
	log     zerolog.Logger
}

// Option configures a GreetService.
type Option func(*GreetService)

// WithSealing enables transparency sealing: on each accepted greet the service
// signs a greet.completed statement with priv and seals it via tp.
func WithSealing(priv ed25519.PrivateKey, tp domain.Transparency) Option {
	return func(g *GreetService) {
		g.priv = priv
		g.tp = tp
	}
}

// NewGreetService builds a greet handler for an agent whose ANS name is selfAns.
func NewGreetService(selfAns string, p domain.GreetPolicy, log zerolog.Logger, opts ...Option) *GreetService {
	g := &GreetService{selfAns: selfAns, policy: p, log: log.With().Str("component", "a2a").Logger()}
	for _, o := range opts {
		o(g)
	}
	return g
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
	payload, jwk, err := crypto.VerifyJWS(jws)
	if err != nil {
		g.log.Warn().Err(err).Msg("greet: identity proof invalid")
		g.writeError(w, req.ID, -32001, "invalid identity proof")
		return
	}
	thumb := crypto.Thumbprint(jwk)

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
		CallerAns:           gp.CallerAns,
		AudienceAns:         gp.AudienceAns,
		Greeting:            gp.Greeting,
		CallerKeyThumbprint: thumb,
	}); err != nil {
		g.log.Warn().Err(err).Str("callerAns", gp.CallerAns).Msg("greet: policy rejected")
		g.writeError(w, req.ID, -32003, "greet not authorized: "+err.Error())
		return
	}

	evidence := g.seal(r, gp, thumb)

	g.log.Info().Str("callerAns", gp.CallerAns).Str("callerKeyThumbprint", thumb).Bool("sealed", evidence != nil).Msg("greet accepted")
	g.writeResult(w, req.ID, &Message{
		Role:  "agent",
		Parts: []Part{{Kind: "text", Text: "hi " + gp.CallerAns + ", this is " + g.selfAns}},
	}, evidence)
}

// seal signs a greet.completed statement and seals it to the transparency log.
// Sealing is best-effort: a failure is logged at ERROR and the greet still
// succeeds without evidence (the greeting is the primary function).
func (g *GreetService) seal(r *http.Request, gp GreetPayload, thumb string) *domain.EvidenceBundle {
	if g.tp == nil || g.priv == nil {
		return nil
	}
	event, err := json.Marshal(greetEvent{
		Type:                "greet.completed",
		CallerAns:           gp.CallerAns,
		AudienceAns:         gp.AudienceAns,
		Greeting:            gp.Greeting,
		CallerKeyThumbprint: thumb,
		At:                  time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		g.log.Error().Err(err).Msg("seal: marshal event")
		return nil
	}
	statement, err := crypto.SignCOSE1(g.priv, event)
	if err != nil {
		g.log.Error().Err(err).Msg("seal: sign statement")
		return nil
	}
	receipt, err := g.tp.Seal(r.Context(), statement)
	if err != nil {
		g.log.Error().Err(err).Msg("seal: transparency seal")
		return nil
	}
	g.log.Info().Int("entryIndex", receipt.EntryIndex).Int("treeSize", receipt.TreeSize).Msg("greet sealed")
	return &domain.EvidenceBundle{Statement: statement, Receipt: receipt}
}

func (g *GreetService) writeResult(w http.ResponseWriter, id int, msg *Message, evidence *domain.EvidenceBundle) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(rpcResponse{JSONRPC: "2.0", ID: id, Result: msg, Evidence: evidence}); err != nil {
		g.log.Error().Err(err).Msg("greet: encode result")
	}
}

func (g *GreetService) writeError(w http.ResponseWriter, id, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: message}}); err != nil {
		g.log.Error().Err(err).Msg("greet: encode error")
	}
}
```

- [ ] **Step 2: Replace `internal/comms/a2a/client.go` with:**

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
	"github.com/an-ciobanu/agent-mesh/internal/domain"
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
// returns the peer's reply text plus any transparency evidence the peer sealed
// (nil if the peer did not seal).
func (c *Client) SendGreet(ctx context.Context, endpoint string, priv ed25519.PrivateKey, payload GreetPayload) (string, *domain.EvidenceBundle, error) {
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", nil, fmt.Errorf("marshal greet payload: %w", err)
	}
	jws, err := crypto.SignJWS(priv, pb)
	if err != nil {
		return "", nil, fmt.Errorf("sign greet: %w", err)
	}

	body, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  MethodMessageSend,
		Params:  messageParams{Message: Message{Role: "user", Parts: []Part{{Kind: "text", Text: payload.Greeting}}}},
	})
	if err != nil {
		return "", nil, fmt.Errorf("marshal rpc request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderRequestJWS, jws)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("send greet: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("greet: unexpected status %d", resp.StatusCode)
	}

	var out rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", nil, fmt.Errorf("decode response: %w", err)
	}
	if out.Error != nil {
		return "", nil, fmt.Errorf("greet rejected: %s (code %d)", out.Error.Message, out.Error.Code)
	}
	if out.Result == nil || len(out.Result.Parts) == 0 {
		return "", nil, fmt.Errorf("greet: empty reply")
	}
	return out.Result.Parts[0].Text, out.Evidence, nil
}
```

- [ ] **Step 3: Update `internal/comms/a2a/client_test.go`**

The existing two `SendGreet` calls now return three values. In `TestClientSendGreetRoundTrip`, change:

```go
	reply, err := NewClient().SendGreet(context.Background(), ts.URL+"/a2a", priv, GreetPayload{
```
to:
```go
	reply, _, err := NewClient().SendGreet(context.Background(), ts.URL+"/a2a", priv, GreetPayload{
```

In `TestClientSendGreetSurfacesRPCError`, change:
```go
	_, err := NewClient().SendGreet(context.Background(), ts.URL+"/a2a", priv, GreetPayload{
```
to:
```go
	_, _, err := NewClient().SendGreet(context.Background(), ts.URL+"/a2a", priv, GreetPayload{
```

Then append this new test (add imports `commstl "github.com/an-ciobanu/agent-mesh/internal/comms/transparency"` and `"github.com/an-ciobanu/agent-mesh/internal/tl"`):

```go
func TestClientSendGreetReturnsEvidenceWhenSealing(t *testing.T) {
	tlPriv, _ := crypto.GenerateEd25519()
	tlSrv := httptest.NewServer(tl.NewService(tlPriv, zerolog.Nop()).Handler())
	defer tlSrv.Close()

	self := domain.LocalANSName("greeter-open")
	greeterPriv, _ := crypto.GenerateEd25519()
	svc := NewGreetService(self, policy.Open{}, zerolog.Nop(), WithSealing(greeterPriv, commstl.New(tlSrv.URL)))
	ts := httptest.NewServer(NewMux(Card{Name: "greeter-open", Version: "0.1.0"}, svc, zerolog.Nop()))
	defer ts.Close()

	priv, _ := crypto.GenerateEd25519()
	reply, evidence, err := NewClient().SendGreet(context.Background(), ts.URL+"/a2a", priv, GreetPayload{
		CallerAns:   domain.LocalANSName("visitor"),
		AudienceAns: self,
		Greeting:    "hello there",
	})
	if err != nil {
		t.Fatal(err)
	}
	if reply == "" {
		t.Fatal("empty reply")
	}
	if evidence == nil {
		t.Fatal("expected sealed evidence from a sealing greeter")
	}
	if !crypto.VerifyInclusion(crypto.LeafHash(evidence.Statement), evidence.Receipt.EntryIndex, evidence.Receipt.TreeSize, evidence.Receipt.Proof, evidence.Receipt.Root) {
		t.Fatal("evidence inclusion proof does not verify")
	}
}
```

Ensure `client_test.go` imports include `"github.com/an-ciobanu/agent-mesh/internal/domain"` and `"github.com/an-ciobanu/agent-mesh/internal/policy"` (the new test uses both). `crypto`, `zerolog`, `httptest`, `context` are already imported.

- [ ] **Step 4: Update `internal/comms/a2a/message_test.go`**

The existing tests still compile and pass unchanged (the response `Result` is still `*Message`). Append one sealing test (add imports `commstl "github.com/an-ciobanu/agent-mesh/internal/comms/transparency"` and `"github.com/an-ciobanu/agent-mesh/internal/tl"`):

```go
func TestGreetServiceSealsWhenConfigured(t *testing.T) {
	tlPriv, _ := crypto.GenerateEd25519()
	tlSrv := httptest.NewServer(tl.NewService(tlPriv, zerolog.Nop()).Handler())
	defer tlSrv.Close()

	self := domain.LocalANSName("greeter-open")
	greeterPriv, _ := crypto.GenerateEd25519()
	svc := NewGreetService(self, policy.Open{}, zerolog.Nop(), WithSealing(greeterPriv, commstl.New(tlSrv.URL)))

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
	if out.Evidence == nil {
		t.Fatal("expected sealed evidence in the response")
	}
	if !crypto.VerifyInclusion(crypto.LeafHash(out.Evidence.Statement), out.Evidence.Receipt.EntryIndex, out.Evidence.Receipt.TreeSize, out.Evidence.Receipt.Proof, out.Evidence.Receipt.Root) {
		t.Fatal("sealed evidence inclusion proof does not verify")
	}
}
```

(`signedGreet`/`postGreet` helpers already exist in `message_test.go` from P1.)

- [ ] **Step 5: Run the a2a suite**

Run: `go test ./internal/comms/a2a/ -v`
Expected: PASS (all P1 tests + the two new sealing tests).

- [ ] **Step 6: Commit**

```bash
git add internal/comms/a2a/message.go internal/comms/a2a/client.go internal/comms/a2a/message_test.go internal/comms/a2a/client_test.go
git commit -m "feat(a2a): seal greet.completed and return evidence in the reply"
```

---

## Task 4: Initiator propagates evidence + meshctl greet --audit

**Files:**
- Modify: `internal/greet/initiator.go`
- Modify: `internal/greet/initiator_test.go`
- Modify: `internal/integration/p1_test.go`
- Modify: `cmd/meshctl/main.go`

- [ ] **Step 1: Replace `internal/greet/initiator.go` with:**

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
// security), and sends it an identity-signed greet. It returns the reply, any
// transparency evidence the peer sealed (nil if none), and the peer it greeted.
func Initiate(
	ctx context.Context,
	disco domain.Discovery,
	res *resolver.Resolver,
	cli *a2a.Client,
	priv ed25519.PrivateKey,
	callerAns, toRole, greeting string,
) (string, *domain.EvidenceBundle, domain.AgentInfo, error) {
	peers, err := disco.Search(ctx, toRole)
	if err != nil {
		return "", nil, domain.AgentInfo{}, fmt.Errorf("discover role %q: %w", toRole, err)
	}
	if len(peers) == 0 {
		return "", nil, domain.AgentInfo{}, fmt.Errorf("no agents found for role %q", toRole)
	}
	peer := peers[0]

	card, err := res.FetchCard(ctx, peer.CardURL)
	if err != nil {
		return "", nil, peer, fmt.Errorf("resolve peer card: %w", err)
	}
	if len(card.Security) != 0 {
		return "", nil, peer, fmt.Errorf("peer %q requires authentication not supported in P1", peer.Name)
	}

	reply, evidence, err := cli.SendGreet(ctx, card.URL, priv, a2a.GreetPayload{
		CallerAns:   callerAns,
		AudienceAns: domain.LocalANSName(peer.Name),
		Greeting:    greeting,
	})
	if err != nil {
		return "", nil, peer, err
	}
	return reply, evidence, peer, nil
}
```

- [ ] **Step 2: Update `internal/greet/initiator_test.go`** — both `Initiate` calls gain the evidence return. In `TestInitiateGreetsDiscoveredOpenPeer`:

```go
	reply, _, peer, err := Initiate(ctx, disco, resolver.New(), a2a.NewClient(), priv, caller, "greeter", "hello there")
```

In `TestInitiateErrorsWhenNoPeer`:

```go
	_, _, _, err := Initiate(context.Background(), discovery.New(reg.URL), resolver.New(), a2a.NewClient(),
		priv, domain.LocalANSName("visitor"), "greeter", "hi")
```

In `TestInitiateErrorsWhenPeerRequiresAuth` (added during P1 review), update its `Initiate` call the same way — capture `_, _, _, err`.

- [ ] **Step 3: Update `internal/integration/p1_test.go`** — the `Initiate` call becomes:

```go
	reply, _, peer, err := greet.Initiate(ctx, disco, resolver.New(), a2a.NewClient(), priv, caller, "greeter", "hello there")
```

- [ ] **Step 4: Replace the `runGreet` function in `cmd/meshctl/main.go` with:**

```go
func runGreet(args []string) {
	fs := flag.NewFlagSet("greet", flag.ExitOnError)
	registryURL := fs.String("registry", "http://127.0.0.1:18090", "registry base URL")
	from := fs.String("from", "visitor", "initiator name (identity)")
	toRole := fs.String("to-role", "greeter", "role of the agent to greet")
	text := fs.String("text", "hello", "greeting text")
	keyDir := fs.String("keys", "", "identity key directory (default: ./data/<from>)")
	tlURL := fs.String("transparency", "http://127.0.0.1:18091", "transparency log base URL (for --audit)")
	doAudit := fs.Bool("audit", false, "independently audit the greeter's sealed evidence")
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
	ctx := context.Background()

	reply, evidence, peer, err := greet.Initiate(
		ctx,
		discovery.New(*registryURL),
		resolver.New(),
		a2a.NewClient(),
		priv, callerAns, *toRole, *text,
	)
	if err != nil {
		log.Fatal().Err(err).Msg("greet failed")
	}
	fmt.Printf("greeted %s (%s)\nreply: %s\n", peer.Name, peer.BaseURL, reply)
	if evidence != nil {
		fmt.Printf("sealed: entry %d of %d\n", evidence.Receipt.EntryIndex, evidence.Receipt.TreeSize)
	}

	if *doAudit {
		if evidence == nil {
			log.Fatal().Msg("--audit requested but the greeter returned no evidence (run the agent with --transparency)")
		}
		tlPub, err := transparency.New(*tlURL).FetchPubKey(ctx)
		if err != nil {
			log.Fatal().Err(err).Msg("fetch transparency-log pubkey")
		}
		auditorPriv, err := crypto.GenerateEd25519()
		if err != nil {
			log.Fatal().Err(err).Msg("generate auditor key")
		}
		verdict, _, err := audit.New(domain.LocalANSName("auditor"), auditorPriv, log).Verify(ctx, *evidence, tlPub)
		if err != nil {
			log.Fatal().Err(err).Msg("audit")
		}
		fmt.Printf("audit verdict: %s\n", verdict.Verdict)
		for _, c := range verdict.Checks {
			fmt.Printf("  - %s\n", c)
		}
	}
}
```

- [ ] **Step 5: Update `cmd/meshctl/main.go` imports**

Add to the import block:

```go
	"github.com/an-ciobanu/agent-mesh/internal/audit"
```

(`context`, `flag`, `fmt`, `os`, `path/filepath`, `github.com/rs/zerolog`, and the agent-mesh `comms/a2a`, `comms/discovery`, `comms/resolver`, `comms/transparency`, `crypto`, `domain`, `greet` packages are already imported from P1/P2a.)

- [ ] **Step 6: Build + run the affected suites**

Run: `go build ./... && go test ./internal/greet/ ./internal/integration/ -run 'Initiate|P1' -v`
Expected: builds; PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/greet/initiator.go internal/greet/initiator_test.go internal/integration/p1_test.go cmd/meshctl/main.go
git commit -m "feat(greet,meshctl): propagate evidence; greet --audit runs the auditor"
```

---

## Task 5: Wire sealing into the agent binary

**Files:**
- Modify: `cmd/agent/main.go`

- [ ] **Step 1: Add the `--transparency` flag**

In the flag block of `cmd/agent/main.go`, add:

```go
	transparencyURL := flag.String("transparency", "", "transparency log base URL; enables sealing of accepted greets")
```

- [ ] **Step 2: Keep the identity key and build the greet service with optional sealing**

The P1 code loads the key but discards it (`if _, err := crypto.LoadOrCreateEd25519(...)`). Change that line to keep the key:

```go
	priv, err := crypto.LoadOrCreateEd25519(filepath.Join(dir, "id_ed25519.seed"))
	if err != nil {
		log.Fatal().Err(err).Msg("load identity key")
	}
```

Then replace the `greetSvc := a2a.NewGreetService(selfAns, policy.Open{}, log)` line with:

```go
	var opts []a2a.Option
	if *transparencyURL != "" {
		opts = append(opts, a2a.WithSealing(priv, transparency.New(*transparencyURL)))
		log.Info().Str("transparency", *transparencyURL).Msg("greet sealing enabled")
	}
	greetSvc := a2a.NewGreetService(selfAns, policy.Open{}, log, opts...)
```

- [ ] **Step 3: Add the import**

Add to `cmd/agent/main.go` imports:

```go
	"github.com/an-ciobanu/agent-mesh/internal/comms/transparency"
```

- [ ] **Step 4: Build + smoke**

Run:
```bash
make build
go run ./cmd/registry --addr 127.0.0.1:18090 & REG=$!
go run ./cmd/transparency --addr 127.0.0.1:18091 & TL=$!
sleep 0.7
go run ./cmd/agent --name greeter-open --role greeter --addr 127.0.0.1:18101 --registry http://127.0.0.1:18090 --transparency http://127.0.0.1:18091 & AG=$!
sleep 1
./bin/meshctl greet --registry http://127.0.0.1:18090 --transparency http://127.0.0.1:18091 --audit
kill $AG $TL $REG
```
Expected: prints the reply, `sealed: entry 0 of 1`, and `audit verdict: valid` with OK check lines.

- [ ] **Step 5: Commit**

```bash
git add cmd/agent/main.go
git commit -m "feat(agent): --transparency flag enables greet sealing"
```

---

## Task 6: End-to-end integration test

**Files:**
- Create: `internal/integration/p2b_test.go`

- [ ] **Step 1: Write the test**

```go
package integration

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/audit"
	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/discovery"
	"github.com/an-ciobanu/agent-mesh/internal/comms/resolver"
	commstl "github.com/an-ciobanu/agent-mesh/internal/comms/transparency"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/greet"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
	"github.com/an-ciobanu/agent-mesh/internal/registry"
	"github.com/an-ciobanu/agent-mesh/internal/tl"
)

func TestP2B_GreetSealAudit(t *testing.T) {
	reg := httptest.NewServer(registry.New(zerolog.Nop()).Handler())
	defer reg.Close()

	tlPriv, _ := crypto.GenerateEd25519()
	tlSrv := httptest.NewServer(tl.NewService(tlPriv, zerolog.Nop()).Handler())
	defer tlSrv.Close()

	const name = "greeter-open"
	self := domain.LocalANSName(name)
	greeterPriv, _ := crypto.GenerateEd25519()
	svc := a2a.NewGreetService(self, policy.Open{}, zerolog.Nop(), a2a.WithSealing(greeterPriv, commstl.New(tlSrv.URL)))
	agent := httptest.NewServer(a2a.NewMux(a2a.Card{Name: name, Version: "0.1.0", Security: []map[string][]string{}}, svc, zerolog.Nop()))
	defer agent.Close()

	disco := discovery.New(reg.URL)
	ctx := context.Background()
	if err := disco.Register(ctx, domain.AgentInfo{
		Name: name, Role: "greeter", BaseURL: agent.URL, CardURL: agent.URL + "/.well-known/agent-card.json",
	}); err != nil {
		t.Fatal(err)
	}

	priv, _ := crypto.GenerateEd25519()
	_, evidence, _, err := greet.Initiate(ctx, disco, resolver.New(), a2a.NewClient(), priv, domain.LocalANSName("visitor"), "greeter", "hello there")
	if err != nil {
		t.Fatalf("greet: %v", err)
	}
	if evidence == nil {
		t.Fatal("expected sealed evidence")
	}

	tlPub, err := commstl.New(tlSrv.URL).FetchPubKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	auditorPriv, _ := crypto.GenerateEd25519()
	auditor := audit.New(domain.LocalANSName("auditor"), auditorPriv, zerolog.Nop())

	verdict, _, err := auditor.Verify(ctx, *evidence, tlPub)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Verdict != "valid" {
		t.Fatalf("verdict = %q, checks=%v", verdict.Verdict, verdict.Checks)
	}

	// Tamper: a corrupted statement must be judged invalid.
	bad := *evidence
	bad.Statement = append([]byte(nil), evidence.Statement...)
	bad.Statement[len(bad.Statement)-5] ^= 0xff
	badVerdict, _, err := auditor.Verify(ctx, bad, tlPub)
	if err != nil {
		t.Fatal(err)
	}
	if badVerdict.Verdict != "invalid" {
		t.Fatal("tampered evidence must be judged invalid")
	}
}
```

- [ ] **Step 2: Run test**

Run: `go test ./internal/integration/ -run P2B -v`
Expected: PASS.

- [ ] **Step 3: Full suite + check**

Run: `make check`
Expected: gofmt/vet clean, all tests PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/integration/p2b_test.go
git commit -m "test(integration): P2b greet -> seal -> audit (valid; tamper invalid)"
```

---

## Task 7: Demo script

**Files:**
- Create: `scripts/demo/p2b-greet-audit.sh`

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# P2b demo: registry + transparency log + a sealing greeter. meshctl discovers
# the greeter, sends an identity-signed greet; the greeter seals a greet.completed
# statement to the log and returns the evidence; meshctl independently audits it.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

make build

REG_ADDR="127.0.0.1:18090"
TL_ADDR="127.0.0.1:18091"
pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

./bin/registry --addr "$REG_ADDR" & pids+=("$!")
./bin/transparency --addr "$TL_ADDR" & pids+=("$!")
sleep 0.7

./bin/agent --name greeter-open --role greeter --addr 127.0.0.1:18101 \
  --registry "http://$REG_ADDR" --transparency "http://$TL_ADDR" & pids+=("$!")
sleep 1

echo "== meshctl greet --audit =="
OUT=$(./bin/meshctl greet --registry "http://$REG_ADDR" --transparency "http://$TL_ADDR" \
  --from visitor --to-role greeter --text "hello there" --audit)
echo "$OUT"

echo "$OUT" | grep -q "sealed: entry"
echo "$OUT" | grep -q "audit verdict: valid"
echo "P2b demo OK"
```

- [ ] **Step 2: Make executable and run**

Run:
```bash
chmod +x scripts/demo/p2b-greet-audit.sh
./scripts/demo/p2b-greet-audit.sh
```
Expected: prints the reply, `sealed: entry 0 of 1`, `audit verdict: valid` with OK checks, then `P2b demo OK`.

- [ ] **Step 3: Commit**

```bash
git add scripts/demo/p2b-greet-audit.sh
git commit -m "chore(demo): P2b greet + seal + audit script"
```

---

## Self-review

**Spec coverage (P2b scope of spec §5.4 / §6 / §10):**
- Greeter seals "greet.completed" to the transparency log on accept → Task 3 (`seal`), wired in Task 5. ✓
- Evidence (statement + receipt) returned to the caller → Task 3 (response `Evidence`), Task 3/4 (SendGreet/Initiate propagate). ✓
- Auditor independently verifies the bundle and returns a **signed verdict** → Tasks 1, 2; driven by Task 4 (`meshctl greet --audit`). ✓
- Provable: integration test (valid + tamper) + demo → Tasks 6, 7. ✓
- `GreetPolicy` seam preserved; sealing is an orthogonal option (`WithSealing`) so open/mandate/nonce policies are unaffected. ✓
- Deferred correctly (absent): MCP exposure of the auditor (P3), mandate/OAuth2 (P3), DPoP/nonce (P4), UI (P5). The auditor is library + CLI for now, noted in Scope.

**Placeholder scan:** none — every step has concrete code or an exact command with expected output. (Task 2's test contains an explicit correction for `TestAuditorRejectsWrongTLKey`; the corrected body + `crypto/ed25519` import is the version to use.)

**Type consistency check:**
- `domain.Verdict{Verdict, Checks, AuditorAns}` — defined Task 1; produced by `audit.Auditor.Verify` (Task 2); printed by meshctl (Task 4). ✓
- `audit.New(string, ed25519.PrivateKey, zerolog.Logger) *Auditor` + `Verify(ctx, domain.EvidenceBundle, ed25519.PublicKey) (domain.Verdict, []byte, error)` — defined Task 2; used in Task 4 (meshctl) and Task 6 (integration). ✓
- `a2a.WithSealing(ed25519.PrivateKey, domain.Transparency) Option` + `NewGreetService(selfAns, GreetPolicy, log, ...Option)` — defined Task 3; existing 3-arg call sites still compile (variadic); sealing call sites in Task 3 tests, Task 5 (cmd/agent), Task 6 (integration). ✓
- `a2a.Client.SendGreet(ctx, endpoint, priv, GreetPayload) (string, *domain.EvidenceBundle, error)` — new 3-return; updated at every call site: client_test (Task 3), greet.Initiate (Task 4). ✓
- `greet.Initiate(...) (string, *domain.EvidenceBundle, domain.AgentInfo, error)` — new signature (Task 4); updated at initiator_test (Task 4), integration/p1_test (Task 4), meshctl (Task 4). No other callers. ✓
- `rpcResponse.Evidence` sibling field carries `*domain.EvidenceBundle`; `Result` stays `*Message` so all P1 message_test assertions remain valid. ✓
- `greetEvent` (a2a, Task 3) is the sealed statement payload; the auditor treats the statement as opaque bytes (leaf hash + COSE verify), so no cross-package shape coupling is required. ✓
- `receiptClaims` is defined independently in both `tl` (P2a) and `audit` (Task 2) with the same JSON tags (`entryIndex`,`treeSize`,`root`); the auditor parses what the TL wrote — consistent. ✓
