# P5a — Agent-Emitted Events, Greet-ID Correlation & Trigger Endpoint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give each agent a structured, per-step event stream (written to stdout as JSON lines) so the interaction between two real agents can later be rendered from *both agents' own point of view*, correlated by a shared greet id, and let an agent be told to greet a specific peer so an external driver (the P5b orchestrator) can trigger real agent-to-agent greets.

**Architecture:** A new `internal/events` package defines an `Event`, an `Emitter` (JSON-lines to an `io.Writer`, plus a `Nop`), and a **context-scoped** emitter so guards and the initiator emit without any change to their signatures or the domain DTOs. The A2A responder puts an emitter + greet id into the request context (greet id read from a new `X-ANS-Greet-Id` header, generated if absent) and emits `jws.verify` / `gate` / `seal`; the greet guards emit their individual checks; the initiator emits its discovery/acquire/send steps. `greet.Initiate` is refactored to expose `greetPeer` (greet a specific discovered peer), and the agent gains an opt-in `POST /trigger/greet` endpoint that initiates a real greet using the agent's own identity and reports the outcome. **No change to the A2A JSON-RPC request/response body** — correlation rides an HTTP header, events ride a side channel (stdout). The transparency log is untouched (it stays the audit capstone, surfaced in P5b).

**Tech Stack:** Go, `zerolog` (logs → stderr; events → stdout), stdlib `net/http`, existing `internal/{crypto,comms/a2a,comms/mcp,comms/resolver,comms/discovery,policy,greet}`.

---

## File Structure

**New:**
- `internal/events/events.go` — `Event`, `Emitter`, `JSONEmitter`, `Nop`, context scope, `Emit`/`GreetIDFromContext` helpers.
- `internal/events/events_test.go` — unit tests.
- `internal/comms/a2a/trigger.go` — `TriggerService` (`POST /trigger/greet`).
- `internal/comms/a2a/trigger_test.go` — unit test.

**Modified:**
- `internal/comms/a2a/message.go` — `HeaderGreetID`, `WithEvents` option, emit responder events, install context scope for guards.
- `internal/comms/a2a/client.go` — `WithGreetID` send option.
- `internal/policy/{open,mandate,nonce}.go` — emit per-check events via context (no signature change).
- `internal/greet/initiator.go` — extract `greetPeer`, emit initiator events, propagate greet id.
- `cmd/agent/main.go` — `--events` and `--allow-trigger` flags; wire emitter + trigger endpoint.
- `internal/greet/*_test.go`, `internal/policy/*_test.go` — assertions that emission is a no-op without a scope and fires with one.

**Event JSON contract** (one object per stdout line; consumed by the P5b orchestrator):

```json
{"greetId":"<hex>","agent":"<name>","role":"initiator|responder","step":"<step>","status":"ok|fail|info","detail":{"k":"v"},"ts":"2026-09-25T12:00:00Z"}
```

---

### Task 1: `internal/events` package

**Files:**
- Create: `internal/events/events.go`
- Test: `internal/events/events_test.go`

- [ ] **Step 1: Write the failing test**

```go
package events

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestJSONEmitterWritesOneLinePerEvent(t *testing.T) {
	var buf bytes.Buffer
	em := NewJSONEmitter(&buf)
	em.Emit(Event{GreetID: "g1", Agent: "chris", Role: RoleInitiator, Step: "greet.send", Status: StatusOK})
	em.Emit(Event{GreetID: "g1", Agent: "ema", Role: RoleResponder, Step: "gate", Status: StatusFail})

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d: %q", len(lines), buf.String())
	}
	var e Event
	if err := json.Unmarshal([]byte(lines[1]), &e); err != nil {
		t.Fatalf("line not valid JSON: %v", err)
	}
	if e.Agent != "ema" || e.Step != "gate" || e.Status != StatusFail {
		t.Fatalf("unexpected event: %+v", e)
	}
	if e.TS.IsZero() {
		t.Fatalf("emitter must stamp TS")
	}
}

func TestEmitFromContextIsNoopWithoutScope(t *testing.T) {
	// Must not panic and must do nothing when no scope is installed.
	Emit(context.Background(), "gate", StatusOK, nil)
}

func TestEmitFromContextUsesScope(t *testing.T) {
	var buf bytes.Buffer
	ctx := WithScope(context.Background(), NewJSONEmitter(&buf), "g7", "ema", RoleResponder)
	if got := GreetIDFromContext(ctx); got != "g7" {
		t.Fatalf("GreetIDFromContext = %q, want g7", got)
	}
	Emit(ctx, "authority.pin", StatusOK, map[string]string{"authority": "auth-1"})

	var e Event
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &e); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if e.GreetID != "g7" || e.Agent != "ema" || e.Role != RoleResponder || e.Step != "authority.pin" {
		t.Fatalf("scope not applied: %+v", e)
	}
	if e.Detail["authority"] != "auth-1" {
		t.Fatalf("detail lost: %+v", e.Detail)
	}
}

func TestNewGreetIDIsHexAndUnique(t *testing.T) {
	a, b := NewGreetID(), NewGreetID()
	if len(a) != 32 || a == b {
		t.Fatalf("weak greet id: %q %q", a, b)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/events/`
Expected: FAIL (package does not compile — `events.go` not written).

- [ ] **Step 3: Write the implementation**

```go
// Package events carries a per-step, per-agent event stream so an interaction
// between two agents can be reconstructed from each agent's own point of view.
// Events are written as JSON lines to a side channel (stdout); ordinary logs go
// to stderr. Emission is context-scoped: guards and initiators emit through the
// request/call context, so their signatures and the domain DTOs never change,
// and callers without a scope (e.g. unit tests, meshctl) get a silent no-op.
package events

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Roles.
const (
	RoleInitiator = "initiator"
	RoleResponder = "responder"
)

// Statuses.
const (
	StatusOK   = "ok"
	StatusFail = "fail"
	StatusInfo = "info"
)

// Event is a single step in a greet, reported by the agent that performed it.
type Event struct {
	GreetID string            `json:"greetId"`
	Agent   string            `json:"agent"`
	Role    string            `json:"role"`
	Step    string            `json:"step"`
	Status  string            `json:"status"`
	Detail  map[string]string `json:"detail,omitempty"`
	TS      time.Time         `json:"ts"`
}

// Emitter records events.
type Emitter interface {
	Emit(Event)
}

// Nop is an Emitter that discards events. It is the zero-value behavior when no
// emitter is installed.
type Nop struct{}

// Emit does nothing.
func (Nop) Emit(Event) {}

// JSONEmitter writes one JSON object per line to w, safe for concurrent use.
type JSONEmitter struct {
	mu  sync.Mutex
	enc *json.Encoder
}

// NewJSONEmitter builds a JSONEmitter over w.
func NewJSONEmitter(w io.Writer) *JSONEmitter {
	return &JSONEmitter{enc: json.NewEncoder(w)}
}

// Emit stamps TS if unset and writes the event as one line.
func (j *JSONEmitter) Emit(e Event) {
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	_ = j.enc.Encode(e) // json.Encoder.Encode appends a newline
}

// NewGreetID returns a random 128-bit hex id correlating both agents' events.
func NewGreetID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type scopeKey struct{}

type scope struct {
	em      Emitter
	greetID string
	agent   string
	role    string
}

// WithScope installs an emitter and the fixed per-interaction fields into ctx.
func WithScope(ctx context.Context, em Emitter, greetID, agent, role string) context.Context {
	if em == nil {
		em = Nop{}
	}
	return context.WithValue(ctx, scopeKey{}, &scope{em: em, greetID: greetID, agent: agent, role: role})
}

// GreetIDFromContext returns the scope's greet id, or "" if no scope.
func GreetIDFromContext(ctx context.Context) string {
	if s, ok := ctx.Value(scopeKey{}).(*scope); ok {
		return s.greetID
	}
	return ""
}

// Emit reports a step using the emitter and fixed fields in ctx. It is a no-op
// when no scope is installed.
func Emit(ctx context.Context, step, status string, detail map[string]string) {
	s, ok := ctx.Value(scopeKey{}).(*scope)
	if !ok {
		return
	}
	s.em.Emit(Event{
		GreetID: s.greetID,
		Agent:   s.agent,
		Role:    s.role,
		Step:    step,
		Status:  status,
		Detail:  detail,
	})
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/events/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/events/
git commit -m "feat(events): context-scoped per-agent event stream (JSON lines)"
```

---

### Task 2: A2A responder emits events + greet-id header

**Files:**
- Modify: `internal/comms/a2a/message.go`
- Modify: `internal/comms/a2a/client.go`
- Test: `internal/comms/a2a/message_test.go` (add cases; keep existing)

- [ ] **Step 1: Write the failing test**

Add to `internal/comms/a2a/message_test.go` (adapt imports/helpers to the file's existing test setup — it already builds a `GreetService` and posts a signed greet; reuse that harness):

```go
func TestHandleMessageSendEmitsResponderEvents(t *testing.T) {
	var buf bytes.Buffer
	em := events.NewJSONEmitter(&buf)

	// Build an OPEN greeter with events enabled. (Reuse the existing helper that
	// signs a greet and returns an *httptest.Server or handler; pass WithEvents.)
	svc := NewGreetService(domain.LocalANSName("ema"), policy.Open{},
		zerolog.Nop(), WithEvents(em, "ema", "greeter-open"))

	rr := postSignedGreet(t, svc, "chris", "ema", "hi", func(h http.Header) {
		h.Set(HeaderGreetID, "g42")
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}

	var sawJWS, sawGate bool
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var e events.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("bad event line %q: %v", line, err)
		}
		if e.GreetID != "g42" || e.Agent != "ema" || e.Role != events.RoleResponder {
			t.Fatalf("wrong scope on event: %+v", e)
		}
		switch e.Step {
		case "jws.verify":
			sawJWS = e.Status == events.StatusOK
		case "gate":
			sawGate = e.Status == events.StatusOK
		}
	}
	if !sawJWS || !sawGate {
		t.Fatalf("missing responder events: jws=%v gate=%v (%s)", sawJWS, sawGate, buf.String())
	}
}
```

> **Note:** if `postSignedGreet(...)` with a header-mutator does not already exist in the test file, add a small local helper mirroring the existing signed-greet POST used by the current tests, adding an optional `func(http.Header)` to set `X-ANS-Greet-Id`. Do not change the wire body.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/comms/a2a/ -run EmitsResponderEvents`
Expected: FAIL (`WithEvents`, `HeaderGreetID` undefined).

- [ ] **Step 3: Implement**

In `internal/comms/a2a/message.go`:

Add the header const to the `const (...)` block:

```go
	// HeaderGreetID correlates both agents' event streams for one greet. The
	// initiator sets it; the responder generates one if absent. It is metadata
	// only — it does not alter the JSON-RPC request/response body.
	HeaderGreetID = "X-ANS-Greet-Id"
```

Add fields to `GreetService` and a `WithEvents` option:

```go
type GreetService struct {
	selfAns   string
	policy    domain.GreetPolicy
	priv      ed25519.PrivateKey
	tp        domain.Transparency
	log       zerolog.Logger
	events    events.Emitter // nil-safe via events.Nop
	agentName string
	role      string
}

// WithEvents makes the service emit per-step responder events (and install an
// emitter scope on the request context so the greet policy can emit its checks).
func WithEvents(em events.Emitter, agentName, role string) Option {
	return func(g *GreetService) {
		g.events = em
		g.agentName = agentName
		g.role = role
	}
}
```

Import `"github.com/an-ciobanu/agent-mesh/internal/events"`. In `NewGreetService`, default the emitter:

```go
	g := &GreetService{selfAns: selfAns, policy: p, events: events.Nop{}, role: "responder", log: log.With().Str("component", "a2a").Logger()}
```

In `HandleMessageSend`, right after decoding succeeds and before/at the identity check, establish the scope, then emit at each decision point. Replace the identity/audience/policy/seal section so it reads:

```go
	greetID := r.Header.Get(HeaderGreetID)
	if greetID == "" {
		greetID = events.NewGreetID()
	}
	name := g.agentName
	if name == "" {
		name = g.selfAns
	}
	ctx := events.WithScope(r.Context(), g.events, greetID, name, events.RoleResponder)

	jws := r.Header.Get(HeaderRequestJWS)
	if jws == "" {
		events.Emit(ctx, "jws.verify", events.StatusFail, map[string]string{"error": "missing identity proof"})
		g.log.Warn().Msg("greet: missing identity proof")
		g.writeError(w, req.ID, -32000, "missing identity proof")
		return
	}
	payload, jwk, err := crypto.VerifyJWS(jws)
	if err != nil {
		events.Emit(ctx, "jws.verify", events.StatusFail, map[string]string{"error": err.Error()})
		g.log.Warn().Err(err).Msg("greet: identity proof invalid")
		g.writeError(w, req.ID, -32001, "invalid identity proof")
		return
	}
	thumb := crypto.Thumbprint(jwk)
	events.Emit(ctx, "jws.verify", events.StatusOK, map[string]string{"thumbprint": thumb})

	var gp GreetPayload
	if err := json.Unmarshal(payload, &gp); err != nil {
		g.writeError(w, req.ID, -32602, "invalid greet payload")
		return
	}
	if gp.AudienceAns != g.selfAns {
		events.Emit(ctx, "audience", events.StatusFail, map[string]string{"audience": gp.AudienceAns, "self": g.selfAns})
		g.log.Warn().Str("audienceAns", gp.AudienceAns).Str("selfAns", g.selfAns).Msg("greet: audience mismatch")
		g.writeError(w, req.ID, -32002, "audience mismatch")
		return
	}

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

	if err := g.policy.Authorize(ctx, domain.GreetRequest{
		CallerAns:           gp.CallerAns,
		AudienceAns:         gp.AudienceAns,
		Greeting:            gp.Greeting,
		CallerKeyThumbprint: thumb,
		Mandate:             mandate,
		DPoPProof:           r.Header.Get(HeaderDPoP),
		HTTPMethod:          r.Method,
		HTTPURL:             "http://" + r.Host + r.URL.Path,
	}); err != nil {
		events.Emit(ctx, "gate", events.StatusFail, map[string]string{"reason": err.Error()})
		g.log.Warn().Err(err).Str("callerAns", gp.CallerAns).Msg("greet: policy rejected")
		g.writeError(w, req.ID, -32003, "greet not authorized: "+err.Error())
		return
	}
	events.Emit(ctx, "gate", events.StatusOK, nil)

	evidence := g.sealCtx(ctx, r, gp, thumb)
	...
```

Change `seal` to accept the context so it can emit the seal event; rename call site to `g.sealCtx(ctx, r, gp, thumb)` and update the method:

```go
func (g *GreetService) sealCtx(ctx context.Context, r *http.Request, gp GreetPayload, thumb string) *domain.EvidenceBundle {
	if g.tp == nil || g.priv == nil {
		return nil
	}
	// ... unchanged marshal + SignCOSE1 ...
	receipt, err := g.tp.Seal(r.Context(), statement)
	if err != nil {
		events.Emit(ctx, "seal", events.StatusFail, map[string]string{"error": err.Error()})
		g.log.Error().Err(err).Msg("seal: transparency seal")
		return nil
	}
	events.Emit(ctx, "seal", events.StatusOK, map[string]string{
		"entryIndex": strconv.Itoa(receipt.EntryIndex),
		"treeSize":   strconv.Itoa(receipt.TreeSize),
	})
	g.log.Info().Int("entryIndex", receipt.EntryIndex).Int("treeSize", receipt.TreeSize).Msg("greet sealed")
	return &domain.EvidenceBundle{Statement: statement, Receipt: receipt}
}
```

Add `"strconv"` to imports.

In `internal/comms/a2a/client.go`, add:

```go
// WithGreetID sets the greet-id correlation header so the responder's events
// share the initiator's id. Empty id is a no-op (the responder will mint one).
func WithGreetID(id string) SendOption {
	return func(h http.Header) {
		if id != "" {
			h.Set(HeaderGreetID, id)
		}
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/comms/a2a/`
Expected: PASS (new test + all existing).

- [ ] **Step 5: Commit**

```bash
git add internal/comms/a2a/
git commit -m "feat(a2a): emit responder events; X-ANS-Greet-Id correlation header"
```

---

### Task 3: Greet policies emit their per-check events

**Files:**
- Modify: `internal/policy/open.go`, `internal/policy/mandate.go`, `internal/policy/nonce.go`
- Test: `internal/policy/mandate_test.go`, `internal/policy/nonce_test.go` (add one case each)

The guards already receive `ctx`; start using it for emission only (behavior otherwise identical, fail-closed logic unchanged).

- [ ] **Step 1: Write the failing test**

Add to `internal/policy/nonce_test.go` (reuse the file's existing helper that builds a valid DPoP proof + store; if a valid-accept test already exists, wrap its setup):

```go
func TestNonceEmitsChecks(t *testing.T) {
	var buf bytes.Buffer
	// Build the SAME valid request the existing accept test uses:
	pol, req := validNonceCase(t) // existing helper OR inline the accept setup
	ctx := events.WithScope(context.Background(), events.NewJSONEmitter(&buf), "g1", "ema", events.RoleResponder)

	if err := pol.Authorize(ctx, req); err != nil {
		t.Fatalf("expected accept, got %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, `"step":"dpop.verify"`) || !strings.Contains(got, `"step":"nonce.consume"`) {
		t.Fatalf("missing check events: %s", got)
	}
}
```

> If `validNonceCase` does not exist, inline the accept-path setup from the existing passing test in this file. Add a matching `TestMandateEmitsChecks` asserting `mandate.verify` and `authority.pin` events on the accept path.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/ -run EmitsChecks`
Expected: FAIL (no events emitted yet).

- [ ] **Step 3: Implement**

`internal/policy/open.go` — add an import for events and emit a single gate event:

```go
func (Open) Authorize(ctx context.Context, _ domain.GreetRequest) error {
	events.Emit(ctx, "gate", events.StatusOK, map[string]string{"policy": "open"})
	return nil
}
```

`internal/policy/mandate.go` — in `Authorize`, replace `_ context.Context` with `ctx context.Context` and emit at the two key checks. After `crypto.VerifyCOSE1` succeeds:

```go
	events.Emit(ctx, "mandate.verify", events.StatusOK, nil)
	if !signer.Equal(m.authorityPub) {
		events.Emit(ctx, "authority.pin", events.StatusFail, map[string]string{"authority": m.authorityAns})
		return fmt.Errorf("mandate not signed by the trusted authority")
	}
	events.Emit(ctx, "authority.pin", events.StatusOK, map[string]string{"authority": m.authorityAns})
```

(Emit a `mandate.verify` fail before returning the `mandate signature invalid` error too.)

`internal/policy/nonce.go` — replace `_ context.Context` with `ctx context.Context` and emit:

```go
	claims, thumb, err := crypto.VerifyDPoPProof(req.DPoPProof)
	if err != nil {
		events.Emit(ctx, "dpop.verify", events.StatusFail, map[string]string{"error": err.Error()})
		return fmt.Errorf("DPoP proof invalid: %w", err)
	}
	events.Emit(ctx, "dpop.verify", events.StatusOK, map[string]string{"thumbprint": thumb})
	// ... htm/htu/iat checks unchanged ...
	if !n.store.Consume(claims.Nonce) {
		events.Emit(ctx, "nonce.consume", events.StatusFail, nil)
		return fmt.Errorf("DPoP nonce not recognized or already used")
	}
	events.Emit(ctx, "nonce.consume", events.StatusOK, nil)
```

Add `"github.com/an-ciobanu/agent-mesh/internal/events"` to each file's imports.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/policy/`
Expected: PASS (new + existing; existing tests pass `context.Background()` → no scope → emission is a silent no-op).

- [ ] **Step 5: Commit**

```bash
git add internal/policy/
git commit -m "feat(policy): guards emit per-check events via context scope"
```

---

### Task 4: `greetPeer` refactor + initiator events

**Files:**
- Modify: `internal/greet/initiator.go`
- Test: `internal/greet/greetpeer_test.go` (new) + existing `internal/greet/*_test.go` stay green

- [ ] **Step 1: Write the failing test**

Create `internal/greet/greetpeer_test.go`. Use the existing greet tests' harness style (they stand up an in-process open greeter). Assert `GreetPeer` greets a specific peer and that initiator events are emitted when a scope is present:

```go
package greet

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
	"github.com/an-ciobanu/agent-mesh/internal/comms/resolver"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/events"
)

func TestGreetPeerOpenEmitsInitiatorEvents(t *testing.T) {
	peer, priv := startOpenGreeter(t) // existing/adapted helper: returns domain.AgentInfo + caller key

	var buf bytes.Buffer
	ctx := events.WithScope(context.Background(), events.NewJSONEmitter(&buf), "g9", "chris", events.RoleInitiator)

	reply, _, err := GreetPeer(ctx, resolver.New(), a2a.NewClient(), mcp.NewClient(), nil,
		priv, domain.LocalANSName("chris"), peer, "hello")
	if err != nil {
		t.Fatalf("GreetPeer: %v", err)
	}
	if reply == "" {
		t.Fatalf("empty reply")
	}
	got := buf.String()
	for _, want := range []string{`"step":"card.read"`, `"step":"greet.send"`, `"step":"greet.reply"`, `"greetId":"g9"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s in events: %s", want, got)
		}
	}
}
```

> Adapt `startOpenGreeter` to the helper the existing greet tests use (e.g. the one behind `mandate_initiate_test.go`). `GreetPeer` takes a discovery for the mandate case; pass `nil` for the open case and guard nil use inside `acquireMandate` paths (the open case never reaches it).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/greet/ -run GreetPeer`
Expected: FAIL (`GreetPeer` undefined).

- [ ] **Step 3: Implement**

Refactor `internal/greet/initiator.go`. Keep `Initiate` as the discover-by-role entry point; extract everything after peer selection into exported `GreetPeer`, and emit events through `ctx`. Add `"github.com/an-ciobanu/agent-mesh/internal/events"` to imports.

```go
func Initiate(
	ctx context.Context,
	disco domain.Discovery,
	res *resolver.Resolver,
	cli *a2a.Client,
	mcpCli *mcp.Client,
	priv ed25519.PrivateKey,
	callerAns, toRole, greeting string,
) (string, *domain.EvidenceBundle, domain.AgentInfo, error) {
	events.Emit(ctx, "discover", events.StatusInfo, map[string]string{"role": toRole})
	peers, err := disco.Search(ctx, toRole)
	if err != nil {
		return "", nil, domain.AgentInfo{}, fmt.Errorf("discover role %q: %w", toRole, err)
	}
	if len(peers) == 0 {
		return "", nil, domain.AgentInfo{}, fmt.Errorf("no agents found for role %q", toRole)
	}
	peer := peers[0]
	reply, evidence, err := GreetPeer(ctx, res, cli, mcpCli, disco, priv, callerAns, peer, greeting)
	return reply, evidence, peer, err
}

// GreetPeer greets a specific, already-discovered peer: read its card, satisfy
// whatever requirement the card advertises (mandate or DPoP nonce), and send an
// identity-signed greet. disco is used only to discover a mandate authority and
// may be nil for open/nonce peers. Steps are emitted through ctx (no-op if no
// scope). Nothing about the peer or authority is hardcoded.
func GreetPeer(
	ctx context.Context,
	res *resolver.Resolver,
	cli *a2a.Client,
	mcpCli *mcp.Client,
	disco domain.Discovery,
	priv ed25519.PrivateKey,
	callerAns string,
	peer domain.AgentInfo,
	greeting string,
) (string, *domain.EvidenceBundle, error) {
	card, err := res.FetchCard(ctx, peer.CardURL)
	if err != nil {
		return "", nil, fmt.Errorf("resolve peer card: %w", err)
	}
	events.Emit(ctx, "card.read", events.StatusOK, map[string]string{"peer": peer.Name, "url": card.URL})

	audienceAns := domain.LocalANSName(peer.Name)
	greetID := events.GreetIDFromContext(ctx)
	opts := []a2a.SendOption{a2a.WithGreetID(greetID)}

	if ext, ok := mandateExtension(card); ok {
		events.Emit(ctx, "requirement", events.StatusInfo, map[string]string{"type": "mandate"})
		if disco == nil {
			return "", nil, fmt.Errorf("peer %q requires a mandate but no discovery is available", peer.Name)
		}
		mandate, merr := acquireMandate(ctx, disco, mcpCli, ext, callerAns, audienceAns)
		if merr != nil {
			events.Emit(ctx, "mandate.acquire", events.StatusFail, map[string]string{"error": merr.Error()})
			return "", nil, merr
		}
		events.Emit(ctx, "mandate.acquire", events.StatusOK, map[string]string{"authority": stringParam(ext.Params, "authorityRole", "authority")})
		opts = append(opts, a2a.WithMandate(mandate))
	} else if _, ok := nonceExtension(card); ok {
		events.Emit(ctx, "requirement", events.StatusInfo, map[string]string{"type": "nonce"})
		proof, nerr := acquireDPoPProof(ctx, mcpCli, peer.BaseURL, card.URL)
		if nerr != nil {
			events.Emit(ctx, "dpop.build", events.StatusFail, map[string]string{"error": nerr.Error()})
			return "", nil, nerr
		}
		events.Emit(ctx, "dpop.build", events.StatusOK, map[string]string{"htu": card.URL})
		opts = append(opts, a2a.WithDPoP(proof))
	} else if len(card.Security) != 0 {
		return "", nil, fmt.Errorf("peer %q requires unsupported authentication", peer.Name)
	} else {
		events.Emit(ctx, "requirement", events.StatusInfo, map[string]string{"type": "open"})
	}

	events.Emit(ctx, "greet.send", events.StatusInfo, map[string]string{"to": peer.Name})
	reply, evidence, err := cli.SendGreet(ctx, card.URL, priv, a2a.GreetPayload{
		CallerAns:   callerAns,
		AudienceAns: audienceAns,
		Greeting:    greeting,
	}, opts...)
	if err != nil {
		events.Emit(ctx, "greet.rejected", events.StatusFail, map[string]string{"error": err.Error()})
		return "", nil, err
	}
	events.Emit(ctx, "greet.reply", events.StatusOK, map[string]string{"reply": reply})
	return reply, evidence, nil
}
```

Also emit the nonce fetch inside `acquireDPoPProof` (optional, improves the nonce trace): after a successful `get_nonce`, `events.Emit(ctx, "nonce.get", events.StatusOK, nil)`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/greet/`
Expected: PASS (new + existing; existing callers pass no scope → no-op).

- [ ] **Step 5: Commit**

```bash
git add internal/greet/
git commit -m "feat(greet): extract GreetPeer; emit initiator events; propagate greet id"
```

---

### Task 5: Agent `--events` and `--allow-trigger`

**Files:**
- Create: `internal/comms/a2a/trigger.go`
- Test: `internal/comms/a2a/trigger_test.go`
- Modify: `cmd/agent/main.go`

- [ ] **Step 1: Write the failing test**

`internal/comms/a2a/trigger_test.go`:

```go
package a2a

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/events"
)

func TestTriggerGreetRejectsBadBody(t *testing.T) {
	ts := NewTriggerService("chris", nil, zerolog.Nop(), events.Nop{})
	rr := httptest.NewRecorder()
	ts.HandleGreet(rr, httptest.NewRequest(http.MethodPost, "/trigger/greet", strings.NewReader("{")))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestTriggerGreetInvokesGreetFuncWithScope(t *testing.T) {
	var buf bytes.Buffer
	var gotGreetID, gotToName string
	greetFn := func(greetID, toRole, toName, text string) (string, bool, error) {
		gotGreetID, gotToName = greetID, toName
		return "hi chris, this is ema", true, nil
	}
	ts := NewTriggerService("chris", greetFn, zerolog.Nop(), events.NewJSONEmitter(&buf))

	body, _ := json.Marshal(triggerReq{ToName: "ema", Text: "hello"})
	rr := httptest.NewRecorder()
	ts.HandleGreet(rr, httptest.NewRequest(http.MethodPost, "/trigger/greet", bytes.NewReader(body)))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	var out triggerResp
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("bad resp: %v", err)
	}
	if !out.Accepted || out.GreetID == "" || out.GreetID != gotGreetID || gotToName != "ema" {
		t.Fatalf("unexpected: %+v (gotGreetID=%s toName=%s)", out, gotGreetID, gotToName)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/comms/a2a/ -run Trigger`
Expected: FAIL (`NewTriggerService` etc. undefined).

- [ ] **Step 3: Implement `internal/comms/a2a/trigger.go`**

```go
package a2a

import (
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/events"
)

// GreetFunc initiates a greet from this agent to a peer identified by role or
// name, using the agent's own identity. It returns the reply, whether the peer
// accepted, and any error. The greet id is supplied so events correlate.
type GreetFunc func(greetID, toRole, toName, text string) (reply string, accepted bool, err error)

type triggerReq struct {
	ToRole string `json:"toRole,omitempty"`
	ToName string `json:"toName,omitempty"`
	Text   string `json:"text,omitempty"`
}

type triggerResp struct {
	GreetID  string `json:"greetId"`
	Reply    string `json:"reply,omitempty"`
	Accepted bool   `json:"accepted"`
	Error    string `json:"error,omitempty"`
}

// TriggerService exposes POST /trigger/greet so a driver (the P5b orchestrator)
// can make this agent initiate a real greet. It is opt-in (mounted only when the
// agent is started with --allow-trigger) and never enabled on a plain server.
type TriggerService struct {
	self  string
	greet GreetFunc
	log   zerolog.Logger
	em    events.Emitter
}

// NewTriggerService builds a trigger handler for the agent named self.
func NewTriggerService(self string, greet GreetFunc, log zerolog.Logger, em events.Emitter) *TriggerService {
	if em == nil {
		em = events.Nop{}
	}
	return &TriggerService{self: self, greet: greet, log: log.With().Str("component", "trigger").Logger(), em: em}
}

// HandleGreet handles POST /trigger/greet.
func (t *TriggerService) HandleGreet(w http.ResponseWriter, r *http.Request) {
	var req triggerReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.ToRole == "" && req.ToName == "" {
		http.Error(w, "toRole or toName required", http.StatusBadRequest)
		return
	}
	if req.Text == "" {
		req.Text = "hello"
	}
	greetID := events.NewGreetID()

	reply, accepted, err := t.greet(greetID, req.ToRole, req.ToName, req.Text)
	resp := triggerResp{GreetID: greetID, Reply: reply, Accepted: accepted}
	if err != nil {
		resp.Error = err.Error()
		t.log.Warn().Err(err).Str("toName", req.ToName).Str("toRole", req.ToRole).Msg("trigger greet failed")
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
```

- [ ] **Step 4: Wire `cmd/agent/main.go`**

Add flags after the existing ones:

```go
	emitEvents := flag.Bool("events", false, "emit per-step greet events as JSON lines to stdout")
	allowTrigger := flag.Bool("allow-trigger", false, "expose POST /trigger/greet so a driver can make this agent initiate greets (demo only)")
```

After `log := ...` and identity load, build the emitter:

```go
	var em events.Emitter = events.Nop{}
	if *emitEvents {
		em = events.NewJSONEmitter(os.Stdout)
	}
```

Pass events into the greet service (add to the `opts` build, after the sealing option):

```go
	opts = append(opts, a2a.WithEvents(em, *name, *role))
```

After `mux := a2a.NewMux(...)` and the mcp mount, mount the trigger endpoint when enabled. The `GreetFunc` runs the initiator with an initiator scope on the context:

```go
	if *allowTrigger {
		res := resolver.New()
		a2aCli := a2a.NewClient()
		mcpCli := mcp.NewClient()
		greetFn := func(greetID, toRole, toName, text string) (string, bool, error) {
			gctx := events.WithScope(context.Background(), em, greetID, *name, events.RoleInitiator)
			callerAns := selfAns
			var (
				reply string
				err   error
			)
			if toName != "" {
				var peer domain.AgentInfo
				peer, err = resolvePeerByName(gctx, disco, toName)
				if err == nil {
					reply, _, err = greet.GreetPeer(gctx, res, a2aCli, mcpCli, disco, priv, callerAns, peer, text)
				}
			} else {
				reply, _, _, err = greet.Initiate(gctx, disco, res, a2aCli, mcpCli, priv, callerAns, toRole, text)
			}
			if err != nil {
				return "", false, err
			}
			return reply, true, nil
		}
		trig := a2a.NewTriggerService(*name, greetFn, log, em)
		mux.HandleFunc("POST /trigger/greet", trig.HandleGreet)
		log.Info().Msg("trigger endpoint enabled (POST /trigger/greet)")
	}
```

Add a small `resolvePeerByName` helper in `cmd/agent/main.go` (discovery has no by-name lookup; search the peer's role space is not known, so search all-known via the registry's role list is out of scope — instead resolve by name across the roles the orchestrator will pass). Simplest correct approach: the orchestrator passes `toRole` alongside `toName`; resolve by role then match name:

```go
// resolvePeerByName finds a registered peer by exact name. It expects the caller
// to also pass a role (toRole) to scope the search; if toRole is empty it errors,
// keeping discovery honest (no global enumeration).
func resolvePeerByName(ctx context.Context, disco *discovery.Client, name string) (domain.AgentInfo, error) {
	return domain.AgentInfo{}, fmt.Errorf("resolvePeerByName requires a role; pass toRole")
}
```

> **Decision for the implementer:** to keep discovery honest (no global enumeration), the trigger contract is **`toRole` is required; `toName` optionally disambiguates** when several agents share a role. Implement the greetFn to always `disco.Search(ctx, toRole)`, then pick the peer whose `Name == toName` if `toName != ""`, else the first. Replace the `resolvePeerByName` stub with this role-scoped selection and drop the standalone helper. The P5b orchestrator always knows each agent's role, so it will pass `toRole` (and `toName` for exactness).

Add imports to `cmd/agent/main.go`: `"fmt"`, `"github.com/an-ciobanu/agent-mesh/internal/comms/resolver"`, `"github.com/an-ciobanu/agent-mesh/internal/events"`, `"github.com/an-ciobanu/agent-mesh/internal/greet"`.

- [ ] **Step 5: Run tests + build + smoke**

Run:
```bash
go test ./internal/comms/a2a/ -run Trigger
go build ./...
```
Expected: PASS + clean build.

Smoke the trigger + events end to end:
```bash
go build -o bin/registry ./cmd/registry && go build -o bin/agent ./cmd/agent
./bin/registry --addr 127.0.0.1:18090 & REG=$!
sleep 0.5
./bin/agent --name ema  --role greeter-open --addr 127.0.0.1:18201 --registry http://127.0.0.1:18090 --policy open --events > /tmp/ema.events 2>/dev/null & A=$!
./bin/agent --name chris --role visitor --addr 127.0.0.1:18202 --registry http://127.0.0.1:18090 --policy open --events --allow-trigger > /tmp/chris.events 2>/dev/null & B=$!
sleep 1.5
curl -s -XPOST 127.0.0.1:18202/trigger/greet -d '{"toRole":"greeter-open","toName":"ema","text":"hi"}'; echo
echo "--- chris (initiator) events ---"; cat /tmp/chris.events
echo "--- ema (responder) events ---";  cat /tmp/ema.events
kill $A $B $REG 2>/dev/null
```
Expected: the curl returns `{"greetId":"...","reply":"hi ...","accepted":true}`; chris's stdout shows `card.read`/`greet.send`/`greet.reply` with role `initiator`; ema's stdout shows `jws.verify`/`gate` with role `responder`; **both share the same `greetId`**.

- [ ] **Step 6: Commit**

```bash
git add internal/comms/a2a/trigger.go internal/comms/a2a/trigger_test.go cmd/agent/main.go
git commit -m "feat(agent): --events stdout stream and opt-in --allow-trigger greet endpoint"
```

---

### Task 6: Gate

- [ ] **Step 1: Format, vet, build, test**

Run:
```bash
gofmt -l . && go vet ./... && go build ./... && go test ./...
```
Expected: no gofmt output, vet clean, build clean, all tests PASS.

- [ ] **Step 2: Module tidy is a no-op**

Run: `go mod tidy && git diff --exit-code go.mod go.sum`
Expected: no diff (no new external deps were introduced).

- [ ] **Step 3: No AI-assistant trailer on any commit**

Run: `git log origin/master..HEAD --format='%an <%ae>%n%b' | grep -i -E 'co-authored-by|claude|generated with' || echo "clean"`
Expected: `clean`.

- [ ] **Step 4: No regression in existing demos**

Run: `bash scripts/demo/p1-greet.sh && bash scripts/demo/p3b-mandate-greet.sh && bash scripts/demo/p4b-nonce-greet.sh`
Expected: each prints its `... demo OK` line (events/trigger are additive; default agents don't emit or expose the trigger).

---

## Self-Review

**Spec coverage:**
- Agents emit their own per-step events → Tasks 1–4 (events package + responder + guards + initiator). ✅
- Both-POV correlation → `X-ANS-Greet-Id` header (Task 2) + `GreetPeer` propagation (Task 4) + shared id in Task 5 smoke. ✅
- Trigger a specific agent-to-agent greet → `GreetPeer` (Task 4) + `--allow-trigger` endpoint (Task 5). ✅
- Wire body unchanged / TL untouched → only headers + stdout added; `sealCtx` keeps the same statement/receipt. ✅
- Fail-closed unchanged → guards keep identical error returns; emission is additive. ✅

**Placeholder scan:** `resolvePeerByName` is deliberately a stub with an explicit **Decision for the implementer** resolving it to role-scoped selection — no silent placeholder. All other steps carry complete code.

**Type consistency:** `events.Emitter`, `events.WithScope`, `events.Emit`, `events.GreetIDFromContext`, `events.NewGreetID` used identically across tasks; `WithEvents(em, name, role)`, `WithGreetID(id)`, `HeaderGreetID`, `GreetFunc(greetID, toRole, toName, text)`, `triggerReq/triggerResp` names are consistent between definition (Tasks 2/5) and use.

**Scope:** P5a stops at the agent boundary — no orchestrator, no browser, no launcher. Those are P5b, which will `exec` these `--events --allow-trigger` agents, tail stdout, correlate by `greetId`, and render the mocked-up canvas + drawer with the real TL seal as the audit capstone.
