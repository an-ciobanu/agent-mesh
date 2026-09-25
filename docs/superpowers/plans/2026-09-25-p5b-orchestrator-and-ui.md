# P5b — Orchestrator & Browser UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A single-command local demo where a browser shows the mesh's agents as circles that drift and collide; each collision triggers a **real** agent-to-agent greet, and clicking the interaction opens a sequence-diagram drawer reconstructed from the two agents' **own emitted events** (P5a), with the transparency-log seal as the audit capstone.

**Architecture:** A new `internal/orchestrator` package plus `cmd/orchestrator`. The orchestrator **spawns** the whole mesh as child processes (registry, transparency log, authority, and a roster of `--events --allow-trigger` agents), captures each agent's **stdout** (the P5a JSON event lines), and assembles them by `greetId` into interactions. It serves a static UI (`web/index.html`) plus `GET /agents` (the roster), `GET /events` (SSE of the live event stream), and `POST /collide` (which calls an agent's P5a `/trigger/greet` to start a real greet). The browser owns the physics (canvas) and, on each collision, POSTs `/collide` and renders the correlated events streamed back over SSE. Nothing about who-greets-whom or what-auth-is-needed is hardcoded — it is discovered at runtime by the agents, exactly as in P0–P4.

**Tech Stack:** Go stdlib (`net/http` SSE via `http.Flusher`, `os/exec` for child processes, `bufio.Scanner` for stdout), `zerolog`, the P5a `internal/events` package, the existing `internal/audit` package for the TL capstone, and a browser canvas UI (vanilla JS, ported from the approved mockup).

**Prerequisite:** P5a is merged (agents support `--events` and `--allow-trigger`; `internal/events` exists; `greet.GreetPeer` exists).

---

## File Structure

**New:**
- `internal/orchestrator/roster.go` — `Agent`, `Roster`, default roster, policy→UI-type/color mapping.
- `internal/orchestrator/roster_test.go`
- `internal/orchestrator/hub.go` — event ingestion → `Interaction` assembly + SSE broadcast.
- `internal/orchestrator/hub_test.go`
- `internal/orchestrator/driver.go` — `Collide` (calls an agent's `/trigger/greet`).
- `internal/orchestrator/driver_test.go`
- `internal/orchestrator/supervisor.go` — spawn/kill child processes, readiness probes, stdout capture → `hub.Ingest`.
- `cmd/orchestrator/main.go` — wire supervisor + hub + driver + HTTP endpoints; graceful shutdown.
- `web/index.html` — the browser UI (ported from the approved mockup, wired to live data).
- `scripts/demo/p5-ui.sh` — build + run the orchestrator + open the browser.
- `internal/integration/p5_test.go` — end-to-end: spawn the mesh, collide, assert a correlated accepted interaction.

**Modified:**
- `cmd/agent/main.go` — the trigger `greetFn` runs an audit of the sealed evidence against the TL and emits an `audit` event (the TL capstone). (Small, isolated; Task 3.)
- `Makefile` — add `orchestrator` to the build target (if it enumerates binaries).

**Ports (defaults):** registry `127.0.0.1:18090`, transparency `127.0.0.1:18091`, authority `127.0.0.1:18110`, greeters `127.0.0.1:18201+`, orchestrator UI `127.0.0.1:18080`.

**Default roster** (human names; type derived from policy):

| Name | Role | Policy | UI type | Color |
|------|------|--------|---------|-------|
| authority-1 | authority | (authority binary) | authority | gray |
| Ada | greeter-open | open | simple | red |
| Noah | greeter-open | open | simple | red |
| Ema | greeter-open | open | simple | red |
| Zoe | greeter-nonce | nonce | nonce | yellow |
| Chris | greeter-mandate | mandate | token | blue |

Any non-authority agent can be the initiator of a collision (all greeters get `--allow-trigger`); the required auth is discovered from the target's card at runtime.

---

### Task 1: Roster + policy→type/color mapping

**Files:** Create `internal/orchestrator/roster.go`, `internal/orchestrator/roster_test.go`

- [ ] **Step 1: Write the failing test**

```go
package orchestrator

import "testing"

func TestDefaultRosterMapsPolicyToType(t *testing.T) {
	r := DefaultRoster()
	byName := map[string]Agent{}
	for _, a := range r.Agents {
		byName[a.Name] = a
	}
	if got := byName["Ada"]; got.Type != "simple" || got.Color != "#f4523b" || got.Policy != "open" {
		t.Fatalf("Ada = %+v", got)
	}
	if got := byName["Zoe"]; got.Type != "nonce" || got.Color != "#f2c94c" {
		t.Fatalf("Zoe = %+v", got)
	}
	if got := byName["Chris"]; got.Type != "token" || got.Color != "#4aa3ff" {
		t.Fatalf("Chris = %+v", got)
	}
	if got := byName["authority-1"]; got.Type != "authority" {
		t.Fatalf("authority = %+v", got)
	}
}

func TestRosterByName(t *testing.T) {
	r := DefaultRoster()
	a, ok := r.ByName("Zoe")
	if !ok || a.Role != "greeter-nonce" {
		t.Fatalf("ByName(Zoe) = %+v ok=%v", a, ok)
	}
	if _, ok := r.ByName("nobody"); ok {
		t.Fatalf("ByName(nobody) should be false")
	}
}

func TestGreetersHaveDistinctAddrs(t *testing.T) {
	seen := map[string]bool{}
	for _, a := range DefaultRoster().Agents {
		if seen[a.Addr] {
			t.Fatalf("duplicate addr %s", a.Addr)
		}
		seen[a.Addr] = true
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/orchestrator/`
Expected: FAIL (package missing).

- [ ] **Step 3: Implement `internal/orchestrator/roster.go`**

```go
// Package orchestrator runs the P5 demo mesh: it spawns the registry, the
// transparency log, an authority, and a roster of event-emitting agents; it
// captures the agents' event streams and assembles them, by greet id, into the
// two-point-of-view interactions the browser renders.
package orchestrator

// UI colors (must match web/index.html).
const (
	ColorSimple    = "#f4523b" // open   greeter -> red
	ColorNonce     = "#f2c94c" // nonce  greeter -> yellow
	ColorToken     = "#4aa3ff" // mandate greeter -> blue
	ColorAuthority = "#8b93a7" // authority -> gray
)

// Agent is one member of the demo mesh.
type Agent struct {
	Name   string `json:"name"`
	Role   string `json:"role"`
	Policy string `json:"policy"` // open | nonce | mandate | authority
	Type   string `json:"type"`   // simple | nonce | token | authority (UI)
	Color  string `json:"color"`
	Addr   string `json:"-"`      // host:port (not exposed to the browser)
}

// BaseURL returns the agent's HTTP base URL.
func (a Agent) BaseURL() string { return "http://" + a.Addr }

// Roster is the set of agents in the demo.
type Roster struct {
	Agents []Agent
}

// ByName returns the agent with the given name.
func (r Roster) ByName(name string) (Agent, bool) {
	for _, a := range r.Agents {
		if a.Name == name {
			return a, true
		}
	}
	return Agent{}, false
}

// Greeters returns the non-authority agents (the collidable ones).
func (r Roster) Greeters() []Agent {
	var out []Agent
	for _, a := range r.Agents {
		if a.Policy != "authority" {
			out = append(out, a)
		}
	}
	return out
}

func mkAgent(name, role, policy, addr string) Agent {
	a := Agent{Name: name, Role: role, Policy: policy, Addr: addr}
	switch policy {
	case "open":
		a.Type, a.Color = "simple", ColorSimple
	case "nonce":
		a.Type, a.Color = "nonce", ColorNonce
	case "mandate":
		a.Type, a.Color = "token", ColorToken
	case "authority":
		a.Type, a.Color = "authority", ColorAuthority
	}
	return a
}

// DefaultRoster is the demo's fixed set of agents. Circles in the UI are these
// real processes; the count is a launch-time property (real OS processes), not a
// browser slider.
func DefaultRoster() Roster {
	return Roster{Agents: []Agent{
		mkAgent("authority-1", "authority", "authority", "127.0.0.1:18110"),
		mkAgent("Ada", "greeter-open", "open", "127.0.0.1:18201"),
		mkAgent("Noah", "greeter-open", "open", "127.0.0.1:18202"),
		mkAgent("Ema", "greeter-open", "open", "127.0.0.1:18205"),
		mkAgent("Zoe", "greeter-nonce", "nonce", "127.0.0.1:18203"),
		mkAgent("Chris", "greeter-mandate", "mandate", "127.0.0.1:18204"),
	}}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/orchestrator/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/orchestrator/roster.go internal/orchestrator/roster_test.go
git commit -m "feat(orchestrator): agent roster + policy-to-UI-type/color mapping"
```

---

### Task 2: Hub — interaction assembly + SSE

**Files:** Create `internal/orchestrator/hub.go`, `internal/orchestrator/hub_test.go`

The hub ingests P5a events (from agent stdout), groups them by `greetId` into an `Interaction` (deriving from/to/type/verdict), and broadcasts every event to SSE subscribers.

- [ ] **Step 1: Write the failing test**

```go
package orchestrator

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/events"
)

func ev(greetID, agent, role, step, status string, detail map[string]string) events.Event {
	return events.Event{GreetID: greetID, Agent: agent, Role: role, Step: step, Status: status, Detail: detail, TS: time.Now()}
}

func TestHubAssemblesInteractionAndVerdict(t *testing.T) {
	h := NewHub(zerolog.Nop())
	h.Ingest(ev("g1", "Noah", events.RoleInitiator, "card.read", events.StatusOK, map[string]string{"peer": "Ada"}))
	h.Ingest(ev("g1", "Noah", events.RoleInitiator, "requirement", events.StatusInfo, map[string]string{"type": "open"}))
	h.Ingest(ev("g1", "Ada", events.RoleResponder, "jws.verify", events.StatusOK, nil))
	h.Ingest(ev("g1", "Ada", events.RoleResponder, "gate", events.StatusOK, nil))
	h.Ingest(ev("g1", "Noah", events.RoleInitiator, "greet.reply", events.StatusOK, map[string]string{"reply": "hi"}))

	it, ok := h.Interaction("g1")
	if !ok {
		t.Fatal("no interaction")
	}
	if it.From != "Noah" || it.To != "Ada" || it.Type != "open" {
		t.Fatalf("from/to/type = %s/%s/%s", it.From, it.To, it.Type)
	}
	if it.Verdict != "accepted" {
		t.Fatalf("verdict = %q", it.Verdict)
	}
	if len(it.Events) != 5 {
		t.Fatalf("events = %d", len(it.Events))
	}
}

func TestHubRejectionVerdict(t *testing.T) {
	h := NewHub(zerolog.Nop())
	h.Ingest(ev("g2", "Noah", events.RoleInitiator, "requirement", events.StatusInfo, map[string]string{"type": "nonce"}))
	h.Ingest(ev("g2", "Zoe", events.RoleResponder, "gate", events.StatusFail, map[string]string{"reason": "nonce already used"}))
	h.Ingest(ev("g2", "Noah", events.RoleInitiator, "greet.rejected", events.StatusFail, map[string]string{"error": "greet rejected"}))
	it, _ := h.Interaction("g2")
	if it.Verdict != "rejected" || it.Reason == "" {
		t.Fatalf("verdict=%q reason=%q", it.Verdict, it.Reason)
	}
}

func TestHubBroadcastsToSubscribers(t *testing.T) {
	h := NewHub(zerolog.Nop())
	ch, cancel := h.Subscribe()
	defer cancel()
	h.Ingest(ev("g3", "Ada", events.RoleResponder, "gate", events.StatusOK, nil))

	select {
	case raw := <-ch:
		var e events.Event
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatalf("bad frame: %v", err)
		}
		if e.GreetID != "g3" || e.Step != "gate" {
			t.Fatalf("frame = %+v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("no broadcast received")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/orchestrator/ -run Hub`
Expected: FAIL (`NewHub` undefined).

- [ ] **Step 3: Implement `internal/orchestrator/hub.go`**

```go
package orchestrator

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/events"
)

// Interaction is the assembled, both-point-of-view record of one greet.
type Interaction struct {
	GreetID string         `json:"greetId"`
	From    string         `json:"from"`
	To      string         `json:"to"`
	Type    string         `json:"type"` // open | nonce | mandate (from initiator's requirement)
	Verdict string         `json:"verdict"` // "" | accepted | rejected
	Reason  string         `json:"reason,omitempty"`
	Events  []events.Event `json:"events"`
}

// Hub ingests agent events, assembles interactions, and fans out every event to
// SSE subscribers.
type Hub struct {
	mu    sync.Mutex
	inter map[string]*Interaction
	subs  map[chan []byte]struct{}
	log   zerolog.Logger
}

// NewHub builds an empty hub.
func NewHub(log zerolog.Logger) *Hub {
	return &Hub{
		inter: map[string]*Interaction{},
		subs:  map[chan []byte]struct{}{},
		log:   log.With().Str("component", "hub").Logger(),
	}
}

// Ingest records one event and broadcasts it.
func (h *Hub) Ingest(e events.Event) {
	h.mu.Lock()
	it := h.inter[e.GreetID]
	if it == nil {
		it = &Interaction{GreetID: e.GreetID}
		h.inter[e.GreetID] = it
	}
	it.Events = append(it.Events, e)
	if e.Role == events.RoleInitiator && it.From == "" {
		it.From = e.Agent
	}
	if e.Role == events.RoleResponder && it.To == "" {
		it.To = e.Agent
	}
	switch e.Step {
	case "requirement":
		if t := e.Detail["type"]; t != "" {
			it.Type = t
		}
	case "greet.reply":
		it.Verdict = "accepted"
	case "greet.rejected":
		it.Verdict = "rejected"
		if r := e.Detail["error"]; r != "" {
			it.Reason = r
		}
	case "gate":
		if e.Status == events.StatusFail && it.Reason == "" {
			it.Reason = e.Detail["reason"]
		}
	}
	h.mu.Unlock()

	frame, err := json.Marshal(e)
	if err != nil {
		h.log.Error().Err(err).Msg("marshal event frame")
		return
	}
	h.broadcast(frame)
}

func (h *Hub) broadcast(frame []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- frame:
		default: // drop for a slow subscriber; never block ingestion
		}
	}
}

// Subscribe returns a channel of event frames and a cancel func.
func (h *Hub) Subscribe() (<-chan []byte, func()) {
	ch := make(chan []byte, 64)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		if _, ok := h.subs[ch]; ok {
			delete(h.subs, ch)
			close(ch)
		}
		h.mu.Unlock()
	}
}

// Interaction returns a copy-ish snapshot of the interaction for greetID.
func (h *Hub) Interaction(greetID string) (Interaction, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	it, ok := h.inter[greetID]
	if !ok {
		return Interaction{}, false
	}
	return *it, true
}

// ServeSSE streams events to the browser as Server-Sent Events.
func (h *Hub) ServeSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch, cancel := h.Subscribe()
	defer cancel()
	for {
		select {
		case <-r.Context().Done():
			return
		case frame, ok := <-ch:
			if !ok {
				return
			}
			if _, err := w.Write([]byte("data: ")); err != nil {
				return
			}
			if _, err := w.Write(frame); err != nil {
				return
			}
			if _, err := w.Write([]byte("\n\n")); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/orchestrator/ -run Hub`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/orchestrator/hub.go internal/orchestrator/hub_test.go
git commit -m "feat(orchestrator): event hub — interaction assembly + SSE broadcast"
```

---

### Task 3: TL audit capstone — initiator emits an `audit` event

**Files:** Modify `cmd/agent/main.go`

The greeter seals accepted greets and returns the evidence to the initiator in the A2A response (P2/P5a). Here the initiator, when it receives evidence, independently audits it against the transparency log (reusing `internal/audit`, exactly as `meshctl greet --audit` does) and emits an `audit` event — making the drawer's capstone a real, verified inclusion proof rather than a claim.

- [ ] **Step 1: Extend the trigger `greetFn` (no unit test — covered by Task 8 integration + smoke)**

In `cmd/agent/main.go`, the P5a `greetFn` currently discards the evidence: `reply, _, err := greet.GreetPeer(...)`. Change it to capture and audit the evidence, and add a `--transparency` awareness for the audit (the greeter already gets `--transparency` for sealing; the initiator uses the same URL to fetch the TL pubkey). Update the closure:

```go
		greetFn := func(greetID, toRole, toName, text string) (string, bool, error) {
			if toRole == "" {
				return "", false, fmt.Errorf("toRole is required")
			}
			gctx := events.WithScope(context.Background(), em, greetID, *name, events.RoleInitiator)
			peers, serr := disco.Search(gctx, toRole)
			if serr != nil {
				return "", false, fmt.Errorf("discover role %q: %w", toRole, serr)
			}
			if len(peers) == 0 {
				return "", false, fmt.Errorf("no agents found for role %q", toRole)
			}
			peer := peers[0]
			if toName != "" {
				found := false
				for _, p := range peers {
					if p.Name == toName {
						peer, found = p, true
						break
					}
				}
				if !found {
					return "", false, fmt.Errorf("no agent named %q in role %q", toName, toRole)
				}
			}
			reply, evidence, err := greet.GreetPeer(gctx, res, a2aCli, mcpCli, disco, priv, selfAns, peer, text)
			if err != nil {
				return "", false, err
			}
			auditEvidence(gctx, *transparencyURL, evidence, log)
			return reply, true, nil
		}
```

Add a helper in `cmd/agent/main.go`:

```go
// auditEvidence independently verifies the greeter's sealed evidence against the
// transparency log and emits an `audit` event so the UI can show the TL capstone
// (real inclusion proof), not just a claim. Best-effort: any failure emits a
// fail-status audit event and returns.
func auditEvidence(ctx context.Context, tlURL string, evidence *domain.EvidenceBundle, log zerolog.Logger) {
	if evidence == nil {
		events.Emit(ctx, "audit", events.StatusInfo, map[string]string{"note": "no evidence (greeter not sealing)"})
		return
	}
	if tlURL == "" {
		events.Emit(ctx, "audit", events.StatusInfo, map[string]string{
			"entryIndex": strconv.Itoa(evidence.Receipt.EntryIndex),
			"treeSize":   strconv.Itoa(evidence.Receipt.TreeSize),
			"note":       "sealed; no --transparency to audit",
		})
		return
	}
	tlPub, err := transparency.New(tlURL).FetchPubKey(ctx)
	if err != nil {
		events.Emit(ctx, "audit", events.StatusFail, map[string]string{"error": "fetch TL pubkey: " + err.Error()})
		return
	}
	auditorPriv, err := crypto.GenerateEd25519()
	if err != nil {
		events.Emit(ctx, "audit", events.StatusFail, map[string]string{"error": "gen auditor key: " + err.Error()})
		return
	}
	verdict, _, err := audit.New(domain.LocalANSName("auditor"), auditorPriv, log).Verify(ctx, *evidence, tlPub)
	if err != nil {
		events.Emit(ctx, "audit", events.StatusFail, map[string]string{"error": err.Error()})
		return
	}
	events.Emit(ctx, "audit", events.StatusOK, map[string]string{
		"verdict":    string(verdict.Verdict),
		"entryIndex": strconv.Itoa(evidence.Receipt.EntryIndex),
		"treeSize":   strconv.Itoa(evidence.Receipt.TreeSize),
	})
}
```

Add imports to `cmd/agent/main.go` as needed: `"strconv"`, `"github.com/an-ciobanu/agent-mesh/internal/audit"`. (`transparency`, `crypto`, `domain`, `events` are already imported.) Note: `verdict.Verdict`'s concrete type — check `internal/audit` for the field/type; if it is already a string, drop the `string(...)` conversion. Confirm against the `runGreet`/`--audit` code in `cmd/meshctl/main.go`, which calls `audit.New(...).Verify(...)` and prints `verdict.Verdict`.

- [ ] **Step 2: Build + vet**

Run: `go build ./... && go vet ./cmd/agent/`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add cmd/agent/main.go
git commit -m "feat(agent): initiator audits sealed evidence against TL and emits audit event"
```

---

### Task 4: Driver — POST /collide → agent trigger

**Files:** Create `internal/orchestrator/driver.go`, `internal/orchestrator/driver_test.go`

- [ ] **Step 1: Write the failing test**

```go
package orchestrator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDriverCollideCallsInitiatorTrigger(t *testing.T) {
	var gotBody map[string]string
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/trigger/greet" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]any{"greetId": "gX", "reply": "hi", "accepted": true})
	}))
	defer stub.Close()

	r := Roster{Agents: []Agent{
		{Name: "Noah", Role: "greeter-open", Policy: "open", Addr: stub.Listener.Addr().String()},
		{Name: "Ada", Role: "greeter-open", Policy: "open", Addr: "127.0.0.1:1"},
	}}
	d := NewDriver(r)

	greetID, err := d.Collide(context.Background(), "Noah", "Ada")
	if err != nil {
		t.Fatalf("Collide: %v", err)
	}
	if greetID != "gX" {
		t.Fatalf("greetID = %q", greetID)
	}
	if gotBody["toRole"] != "greeter-open" || gotBody["toName"] != "Ada" {
		t.Fatalf("trigger body = %+v", gotBody)
	}
}

func TestDriverCollideRejectsAuthorityTarget(t *testing.T) {
	r := Roster{Agents: []Agent{
		{Name: "Noah", Role: "greeter-open", Policy: "open", Addr: "127.0.0.1:1"},
		{Name: "authority-1", Role: "authority", Policy: "authority", Addr: "127.0.0.1:2"},
	}}
	if _, err := NewDriver(r).Collide(context.Background(), "Noah", "authority-1"); err == nil {
		t.Fatal("greeting the authority should error")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/orchestrator/ -run Driver`
Expected: FAIL.

- [ ] **Step 3: Implement `internal/orchestrator/driver.go`**

```go
package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Driver turns a browser collision into a real agent-to-agent greet by calling
// the initiator agent's P5a /trigger/greet endpoint.
type Driver struct {
	roster Roster
	http   *http.Client
}

// NewDriver builds a Driver over the roster.
func NewDriver(r Roster) *Driver {
	return &Driver{roster: r, http: &http.Client{Timeout: 10 * time.Second}}
}

// Collide makes agent `from` greet agent `to`. It returns the greet id so the
// browser can correlate the SSE events. The target must not be the authority.
func (d *Driver) Collide(ctx context.Context, from, to string) (string, error) {
	fromAgent, ok := d.roster.ByName(from)
	if !ok {
		return "", fmt.Errorf("unknown initiator %q", from)
	}
	toAgent, ok := d.roster.ByName(to)
	if !ok {
		return "", fmt.Errorf("unknown target %q", to)
	}
	if toAgent.Policy == "authority" {
		return "", fmt.Errorf("the authority is not greetable")
	}
	body, _ := json.Marshal(map[string]string{"toRole": toAgent.Role, "toName": toAgent.Name, "text": "hi " + toAgent.Name})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fromAgent.BaseURL()+"/trigger/greet", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("trigger %s: %w", from, err)
	}
	defer resp.Body.Close()
	var out struct {
		GreetID string `json:"greetId"`
		Error   string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode trigger response: %w", err)
	}
	if out.GreetID == "" {
		return "", fmt.Errorf("trigger returned no greet id (error: %s)", out.Error)
	}
	return out.GreetID, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/orchestrator/ -run Driver`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/orchestrator/driver.go internal/orchestrator/driver_test.go
git commit -m "feat(orchestrator): driver turns a collision into a real triggered greet"
```

---

### Task 5: Supervisor — spawn the mesh + capture agent stdout

**Files:** Create `internal/orchestrator/supervisor.go`

Spawns the child processes and streams each agent's stdout (P5a JSON event lines) into `hub.Ingest`. This is process-heavy; it is exercised by the Task 8 integration test rather than a unit test.

- [ ] **Step 1: Implement `internal/orchestrator/supervisor.go`**

```go
package orchestrator

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/events"
)

// Supervisor spawns and supervises the demo mesh's child processes.
type Supervisor struct {
	bin         string // directory holding the built binaries (e.g. "bin")
	registry    string // host:port
	transparency string
	roster      Roster
	hub         *Hub
	log         zerolog.Logger

	mu   sync.Mutex
	cmds []*exec.Cmd
}

// NewSupervisor builds a supervisor. binDir holds the compiled binaries.
func NewSupervisor(binDir, registryAddr, transparencyAddr string, roster Roster, hub *Hub, log zerolog.Logger) *Supervisor {
	return &Supervisor{
		bin: binDir, registry: registryAddr, transparency: transparencyAddr,
		roster: roster, hub: hub, log: log.With().Str("component", "supervisor").Logger(),
	}
}

// Start launches registry, transparency, authority, and agents in order, waiting
// for each tier's readiness. Agent stdout is streamed into the hub.
func (s *Supervisor) Start(ctx context.Context) error {
	regURL := "http://" + s.registry
	tlURL := "http://" + s.transparency

	if err := s.spawn(ctx, "registry", nil, s.bin+"/registry", "--addr", s.registry); err != nil {
		return err
	}
	if err := waitReady(ctx, regURL+"/agents", 5*time.Second); err != nil {
		return fmt.Errorf("registry not ready: %w", err)
	}
	if err := s.spawn(ctx, "transparency", nil, s.bin+"/transparency", "--addr", s.transparency); err != nil {
		return err
	}
	if err := waitReady(ctx, tlURL+"/root-keys", 5*time.Second); err != nil {
		s.log.Warn().Err(err).Msg("transparency readiness probe failed; continuing")
	}
	// Authority (if present in the roster).
	for _, a := range s.roster.Agents {
		if a.Policy != "authority" {
			continue
		}
		if err := s.spawn(ctx, a.Name, nil, s.bin+"/authority", "--name", a.Name, "--addr", a.Addr, "--registry", regURL); err != nil {
			return err
		}
		if err := waitReady(ctx, a.BaseURL()+"/.well-known/agent-card.json", 5*time.Second); err != nil {
			s.log.Warn().Err(err).Str("authority", a.Name).Msg("authority readiness probe failed; continuing")
		}
	}
	// Greeters — all emit events and expose the trigger endpoint; all seal.
	for _, a := range s.roster.Greeters() {
		args := []string{
			"--name", a.Name, "--role", a.Role, "--addr", a.Addr,
			"--registry", regURL, "--transparency", tlURL,
			"--policy", a.Policy, "--events", "--allow-trigger",
		}
		if a.Policy == "mandate" {
			args = append(args, "--authority-role", "authority", "--scope", "greet")
		}
		if err := s.spawn(ctx, a.Name, s.hub, s.bin+"/agent", args...); err != nil {
			return err
		}
	}
	// Give agents a moment to register + (mandate greeters) pin the authority.
	for _, a := range s.roster.Greeters() {
		_ = waitReady(ctx, a.BaseURL()+"/.well-known/agent-card.json", 8*time.Second)
	}
	return nil
}

// spawn starts one child. If hub != nil, the child's stdout is parsed as event
// JSON lines and ingested (used for agents). stderr is left attached to the
// orchestrator's stderr for debugging by inheriting it is avoided — we discard.
func (s *Supervisor) spawn(ctx context.Context, name string, hub *Hub, path string, args ...string) error {
	cmd := exec.CommandContext(ctx, path, args...)
	if hub != nil {
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return fmt.Errorf("stdout pipe for %s: %w", name, err)
		}
		go s.pump(name, hub, stdout)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", name, err)
	}
	s.mu.Lock()
	s.cmds = append(s.cmds, cmd)
	s.mu.Unlock()
	s.log.Info().Str("proc", name).Int("pid", cmd.Process.Pid).Msg("spawned")
	return nil
}

func (s *Supervisor) pump(name string, hub *Hub, r interface{ Read([]byte) (int, error) }) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 || line[0] != '{' {
			continue // ignore non-event noise
		}
		var e events.Event
		if err := json.Unmarshal(line, &e); err != nil {
			continue
		}
		hub.Ingest(e)
	}
}

// Stop terminates all child processes.
func (s *Supervisor) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.cmds {
		if c.Process != nil {
			_ = c.Process.Kill()
		}
	}
}

func waitReady(ctx context.Context, url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	cli := &http.Client{Timeout: 500 * time.Millisecond}
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := cli.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
	}
	return fmt.Errorf("timeout waiting for %s", url)
}
```

> **Implementer note:** confirm the registry readiness path (`/agents`) and the transparency path (`/root-keys`) against `internal/registry` and `internal/tl` route registrations; adjust the probe URLs to real GET routes if these differ. `exec.CommandContext` ensures children are killed when the context is cancelled, and `Stop()` is a belt-and-braces kill.

- [ ] **Step 2: Build + vet**

Run: `go build ./... && go vet ./internal/orchestrator/`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add internal/orchestrator/supervisor.go
git commit -m "feat(orchestrator): supervisor spawns the mesh and streams agent events into the hub"
```

---

### Task 6: `cmd/orchestrator` — HTTP endpoints + lifecycle

**Files:** Create `cmd/orchestrator/main.go`; modify `Makefile` if it enumerates binaries.

- [ ] **Step 1: Implement `cmd/orchestrator/main.go`**

```go
// Command orchestrator runs the P5 demo: it spawns the mesh (registry,
// transparency log, authority, and a roster of event-emitting agents), captures
// their event streams, and serves a browser UI that turns canvas collisions into
// real agent-to-agent greets rendered from the agents' own events.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/orchestrator"
)

func main() {
	uiAddr := flag.String("addr", "127.0.0.1:18080", "UI listen address")
	binDir := flag.String("bin", "bin", "directory containing the built binaries")
	webDir := flag.String("web", "web", "directory containing index.html")
	registryAddr := flag.String("registry", "127.0.0.1:18090", "registry listen address")
	tlAddr := flag.String("transparency", "127.0.0.1:18091", "transparency log listen address")
	flag.Parse()

	log := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Str("component", "orchestrator").Logger()

	roster := orchestrator.DefaultRoster()
	hub := orchestrator.NewHub(log)
	driver := orchestrator.NewDriver(roster)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sup := orchestrator.NewSupervisor(*binDir, *registryAddr, *tlAddr, roster, hub, log)
	if err := sup.Start(ctx); err != nil {
		log.Fatal().Err(err).Msg("start mesh")
	}
	defer sup.Stop()

	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServer(http.Dir(*webDir)))
	mux.HandleFunc("GET /agents", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(roster.Agents)
	})
	mux.HandleFunc("GET /events", hub.ServeSSE)
	mux.HandleFunc("POST /collide", func(w http.ResponseWriter, r *http.Request) {
		var body struct{ From, To string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		greetID, err := driver.Collide(r.Context(), body.From, body.To)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		from, _ := roster.ByName(body.From)
		to, _ := roster.ByName(body.To)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"greetId": greetID, "from": from.Name, "to": to.Name, "type": to.Type,
		})
	})

	srv := &http.Server{Addr: *uiAddr, Handler: mux}
	go func() {
		log.Info().Str("addr", *uiAddr).Msg("orchestrator UI listening — open http://" + *uiAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("ui server exited")
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Info().Msg("shutting down mesh")
	shutdownCtx, c := context.WithTimeout(context.Background(), 3*time.Second)
	defer c()
	_ = srv.Shutdown(shutdownCtx)
	cancel()
	sup.Stop()
}
```

- [ ] **Step 2: Build**

Run: `go build ./cmd/orchestrator/ && go vet ./cmd/orchestrator/`
Expected: clean. If the `Makefile` `build` target enumerates binaries, add `orchestrator` so `make build` produces `bin/orchestrator`; verify with `grep -n orchestrator Makefile` after editing.

- [ ] **Step 3: Commit**

```bash
git add cmd/orchestrator/main.go Makefile
git commit -m "feat(orchestrator): cmd/orchestrator — UI, /agents, /events SSE, /collide"
```

---

### Task 7: `web/index.html` — the browser UI (live data)

**Files:** Create `web/index.html`; create `scripts/demo/p5-ui.sh`

The approved visual mockup already exists on disk at
`/Users/aciobanu/Dev/Personal/Full_Projects/ans/agent-mesh/.superpowers/brainstorm/34289-1790348672/content/circles-ui-v2.html`
(gitignored). **Read it and copy it to `web/index.html` as the base**, keeping its dark theme, canvas physics, colors (simple=red `#f4523b`, nonce=yellow `#f2c94c`, token=blue `#4aa3ff`, authority=gray `#8b93a7`), the **speed** slider, the **pause** button, and the click-to-inspect **bottom drawer** with the sequence diagram + expandable rows. Then apply the wiring changes below to replace the *simulated* data with live orchestrator data. (If that file is unavailable, reconstruct the same UI from this description — the wiring code below is the authoritative contract.)

Changes to make:

**(a) Remove the simulated roster + the agent-count slider.** Circles are the real launched agents (fixed roster); keep the speed slider and pause button. Delete the `NAMES`/`buildAgents(n)` random generation and the `#countRange` control. Load the roster from the orchestrator instead:

```js
let agents = [];
async function loadAgents(){
  const res = await fetch('/agents');
  const roster = await res.json(); // [{name, role, policy, type, color}]
  agents = roster.map(a => ({
    name: a.name, type: a.type, color: a.color, policy: a.policy,
    r: a.type === 'authority' ? 24 : 27,
    x: 80 + Math.random()*(Math.max(1,W-160)),
    y: 80 + Math.random()*(Math.max(1,H-160)),
    flash: 0,
  }));
  for (const a of agents){ const s=0.6+Math.random()*0.5, ang=Math.random()*Math.PI*2; a.vx=Math.cos(ang)*s; a.vy=Math.sin(ang)*s; }
}
```
Use `a.color` (from the roster) wherever the mockup used `COL[a.type]`. Keep the `LABEL` map for the small type caption.

**(b) On collision, call the real orchestrator** instead of the simulated `runGreet`. Keep the collision detection + cooldown; replace the trigger:

```js
async function collide(iniName, tgtName){
  try {
    const res = await fetch('/collide', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ From: iniName, To: tgtName }),
    });
    const out = await res.json();
    if (out.error){ return; }                 // e.g. greeting the authority
    interactions[out.greetId] = { greetId: out.greetId, from: out.from, to: out.to, type: out.type, events: [], verdict: '', reason: '' };
    addLogEntry(out.greetId);                  // create the stream row now; SSE fills it
  } catch (e) { /* ignore transient */ }
}
```
In the collision handler, pick initiator/target as the mockup does (skip if target is authority), flash both, then `collide(agents[ini].name, agents[tgt].name)`.

**(c) Consume SSE and assemble interactions client-side**, keyed by greetId:

```js
const interactions = {}; // greetId -> {from,to,type,events,verdict,reason}
const es = new EventSource('/events');
es.onmessage = (m) => {
  const e = JSON.parse(m.data); // one P5a event
  const it = interactions[e.greetId] || (interactions[e.greetId] = {greetId:e.greetId, from:'', to:'', type:'', events:[], verdict:'', reason:''});
  it.events.push(e);
  if (e.role === 'initiator' && !it.from) it.from = e.agent;
  if (e.role === 'responder' && !it.to)   it.to = e.agent;
  if (e.step === 'requirement' && e.detail && e.detail.type) it.type = e.detail.type;
  if (e.step === 'greet.reply')    it.verdict = 'accepted';
  if (e.step === 'greet.rejected'){ it.verdict = 'rejected'; it.reason = (e.detail && e.detail.error) || it.reason; }
  if (e.step === 'gate' && e.status === 'fail' && !it.reason) it.reason = e.detail && e.detail.reason;
  updateLogEntry(it);                          // refresh the stream row's verdict/steps
  drawLinkFor(it);                             // color the canvas link (pending/ok/bad) as in the mockup
  if (drawerGreetID === e.greetId) renderDrawer(it); // live-update if this interaction is open
};
```

**(d) Build the drawer's sequence model from real events** — replace the mockup's simulated `buildDetail(...)` with `modelFromEvents(it)` that maps P5a steps to the lane/step model the existing drawer renderer already consumes (lanes, msg/chk rows, expandable `raw` = the event's `detail`):

```js
function modelFromEvents(it){
  const isToken = it.type === 'mandate' || it.type === 'token';
  const authName = (it.events.find(e => e.step==='mandate.acquire')?.detail?.authority) || 'authority';
  const lanes = isToken
    ? [{name:it.from,role:colorType(it.from),sub:'initiator'},{name:authName,role:'authority',sub:'authority'},{name:it.to,role:colorType(it.to),sub:'greeter · token'}]
    : [{name:it.from,role:colorType(it.from),sub:'initiator'},{name:it.to,role:colorType(it.to),sub:'greeter'}];
  const R = isToken ? 2 : 1; // responder lane index
  const steps = [];
  for (const e of it.events){
    const raw = e.detail || {};
    switch (e.step){
      case 'card.read':      steps.push({t:'msg', from:0, to:R, label:'GET agent-card', head:'►', raw}); break;
      case 'mandate.acquire':
        steps.push({t:'msg', from:0, to:1, label:'POST /mcp issue_mandate', head:'►', raw});
        steps.push({t:'msg', from:1, to:0, cls:'res', label:'COSE token', head:'◄', raw}); break;
      case 'nonce.get':      steps.push({t:'msg', from:0, to:R, label:'MCP get_nonce → nonce', head:'►', raw}); break;
      case 'dpop.build':     steps.push({t:'chk', lane:0, status:e.status, label:'build DPoP proof', raw}); break;
      case 'greet.send':     steps.push({t:'msg', from:0, to:R, label:'POST /a2a greet + JWS', head:'►', raw}); break;
      case 'jws.verify':     steps.push({t:'chk', lane:R, status:e.status, label:'verify identity JWS', raw}); break;
      case 'mandate.verify': steps.push({t:'chk', lane:R, status:e.status, label:'verify COSE mandate', raw}); break;
      case 'authority.pin':  steps.push({t:'chk', lane:R, status:e.status, label:'pin authority key', raw}); break;
      case 'dpop.verify':    steps.push({t:'chk', lane:R, status:e.status, label:'verify DPoP proof', raw}); break;
      case 'nonce.consume':  steps.push({t:'chk', lane:R, status:e.status, label:'consume nonce (single-use)', raw}); break;
      case 'gate':           steps.push({t:'chk', lane:R, status:e.status, label:'gate', raw}); break;
      case 'seal':           steps.push({t:'chk', lane:R, status:e.status, label:'seal → receipt #'+(raw.entryIndex??'?'), raw}); break;
      case 'audit':          steps.push({t:'chk', lane:0, status:e.status, label:'audit vs TL: '+(raw.verdict||raw.note||''), raw}); break;
      case 'greet.reply':    steps.push({t:'msg', from:R, to:0, cls:'ok', label:'200 · reply', head:'◄', raw}); break;
    }
  }
  // Dedupe consecutive identical (t,label,status) rows (e.g. the open path's double 'gate ok').
  const deduped = steps.filter((s,i)=> i===0 || !(s.t===steps[i-1].t && s.label===steps[i-1].label && s.status===steps[i-1].status && s.lane===steps[i-1].lane));
  return { from:it.from, to:it.to, type:it.type, time:new Date().toLocaleTimeString([],{hour12:false}),
           accepted: it.verdict==='accepted', reason: it.reason, lanes, steps: deduped };
}
function colorType(name){ const a = agents.find(x=>x.name===name); return a ? a.type : 'simple'; }
```

Keep the mockup's existing drawer DOM + `renderDrawer`/lane-rendering/expandable-raw code, but have it consume `modelFromEvents(it)`; track `drawerGreetID` so `openDrawer(greetId)` looks up `interactions[greetId]`, and the SSE handler live-updates the open drawer. `addLogEntry`/`updateLogEntry` are small adaptations of the mockup's log-append/finish code, keyed by greetId, each row clickable → `openDrawer(greetId)`.

**(e) Boot:** `await loadAgents()` before starting the animation loop; open the EventSource; keep the speed slider + pause button wiring unchanged.

- [ ] **Step 2: Create `scripts/demo/p5-ui.sh`**

```bash
#!/usr/bin/env bash
# P5 UI demo: build everything, launch the orchestrator (which spawns the whole
# mesh — registry, transparency log, authority, and a roster of event-emitting
# agents), and open the browser. Each collision on the canvas triggers a REAL
# agent-to-agent greet; click an interaction to see the two agents' own events.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

make build
go build -o bin/orchestrator ./cmd/orchestrator

UI_ADDR="127.0.0.1:18080"
echo "== starting orchestrator on http://$UI_ADDR =="
./bin/orchestrator --addr "$UI_ADDR" &
ORCH=$!
cleanup() { kill "$ORCH" 2>/dev/null || true; }
trap cleanup EXIT

sleep 3
URL="http://$UI_ADDR"
if command -v open >/dev/null 2>&1; then open "$URL"; else echo "open $URL"; fi

echo "orchestrator running (pid $ORCH). Press Ctrl-C to stop the whole mesh."
wait "$ORCH"
```

Make it executable: `chmod +x scripts/demo/p5-ui.sh`.

- [ ] **Step 3: Manual smoke (documented; not automated here)**

Run: `bash scripts/demo/p5-ui.sh`, open `http://127.0.0.1:18080`, confirm circles appear (Ada/Noah/Ema red, Zoe yellow, Chris blue, authority-1 gray), collisions produce log entries with accepted/rejected verdicts, and clicking one opens the drawer with real steps + an `audit vs TL` capstone. Ctrl-C stops the whole mesh (no orphan processes: `pgrep -f 'bin/(agent|authority|registry|transparency)'` returns nothing).

- [ ] **Step 4: Commit**

```bash
git add web/index.html scripts/demo/p5-ui.sh
git commit -m "feat(ui): browser UI wired to live orchestrator events + p5-ui launcher"
```

---

### Task 8: End-to-end integration test + gate

**Files:** Create `internal/integration/p5_test.go`

- [ ] **Step 1: Write the integration test**

This spins up the real mesh via the supervisor with a minimal roster, drives one collision through the driver, and asserts the hub assembled a correlated, accepted interaction with events from both agents. It builds the binaries first. Guard with `testing.Short()` so `go test -short` skips it.

```go
package integration

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/orchestrator"
)

func TestP5OrchestratorCollideEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real processes; skipped in -short")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	binDir := t.TempDir()
	for _, b := range []string{"registry", "transparency", "authority", "agent"} {
		cmd := exec.Command("go", "build", "-o", filepath.Join(binDir, b), "./cmd/"+b)
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", b, err, out)
		}
	}

	// Minimal roster on ports unlikely to clash with the demo defaults.
	roster := orchestrator.Roster{Agents: []orchestrator.Agent{
		{Name: "Ada", Role: "greeter-open", Policy: "open", Type: "simple", Addr: "127.0.0.1:19201"},
		{Name: "Noah", Role: "greeter-open", Policy: "open", Type: "simple", Addr: "127.0.0.1:19202"},
	}}
	hub := orchestrator.NewHub(zerolog.Nop())
	sup := orchestrator.NewSupervisor(binDir, "127.0.0.1:19090", "127.0.0.1:19091", roster, hub, zerolog.Nop())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("start mesh: %v", err)
	}
	defer sup.Stop()

	greetID, err := orchestrator.NewDriver(roster).Collide(ctx, "Noah", "Ada")
	if err != nil {
		t.Fatalf("collide: %v", err)
	}

	// Poll for the assembled interaction to complete.
	var it orchestrator.Interaction
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if got, ok := hub.Interaction(greetID); ok && got.Verdict != "" {
			it = got
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if it.Verdict != "accepted" {
		t.Fatalf("verdict = %q (from=%s to=%s events=%d)", it.Verdict, it.From, it.To, len(it.Events))
	}
	if it.From != "Noah" || it.To != "Ada" {
		t.Fatalf("from/to = %s/%s", it.From, it.To)
	}
	var sawInitiator, sawResponder bool
	for _, e := range it.Events {
		if e.Role == "initiator" {
			sawInitiator = true
		}
		if e.Role == "responder" {
			sawResponder = true
		}
	}
	if !sawInitiator || !sawResponder {
		t.Fatalf("missing a point of view: initiator=%v responder=%v", sawInitiator, sawResponder)
	}
}
```

- [ ] **Step 2: Run the integration test**

Run: `go test ./internal/integration/ -run P5Orchestrator -v`
Expected: PASS (takes a few seconds — it builds binaries and spawns processes). If it flakes on readiness, increase the `waitReady` budgets in the supervisor, not the assertion.

- [ ] **Step 3: Gate**

Run:
```bash
gofmt -l . && go vet ./... && go build ./... && go test ./...
go mod tidy && git diff --exit-code go.mod go.sum
git log master..HEAD --format='%an <%ae>%n%b' | grep -i -E 'co-authored-by|claude|generated with' && echo "TRAILER FOUND" || echo "clean"
bash scripts/demo/p1-greet.sh && bash scripts/demo/p3b-mandate-greet.sh && bash scripts/demo/p4b-nonce-greet.sh
```
Expected: gofmt/vet/build clean; all tests pass; tidy no-op; trailer check prints `clean`; the three prior demos each print their `... demo OK` line.

- [ ] **Step 4: Commit**

```bash
git add internal/integration/p5_test.go
git commit -m "test(integration): P5 orchestrator collide end-to-end (both-POV, accepted)"
```

---

## Self-Review

**Spec coverage:**
- Single-command demo → `scripts/demo/p5-ui.sh` + self-contained orchestrator (Tasks 6–7). ✅
- Circles = real agents; collision → real greet → drawer from agents' own events → Tasks 4 (driver), 5 (supervisor stdout capture), 2 (hub), 7 (UI). ✅
- Both-POV correlation by greetId → hub assembly (Task 2) + UI SSE assembly (Task 7); asserted in Task 8. ✅
- TL as audit capstone → Task 3 (`audit` event) surfaced in the drawer (Task 7 `modelFromEvents`). ✅
- Colors/names/speed/pause/click-to-inspect drawer → Task 7, ported from the approved mockup. ✅
- No hardcoding of who-talks-to-whom / auth requirements → unchanged; the agents still discover from cards at runtime (the orchestrator only says "Noah, greet Ada"; Noah discovers what Ada requires). ✅

**Deviation from the mockup (intentional):** the **agent-count slider is removed** — circles are real OS processes fixed at launch (the roster). Speed + pause remain. This keeps the demo honest (a circle is a real agent). The roster is a launch-time property; a future `--agents`/config flag could vary it.

**Placeholder scan:** no TODOs. Task 3 flags one thing to confirm against real code (`audit.Verdict.Verdict` type — string vs typed) with the meshctl reference; Task 5 flags confirming the registry/TL readiness routes. Both are explicit "confirm against existing code" notes, not silent gaps.

**Type consistency:** `Agent{Name,Role,Policy,Type,Color,Addr}`, `Roster.ByName/Greeters`, `Hub.Ingest/Subscribe/Interaction/ServeSSE`, `Interaction{GreetID,From,To,Type,Verdict,Reason,Events}`, `Driver.Collide`, `Supervisor.Start/Stop` are used identically across tasks and by `cmd/orchestrator` and the integration test. The event `step` strings match P5a's emitters exactly (card.read, requirement, mandate.acquire, nonce.get, dpop.build, greet.send, jws.verify, mandate.verify, authority.pin, dpop.verify, nonce.consume, gate, seal, audit, greet.reply, greet.rejected).

**Scope:** P5b completes the P5 UI. After it merges, the backlog (push to origin; swap in-repo SCITT for real ans-tl; ANS registration/DNS/certs; DPoP-bind mandates) remains untouched and optional.
