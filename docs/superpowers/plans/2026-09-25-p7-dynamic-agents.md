# P7 — Dynamic Agents (slider adds/removes real agents at runtime) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A browser slider that adds (and removes) agents to the live mesh. Because circles are **real** agent processes, adding an agent spawns a real `--events --allow-trigger` agent (random name, weighted-random type, mandate agents trust a random existing authority); it registers, collides, and shows full ledgers like any other. Removing kills the most-recently-added agent (never the base roster).

**Architecture:** A thread-safe `AgentBook` holds the mesh's current agents (base + dynamic), mints new random agents (unique name from a pool, next free port, weighted type, random authority for mandate), and supports append / remove-last. The `Supervisor` gains `SpawnOne` (start one agent, wire its stdout into the hub, track it by name) and `Kill(name)`. The `Driver` reads from the `AgentBook` instead of a static `Roster`. `cmd/orchestrator` serves `POST /spawn` and `POST /despawn`; the browser slider reconciles to a target count by calling them, adding/removing circles from the returned agents.

**Tech Stack:** Existing Go (`internal/orchestrator`, `cmd/orchestrator`) + the browser UI.

**Prereq:** P5b + P6 merged (orchestrator, roster with `Agent.Authority`, supervisor, driver, hub, web UI).

---

## File Structure

**New:**
- `internal/orchestrator/book.go` — `AgentBook` (thread-safe agent set + random-agent minting).
- `internal/orchestrator/book_test.go`

**Modified:**
- `internal/orchestrator/supervisor.go` — store the base context; track cmds by name; `SpawnOne(a Agent) error`; `Kill(name string)`.
- `internal/orchestrator/driver.go` — read agents from `*AgentBook`.
- `internal/orchestrator/driver_test.go` — build a book in the test.
- `cmd/orchestrator/main.go` — construct the book; `/agents` from the book; `POST /spawn`, `POST /despawn`.
- `web/index.html` — an "agents" slider that spawns/despawns to a target and adds/removes circles.

---

### Task 1: `AgentBook`

**Files:** Create `internal/orchestrator/book.go`, `internal/orchestrator/book_test.go`

- [ ] **Step 1: Write the failing test**

```go
package orchestrator

import "testing"

func TestBookStartsFromBaseRoster(t *testing.T) {
	b := NewAgentBook(DefaultRoster(), 18300)
	if len(b.List()) != len(DefaultRoster().Agents) {
		t.Fatalf("book should start with the base roster")
	}
	if _, ok := b.ByName("Ada"); !ok {
		t.Fatal("base agent Ada missing")
	}
}

func TestBookMintAddRemove(t *testing.T) {
	b := NewAgentBook(DefaultRoster(), 18300)
	base := len(b.List())

	a, ok := b.NextAgent()
	if !ok {
		t.Fatal("NextAgent should mint an agent")
	}
	if a.Name == "" || a.Addr == "" || a.Type == "" || a.Policy == "" {
		t.Fatalf("minted agent incomplete: %+v", a)
	}
	if a.Policy == "mandate" && a.Authority == "" {
		t.Fatalf("minted mandate agent must trust an authority: %+v", a)
	}
	if _, exists := b.ByName(a.Name); exists {
		t.Fatal("NextAgent must not be in the book until Add")
	}

	b.Add(a)
	if len(b.List()) != base+1 {
		t.Fatalf("Add did not grow the book")
	}
	if got, ok := b.ByName(a.Name); !ok || got.Addr != a.Addr {
		t.Fatal("added agent not found")
	}

	removed, ok := b.RemoveLast()
	if !ok || removed.Name != a.Name {
		t.Fatalf("RemoveLast should return the dynamic agent, got %+v ok=%v", removed, ok)
	}
	if len(b.List()) != base {
		t.Fatalf("RemoveLast did not shrink the book")
	}
}

func TestBookNeverRemovesBaseRoster(t *testing.T) {
	b := NewAgentBook(DefaultRoster(), 18300)
	if _, ok := b.RemoveLast(); ok {
		t.Fatal("RemoveLast must refuse to remove a base-roster agent")
	}
}

func TestBookMintsUniqueNamesAndPorts(t *testing.T) {
	b := NewAgentBook(DefaultRoster(), 18300)
	seenName, seenAddr := map[string]bool{}, map[string]bool{}
	for i := 0; i < 6; i++ {
		a, ok := b.NextAgent()
		if !ok {
			break
		}
		if seenName[a.Name] || seenAddr[a.Addr] {
			t.Fatalf("duplicate name/addr minted: %+v", a)
		}
		seenName[a.Name], seenAddr[a.Addr] = true, true
		b.Add(a)
	}
	if len(seenName) < 4 {
		t.Fatalf("expected several unique agents, got %d", len(seenName))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/orchestrator/ -run Book`
Expected: FAIL (`NewAgentBook` undefined).

- [ ] **Step 3: Implement `internal/orchestrator/book.go`**

```go
package orchestrator

import (
	"math/rand"
	"strconv"
	"sync"
)

// namePool is the set of human names dynamic agents draw from (base-roster names
// excluded at runtime).
var namePool = []string{
	"Luna", "Milo", "Priya", "Theo", "Nina", "Omar", "Sofia", "Ravi",
	"Bao", "Tess", "Jonas", "Iris", "Leo", "Mia", "Ada2", "Noah2",
}

// dynType is a weighted random greeter type for a new agent.
func dynType() (role, policy string) {
	switch n := rand.Intn(100); {
	case n < 60:
		return "greeter-open", "open"
	case n < 85:
		return "greeter-nonce", "nonce"
	default:
		return "greeter-mandate", "mandate"
	}
}

// AgentBook is the mesh's live set of agents: the base roster plus any spawned at
// runtime. It is safe for concurrent use and mints new random agents.
type AgentBook struct {
	mu        sync.Mutex
	agents    []Agent
	baseCount int
	nextPort  int
	usedNames map[string]bool
	usedAddrs map[string]bool
}

// NewAgentBook seeds a book from base; dynamic agents get ports from startPort up.
func NewAgentBook(base Roster, startPort int) *AgentBook {
	b := &AgentBook{
		agents:    append([]Agent(nil), base.Agents...),
		baseCount: len(base.Agents),
		nextPort:  startPort,
		usedNames: map[string]bool{},
		usedAddrs: map[string]bool{},
	}
	for _, a := range base.Agents {
		b.usedNames[a.Name] = true
		b.usedAddrs[a.Addr] = true
	}
	return b
}

// List returns a snapshot of the current agents.
func (b *AgentBook) List() []Agent {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]Agent(nil), b.agents...)
}

// ByName returns the agent with the given name.
func (b *AgentBook) ByName(name string) (Agent, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, a := range b.agents {
		if a.Name == name {
			return a, true
		}
	}
	return Agent{}, false
}

// NextAgent mints (but does not add) a new random dynamic agent: a unique name, a
// free port, a weighted-random type, and — for a mandate greeter — a random
// existing authority to trust. Returns false if no name is available.
func (b *AgentBook) NextAgent() (Agent, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	name := ""
	for _, n := range namePool {
		if !b.usedNames[n] {
			name = n
			break
		}
	}
	if name == "" {
		return Agent{}, false
	}
	// find a free port
	for b.usedAddrs["127.0.0.1:"+strconv.Itoa(b.nextPort)] {
		b.nextPort++
	}
	addr := "127.0.0.1:" + strconv.Itoa(b.nextPort)
	b.nextPort++

	role, policy := dynType()
	a := mkAgent(name, role, policy, addr)
	if policy == "mandate" {
		auths := b.authoritiesLocked()
		if len(auths) == 0 {
			// no authority to trust — fall back to an open greeter
			a = mkAgent(name, "greeter-open", "open", addr)
		} else {
			a.Authority = auths[rand.Intn(len(auths))]
		}
	}
	return a, true
}

// Add appends a minted agent and marks its name/addr used.
func (b *AgentBook) Add(a Agent) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.agents = append(b.agents, a)
	b.usedNames[a.Name] = true
	b.usedAddrs[a.Addr] = true
}

// RemoveLast removes and returns the most-recently-added dynamic agent. It never
// removes a base-roster agent; returns false when only the base remains.
func (b *AgentBook) RemoveLast() (Agent, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.agents) <= b.baseCount {
		return Agent{}, false
	}
	last := b.agents[len(b.agents)-1]
	b.agents = b.agents[:len(b.agents)-1]
	delete(b.usedNames, last.Name)
	delete(b.usedAddrs, last.Addr)
	return last, true
}

func (b *AgentBook) authoritiesLocked() []string {
	var out []string
	for _, a := range b.agents {
		if a.Policy == "authority" {
			out = append(out, a.Name)
		}
	}
	return out
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/orchestrator/ -run Book`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/orchestrator/book.go internal/orchestrator/book_test.go
git commit -m "feat(orchestrator): AgentBook — live agent set + random-agent minting"
```

---

### Task 2: Supervisor SpawnOne/Kill + Driver reads the book

**Files:** Modify `internal/orchestrator/supervisor.go`, `internal/orchestrator/driver.go`, `internal/orchestrator/driver_test.go`

- [ ] **Step 1: Update the driver test to use a book (write first)**

Rewrite `internal/orchestrator/driver_test.go` so `NewDriver` takes a `*AgentBook`:

```go
package orchestrator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func bookWith(agents ...Agent) *AgentBook {
	return NewAgentBook(Roster{Agents: agents}, 18300)
}

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

	b := bookWith(
		Agent{Name: "Noah", Role: "greeter-open", Policy: "open", Addr: stub.Listener.Addr().String()},
		Agent{Name: "Ada", Role: "greeter-open", Policy: "open", Addr: "127.0.0.1:1"},
	)
	greetID, err := NewDriver(b).Collide(context.Background(), "Noah", "Ada")
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
	b := bookWith(
		Agent{Name: "Noah", Role: "greeter-open", Policy: "open", Addr: "127.0.0.1:1"},
		Agent{Name: "authority-1", Role: "authority", Policy: "authority", Addr: "127.0.0.1:2"},
	)
	if _, err := NewDriver(b).Collide(context.Background(), "Noah", "authority-1"); err == nil {
		t.Fatal("greeting the authority should error")
	}
}
```

Run `go test ./internal/orchestrator/ -run Driver` → FAIL (NewDriver still takes Roster).

- [ ] **Step 2: Implement `internal/orchestrator/driver.go`**

Change the driver to hold a `*AgentBook`:

```go
type Driver struct {
	book *AgentBook
	http *http.Client
}

// NewDriver builds a Driver over the live agent book.
func NewDriver(book *AgentBook) *Driver {
	return &Driver{book: book, http: &http.Client{Timeout: 10 * time.Second}}
}
```

In `Collide`, replace `d.roster.ByName(...)` with `d.book.ByName(...)` (both lookups). Everything else is unchanged.

- [ ] **Step 3: Implement supervisor `SpawnOne` / `Kill`**

In `internal/orchestrator/supervisor.go`:

- Add fields: a base context captured in `Start`, and a name→cmd map:
```go
type Supervisor struct {
	// ... existing fields ...
	ctx       context.Context
	cmdByName map[string]*exec.Cmd
}
```
Initialize `cmdByName` in `NewSupervisor` (`cmdByName: map[string]*exec.Cmd{}`). At the top of `Start`, capture the context: `s.ctx = ctx`.

- In `spawn(...)`, after appending to `s.cmds`, also record by name:
```go
	s.cmdByName[name] = cmd
```
(inside the existing `s.mu.Lock()` block).

- Add a helper that builds a greeter's args (extract from the existing greeters loop so `Start` and `SpawnOne` share it):
```go
func (s *Supervisor) greeterArgs(a Agent) []string {
	regURL := "http://" + s.registry
	tlURL := "http://" + s.transparency
	args := []string{
		"--name", a.Name, "--role", a.Role, "--addr", a.Addr,
		"--registry", regURL, "--transparency", tlURL,
		"--policy", a.Policy, "--events", "--allow-trigger",
	}
	if a.Policy == "mandate" {
		args = append(args, "--authority-role", "authority", "--scope", "greet")
		if a.Authority != "" {
			args = append(args, "--authority-name", a.Authority)
		}
	}
	return args
}
```
Use `s.greeterArgs(a)` in the existing greeters loop in `Start` (replace the inline args build).

- Add SpawnOne + Kill:
```go
// SpawnOne starts a single greeter at runtime, streaming its events into the hub,
// and waits briefly for it to become ready. Used by POST /spawn.
func (s *Supervisor) SpawnOne(a Agent) error {
	if err := s.spawn(s.ctx, a.Name, s.hub, s.bin+"/agent", s.greeterArgs(a)...); err != nil {
		return err
	}
	return waitReady(s.ctx, a.BaseURL()+"/.well-known/agent-card.json", 8*time.Second)
}

// Kill terminates a single agent by name (used by POST /despawn).
func (s *Supervisor) Kill(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cmd, ok := s.cmdByName[name]; ok {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		delete(s.cmdByName, name)
	}
}
```

- [ ] **Step 4: Verify**

Run: `go test ./internal/orchestrator/`, `go build ./...`, `go vet ./...`, `gofmt -l internal/orchestrator/`
Expected: PASS + clean.

- [ ] **Step 5: Commit**

```bash
git add internal/orchestrator/
git commit -m "feat(orchestrator): supervisor SpawnOne/Kill; driver reads the live AgentBook"
```

---

### Task 3: `cmd/orchestrator` — book wiring + /spawn + /despawn

**Files:** Modify `cmd/orchestrator/main.go`

- [ ] **Step 1: Implement**

- Build the book from the default roster and pass its snapshot to the supervisor and the driver:
```go
	roster := orchestrator.DefaultRoster()
	book := orchestrator.NewAgentBook(roster, 18300)
	hub := orchestrator.NewHub(log)
	driver := orchestrator.NewDriver(book)
	...
	sup := orchestrator.NewSupervisor(*binDir, *registryAddr, *tlAddr, roster, hub, log)
	if err := sup.Start(ctx); err != nil { ... }
```
- `/agents` returns the live book:
```go
	mux.HandleFunc("GET /agents", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(book.List())
	})
```
- Add spawn/despawn:
```go
	mux.HandleFunc("POST /spawn", func(w http.ResponseWriter, r *http.Request) {
		a, ok := book.NextAgent()
		w.Header().Set("Content-Type", "application/json")
		if !ok {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "no more agents available"})
			return
		}
		if err := sup.SpawnOne(a); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		book.Add(a)
		log.Info().Str("agent", a.Name).Str("policy", a.Policy).Msg("spawned dynamic agent")
		_ = json.NewEncoder(w).Encode(a) // {name, role, policy, type, color}
	})
	mux.HandleFunc("POST /despawn", func(w http.ResponseWriter, r *http.Request) {
		a, ok := book.RemoveLast()
		w.Header().Set("Content-Type", "application/json")
		if !ok {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "no dynamic agents to remove"})
			return
		}
		sup.Kill(a.Name)
		log.Info().Str("agent", a.Name).Msg("despawned dynamic agent")
		_ = json.NewEncoder(w).Encode(map[string]string{"removed": a.Name})
	})
```

- [ ] **Step 2: Build + smoke**

Run:
```bash
go build ./... && go vet ./cmd/orchestrator/ && gofmt -l cmd/orchestrator/
```
Then a runtime smoke:
```bash
make build && go build -o bin/orchestrator ./cmd/orchestrator
mkdir -p /tmp/p7web && cp web/index.html /tmp/p7web/index.html
./bin/orchestrator --addr 127.0.0.1:19080 --registry 127.0.0.1:19090 --transparency 127.0.0.1:19091 --web /tmp/p7web >/tmp/o7.log 2>&1 &
ORCH=$!; sleep 4
echo "--- agents before ---"; curl -s 127.0.0.1:19080/agents | python3 -c 'import sys,json;print(len(json.load(sys.stdin)),"agents")'
echo "--- spawn ---"; curl -s -XPOST 127.0.0.1:19080/spawn; echo
sleep 2
echo "--- agents after spawn ---"; curl -s 127.0.0.1:19080/agents | python3 -c 'import sys,json;print(len(json.load(sys.stdin)),"agents")'
echo "--- despawn ---"; curl -s -XPOST 127.0.0.1:19080/despawn; echo
kill $ORCH 2>/dev/null; sleep 1
echo "--- orphans ---"; pgrep -f 'bin/(agent|authority|registry|transparency)' || echo none
rm -rf /tmp/p7web; # clean any data/<Name> dirs created for dynamic names
```
Expected: agent count grows by 1 after `/spawn` (response is the new agent JSON with name/type/color), the spawned agent is a real process, `/despawn` returns `{"removed": "<name>"}`, and after killing the orchestrator no orphan agents remain. Report the actual outputs; if a spawned mandate agent fails readiness because it couldn't pin its authority, note it (dynamic mandate agents pick an existing authority, which is already up).

- [ ] **Step 3: Commit**

```bash
git add cmd/orchestrator/main.go
git commit -m "feat(orchestrator): POST /spawn and /despawn dynamic agents; /agents from the book"
```

---

### Task 4: Browser slider + gate

**Files:** Modify `web/index.html`

- [ ] **Step 1: Add the slider to the header controls**

In the `.controls` block (next to the speed slider), add:
```html
    <div class="ctrl">
      <label for="agentRange">agents</label>
      <input id="agentRange" type="range" min="0" max="8" step="1" value="0">
      <output id="agentOut">0</output>
    </div>
```
(The slider value is *how many extra* agents beyond the base roster. `0` = base; up to `+8`.)

- [ ] **Step 2: Wire spawn/despawn reconciliation**

Add JS (near the other control wiring). The slider's value is the target number of *extra* agents; reconcile by spawning/despawning one at a time, guarding against overlap. Adding/removing updates the `agents` array (circles):

```js
const agentRange = document.getElementById('agentRange'), agentOut = document.getElementById('agentOut');
let baseCount = 0;         // set after loadAgents()
let extra = 0;             // how many dynamic agents currently live
let reconciling = false;

function addCircle(a){
  agents.push({ name:a.name, type:a.type, color:a.color, policy:a.policy,
    r: a.type==='authority'?24:27,
    x: 80+Math.random()*(Math.max(1,W-160)), y: 80+Math.random()*(Math.max(1,H-160)), flash:0,
    vx: (Math.random()*2-1)*0.9, vy: (Math.random()*2-1)*0.9 });
}
function removeCircleByName(name){
  const i = agents.findIndex(x=>x.name===name); if (i>=0) agents.splice(i,1);
}

async function reconcileAgents(){
  if (reconciling) return;
  reconciling = true;
  agentRange.disabled = true;
  try {
    while (extra < +agentRange.value){
      const res = await fetch('/spawn', {method:'POST'});
      if (!res.ok) { agentRange.value = extra; break; }
      const a = await res.json(); addCircle(a); extra++; agentOut.textContent = extra;
    }
    while (extra > +agentRange.value){
      const res = await fetch('/despawn', {method:'POST'});
      if (!res.ok) { agentRange.value = extra; break; }
      const out = await res.json(); removeCircleByName(out.removed); extra--; agentOut.textContent = extra;
    }
  } finally {
    reconciling = false;
    agentRange.disabled = false;
  }
}
agentRange.addEventListener('change', reconcileAgents); // fires on release, not every drag tick
```

In `loadAgents()`, after populating `agents`, set the baseline:
```js
  baseCount = agents.length;
```

- [ ] **Step 3: Syntax-check**

Run:
```bash
python3 - <<'PY'
import re; html=open('web/index.html').read()
open('/tmp/ui.js','w').write(re.search(r'<script>(.*)</script>', html, re.S).group(1))
PY
node --check /tmp/ui.js && echo "JS OK"
grep -c "/spawn\|/despawn\|agentRange" web/index.html   # expect >=3
```

- [ ] **Step 4: Gate**

Run:
```bash
gofmt -l . && go vet ./... && go build ./... && go test ./...
go mod tidy && git diff --exit-code go.mod go.sum && echo tidy-noop
git log master..HEAD --format='%an <%ae>%n%b' | grep -i -E 'co-authored-by|claude|generated with' && echo TRAILER || echo clean
bash scripts/demo/p1-greet.sh && bash scripts/demo/p3b-mandate-greet.sh && bash scripts/demo/p4b-nonce-greet.sh
```
Expected: gofmt/vet/build clean; all tests pass; tidy no-op; trailer check `clean`; the three demos print their OK lines.

- [ ] **Step 5: Manual smoke (documented)**

`bash scripts/demo/p5-ui.sh`, open the UI, drag the **agents** slider up → new colored circles appear (real processes; they collide and their interactions show full ledgers), drag down → the newest ones disappear. Ctrl-C leaves no orphans (`pgrep -f 'bin/(agent|authority|registry|transparency)'` empty).

- [ ] **Step 6: Commit**

```bash
git add web/index.html
git commit -m "feat(ui): agents slider spawns/removes real agents at runtime"
```

---

## Self-Review

**Spec coverage:** slider adds real agents (Tasks 1–4); weighted-random type incl. mandate-trusting-a-random-authority (Task 1 `NextAgent`); removing kills the newest, never the base (Task 1 `RemoveLast` + Task 3 `/despawn`); spawned agents are real, event-emitting, collidable (Task 2 `SpawnOne` wires stdout→hub with `--events --allow-trigger`). ✅

**Placeholder scan:** none.

**Type consistency:** `AgentBook` (`NewAgentBook`, `List`, `ByName`, `NextAgent`, `Add`, `RemoveLast`) used across book, driver, supervisor(SpawnOne reads Agent), and `cmd/orchestrator`; `NewDriver(*AgentBook)` updated in driver_test and main; `Supervisor.SpawnOne(Agent)`/`Kill(string)`/`greeterArgs(Agent)` used in main. `Agent` shape unchanged. The `/spawn` response is a single `Agent` (name/role/policy/type/color) which the browser turns into a circle; `/despawn` returns `{removed}`.

**Concurrency:** `AgentBook` is mutex-guarded; `Supervisor.Kill`/`spawn` use the existing `s.mu`; the browser reconciles one spawn/despawn at a time behind a `reconciling` flag on the slider's `change` event.

**Scope:** No wire-format or agent-code change — this is orchestrator + UI only. Dynamic mandate agents reuse the P6 named-authority mechanism (pick an existing authority). Base roster is never torn down by the slider.
