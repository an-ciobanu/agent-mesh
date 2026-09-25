# P6 — Multiple Authorities (token greeter names which authority to trust) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Support more than one mandate authority. Each token (mandate) greeter declares, in its Agent Card, the **specific** authority it trusts (by ANS identity), and a caller discovers the authorities and obtains its mandate from **that** one — so the greeter's pinned key and the mandate's issuer always match, even with several authorities registered under the shared `"authority"` role.

**Architecture:** Authorities keep the shared discovery role `"authority"` (identity = their ANS name, not their role). A token greeter is configured with `--authority-name`; it pins that authority's key and advertises `authorityAns` in its `ans:mandate` card extension. The caller's `acquireMandate` discovers all authorities by role, then **selects the one whose ANS matches the card's `authorityAns`** (falling back to the first if unset, for back-compat). The demo roster gains a second authority and a second token greeter so both authorities are exercised.

**Tech Stack:** Existing Go — `internal/greet`, `internal/comms/{a2a,discovery,mcp,authclient}`, `internal/policy`, `cmd/{agent,authority}`, `internal/orchestrator`.

**Back-compat:** With `--authority-name` unset and no `authorityAns` card param (today's single-authority setup, the p3b demo, existing tests), behavior is unchanged: pin/first-match the sole authority.

---

## File Structure

**Modified:**
- `internal/greet/initiator.go` — `acquireMandate` reads `authorityAns` and selects the matching authority via a new testable `selectAuthority` helper; the `mandate.acquire` event reports the actual authority name.
- `cmd/agent/main.go` — `--authority-name` flag; `resolveAuthority` filters discovered authorities by name; card advertises `authorityAns`.
- `internal/orchestrator/roster.go` — `Agent.Authority` field; add `authority-2` and a second token greeter (`Kai` → authority-2); `Chris` → authority-1.
- `internal/orchestrator/supervisor.go` — pass `--authority-name` when spawning a mandate greeter.
- `internal/orchestrator/roster_test.go` — assert the two-authority roster + trust wiring.

**New:**
- `internal/greet/select_authority_test.go` — unit tests for `selectAuthority`.
- `internal/integration/p6_test.go` — two authorities; a greeter trusting authority-2 accepts a caller that (correctly) fetched from authority-2.

---

### Task 1: Authority selection by ANS in the caller

**Files:** Modify `internal/greet/initiator.go`; create `internal/greet/select_authority_test.go`

- [ ] **Step 1: Write the failing test** (`internal/greet/select_authority_test.go`)

```go
package greet

import (
	"testing"

	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

func peers() []domain.AgentInfo {
	return []domain.AgentInfo{
		{Name: "authority-1", Role: "authority", BaseURL: "http://a1"},
		{Name: "authority-2", Role: "authority", BaseURL: "http://a2"},
	}
}

func TestSelectAuthorityByAns(t *testing.T) {
	got, ok := selectAuthority(peers(), domain.LocalANSName("authority-2"))
	if !ok || got.Name != "authority-2" {
		t.Fatalf("selectAuthority = %+v ok=%v; want authority-2", got, ok)
	}
}

func TestSelectAuthorityEmptyAnsFallsBackToFirst(t *testing.T) {
	got, ok := selectAuthority(peers(), "")
	if !ok || got.Name != "authority-1" {
		t.Fatalf("selectAuthority(\"\") = %+v ok=%v; want first (authority-1)", got, ok)
	}
}

func TestSelectAuthorityUnknownAnsFails(t *testing.T) {
	if _, ok := selectAuthority(peers(), domain.LocalANSName("authority-9")); ok {
		t.Fatalf("selectAuthority for unknown ANS should fail closed")
	}
}

func TestSelectAuthorityEmptyPeersFails(t *testing.T) {
	if _, ok := selectAuthority(nil, ""); ok {
		t.Fatalf("selectAuthority(nil) should be false")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/greet/ -run SelectAuthority`
Expected: FAIL (`selectAuthority` undefined).

- [ ] **Step 3: Implement in `internal/greet/initiator.go`**

Add the helper:

```go
// selectAuthority picks the authority a caller must use from those discovered by
// role. When authorityAns is set (the card named a specific authority), it
// returns the peer whose ANS matches — fail closed if none does. When it is
// empty (single-authority / back-compat), it returns the first peer.
func selectAuthority(peers []domain.AgentInfo, authorityAns string) (domain.AgentInfo, bool) {
	if len(peers) == 0 {
		return domain.AgentInfo{}, false
	}
	if authorityAns == "" {
		return peers[0], true
	}
	for _, p := range peers {
		if domain.LocalANSName(p.Name) == authorityAns {
			return p, true
		}
	}
	return domain.AgentInfo{}, false
}
```

Rewrite the discovery/selection part of `acquireMandate` to use it. Change the function so it reads `authorityAns` from the extension params and selects accordingly (replace the existing `authorities[0]` logic):

```go
func acquireMandate(ctx context.Context, disco domain.Discovery, mcpCli *mcp.Client, ext a2a.Extension, callerAns, audienceAns string) ([]byte, string, error) {
	authorityRole := stringParam(ext.Params, "authorityRole", "authority")
	authorityAns := stringParam(ext.Params, "authorityAns", "")
	scope := stringParam(ext.Params, "scope", "greet")

	authorities, err := disco.Search(ctx, authorityRole)
	if err != nil {
		return nil, "", fmt.Errorf("discover authority role %q: %w", authorityRole, err)
	}
	authority, ok := selectAuthority(authorities, authorityAns)
	if !ok {
		return nil, "", fmt.Errorf("no authority %q found under role %q", authorityAns, authorityRole)
	}
	authURL := authority.BaseURL + "/mcp"

	raw, err := mcpCli.Call(ctx, authURL, "issue_mandate", map[string]string{
		"subjectAns":  callerAns,
		"audienceAns": audienceAns,
		"scope":       scope,
	})
	if err != nil {
		return nil, authority.Name, fmt.Errorf("issue_mandate: %w", err)
	}
	var out struct {
		MandateCOSE []byte `json:"mandateCose"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, authority.Name, fmt.Errorf("parse issue_mandate result: %w", err)
	}
	if len(out.MandateCOSE) == 0 {
		return nil, authority.Name, fmt.Errorf("authority returned an empty mandate")
	}
	return out.MandateCOSE, authority.Name, nil
}
```

Update the single caller of `acquireMandate` in `GreetPeer` to the new 3-return signature and report the real authority name in the event:

```go
	if ext, ok := mandateExtension(card); ok {
		events.Emit(ctx, "requirement", events.StatusInfo, map[string]string{"type": "mandate"})
		if disco == nil {
			return "", nil, fmt.Errorf("peer %q requires a mandate but no discovery is available", peer.Name)
		}
		mandate, authName, merr := acquireMandate(ctx, disco, mcpCli, ext, callerAns, audienceAns)
		if merr != nil {
			events.Emit(ctx, "mandate.acquire", events.StatusFail, map[string]string{"error": merr.Error(), "authority": authName})
			return "", nil, merr
		}
		events.Emit(ctx, "mandate.acquire", events.StatusOK, map[string]string{
			"authority": authName,
			"scope":     stringParam(ext.Params, "scope", "greet"),
			"audience":  audienceAns,
			"tool":      "issue_mandate (MCP)",
		})
		opts = append(opts, a2a.WithMandate(mandate))
	} else if ...
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/greet/`
Expected: PASS (new `SelectAuthority` tests + existing mandate tests — the existing single-authority mandate test passes no `authorityAns`, so it takes the fallback path).

- [ ] **Step 5: Commit**

```bash
git add internal/greet/
git commit -m "feat(greet): caller selects the card-named authority by ANS (multi-authority)"
```

---

### Task 2: Greeter names its authority; roster gains a second authority + token greeter

**Files:** Modify `cmd/agent/main.go`, `internal/orchestrator/roster.go`, `internal/orchestrator/supervisor.go`, `internal/orchestrator/roster_test.go`

- [ ] **Step 1: Write the failing test** (add to `internal/orchestrator/roster_test.go`)

```go
func TestRosterHasTwoAuthoritiesAndTrustWiring(t *testing.T) {
	r := DefaultRoster()
	var auth int
	for _, a := range r.Agents {
		if a.Policy == "authority" {
			auth++
		}
	}
	if auth != 2 {
		t.Fatalf("want 2 authorities, got %d", auth)
	}
	chris, _ := r.ByName("Chris")
	kai, ok := r.ByName("Kai")
	if !ok {
		t.Fatal("expected a second token greeter 'Kai'")
	}
	if chris.Policy != "mandate" || chris.Authority != "authority-1" {
		t.Fatalf("Chris should trust authority-1: %+v", chris)
	}
	if kai.Policy != "mandate" || kai.Authority != "authority-2" {
		t.Fatalf("Kai should trust authority-2: %+v", kai)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/orchestrator/ -run TwoAuthorities`
Expected: FAIL (`Agent.Authority` undefined / no Kai / one authority).

- [ ] **Step 3: Implement**

`internal/orchestrator/roster.go` — add the field and wire the roster. Add `Authority string` to `Agent` (JSON-omitted; used only to pass `--authority-name`):

```go
type Agent struct {
	Name      string `json:"name"`
	Role      string `json:"role"`
	Policy    string `json:"policy"`
	Type      string `json:"type"`
	Color     string `json:"color"`
	Addr      string `json:"-"`
	Authority string `json:"-"` // for mandate greeters: the authority (name) this greeter trusts
}
```

Add a variant constructor for a mandate greeter that records its authority, and update `DefaultRoster`:

```go
func mkMandate(name, role, addr, authority string) Agent {
	a := mkAgent(name, role, "mandate", addr)
	a.Authority = authority
	return a
}

func DefaultRoster() Roster {
	return Roster{Agents: []Agent{
		mkAgent("authority-1", "authority", "authority", "127.0.0.1:18110"),
		mkAgent("authority-2", "authority", "authority", "127.0.0.1:18111"),
		mkAgent("Ada", "greeter-open", "open", "127.0.0.1:18201"),
		mkAgent("Noah", "greeter-open", "open", "127.0.0.1:18202"),
		mkAgent("Ema", "greeter-open", "open", "127.0.0.1:18205"),
		mkAgent("Zoe", "greeter-nonce", "nonce", "127.0.0.1:18203"),
		mkMandate("Chris", "greeter-mandate", "127.0.0.1:18204", "authority-1"),
		mkMandate("Kai", "greeter-mandate", "127.0.0.1:18206", "authority-2"),
	}}
}
```

`internal/orchestrator/supervisor.go` — pass `--authority-name` for mandate greeters. In the greeters loop, where the mandate args are appended:

```go
		if a.Policy == "mandate" {
			args = append(args, "--authority-role", "authority", "--scope", "greet")
			if a.Authority != "" {
				args = append(args, "--authority-name", a.Authority)
			}
		}
```

`cmd/agent/main.go` — add the flag and thread it. Add near the other flags:

```go
	authorityName := flag.String("authority-name", "", "specific authority to trust by name (when --policy=mandate); empty = first discovered")
```

Change `resolveAuthority` to filter by name, and have the mandate case advertise `authorityAns`:

```go
	case "mandate":
		authPeer, authPub := resolveAuthority(ctx, disco, authclient.New(), *authorityRole, *authorityName, log)
		authorityAns := domain.LocalANSName(authPeer.Name)
		greetPolicy = policy.NewMandate(selfAns, authorityAns, authPub, *scope, log)
		card.Security = []map[string][]string{{"mandate": {}}}
		card.Capabilities = &a2a.Capabilities{Extensions: []a2a.Extension{{
			URI:         a2a.ExtMandateURI,
			Description: "present a mandate from the authority",
			Required:    true,
			Params:      map[string]any{"authorityRole": *authorityRole, "authorityAns": authorityAns, "scope": *scope},
		}}}
		log.Info().Str("authorityAns", authorityAns).Str("scope", *scope).Msg("mandate policy enabled")
```

Update `resolveAuthority` to accept and apply the name filter:

```go
// resolveAuthority discovers the authority of the given role — optionally the one
// named `name` — and pins its public key, retrying to tolerate startup races. A
// mandate greeter cannot serve without a pinned authority key, so failure is
// fatal (fail closed).
func resolveAuthority(ctx context.Context, disco *discovery.Client, ac *authclient.Client, role, name string, log zerolog.Logger) (domain.AgentInfo, ed25519.PublicKey) {
	for i := 0; i < 20; i++ {
		peers, err := disco.Search(ctx, role)
		if err == nil && len(peers) > 0 {
			for _, p := range peers {
				if name != "" && p.Name != name {
					continue
				}
				pub, perr := ac.FetchPubKey(ctx, p.BaseURL)
				if perr == nil {
					log.Info().Str("authority", p.Name).Str("baseURL", p.BaseURL).Msg("pinned authority key")
					return p, pub
				}
				log.Warn().Err(perr).Str("authority", p.Name).Msg("fetch authority pubkey; retrying")
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	log.Fatal().Str("role", role).Str("name", name).Msg("could not resolve/pin the authority; a mandate greeter cannot start without it")
	return domain.AgentInfo{}, nil // unreachable
}
```

- [ ] **Step 4: Run tests + build**

Run:
```bash
go test ./internal/orchestrator/
go build ./...
go vet ./...
```
Expected: PASS + clean.

- [ ] **Step 5: Commit**

```bash
git add cmd/agent/main.go internal/orchestrator/
git commit -m "feat(orchestrator): greeter pins/advertises a named authority; roster adds authority-2 + Kai"
```

---

### Task 3: Multi-authority integration test + gate

**Files:** Create `internal/integration/p6_test.go`

- [ ] **Step 1: Write the integration test**

Spins up two authorities plus a mandate greeter trusting authority-2, then greets it and asserts acceptance — proving the caller followed the card to the correct authority. Build binaries like `p5_test.go`; guard with `testing.Short()`.

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

func TestP6MandateFollowsNamedAuthority(t *testing.T) {
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

	roster := orchestrator.Roster{Agents: []orchestrator.Agent{
		{Name: "authority-1", Role: "authority", Policy: "authority", Addr: "127.0.0.1:19110"},
		{Name: "authority-2", Role: "authority", Policy: "authority", Addr: "127.0.0.1:19111"},
		{Name: "Ada", Role: "greeter-open", Policy: "open", Type: "simple", Addr: "127.0.0.1:19201"},
		{Name: "Kai", Role: "greeter-mandate", Policy: "mandate", Type: "token", Addr: "127.0.0.1:19206", Authority: "authority-2"},
	}}
	hub := orchestrator.NewHub(zerolog.Nop())
	sup := orchestrator.NewSupervisor(binDir, "127.0.0.1:19090", "127.0.0.1:19091", roster, hub, zerolog.Nop())

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("start mesh: %v", err)
	}
	defer sup.Stop()

	greetID, err := orchestrator.NewDriver(roster).Collide(ctx, "Ada", "Kai")
	if err != nil {
		t.Fatalf("collide: %v", err)
	}

	var it orchestrator.Interaction
	deadline := time.Now().Add(12 * time.Second)
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
	// The mandate.acquire step must name the authority the card pointed to.
	var acquiredFrom string
	for _, e := range it.Events {
		if e.Step == "mandate.acquire" && e.Status == "ok" {
			acquiredFrom = e.Detail["authority"]
		}
	}
	if acquiredFrom != "authority-2" {
		t.Fatalf("mandate acquired from %q; want authority-2", acquiredFrom)
	}
}
```

- [ ] **Step 2: Run it**

Run: `go test ./internal/integration/ -run P6 -v`
Expected: PASS (a few seconds). If it flakes on startup timing, raise `waitReady` budgets in the supervisor, not the assertions.

- [ ] **Step 3: Gate**

Run:
```bash
gofmt -l . && go vet ./... && go build ./... && go test ./...
go mod tidy && git diff --exit-code go.mod go.sum
git log master..HEAD --format='%an <%ae>%n%b' | grep -i -E 'co-authored-by|claude|generated with' && echo "TRAILER FOUND" || echo "clean"
bash scripts/demo/p1-greet.sh && bash scripts/demo/p3b-mandate-greet.sh && bash scripts/demo/p4b-nonce-greet.sh
```
Expected: gofmt/vet/build clean; all tests pass; tidy no-op; trailer check `clean`; the three demos each print their `... demo OK` line (p3b still uses a single authority via the fallback path — proves back-compat).

- [ ] **Step 4: Commit**

```bash
git add internal/integration/p6_test.go
git commit -m "test(integration): mandate greet follows the card-named authority (two authorities)"
```

---

## Self-Review

**Spec coverage:**
- Multiple authorities under one role → roster adds authority-2 (Task 2). ✅
- Token greeter names which authority → `authorityAns` card param + `--authority-name` + pinning the named key (Task 2). ✅
- Caller calls the right authority → `selectAuthority` by ANS in `acquireMandate` (Task 1). ✅
- Both authorities exercised → Chris→authority-1, Kai→authority-2 (Task 2); integration proves the follow (Task 3). ✅
- Back-compat → empty `authorityAns`/`--authority-name` falls back to first; p3b demo + existing mandate tests unchanged (Tasks 1 & 3). ✅

**Placeholder scan:** none.

**Type consistency:** `selectAuthority(peers, authorityAns) (domain.AgentInfo, bool)`; `acquireMandate(...) ([]byte, string, error)` (new 3-tuple) and its sole caller updated; `resolveAuthority(ctx, disco, ac, role, name, log)` (new `name` param) and its sole caller updated; `Agent.Authority` used in roster, supervisor, and the p6 test. The `mandate.acquire` event's `authority` field now carries the authority **name** (consumed by the p6 assertion and shown in the UI ledger).

**Scope:** No wire-format change (card params are an open map; adding `authorityAns` is additive). The UI needs no change — the ledger already renders `detail.authority`, which now shows the specific authority. Each greeter still trusts exactly one authority; trusting a *set* is future work.
