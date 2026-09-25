# agent-mesh P4b — Nonce Flow + Wiring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the nonce greeter (agent type 3) run end-to-end: a greeter advertises a DPoP/nonce requirement on its card and serves a `get_nonce` MCP tool; the initiator discovers the requirement, fetches a nonce, builds a P-256/ES256 DPoP proof over it, and greets; the greeter's `policy.Nonce` guard verifies and accepts exactly once.

**Architecture:** Completes P4. The A2A greet transport gains an `X-ANS-DPoP` header (a compact JWS, carried verbatim — it is ASCII) that the client attaches and the server extracts into `GreetRequest.DPoPProof`, while the handler also fills `GreetRequest.HTTPMethod`/`HTTPURL` so the guard can bind `htm`/`htu`. The Agent Card gains an `ExtNonceURI` extension so a greeter can advertise the requirement. `greet.Initiate` becomes nonce-aware: on detecting the nonce extension it generates a per-session P-256 key, calls the greeter's own `get_nonce` MCP tool, builds the DPoP proof (`htm`/`htu`/`iat`/`jti`/nonce), and attaches it. `cmd/agent --policy nonce` builds the `policy.Nonce` guard over a nonce `Store`, serves `/mcp` (get_nonce) alongside `/a2a`, and advertises the extension. The nonce greeter is self-contained — it issues its own challenges, so no authority is involved.

**Tech Stack:** Go 1.23, existing deps; no new third-party dependencies.

**Scope:** P4b is the flow + wiring for the nonce greeter, building on P4a (merged: DPoP crypto, the nonce `Store` + `get_nonce` tool, the `policy.Nonce` guard, and `GreetRequest.DPoPProof/HTTPMethod/HTTPURL`). Retrofitting DPoP-binding onto P3 mandates (mandate `jkt`) remains a separate future item. The circles-collision UI is **P5**.

**Baseline:** P0–P4a merged on `master`. Reuse: `crypto.{GenerateDPoPKey,CreateDPoPProof,DPoPClaims}`; `nonce.{NewStore,Store.MCPTool}`; `policy.{Open,Mandate,NewNonce}`; `mcp.{NewServer,NewClient,Client.Call,ToolFunc}`; `a2a.{Card,Capabilities,Extension,ExtMandateURI,SendOption,WithMandate,SendGreet,NewGreetService,NewMux,HandleMessageSend}`; `discovery`, `resolver`, `authclient`; `domain.{GreetRequest,GreetPayload,AgentInfo,LocalANSName}`. Do all work on a branch off `master` (e.g. `p4b-nonce-flow`).

---

## File structure (this plan)

```
internal/comms/a2a/card.go                    # MODIFY: add ExtNonceURI const
internal/comms/a2a/message.go                 # MODIFY: HeaderDPoP; extract DPoP proof + fill HTTPMethod/HTTPURL
internal/comms/a2a/client.go                  # MODIFY: WithDPoP SendOption
internal/comms/a2a/dpop_transport_test.go     # NEW: DPoP header reaches policy; htm/htu populated
internal/greet/initiator.go                   # MODIFY: nonce-aware branch (get_nonce -> DPoP proof)
internal/greet/nonce_initiate_test.go         # NEW: greet-package nonce flow coverage
cmd/agent/main.go                             # MODIFY: --policy nonce (serve /mcp get_nonce + guard + card ext)
internal/integration/p4b_test.go              # NEW: end-to-end nonce greet + rejections
scripts/demo/p4b-nonce-greet.sh               # NEW: runnable demo
```

Conventions unchanged: hexagonal Go; injected `zerolog.Logger` tagged `component`; no `fmt.Println`/`log` in library code; `gofmt`/`go vet` clean before every commit; **no AI `Co-Authored-By:` trailer**, no `git commit -s`.

---

## Task 1: A2A transport — carry the DPoP proof + bind htm/htu

**Files:**
- Modify: `internal/comms/a2a/card.go` (add `ExtNonceURI`)
- Modify: `internal/comms/a2a/message.go`
- Modify: `internal/comms/a2a/client.go`
- Test: `internal/comms/a2a/dpop_transport_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/comms/a2a/dpop_transport_test.go`. NOTE: package `a2a` already has a `capturePolicy` and a `testKey` helper (from `mandate_transport_test.go`) — REUSE them; do not redefine them.

```go
package a2a

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

func TestDPoPHeaderReachesPolicyWithBinding(t *testing.T) {
	pol := &capturePolicy{}
	svc := NewGreetService(domain.LocalANSName("greeter-nonce"), pol, zerolog.Nop())
	mux := http.NewServeMux()
	mux.HandleFunc("POST /a2a", svc.HandleMessageSend)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	priv := testKey(t)
	proof := "eyJ.header.sig" // opaque to the transport; the policy verifies it
	_, _, err := NewClient().SendGreet(context.Background(), ts.URL+"/a2a", priv, GreetPayload{
		CallerAns:   domain.LocalANSName("visitor"),
		AudienceAns: domain.LocalANSName("greeter-nonce"),
		Greeting:    "hi",
	}, WithDPoP(proof))
	if err != nil {
		t.Fatal(err)
	}
	if pol.last.DPoPProof != proof {
		t.Fatalf("policy did not receive the DPoP proof: got %q", pol.last.DPoPProof)
	}
	if pol.last.HTTPMethod != "POST" {
		t.Fatalf("HTTPMethod not bound: got %q", pol.last.HTTPMethod)
	}
	if !strings.HasSuffix(pol.last.HTTPURL, "/a2a") || !strings.HasPrefix(pol.last.HTTPURL, "http://") {
		t.Fatalf("HTTPURL not bound to the request: got %q", pol.last.HTTPURL)
	}
}

func TestNoDPoPHeaderMeansEmptyProof(t *testing.T) {
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
	if pol.last.DPoPProof != "" {
		t.Fatalf("expected empty DPoP proof, got %q", pol.last.DPoPProof)
	}
}

func TestExtNonceURIDefined(t *testing.T) {
	if ExtNonceURI == "" || ExtNonceURI == ExtMandateURI {
		t.Fatal("ExtNonceURI must be a distinct non-empty URI")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/comms/a2a/ -run 'DPoP|ExtNonce' -v`
Expected: FAIL — `undefined: WithDPoP`, `undefined: ExtNonceURI`, and no `DPoPProof`/`HTTPMethod`/`HTTPURL` populated.

- [ ] **Step 3: Add `ExtNonceURI` in `internal/comms/a2a/card.go`**

Next to the existing `ExtMandateURI` const:

```go
// ExtNonceURI identifies the agent-mesh "DPoP nonce required" A2A capabilities
// extension. A greeter that advertises it requires callers to obtain a nonce
// (via its get_nonce MCP tool) and present a DPoP proof-of-possession over it.
const ExtNonceURI = "https://agent-mesh.local/ext/nonce/v1"
```

- [ ] **Step 4: Extract the DPoP header + bind the request in `internal/comms/a2a/message.go`**

Add the constant to the existing `const (...)` block (alongside `HeaderMandate`):

```go
	// HeaderDPoP carries the caller's RFC 9449 DPoP proof (an ES256 compact JWS)
	// verbatim. Optional; a nonce-gated policy requires it.
	HeaderDPoP = "X-ANS-DPoP"
```

In `HandleMessageSend`, extend the `domain.GreetRequest{...}` literal passed to `g.policy.Authorize(...)` to also carry the DPoP proof and the request binding. The proof needs no decoding (it is an ASCII compact JWS):

```go
	if err := g.policy.Authorize(r.Context(), domain.GreetRequest{
		CallerAns:           gp.CallerAns,
		AudienceAns:         gp.AudienceAns,
		Greeting:            gp.Greeting,
		CallerKeyThumbprint: thumb,
		Mandate:             mandate,
		DPoPProof:           r.Header.Get(HeaderDPoP),
		HTTPMethod:          r.Method,
		HTTPURL:             "http://" + r.Host + r.URL.Path,
	}); err != nil {
```

(The `htu` is reconstructed as `http://<host><path>`; the greeter serves plain HTTP locally, matching `serveCard`'s scheme. The initiator builds its proof's `htu` from the card URL, which is `http://<host>/a2a` — they match.)

- [ ] **Step 5: Add the `WithDPoP` send option in `internal/comms/a2a/client.go`**

```go
// WithDPoP attaches an RFC 9449 DPoP proof (a compact JWS) to the greet via the
// X-ANS-DPoP header.
func WithDPoP(proof string) SendOption {
	return func(h http.Header) {
		h.Set(HeaderDPoP, proof)
	}
}
```

(`SendOption = func(http.Header)` already exists from P3b-1; no signature change to `SendGreet`.)

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./internal/comms/a2a/ -run 'DPoP|ExtNonce' -v` (PASS), then `go test ./internal/comms/a2a/` (all existing pass). `gofmt -l internal/comms/a2a/` clean, `go vet ./internal/comms/a2a/...` clean, `go build ./...` clean.

- [ ] **Step 7: Commit**

```bash
git add internal/comms/a2a/card.go internal/comms/a2a/message.go internal/comms/a2a/client.go internal/comms/a2a/dpop_transport_test.go
git commit -m "feat(a2a): carry a DPoP proof via X-ANS-DPoP and bind htm/htu; add ExtNonceURI"
```

---

## Task 2: nonce-aware initiator

**Files:**
- Modify: `internal/greet/initiator.go`
- Test: `internal/greet/nonce_initiate_test.go`

The initiator detects the nonce extension, fetches a nonce from the greeter's own `get_nonce` MCP tool, builds a per-session DPoP proof over it, and attaches it. This slots in beside the existing mandate branch — no signature change (Initiate already takes `mcpCli *mcp.Client`).

- [ ] **Step 1: Add the nonce branch + helpers to `internal/greet/initiator.go`**

Add imports: `"crypto/rand"`, `"encoding/hex"`, `"time"`, and `"github.com/an-ciobanu/agent-mesh/internal/crypto"`.

In `Initiate`, change the extension dispatch so it also handles the nonce extension. Replace the current `if ext, ok := mandateExtension(card); ok { ... } else if len(card.Security) != 0 { ... }` block with:

```go
	if ext, ok := mandateExtension(card); ok {
		mandate, merr := acquireMandate(ctx, disco, mcpCli, ext, callerAns, audienceAns)
		if merr != nil {
			return "", nil, peer, merr
		}
		opts = append(opts, a2a.WithMandate(mandate))
	} else if _, ok := nonceExtension(card); ok {
		proof, nerr := acquireDPoPProof(ctx, mcpCli, peer.BaseURL, card.URL)
		if nerr != nil {
			return "", nil, peer, nerr
		}
		opts = append(opts, a2a.WithDPoP(proof))
	} else if len(card.Security) != 0 {
		return "", nil, peer, fmt.Errorf("peer %q requires unsupported authentication", peer.Name)
	}
```

Add these helpers (near `mandateExtension`/`acquireMandate`):

```go
// nonceExtension returns the DPoP-nonce extension if the card advertises it.
func nonceExtension(card a2a.Card) (a2a.Extension, bool) {
	if card.Capabilities == nil {
		return a2a.Extension{}, false
	}
	for _, e := range card.Capabilities.Extensions {
		if e.URI == a2a.ExtNonceURI {
			return e, true
		}
	}
	return a2a.Extension{}, false
}

// acquireDPoPProof fetches a fresh nonce from the greeter's get_nonce MCP tool
// and returns a per-session DPoP proof (P-256/ES256) over it, bound to htu.
func acquireDPoPProof(ctx context.Context, mcpCli *mcp.Client, peerBaseURL, htu string) (string, error) {
	raw, err := mcpCli.Call(ctx, peerBaseURL+"/mcp", "get_nonce", map[string]string{})
	if err != nil {
		return "", fmt.Errorf("get_nonce: %w", err)
	}
	var out struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("parse get_nonce result: %w", err)
	}
	if out.Nonce == "" {
		return "", fmt.Errorf("greeter returned an empty nonce")
	}
	key, err := crypto.GenerateDPoPKey()
	if err != nil {
		return "", fmt.Errorf("generate dpop key: %w", err)
	}
	proof, err := crypto.CreateDPoPProof(key, crypto.DPoPClaims{
		HTM:   "POST",
		HTU:   htu,
		IAT:   time.Now().Unix(),
		JTI:   randID(),
		Nonce: out.Nonce,
	})
	if err != nil {
		return "", fmt.Errorf("create dpop proof: %w", err)
	}
	return proof, nil
}

func randID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
```

- [ ] **Step 2: Write the greet-package test**

Create `internal/greet/nonce_initiate_test.go`:

```go
package greet

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/discovery"
	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
	"github.com/an-ciobanu/agent-mesh/internal/comms/resolver"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/nonce"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
	"github.com/an-ciobanu/agent-mesh/internal/registry"
)

func nonceCard(name string) a2a.Card {
	return a2a.Card{
		Name: name, Version: "0.1.0",
		Security: []map[string][]string{{"dpop": {}}},
		Capabilities: &a2a.Capabilities{Extensions: []a2a.Extension{{
			URI: a2a.ExtNonceURI, Required: true,
		}}},
	}
}

func TestInitiateNonceHappyPath(t *testing.T) {
	ctx := context.Background()
	reg := httptest.NewServer(registry.New(zerolog.Nop()).Handler())
	defer reg.Close()
	disco := discovery.New(reg.URL)

	const gname = "greeter-nonce"
	self := domain.LocalANSName(gname)
	store := nonce.NewStore(time.Minute)
	guard := policy.NewNonce(self, store, zerolog.Nop())

	mux := a2a.NewMux(nonceCard(gname), a2a.NewGreetService(self, guard, zerolog.Nop()), zerolog.Nop())
	mcpSrv := mcp.NewServer(zerolog.Nop())
	mcpSrv.Register("get_nonce", store.MCPTool())
	mux.Handle("/mcp", mcpSrv.Handler())
	greeter := httptest.NewServer(mux)
	defer greeter.Close()

	if err := disco.Register(ctx, domain.AgentInfo{Name: gname, Role: "greeter-nonce", BaseURL: greeter.URL, CardURL: greeter.URL + "/.well-known/agent-card.json"}); err != nil {
		t.Fatal(err)
	}

	visitorPriv, _ := crypto.GenerateEd25519()
	reply, _, peer, err := Initiate(ctx, disco, resolver.New(), a2a.NewClient(), mcp.NewClient(),
		visitorPriv, domain.LocalANSName("visitor"), "greeter-nonce", "hello")
	if err != nil {
		t.Fatalf("nonce greet failed: %v", err)
	}
	if peer.Name != gname || reply == "" {
		t.Fatalf("unexpected result: peer=%s reply=%q", peer.Name, reply)
	}
}

func TestInitiateNonceNoGetNonce(t *testing.T) {
	ctx := context.Background()
	reg := httptest.NewServer(registry.New(zerolog.Nop()).Handler())
	defer reg.Close()
	disco := discovery.New(reg.URL)

	const gname = "greeter-nonce"
	self := domain.LocalANSName(gname)
	// Greeter advertises the nonce extension but serves NO /mcp get_nonce.
	greeter := httptest.NewServer(a2a.NewMux(nonceCard(gname), a2a.NewGreetService(self, policy.Open{}, zerolog.Nop()), zerolog.Nop()))
	defer greeter.Close()
	if err := disco.Register(ctx, domain.AgentInfo{Name: gname, Role: "greeter-nonce", BaseURL: greeter.URL, CardURL: greeter.URL + "/.well-known/agent-card.json"}); err != nil {
		t.Fatal(err)
	}

	visitorPriv, _ := crypto.GenerateEd25519()
	if _, _, _, err := Initiate(ctx, disco, resolver.New(), a2a.NewClient(), mcp.NewClient(),
		visitorPriv, domain.LocalANSName("visitor"), "greeter-nonce", "hi"); err == nil {
		t.Fatal("expected error when the greeter has no get_nonce endpoint")
	}
}
```

(No import cycle: `greet` test importing `nonce`/`policy`/`registry` — none import `greet`.)

- [ ] **Step 3: Run tests**

Run: `go test ./internal/greet/ -run Nonce -v` (PASS), then `go test ./internal/greet/ -v` (all — open, mandate, nonce), `go test ./internal/greet/ -cover` (report). `gofmt -l internal/greet/` clean, `go vet ./internal/greet/...` clean, `go build ./...` clean.

- [ ] **Step 4: Commit**

```bash
git add internal/greet/initiator.go internal/greet/nonce_initiate_test.go
git commit -m "feat(greet): nonce-aware initiator (get_nonce + DPoP proof-of-possession)"
```

---

## Task 3: cmd/agent — nonce mode

**Files:**
- Modify: `cmd/agent/main.go`

Extend `--policy` to accept `nonce`: build a nonce `Store` + `policy.Nonce`, serve `get_nonce` at `/mcp` alongside `/a2a`, and advertise the `ExtNonceURI` extension.

- [ ] **Step 1: Read the current file**

Read `cmd/agent/main.go`. It already has `--policy` (open|mandate), `--authority-role`, `--scope`, the `disco`/`ctx` setup, the `greetPolicy`/`card` block with the `mandate` case, `greetSvc := a2a.NewGreetService(...)`, and `srv := &http.Server{Addr: *addr, Handler: a2a.NewMux(card, greetSvc, log)}`.

- [ ] **Step 2: Add flag + imports**

Add flag:
```go
	nonceTTL := flag.Duration("nonce-ttl", 2*time.Minute, "nonce validity window (when --policy=nonce)")
```
Add imports: `"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"` and `"github.com/an-ciobanu/agent-mesh/internal/nonce"` (policy, a2a, discovery, domain, time already imported).

- [ ] **Step 3: Add the nonce case + serve /mcp**

The mux is currently built inline in the `http.Server` literal. Change it so the mux is a named variable and the nonce case can add `/mcp`. Introduce a `var mcpHandler http.Handler` set only in nonce mode, and after building the mux, mount it.

Replace the `if *policyName == "mandate" { ... }` block with an added nonce branch and a captured mcp handler:

```go
	var mcpHandler http.Handler

	switch *policyName {
	case "open":
		// default greetPolicy (policy.Open{}) and open card already set above.
	case "mandate":
		authPeer, authPub := resolveAuthority(ctx, disco, authclient.New(), *authorityRole, log)
		authorityAns := domain.LocalANSName(authPeer.Name)
		greetPolicy = policy.NewMandate(selfAns, authorityAns, authPub, *scope, log)
		card.Security = []map[string][]string{{"mandate": {}}}
		card.Capabilities = &a2a.Capabilities{Extensions: []a2a.Extension{{
			URI:         a2a.ExtMandateURI,
			Description: "present a mandate from the authority",
			Required:    true,
			Params:      map[string]any{"authorityRole": *authorityRole, "scope": *scope},
		}}}
		log.Info().Str("authorityAns", authorityAns).Str("scope", *scope).Msg("mandate policy enabled")
	case "nonce":
		store := nonce.NewStore(*nonceTTL)
		greetPolicy = policy.NewNonce(selfAns, store, log)
		mcpSrv := mcp.NewServer(log)
		mcpSrv.Register("get_nonce", store.MCPTool())
		mcpHandler = mcpSrv.Handler()
		card.Security = []map[string][]string{{"dpop": {}}}
		card.Capabilities = &a2a.Capabilities{Extensions: []a2a.Extension{{
			URI:         a2a.ExtNonceURI,
			Description: "obtain a nonce via get_nonce and present a DPoP proof",
			Required:    true,
		}}}
		log.Info().Dur("nonceTTL", *nonceTTL).Msg("nonce policy enabled")
	default:
		log.Fatal().Str("policy", *policyName).Msg("unknown --policy (want: open | mandate | nonce)")
	}
```

(If the current code uses an `if *policyName == "mandate"` rather than a `switch`, convert it to the `switch` above, preserving the existing open default and mandate body exactly.)

Then build the mux as a named variable and mount `/mcp` if present, and use it in the server:

```go
	greetSvc := a2a.NewGreetService(selfAns, greetPolicy, log, opts...)
	mux := a2a.NewMux(card, greetSvc, log)
	if mcpHandler != nil {
		mux.Handle("/mcp", mcpHandler)
	}
	srv := &http.Server{Addr: *addr, Handler: mux}
```

(`a2a.NewMux` returns `*http.ServeMux`, so `mux.Handle` is available. Mounting the mcp handler — itself a mux matching `POST /mcp` — at `/mcp` routes correctly because the inner mux matches on the full request path.)

- [ ] **Step 4: Build + smoke test**

Run: `go build ./cmd/agent/` and `go build ./...` (exit 0). `gofmt -l cmd/agent/` clean, `go vet ./cmd/agent/...` clean.

Smoke test (do it, then clean up; build into a scratch dir, `-o` to avoid stray repo-root binaries): start `registry`, then `agent --name greeter-nonce --role greeter-nonce --policy nonce --registry http://<reg>`; confirm it logs "nonce policy enabled" and registers; then `meshctl greet --from visitor --to-role greeter-nonce --text hi` returns a `reply:` line; confirm the greeter logs "nonce proof accepted". Kill all, remove scratch artifacts, confirm `git status` clean before committing. Paste the relevant lines.

- [ ] **Step 5: Commit**

```bash
git add cmd/agent/main.go
git commit -m "feat(cmd): agent --policy nonce mode (serve get_nonce + DPoP guard)"
```

---

## Task 4: end-to-end integration test

**Files:**
- Create: `internal/integration/p4b_test.go`

- [ ] **Step 1: Write the test**

```go
package integration

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/discovery"
	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
	"github.com/an-ciobanu/agent-mesh/internal/comms/resolver"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/greet"
	"github.com/an-ciobanu/agent-mesh/internal/nonce"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
	"github.com/an-ciobanu/agent-mesh/internal/registry"
)

func TestP4B_NonceGreetEndToEnd(t *testing.T) {
	ctx := context.Background()
	reg := httptest.NewServer(registry.New(zerolog.Nop()).Handler())
	defer reg.Close()
	disco := discovery.New(reg.URL)

	const gname = "greeter-nonce"
	self := domain.LocalANSName(gname)
	store := nonce.NewStore(time.Minute)
	guard := policy.NewNonce(self, store, zerolog.Nop())

	mux := a2a.NewMux(a2a.Card{
		Name: gname, Version: "0.1.0",
		Security: []map[string][]string{{"dpop": {}}},
		Capabilities: &a2a.Capabilities{Extensions: []a2a.Extension{{URI: a2a.ExtNonceURI, Required: true}}},
	}, a2a.NewGreetService(self, guard, zerolog.Nop()), zerolog.Nop())
	mcpSrv := mcp.NewServer(zerolog.Nop())
	mcpSrv.Register("get_nonce", store.MCPTool())
	mux.Handle("/mcp", mcpSrv.Handler())
	greeter := httptest.NewServer(mux)
	defer greeter.Close()
	if err := disco.Register(ctx, domain.AgentInfo{Name: gname, Role: "greeter-nonce", BaseURL: greeter.URL, CardURL: greeter.URL + "/.well-known/agent-card.json"}); err != nil {
		t.Fatal(err)
	}

	visitorPriv, _ := crypto.GenerateEd25519()
	visitorAns := domain.LocalANSName("visitor")
	greetEndpoint := greeter.URL + "/a2a"
	htu := greetEndpoint // card.URL resolves to this same host+/a2a

	// Happy path: initiator discovers the requirement, gets a nonce, proves, greets.
	reply, _, peer, err := greet.Initiate(ctx, disco, resolver.New(), a2a.NewClient(), mcp.NewClient(),
		visitorPriv, visitorAns, "greeter-nonce", "hello")
	if err != nil {
		t.Fatalf("nonce greet failed: %v", err)
	}
	if peer.Name != gname || reply == "" {
		t.Fatalf("unexpected greet result: peer=%s reply=%q", peer.Name, reply)
	}

	// Negative 1: a greet with NO DPoP proof is rejected.
	if _, _, err := a2a.NewClient().SendGreet(ctx, greetEndpoint, visitorPriv, a2a.GreetPayload{
		CallerAns: visitorAns, AudienceAns: self, Greeting: "sneak",
	}); err == nil {
		t.Fatal("expected rejection: no DPoP proof")
	}

	// Negative 2: a replayed nonce is rejected (consume once).
	nonceCli := mcp.NewClient()
	raw, err := nonceCli.Call(ctx, greeter.URL+"/mcp", "get_nonce", map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	key, _ := crypto.GenerateDPoPKey()
	mkProof := func(n string) string {
		p, perr := crypto.CreateDPoPProof(key, crypto.DPoPClaims{HTM: "POST", HTU: htu, IAT: time.Now().Unix(), JTI: "j", Nonce: n})
		if perr != nil {
			t.Fatal(perr)
		}
		return p
	}
	if _, _, err := a2a.NewClient().SendGreet(ctx, greetEndpoint, visitorPriv, a2a.GreetPayload{
		CallerAns: visitorAns, AudienceAns: self, Greeting: "first",
	}, a2a.WithDPoP(mkProof(got.Nonce))); err != nil {
		t.Fatalf("first use of nonce should succeed: %v", err)
	}
	if _, _, err := a2a.NewClient().SendGreet(ctx, greetEndpoint, visitorPriv, a2a.GreetPayload{
		CallerAns: visitorAns, AudienceAns: self, Greeting: "replay",
	}, a2a.WithDPoP(mkProof(got.Nonce))); err == nil {
		t.Fatal("expected rejection: replayed (already-consumed) nonce")
	}

	// Negative 3: a proof bound to the wrong htu is rejected.
	raw2, _ := nonceCli.Call(ctx, greeter.URL+"/mcp", "get_nonce", map[string]string{})
	var got2 struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(raw2, &got2); err != nil {
		t.Fatal(err)
	}
	badHTU, _ := crypto.CreateDPoPProof(key, crypto.DPoPClaims{HTM: "POST", HTU: "http://evil.example/a2a", IAT: time.Now().Unix(), JTI: "j2", Nonce: got2.Nonce})
	if _, _, err := a2a.NewClient().SendGreet(ctx, greetEndpoint, visitorPriv, a2a.GreetPayload{
		CallerAns: visitorAns, AudienceAns: self, Greeting: "wrong-htu",
	}, a2a.WithDPoP(badHTU)); err == nil {
		t.Fatal("expected rejection: DPoP htu mismatch")
	}
}
```

- [ ] **Step 2: Run the test**

Run: `go test ./internal/integration/ -run P4B -v` (PASS), then `go test ./internal/integration/ -v` (all P0..P4B pass). `gofmt -l internal/integration/` clean, `go vet ./internal/integration/...` clean.

- [ ] **Step 3: Commit**

```bash
git add internal/integration/p4b_test.go
git commit -m "test(integration): P4b end-to-end nonce greet + fail-closed rejections"
```

---

## Task 5: demo script

**Files:**
- Create: `scripts/demo/p4b-nonce-greet.sh`

- [ ] **Step 1: Read the existing demo scripts** (`scripts/demo/p3b-mandate-greet.sh`, `p2b-greet-audit.sh`) and match conventions.

- [ ] **Step 2: Create `scripts/demo/p4b-nonce-greet.sh`**

```bash
#!/usr/bin/env bash
# P4b demo: start the registry and a nonce-gated greeter. The greeter's card
# advertises that a DPoP proof-of-possession is required; meshctl discovers the
# greeter, fetches a nonce from its get_nonce MCP tool, builds a P-256 DPoP proof
# over it, and greets. The nonce greeter is self-contained (no authority).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

make build

REG_ADDR="127.0.0.1:18090"
GREETER_ADDR="127.0.0.1:18103"
pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

./bin/registry --addr "$REG_ADDR" & pids+=("$!")
sleep 0.5
./bin/agent --name greeter-nonce --role greeter-nonce --addr "$GREETER_ADDR" \
	--registry "http://$REG_ADDR" --policy nonce & pids+=("$!")
sleep 1

echo "== meshctl greet (nonce / DPoP-gated) =="
OUT=$(./bin/meshctl greet --from visitor --to-role greeter-nonce --text "hello there")
echo "$OUT"
echo "$OUT" | grep -q "reply:"

echo "P4b demo OK"
```

- [ ] **Step 3: Make executable and RUN it**

```bash
chmod +x scripts/demo/p4b-nonce-greet.sh
./scripts/demo/p4b-nonce-greet.sh
```
Expected: the greeter logs "nonce policy enabled" and "nonce proof accepted"; `meshctl` prints `greeted greeter-nonce (...)` and a `reply:` line; then `P4b demo OK`; exit 0. Paste the full output. Confirm `git status` shows only the new script (bin/ and data/ are gitignored).

- [ ] **Step 4: Commit**

```bash
git add scripts/demo/p4b-nonce-greet.sh
git commit -m "chore(demo): P4b nonce-gated greet (DPoP proof-of-possession)"
```

---

## Task 6: gate + re-run all demos

**Files:** none (verification only).

- [ ] **Step 1: Full gate**

```bash
gofmt -l .          # expect no output
go vet ./...        # expect clean
go build ./...      # expect exit 0
go test ./...       # expect all pass
go mod tidy && git diff --exit-code go.mod go.sum   # expect no changes
git log master..HEAD --format='%b' | grep -i "co-authored-by" && echo FOUND || echo NONE   # expect NONE
git status --porcelain   # expect empty
```

- [ ] **Step 2: Re-run every demo (cross-phase no-regression)**

Run each one at a time and confirm its final "… OK"/reply line:
```bash
./scripts/demo/p0-discovery.sh
./scripts/demo/p1-greet.sh
./scripts/demo/p2a-transparency.sh
./scripts/demo/p2b-greet-audit.sh
./scripts/demo/p3a-mandate.sh
./scripts/demo/p3b-mandate-greet.sh
./scripts/demo/p4b-nonce-greet.sh
```

---

## Self-review

**Spec coverage (P4b scope):**
- Carry the DPoP proof + bind htm/htu → Task 1 (`X-ANS-DPoP` header, `WithDPoP`, server fills `HTTPMethod`/`HTTPURL`) + `ExtNonceURI`. ✓
- Nonce-aware initiator (discovers the requirement from the card, fetches a nonce, builds a per-session DPoP proof) → Task 2. ✓
- `cmd/agent --policy nonce`: serve `get_nonce` at `/mcp`, enforce `policy.Nonce`, advertise the extension → Task 3. ✓
- End-to-end proof incl. fail-closed rejections (no proof; replayed nonce; wrong htu) → Task 4. ✓
- Runnable demo + no-regression across all phases → Tasks 5, 6. ✓
- Deferred correctly (absent): mandate DPoP-binding (future); UI (P5). Noted in Scope.

**Placeholder scan:** none — every step has concrete code or an exact command with expected output.

**Type consistency check:**
- `a2a.HeaderDPoP` const, `a2a.WithDPoP(string) SendOption`, `a2a.ExtNonceURI` — defined Task 1; used by the initiator (Task 2), `cmd/agent` (Task 3), and the integration test (Task 4). `SendOption = func(http.Header)` (P3b-1) unchanged. ✓
- The a2a handler fills `GreetRequest.DPoPProof` (= `X-ANS-DPoP` verbatim), `HTTPMethod` (= `r.Method`), `HTTPURL` (= `http://`+host+path) — the exact fields `policy.Nonce.Authorize` reads (P4a). ✓
- `greet.Initiate` signature unchanged (already takes `mcpCli *mcp.Client` from P3b-2); the nonce branch calls the greeter's own `peer.BaseURL + "/mcp"` `get_nonce`, parses `{nonce}`, and builds `crypto.CreateDPoPProof(crypto.GenerateDPoPKey(), crypto.DPoPClaims{...})` with `HTU = card.URL` — which equals the server's reconstructed htu (`http://`+host+`/a2a`). ✓
- `nonce.NewStore(ttl).MCPTool()` returns `mcp.ToolFunc`; registered as `get_nonce` on both the integration greeter (Task 4) and `cmd/agent` (Task 3). `policy.NewNonce(selfAns, store, log)` shares the SAME `*nonce.Store` instance as the `get_nonce` tool, so issued nonces are the ones consumed. ✓
- `a2a.NewMux` returns `*http.ServeMux`; Tasks 3 and 4 call `mux.Handle("/mcp", mcpSrv.Handler())` on it. The get_nonce mcp handler matches `POST /mcp`; the initiator posts get_nonce there. ✓
- Open/mandate greet paths unchanged: a card without the nonce (or mandate) extension and empty Security still takes the open branch; the a2a handler always sets DPoP/HTTP fields but non-nonce policies ignore them. ✓
