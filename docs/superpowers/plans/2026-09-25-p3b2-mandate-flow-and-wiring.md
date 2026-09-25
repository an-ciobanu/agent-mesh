# agent-mesh P3b-2 — Mandate Flow + Wiring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make mandate-gated greeting run end-to-end: an initiator discovers the requirement from a greeter's Agent Card (nothing hardcoded), obtains a mandate from the authority the card points to (via `issue_mandate` over MCP), and greets; a `cmd/agent` mandate mode pins the authority key at startup and enforces the P3b-1 guard.

**Architecture:** Completes P3b. Adds `crypto.PublicKeyFromJWK` and a small `authclient` that fetches an authority's `/pubkey`. The `greet.Initiate` initiator becomes mandate-aware: it reads the peer's card, and if the card advertises the `ExtMandateURI` extension it discovers the authority by the role named in the extension, calls `issue_mandate` over MCP, and attaches the mandate via the `X-ANS-Mandate` header (all from P3b-1). `cmd/agent` gains a `--policy mandate` mode that, at startup, discovers + pins the authority's Ed25519 key, builds the `policy.Mandate` guard, and advertises the card extension. A full integration test proves the happy path plus fail-closed rejections; a demo runs it as real processes.

**Tech Stack:** Go 1.23, existing deps (`rs/zerolog`, `veraison/go-cose` via `internal/crypto`); no new dependencies.

**Scope:** P3b-2 is the flow + wiring. It builds on P3b-1 (already merged: `GreetRequest.Mandate`, card `capabilities.extensions` + `ExtMandateURI`, the `X-ANS-Mandate` transport with `a2a.WithMandate`, and the `policy.Mandate` guard). DPoP sender-constraint (binding a mandate to the caller's key) and single-use/`jti` tracking remain **P4**. The nonce greeter is **P4**; the UI is **P5**.

**Baseline:** P0–P3b-1 merged on `master`. Reuse: `crypto.{JWK,PublicJWK,VerifyCOSE1,SignCOSE1,GenerateEd25519,LoadOrCreateEd25519}`; `domain.{AgentInfo,Discovery,GreetPayload,LocalANSName,EvidenceBundle}`; `a2a.{Card,Capabilities,Extension,ExtMandateURI,Client,SendGreet,WithMandate,SendOption,NewGreetService,NewMux}`; `mcp.{NewClient,Client.Call}`; `authority.{New,MCPTool}`; `policy.{Open,NewMandate}`; `discovery.{New,Search}`; `resolver.{New,FetchCard}`; `registry.New`. Do all work on a branch off `master` (e.g. `p3b2-mandate-flow`).

---

## File structure (this plan)

```
internal/crypto/keys.go                        # MODIFY: add PublicKeyFromJWK
internal/crypto/keys_test.go                   # MODIFY/CREATE: PublicKeyFromJWK tests
internal/comms/authclient/client.go            # NEW: fetch an authority's /pubkey
internal/comms/authclient/client_test.go       # NEW
internal/greet/initiator.go                    # MODIFY: mandate-aware Initiate (reads card, acquires mandate)
internal/greet/initiator_test.go               # MODIFY (if it calls Initiate): update signature; add mandate case if present
cmd/meshctl/main.go                            # MODIFY: pass mcp.NewClient() to Initiate
internal/integration/p1_test.go                # MODIFY: update Initiate call signature
internal/integration/p2b_test.go               # MODIFY: update Initiate call signature
cmd/agent/main.go                              # MODIFY: --policy mandate mode (pin authority key, advertise extension)
internal/integration/p3b_test.go               # NEW: end-to-end mandate greet + rejections
scripts/demo/p3b-mandate-greet.sh              # NEW: runnable demo
```

Conventions unchanged: hexagonal Go; injected `zerolog.Logger` tagged `component`; no `fmt.Println`/`log` in library code (cmd stdout via logger/`fmt` in CLI is fine); crypto targets 100%; `gofmt`/`go vet` clean before every commit; **no AI `Co-Authored-By:` trailer**, no `git commit -s`.

---

## Task 1: crypto — JWK → Ed25519 public key

**Files:**
- Modify: `internal/crypto/keys.go`
- Test: `internal/crypto/keys_test.go` (append if it exists; else create)

- [ ] **Step 1: Write the failing test**

First check whether `internal/crypto/keys_test.go` exists (`ls internal/crypto/`). If it exists, APPEND the function below (reuse its `package crypto` and imports; add `"crypto/ed25519"`/`"strings"` only if missing). If not, create it:

```go
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestPublicKeyFromJWKRoundTrip(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	got, err := PublicKeyFromJWK(PublicJWK(pub))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(pub) {
		t.Fatal("round-tripped key does not match")
	}
}

func TestPublicKeyFromJWKRejectsWrongType(t *testing.T) {
	if _, err := PublicKeyFromJWK(JWK{Kty: "RSA", Crv: "Ed25519", X: "x"}); err == nil {
		t.Fatal("expected error for non-OKP key")
	}
	if _, err := PublicKeyFromJWK(JWK{Kty: "OKP", Crv: "P-256", X: "x"}); err == nil {
		t.Fatal("expected error for non-Ed25519 curve")
	}
}

func TestPublicKeyFromJWKRejectsBadX(t *testing.T) {
	if _, err := PublicKeyFromJWK(JWK{Kty: "OKP", Crv: "Ed25519", X: "!!!not base64!!!"}); err == nil {
		t.Fatal("expected error for invalid base64 x")
	}
	if _, err := PublicKeyFromJWK(JWK{Kty: "OKP", Crv: "Ed25519", X: "YWJj"}); err == nil {
		t.Fatal("expected error for wrong key size")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/crypto/ -run PublicKeyFromJWK -v`
Expected: FAIL — `undefined: PublicKeyFromJWK`.

- [ ] **Step 3: Add the function to `internal/crypto/keys.go`**

(`crypto/ed25519`, `encoding/base64`, and `fmt` are already imported by this file.) Add:

```go
// PublicKeyFromJWK converts an Ed25519 OKP JWK to a public key. It is the
// inverse of PublicJWK.
func PublicKeyFromJWK(j JWK) (ed25519.PublicKey, error) {
	if j.Kty != "OKP" || j.Crv != "Ed25519" {
		return nil, fmt.Errorf("jwk: not an Ed25519 OKP key")
	}
	raw, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, fmt.Errorf("jwk: decode x: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("jwk: bad key size %d", len(raw))
	}
	return ed25519.PublicKey(raw), nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/crypto/ -run PublicKeyFromJWK -v` (PASS), then `go test ./internal/crypto/ -cover` — expect 100% still (crypto target).

- [ ] **Step 5: Commit**

```bash
git add internal/crypto/keys.go internal/crypto/keys_test.go
git commit -m "feat(crypto): PublicKeyFromJWK (inverse of PublicJWK)"
```

---

## Task 2: authclient — fetch an authority's public key

**Files:**
- Create: `internal/comms/authclient/client.go`
- Test: `internal/comms/authclient/client_test.go`

- [ ] **Step 1: Write the failing test**

```go
package authclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
)

func TestFetchPubKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /pubkey", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(crypto.PublicJWK(pub))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	got, err := New().FetchPubKey(context.Background(), ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(pub) {
		t.Fatal("fetched key does not match")
	}
}

func TestFetchPubKeyNon200(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer ts.Close()
	if _, err := New().FetchPubKey(context.Background(), ts.URL); err == nil {
		t.Fatal("expected error on non-200 status")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/comms/authclient/ -v`
Expected: FAIL — package/`New` undefined.

- [ ] **Step 3: Write `internal/comms/authclient/client.go`**

```go
// Package authclient fetches a mandate authority's public key over HTTP.
package authclient

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
)

// Client fetches authority public keys.
type Client struct {
	http *http.Client
}

// New returns a client with a bounded timeout.
func New() *Client {
	return &Client{http: &http.Client{Timeout: 5 * time.Second}}
}

// FetchPubKey GETs baseURL/pubkey and returns the authority's Ed25519 key.
func (c *Client) FetchPubKey(ctx context.Context, baseURL string) (ed25519.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/pubkey", nil)
	if err != nil {
		return nil, fmt.Errorf("build pubkey request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pubkey request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pubkey: unexpected status %d", resp.StatusCode)
	}
	var jwk crypto.JWK
	if err := json.NewDecoder(resp.Body).Decode(&jwk); err != nil {
		return nil, fmt.Errorf("decode jwk: %w", err)
	}
	pub, err := crypto.PublicKeyFromJWK(jwk)
	if err != nil {
		return nil, fmt.Errorf("authority pubkey: %w", err)
	}
	return pub, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/comms/authclient/ -v` (PASS), `go test ./internal/comms/authclient/ -cover` (report; expect ≥90%).

- [ ] **Step 5: Commit**

```bash
git add internal/comms/authclient/client.go internal/comms/authclient/client_test.go
git commit -m "feat(authclient): fetch an authority's Ed25519 public key"
```

---

## Task 3: mandate-aware initiator + update callers

**Files:**
- Modify: `internal/greet/initiator.go`
- Modify: `internal/greet/initiator_test.go` (only if it calls `Initiate` — update the call signature)
- Modify: `cmd/meshctl/main.go`
- Modify: `internal/integration/p1_test.go`, `internal/integration/p2b_test.go`

The initiator becomes mandate-aware: it reads the peer's card and, if the card advertises the mandate extension, discovers the authority by the role the extension names, obtains a mandate over MCP, and attaches it. Nothing about the peer or authority is hardcoded — the requirement is discovered from the card.

- [ ] **Step 1: Replace `internal/greet/initiator.go` with the mandate-aware version**

```go
// Package greet drives an initiator: discover a peer, resolve how to call it,
// satisfy any mandate requirement its card advertises, and send an
// identity-signed greet.
package greet

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
	"github.com/an-ciobanu/agent-mesh/internal/comms/resolver"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

// Initiate finds a peer of role toRole, reads its Agent Card to learn how to
// call it, satisfies any mandate requirement the card advertises (by discovering
// the authority the card points to and obtaining a mandate over MCP), and sends
// an identity-signed greet. It returns the reply, any transparency evidence the
// peer sealed (nil if none), and the peer it greeted. Nothing about the peer or
// the authority is hardcoded: the requirement is discovered from the card.
func Initiate(
	ctx context.Context,
	disco domain.Discovery,
	res *resolver.Resolver,
	cli *a2a.Client,
	mcpCli *mcp.Client,
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

	audienceAns := domain.LocalANSName(peer.Name)
	var opts []a2a.SendOption

	if ext, ok := mandateExtension(card); ok {
		mandate, merr := acquireMandate(ctx, disco, mcpCli, ext, callerAns, audienceAns)
		if merr != nil {
			return "", nil, peer, merr
		}
		opts = append(opts, a2a.WithMandate(mandate))
	} else if len(card.Security) != 0 {
		return "", nil, peer, fmt.Errorf("peer %q requires unsupported authentication", peer.Name)
	}

	reply, evidence, err := cli.SendGreet(ctx, card.URL, priv, a2a.GreetPayload{
		CallerAns:   callerAns,
		AudienceAns: audienceAns,
		Greeting:    greeting,
	}, opts...)
	if err != nil {
		return "", nil, peer, err
	}
	return reply, evidence, peer, nil
}

// mandateExtension returns the mandate-required extension if the card advertises it.
func mandateExtension(card a2a.Card) (a2a.Extension, bool) {
	if card.Capabilities == nil {
		return a2a.Extension{}, false
	}
	for _, e := range card.Capabilities.Extensions {
		if e.URI == a2a.ExtMandateURI {
			return e, true
		}
	}
	return a2a.Extension{}, false
}

// acquireMandate discovers the authority named by the extension and obtains a
// mandate for callerAns->audienceAns via the authority's issue_mandate MCP tool.
func acquireMandate(ctx context.Context, disco domain.Discovery, mcpCli *mcp.Client, ext a2a.Extension, callerAns, audienceAns string) ([]byte, error) {
	authorityRole := stringParam(ext.Params, "authorityRole", "authority")
	scope := stringParam(ext.Params, "scope", "greet")

	authorities, err := disco.Search(ctx, authorityRole)
	if err != nil {
		return nil, fmt.Errorf("discover authority role %q: %w", authorityRole, err)
	}
	if len(authorities) == 0 {
		return nil, fmt.Errorf("no authority found for role %q", authorityRole)
	}
	authURL := authorities[0].BaseURL + "/mcp"

	raw, err := mcpCli.Call(ctx, authURL, "issue_mandate", map[string]string{
		"subjectAns":  callerAns,
		"audienceAns": audienceAns,
		"scope":       scope,
	})
	if err != nil {
		return nil, fmt.Errorf("issue_mandate: %w", err)
	}
	var out struct {
		MandateCOSE []byte `json:"mandateCose"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("parse issue_mandate result: %w", err)
	}
	if len(out.MandateCOSE) == 0 {
		return nil, fmt.Errorf("authority returned an empty mandate")
	}
	return out.MandateCOSE, nil
}

// stringParam reads a string extension param, falling back to def.
func stringParam(params map[string]any, key, def string) string {
	if params != nil {
		if v, ok := params[key].(string); ok && v != "" {
			return v
		}
	}
	return def
}
```

- [ ] **Step 2: Update all callers to pass an `*mcp.Client`**

Find every caller: `grep -rn "greet.Initiate" cmd/ internal/`. Each must add an `mcp.NewClient()` argument in the 5th position (after `cli`, before `priv`).

In `cmd/meshctl/main.go` `runGreet`, change the call to:
```go
	reply, evidence, peer, err := greet.Initiate(
		ctx,
		discovery.New(*registryURL),
		resolver.New(),
		a2a.NewClient(),
		mcp.NewClient(),
		priv, callerAns, *toRole, *text,
	)
```
(`mcp` is already imported in `cmd/meshctl/main.go`.)

In `internal/integration/p1_test.go` and `internal/integration/p2b_test.go`, update their `greet.Initiate(...)` calls to insert `mcp.NewClient()` in the same position, and add the import `"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"` to each test file.

If `internal/greet/initiator_test.go` exists and calls `Initiate`, update those calls the same way (add `mcp.NewClient()`), and add the `mcp` import.

- [ ] **Step 3: Build and test**

Run:
```bash
go build ./...
go test ./internal/greet/ ./internal/integration/ ./cmd/... -count=1
```
Expected: all compile and pass. The open-greet paths (P1/P2b) still work — a card with no mandate extension and empty `Security` takes the open branch unchanged.

`gofmt -l internal/greet/ cmd/meshctl/ internal/integration/` clean, `go vet ./internal/greet/... ./cmd/meshctl/... ./internal/integration/...` clean.

- [ ] **Step 4: Commit**

```bash
git add internal/greet/initiator.go cmd/meshctl/main.go internal/integration/p1_test.go internal/integration/p2b_test.go
# include internal/greet/initiator_test.go only if it was modified
git commit -m "feat(greet): mandate-aware initiator (discovers requirement from the card)"
```

---

## Task 4: cmd/agent — mandate mode

**Files:**
- Modify: `cmd/agent/main.go`

Add a `--policy mandate` mode that, at startup, discovers and pins the authority's key, builds the `policy.Mandate` guard, and advertises the mandate extension on the card.

- [ ] **Step 1: Add flags**

After the existing flags in `main`, add:
```go
	policyName := flag.String("policy", "open", "greet policy: open | mandate")
	authorityRole := flag.String("authority-role", "authority", "role of the mandate authority (when --policy=mandate)")
	scope := flag.String("scope", "greet", "required mandate scope (when --policy=mandate)")
```

- [ ] **Step 2: Add imports**

Add to the import block: `"crypto/ed25519"`, `"github.com/an-ciobanu/agent-mesh/internal/comms/authclient"`, and `"github.com/an-ciobanu/agent-mesh/internal/policy"` (policy is likely already imported; do not duplicate).

- [ ] **Step 3: Build the policy and card by mode**

Create the discovery client once, early (it is currently created lower down for registration — move that single `disco := discovery.New(*registryURL)` up to just after the logger/key setup, and reuse it). Replace the current `card := a2a.Card{...}` + `policy.Open{}` wiring with:

```go
	disco := discovery.New(*registryURL)
	ctx := context.Background()

	var greetPolicy domain.GreetPolicy = policy.Open{}
	card := a2a.Card{
		Name:    *name,
		Version: "0.1.0",
		// URL is filled in per-request by serveCard from the request host.
		Security: []map[string][]string{}, // open by default
	}

	if *policyName == "mandate" {
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
	}
```

Then change the greet-service construction to use `greetPolicy` instead of `policy.Open{}`:
```go
	greetSvc := a2a.NewGreetService(selfAns, greetPolicy, log, opts...)
```

Update the registration block to reuse the `disco` and `ctx` created above (remove the now-duplicate `disco := discovery.New(*registryURL)` and `ctx := context.Background()` that appear later; keep the retry loop).

- [ ] **Step 4: Add the `resolveAuthority` helper**

Below `main`:
```go
// resolveAuthority discovers the authority of the given role and pins its public
// key, retrying to tolerate startup races. A mandate greeter cannot serve
// without a pinned authority key, so failure is fatal (fail closed).
func resolveAuthority(ctx context.Context, disco *discovery.Client, ac *authclient.Client, role string, log zerolog.Logger) (domain.AgentInfo, ed25519.PublicKey) {
	for i := 0; i < 20; i++ {
		peers, err := disco.Search(ctx, role)
		if err == nil && len(peers) > 0 {
			pub, perr := ac.FetchPubKey(ctx, peers[0].BaseURL)
			if perr == nil {
				log.Info().Str("authority", peers[0].Name).Str("baseURL", peers[0].BaseURL).Msg("pinned authority key")
				return peers[0], pub
			}
			log.Warn().Err(perr).Msg("fetch authority pubkey; retrying")
		}
		time.Sleep(250 * time.Millisecond)
	}
	log.Fatal().Str("role", role).Msg("could not resolve/pin the authority; a mandate greeter cannot start without it")
	return domain.AgentInfo{}, nil // unreachable
}
```

(`discovery.New` returns `*discovery.Client`; `disco.Search(ctx, role)` returns `[]domain.AgentInfo`; both already used in this file/elsewhere.)

- [ ] **Step 5: Build + smoke test**

Run: `go build ./cmd/agent/` and `go build ./...` (exit 0). `gofmt -l cmd/agent/` clean, `go vet ./cmd/agent/...` clean.

Smoke test (recommended; clean up afterward): build `registry`, `authority`, `agent`, `meshctl` into a scratch dir; start registry, then authority, then `agent --name greeter-mandate --role greeter-mandate --policy mandate --authority-role authority`; confirm the agent logs "pinned authority key" and "mandate policy enabled" and registers; then `meshctl greet --to-role greeter-mandate` returns a reply; kill all and remove scratch artifacts. Report what you did. If awkward, at minimum ensure `make build` succeeds and rely on Task 5's integration test + Task 6's demo.

- [ ] **Step 6: Commit**

```bash
git add cmd/agent/main.go
git commit -m "feat(cmd): agent --policy mandate mode (pin authority key, advertise extension)"
```

---

## Task 5: end-to-end integration test

**Files:**
- Create: `internal/integration/p3b_test.go`

- [ ] **Step 1: Write the test**

```go
package integration

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/authority"
	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/authclient"
	"github.com/an-ciobanu/agent-mesh/internal/comms/discovery"
	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
	"github.com/an-ciobanu/agent-mesh/internal/comms/resolver"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/greet"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
	"github.com/an-ciobanu/agent-mesh/internal/registry"
)

func TestP3B_MandateGreetEndToEnd(t *testing.T) {
	ctx := context.Background()
	reg := httptest.NewServer(registry.New(zerolog.Nop()).Handler())
	defer reg.Close()
	disco := discovery.New(reg.URL)

	// Authority: serves issue_mandate over MCP and its /pubkey.
	authPriv, _ := crypto.GenerateEd25519()
	authAns := domain.LocalANSName("authority-1")
	auth := authority.New(authAns, authPriv, time.Hour, zerolog.Nop())
	mcpSrv := mcp.NewServer(zerolog.Nop())
	mcpSrv.Register("issue_mandate", auth.MCPTool())
	authMux := http.NewServeMux()
	authMux.Handle("/mcp", mcpSrv.Handler())
	authMux.HandleFunc("GET /pubkey", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(crypto.PublicJWK(authPriv.Public().(ed25519.PublicKey)))
	})
	authSrv := httptest.NewServer(authMux)
	defer authSrv.Close()
	if err := disco.Register(ctx, domain.AgentInfo{
		Name: "authority-1", Role: "authority", BaseURL: authSrv.URL, CardURL: authSrv.URL + "/.well-known/agent-card.json",
	}); err != nil {
		t.Fatal(err)
	}

	// Mandate greeter: pins the authority key and advertises the extension.
	const gname = "greeter-mandate"
	self := domain.LocalANSName(gname)
	authPub, err := authclient.New().FetchPubKey(ctx, authSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	guard := policy.NewMandate(self, authAns, authPub, "greet", zerolog.Nop())
	svc := a2a.NewGreetService(self, guard, zerolog.Nop())
	card := a2a.Card{
		Name: gname, Version: "0.1.0",
		Security: []map[string][]string{{"mandate": {}}},
		Capabilities: &a2a.Capabilities{Extensions: []a2a.Extension{{
			URI: a2a.ExtMandateURI, Required: true,
			Params: map[string]any{"authorityRole": "authority", "scope": "greet"},
		}}},
	}
	greeter := httptest.NewServer(a2a.NewMux(card, svc, zerolog.Nop()))
	defer greeter.Close()
	if err := disco.Register(ctx, domain.AgentInfo{
		Name: gname, Role: "greeter-mandate", BaseURL: greeter.URL, CardURL: greeter.URL + "/.well-known/agent-card.json",
	}); err != nil {
		t.Fatal(err)
	}

	visitorPriv, _ := crypto.GenerateEd25519()
	visitorAns := domain.LocalANSName("visitor")

	// Happy path: the initiator discovers the requirement, gets a mandate, greets.
	reply, _, peer, err := greet.Initiate(ctx, disco, resolver.New(), a2a.NewClient(), mcp.NewClient(),
		visitorPriv, visitorAns, "greeter-mandate", "hello")
	if err != nil {
		t.Fatalf("mandate greet failed: %v", err)
	}
	if peer.Name != gname || reply == "" {
		t.Fatalf("unexpected greet result: peer=%s reply=%q", peer.Name, reply)
	}

	greetEndpoint := greeter.URL + "/a2a"

	// Negative 1: a direct greet with NO mandate is rejected (fail closed).
	if _, _, err := a2a.NewClient().SendGreet(ctx, greetEndpoint, visitorPriv, a2a.GreetPayload{
		CallerAns: visitorAns, AudienceAns: self, Greeting: "sneak in",
	}); err == nil {
		t.Fatal("expected rejection: no mandate presented")
	}

	// Negative 2: a mandate forged by a non-authority key is rejected.
	forgerPriv, _ := crypto.GenerateEd25519()
	forger := authority.New(authAns, forgerPriv, time.Hour, zerolog.Nop())
	forged, err := forger.IssueMandate(visitorAns, self, "greet")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a2a.NewClient().SendGreet(ctx, greetEndpoint, visitorPriv, a2a.GreetPayload{
		CallerAns: visitorAns, AudienceAns: self, Greeting: "forged",
	}, a2a.WithMandate(forged)); err == nil {
		t.Fatal("expected rejection: mandate not signed by the trusted authority")
	}
}
```

- [ ] **Step 2: Run the test**

Run: `go test ./internal/integration/ -run P3B -v` (PASS), then `go test ./internal/integration/ -v` — all P0..P3B pass.
`gofmt -l internal/integration/p3b_test.go` clean, `go vet ./internal/integration/...` clean.

- [ ] **Step 3: Commit**

```bash
git add internal/integration/p3b_test.go
git commit -m "test(integration): P3b end-to-end mandate greet + fail-closed rejections"
```

---

## Task 6: demo script

**Files:**
- Create: `scripts/demo/p3b-mandate-greet.sh`

- [ ] **Step 1: Write the script**

Match the existing demo scripts' conventions (read `scripts/demo/p2b-greet-audit.sh` and `scripts/demo/p3a-mandate.sh` first; mirror shebang, `set -euo pipefail`, root computation, `make build`, pids/trap, ports, sleeps).

```bash
#!/usr/bin/env bash
# P3b demo: start the registry, an authority, and a mandate-gated greeter. The
# greeter's card advertises that a mandate is required and points to the
# authority by role. meshctl discovers the greeter, follows the card to the
# authority, obtains a mandate over MCP (issue_mandate), and greets — all with
# nothing hardcoded about who to talk to.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

make build

REG_ADDR="127.0.0.1:18090"
AUTH_ADDR="127.0.0.1:18110"
GREETER_ADDR="127.0.0.1:18102"
pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

./bin/registry --addr "$REG_ADDR" & pids+=("$!")
sleep 0.5
./bin/authority --name authority-1 --addr "$AUTH_ADDR" --registry "http://$REG_ADDR" & pids+=("$!")
sleep 1
./bin/agent --name greeter-mandate --role greeter-mandate --addr "$GREETER_ADDR" \
	--registry "http://$REG_ADDR" --policy mandate --authority-role authority --scope greet & pids+=("$!")
sleep 1

echo "== meshctl greet (mandate-gated) =="
OUT=$(./bin/meshctl greet --from visitor --to-role greeter-mandate --text "hello there")
echo "$OUT"
echo "$OUT" | grep -q "reply:"

echo "P3b demo OK"
```

- [ ] **Step 2: Make executable and run**

Run:
```bash
chmod +x scripts/demo/p3b-mandate-greet.sh
./scripts/demo/p3b-mandate-greet.sh
```
Expected: the greeter logs pinning the authority key; `meshctl` prints `greeted greeter-mandate (...)` and a `reply:` line; then `P3b demo OK`; exit 0. Confirm `git status` shows only the new script (no `data/`/`bin/` leakage — both gitignored).

- [ ] **Step 3: Commit**

```bash
git add scripts/demo/p3b-mandate-greet.sh
git commit -m "chore(demo): P3b mandate-gated greet over MCP + A2A"
```

---

## Task 7: gate + branch verification

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

- [ ] **Step 3: Re-run every demo (no regressions across phases)**

Run each and confirm its final "… OK" line:
```bash
./scripts/demo/p0-discovery.sh
./scripts/demo/p1-greet.sh
./scripts/demo/p2a-transparency.sh
./scripts/demo/p2b-greet-audit.sh
./scripts/demo/p3a-mandate.sh
./scripts/demo/p3b-mandate-greet.sh
```
(If a demo needs a component another demo left running on the same port, run them one at a time — each script starts and cleans up its own processes.)

---

## Self-review

**Spec coverage (P3b-2 scope):**
- Supply the guard's pinned key over the network → Task 1 (`crypto.PublicKeyFromJWK`) + Task 2 (`authclient.FetchPubKey`). ✓
- Mandate-aware initiator that discovers the requirement from the card (no hardcoding), obtains a mandate over MCP, and presents it → Task 3. ✓
- `cmd/agent` mandate mode: pin the authority key at startup, advertise the extension, enforce the guard → Task 4. ✓
- End-to-end proof incl. fail-closed rejections (no mandate; forged authority) → Task 5. ✓
- Runnable demo + no-regression check across all phases → Tasks 6, 7. ✓
- Deferred correctly (absent): DPoP mandate→caller-key binding and single-use/`jti` (P4); nonce greeter (P4); UI (P5). Noted in Scope.

**Placeholder scan:** none — every step has concrete code or an exact command with expected output.

**Type consistency check:**
- `crypto.PublicKeyFromJWK(JWK) (ed25519.PublicKey, error)` — Task 1; used by `authclient` (Task 2). Inverse of existing `crypto.PublicJWK(ed25519.PublicKey) JWK`. ✓
- `authclient.New() *Client` + `FetchPubKey(ctx, baseURL string) (ed25519.PublicKey, error)` — Task 2; used by `cmd/agent` (Task 4) and the integration test (Task 5). ✓
- `greet.Initiate(ctx, disco, res, cli, mcpCli, priv, callerAns, toRole, greeting)` — new 5th param `*mcp.Client` (Task 3). All callers updated: `cmd/meshctl` (Task 3), `internal/integration/p1_test.go` + `p2b_test.go` (Task 3), and `p3b_test.go` uses the new signature (Task 5). Open path unchanged when no extension + empty Security. ✓
- Card detection uses `a2a.Card.Capabilities.Extensions[].URI == a2a.ExtMandateURI` and `a2a.WithMandate` / `a2a.SendOption` (all from P3b-1). ✓
- The `issue_mandate` result `{"mandateCose": <base64>}` produced by `authority` (P3a) is decoded identically in `acquireMandate` (Task 3) via `struct{ MandateCOSE []byte }` — same shape as `meshctl mandate-check` and the P3a integration test. ✓
- `policy.NewMandate(selfAns, authorityAns string, authorityPub ed25519.PublicKey, scope string, log)` (P3b-1) — wired in `cmd/agent` (Task 4, pinned key from `authclient`) and the integration test (Task 5). ✓
- Registry/discovery/greet-service/mux APIs (`registry.New().Handler()`, `discovery.New().Search/Register`, `a2a.NewGreetService`, `a2a.NewMux`) match their existing signatures as used in `p2b_test.go`. ✓
- `authority.New(ans, priv, ttl, log)` + `IssueMandate/MCPTool` (P3a) — used by the integration test for both the real authority and the forger. ✓
