# agent-mesh P0 — Scaffold & Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the agent-mesh repo with a discovery registry and a base agent that registers itself and serves its A2A Agent Card, so an agent can be discovered by role.

**Architecture:** Hexagonal Go. A `Discovery` port in `internal/domain` is implemented by an HTTP registry client (`internal/comms/discovery`) talking to a standalone in-memory registry service (`internal/registry`, `cmd/registry`). The base agent (`cmd/agent`) loads an Ed25519 identity, serves a minimal A2A Agent Card, and registers with the registry at startup.

**Tech Stack:** Go 1.23, standard library `net/http` (1.22+ method routing), `crypto/ed25519`, `github.com/rs/zerolog` for structured logging.

**Scope:** This plan is P0 only. Phases P1–P5 (simple greet, transparency, mandate, nonce, UI) are planned separately once P0 lands. See `docs/superpowers/specs/2026-09-25-agent-mesh-design.md`.

---

## File structure (created in this plan)

```
go.mod                                  # module github.com/an-ciobanu/agent-mesh
Makefile                                # build / test / test-cover / vet / fmt / check
internal/domain/discovery.go            # AgentInfo type + Discovery port
internal/crypto/keys.go                 # Ed25519 keygen/load, JWK, RFC 7638 thumbprint
internal/crypto/keys_test.go
internal/registry/service.go            # in-memory registry + HTTP handler
internal/registry/service_test.go
internal/comms/discovery/client.go      # HTTP client implementing domain.Discovery
internal/comms/discovery/client_test.go
internal/comms/a2a/card.go              # Agent Card struct + handler
internal/comms/a2a/card_test.go
internal/integration/p0_test.go         # end-to-end: register -> search -> fetch card
cmd/registry/main.go                    # registry binary
cmd/agent/main.go                       # base agent binary
scripts/demo/p0-discovery.sh            # runnable demo
```

Convention notes (from the workspace ANS CLAUDE.md): injected `zerolog.Logger` tagged with a `component` field, no `fmt.Println` in library code, `internal/domain` and `internal/crypto` target ~100% coverage, `make check` green before every commit, and **no AI `Co-Authored-By:` trailer** on commits.

---

## Task 1: Repo scaffold (go.mod, Makefile, dependency)

**Files:**
- Create: `go.mod`
- Create: `Makefile`

- [ ] **Step 1: Create `go.mod`**

```
module github.com/an-ciobanu/agent-mesh

go 1.23
```

- [ ] **Step 2: Add the zerolog dependency and tidy**

Run:
```bash
go get github.com/rs/zerolog@v1.33.0
go mod tidy
```
Expected: `go.mod` gains `require github.com/rs/zerolog v1.33.0` and `go.sum` is written.

- [ ] **Step 3: Create `Makefile`**

```makefile
GO ?= go

.PHONY: build test test-cover vet fmt tidy check

build:
	@mkdir -p bin
	$(GO) build -o bin/ ./cmd/...

test:
	$(GO) test ./...

test-cover:
	$(GO) test -cover ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -l -w .

tidy:
	$(GO) mod tidy

check: fmt vet test
```

- [ ] **Step 4: Verify the module builds (no packages yet)**

Run: `go build ./...`
Expected: exits 0 with no output.

- [ ] **Step 5: Commit**

```bash
git add go.mod go.sum Makefile
git commit -m "chore: scaffold go module, Makefile, zerolog dependency"
```

---

## Task 2: Crypto — Ed25519 keys, JWK, thumbprint

**Files:**
- Create: `internal/crypto/keys.go`
- Test: `internal/crypto/keys_test.go`

- [ ] **Step 1: Write the failing test**

```go
package crypto

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"
)

func TestPublicJWKAndThumbprintDeterministic(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize) // all-zero seed -> deterministic key
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	jwk := PublicJWK(pub)
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" || jwk.X == "" {
		t.Fatalf("unexpected jwk: %+v", jwk)
	}

	tp1 := Thumbprint(jwk)
	tp2 := Thumbprint(PublicJWK(pub))
	if tp1 == "" || tp1 != tp2 {
		t.Fatalf("thumbprint not deterministic: %q vs %q", tp1, tp2)
	}
}

func TestLoadOrCreateEd25519Persists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id_ed25519.seed")

	k1, err := LoadOrCreateEd25519(path)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := LoadOrCreateEd25519(path)
	if err != nil {
		t.Fatal(err)
	}
	if !k1.Equal(k2) {
		t.Fatal("expected the same key when reloading from disk")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/crypto/ -run TestPublicJWK -v`
Expected: FAIL — `undefined: PublicJWK` (build error).

- [ ] **Step 3: Write the implementation**

```go
// Package crypto holds agent-mesh key management and signing primitives.
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// JWK is a minimal JSON Web Key for an Ed25519 public key (OKP).
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
}

// GenerateEd25519 returns a fresh Ed25519 private key.
func GenerateEd25519() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	return priv, nil
}

// LoadOrCreateEd25519 loads a 32-byte seed from path, or creates, persists,
// and returns a new key when the file does not yet exist.
func LoadOrCreateEd25519(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(b) != ed25519.SeedSize {
			return nil, fmt.Errorf("key file %s: want %d-byte seed, got %d", path, ed25519.SeedSize, len(b))
		}
		return ed25519.NewKeyFromSeed(b), nil
	case errors.Is(err, os.ErrNotExist):
		priv, gerr := GenerateEd25519()
		if gerr != nil {
			return nil, gerr
		}
		if mkErr := os.MkdirAll(filepath.Dir(path), 0o700); mkErr != nil {
			return nil, fmt.Errorf("create key dir: %w", mkErr)
		}
		if wErr := os.WriteFile(path, priv.Seed(), 0o600); wErr != nil {
			return nil, fmt.Errorf("write key file: %w", wErr)
		}
		return priv, nil
	default:
		return nil, fmt.Errorf("read key file %s: %w", path, err)
	}
}

// PublicJWK builds a JWK from an Ed25519 public key.
func PublicJWK(pub ed25519.PublicKey) JWK {
	return JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
	}
}

// Thumbprint returns the RFC 7638 JWK thumbprint (base64url SHA-256 over the
// canonical JSON of the required members, in lexicographic order).
func Thumbprint(j JWK) string {
	canonical := fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q}`, j.Crv, j.Kty, j.X)
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/crypto/ -v`
Expected: PASS (both tests).

- [ ] **Step 5: Commit**

```bash
git add internal/crypto/keys.go internal/crypto/keys_test.go
git commit -m "feat(crypto): ed25519 keygen/load, JWK, RFC 7638 thumbprint"
```

---

## Task 3: Domain — AgentInfo and the Discovery port

**Files:**
- Create: `internal/domain/discovery.go`

- [ ] **Step 1: Write the file**

```go
// Package domain holds agent-mesh core types and ports (no I/O).
package domain

import "context"

// AgentInfo is the public discovery record an agent publishes to the registry.
type AgentInfo struct {
	Name    string `json:"name"`    // unique instance name, e.g. "greeter-open"
	Role    string `json:"role"`    // coarse role, e.g. "greeter", "authority"
	BaseURL string `json:"baseURL"` // e.g. "http://127.0.0.1:18101"
	CardURL string `json:"cardURL"` // baseURL + "/.well-known/agent-card.json"
}

// Discovery is the registry port: agents register, callers search by role.
type Discovery interface {
	Register(ctx context.Context, info AgentInfo) error
	Search(ctx context.Context, role string) ([]AgentInfo, error)
}
```

- [ ] **Step 2: Verify it compiles**

Run: `go build ./internal/domain/`
Expected: exits 0.

- [ ] **Step 3: Commit**

```bash
git add internal/domain/discovery.go
git commit -m "feat(domain): AgentInfo type and Discovery port"
```

---

## Task 4: Registry service (in-memory, HTTP)

**Files:**
- Create: `internal/registry/service.go`
- Test: `internal/registry/service_test.go`

- [ ] **Step 1: Write the failing test**

```go
package registry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

func TestRegisterThenSearchByRole(t *testing.T) {
	ts := httptest.NewServer(New(zerolog.Nop()).Handler())
	defer ts.Close()

	body := `{"name":"greeter-open","role":"greeter","baseURL":"http://x","cardURL":"http://x/.well-known/agent-card.json"}`
	resp, err := http.Post(ts.URL+"/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("register status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp, err = http.Get(ts.URL + "/search?role=greeter")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var got []domain.AgentInfo
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "greeter-open" {
		t.Fatalf("unexpected search result: %+v", got)
	}
}

func TestRegisterRejectsMissingFields(t *testing.T) {
	ts := httptest.NewServer(New(zerolog.Nop()).Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/register", "application/json", strings.NewReader(`{"role":"greeter"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for missing name/baseURL, got %d", resp.StatusCode)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/registry/ -v`
Expected: FAIL — `undefined: New`.

- [ ] **Step 3: Write the implementation**

```go
// Package registry is the in-memory discovery service for agent-mesh.
package registry

import (
	"encoding/json"
	"net/http"
	"sort"
	"sync"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

// Service is an in-memory registry keyed by agent name.
type Service struct {
	log    zerolog.Logger
	mu     sync.RWMutex
	byName map[string]domain.AgentInfo
}

// New returns a ready registry that logs under component "registry".
func New(log zerolog.Logger) *Service {
	return &Service{
		log:    log.With().Str("component", "registry").Logger(),
		byName: make(map[string]domain.AgentInfo),
	}
}

// Handler returns the registry HTTP routes.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /register", s.handleRegister)
	mux.HandleFunc("GET /search", s.handleSearch)
	return mux
}

func (s *Service) handleRegister(w http.ResponseWriter, r *http.Request) {
	var info domain.AgentInfo
	if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
		s.log.Warn().Err(err).Msg("register: invalid body")
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if info.Name == "" || info.BaseURL == "" {
		http.Error(w, "name and baseURL required", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.byName[info.Name] = info
	s.mu.Unlock()
	s.log.Info().Str("name", info.Name).Str("role", info.Role).Str("baseURL", info.BaseURL).Msg("agent registered")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) handleSearch(w http.ResponseWriter, r *http.Request) {
	role := r.URL.Query().Get("role")

	s.mu.RLock()
	out := make([]domain.AgentInfo, 0, len(s.byName))
	for _, info := range s.byName {
		if role == "" || info.Role == role {
			out = append(out, info)
		}
	}
	s.mu.RUnlock()

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(out); err != nil {
		s.log.Error().Err(err).Msg("search: encode response")
		return
	}
	s.log.Debug().Str("role", role).Int("results", len(out)).Msg("search served")
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/registry/ -v`
Expected: PASS (both tests).

- [ ] **Step 5: Commit**

```bash
git add internal/registry/service.go internal/registry/service_test.go
git commit -m "feat(registry): in-memory discovery service with register/search"
```

---

## Task 5: Discovery client (HTTP adapter for the port)

**Files:**
- Create: `internal/comms/discovery/client.go`
- Test: `internal/comms/discovery/client_test.go`

- [ ] **Step 1: Write the failing test**

```go
package discovery

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/registry"
)

func TestClientRegisterAndSearchRoundTrip(t *testing.T) {
	reg := httptest.NewServer(registry.New(zerolog.Nop()).Handler())
	defer reg.Close()

	c := New(reg.URL)
	ctx := context.Background()

	want := domain.AgentInfo{
		Name:    "authority-1",
		Role:    "authority",
		BaseURL: "http://127.0.0.1:18120",
		CardURL: "http://127.0.0.1:18120/.well-known/agent-card.json",
	}
	if err := c.Register(ctx, want); err != nil {
		t.Fatalf("register: %v", err)
	}

	got, err := c.Search(ctx, "authority")
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("search result = %+v, want [%+v]", got, want)
	}

	empty, err := c.Search(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("search empty: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("expected no results, got %+v", empty)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/comms/discovery/ -v`
Expected: FAIL — `undefined: New`.

- [ ] **Step 3: Write the implementation**

```go
// Package discovery is the HTTP client adapter for the domain.Discovery port.
package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

// Client talks to a registry service over HTTP.
type Client struct {
	base string
	http *http.Client
}

// New returns a discovery client for the given registry base URL.
func New(registryBaseURL string) *Client {
	return &Client{base: registryBaseURL, http: http.DefaultClient}
}

// Register publishes this agent's discovery record.
func (c *Client) Register(ctx context.Context, info domain.AgentInfo) error {
	b, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("marshal agent info: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/register", bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("build register request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("register request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("register: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// Search returns agents matching role (empty role returns all).
func (c *Client) Search(ctx context.Context, role string) ([]domain.AgentInfo, error) {
	u := c.base + "/search?" + url.Values{"role": {role}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("build search request: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("search request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("search: unexpected status %d", resp.StatusCode)
	}

	var out []domain.AgentInfo
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode search response: %w", err)
	}
	return out, nil
}

// Compile-time assertion that Client satisfies the port.
var _ domain.Discovery = (*Client)(nil)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/comms/discovery/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/comms/discovery/client.go internal/comms/discovery/client_test.go
git commit -m "feat(discovery): HTTP registry client implementing Discovery port"
```

---

## Task 6: A2A Agent Card (struct + handler)

**Files:**
- Create: `internal/comms/a2a/card.go`
- Test: `internal/comms/a2a/card_test.go`

- [ ] **Step 1: Write the failing test**

```go
package a2a

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
)

func TestCardHandlerServesJSON(t *testing.T) {
	card := Card{
		Name:     "greeter-open",
		URL:      "http://127.0.0.1:18101",
		Version:  "0.1.0",
		Security: []map[string][]string{}, // open
	}
	ts := httptest.NewServer(CardHandler(card, zerolog.Nop()))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/.well-known/agent-card.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	var got Card
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Name != "greeter-open" || got.Version != "0.1.0" {
		t.Fatalf("unexpected card: %+v", got)
	}
	if got.Security == nil {
		t.Fatal("security must serialize as [], not null")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/comms/a2a/ -v`
Expected: FAIL — `undefined: Card`.

- [ ] **Step 3: Write the implementation**

```go
// Package a2a serves and reads A2A Agent Cards.
package a2a

import (
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog"
)

// Card is a minimal A2A Agent Card. Security is an OpenAPI-style list of
// scheme requirement maps; an empty slice means "open" (no auth).
type Card struct {
	Name        string                `json:"name"`
	Description string                `json:"description,omitempty"`
	URL         string                `json:"url"`
	Version     string                `json:"version"`
	Security    []map[string][]string `json:"security"`
}

// CardHandler serves a fixed Agent Card at /.well-known/agent-card.json.
func CardHandler(card Card, log zerolog.Logger) http.Handler {
	l := log.With().Str("component", "a2a").Logger()
	if card.Security == nil {
		card.Security = []map[string][]string{}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/agent-card.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(card); err != nil {
			l.Error().Err(err).Msg("encode agent card")
			return
		}
		l.Debug().Str("name", card.Name).Msg("served agent card")
	})
	return mux
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/comms/a2a/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/comms/a2a/card.go internal/comms/a2a/card_test.go
git commit -m "feat(a2a): minimal Agent Card struct and well-known handler"
```

---

## Task 7: Registry binary

**Files:**
- Create: `cmd/registry/main.go`

- [ ] **Step 1: Write the binary**

```go
// Command registry runs the agent-mesh discovery service.
package main

import (
	"flag"
	"net/http"
	"os"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/registry"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:18090", "listen address")
	flag.Parse()

	log := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()
	svc := registry.New(log)

	log.Info().Str("addr", *addr).Msg("registry listening")
	if err := http.ListenAndServe(*addr, svc.Handler()); err != nil {
		log.Fatal().Err(err).Msg("registry server exited")
	}
}
```

- [ ] **Step 2: Build it**

Run: `go build ./cmd/registry/`
Expected: exits 0.

- [ ] **Step 3: Commit**

```bash
git add cmd/registry/main.go
git commit -m "feat(cmd): registry binary"
```

---

## Task 8: Base agent binary

**Files:**
- Create: `cmd/agent/main.go`

- [ ] **Step 1: Write the binary**

```go
// Command agent runs a single agent-mesh agent: it loads an Ed25519 identity,
// serves its A2A Agent Card, and registers with the discovery registry.
package main

import (
	"context"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/discovery"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

func main() {
	name := flag.String("name", "", "unique agent name (required)")
	role := flag.String("role", "greeter", "agent role")
	addr := flag.String("addr", "127.0.0.1:18101", "listen address")
	registryURL := flag.String("registry", "http://127.0.0.1:18090", "registry base URL")
	keyDir := flag.String("keys", "", "identity key directory (default: ./data/<name>)")
	flag.Parse()

	log := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Str("agent", *name).Logger()
	if *name == "" {
		log.Fatal().Msg("--name is required")
	}

	dir := *keyDir
	if dir == "" {
		dir = filepath.Join("data", *name)
	}
	if _, err := crypto.LoadOrCreateEd25519(filepath.Join(dir, "id_ed25519.seed")); err != nil {
		log.Fatal().Err(err).Msg("load identity key")
	}

	baseURL := "http://" + *addr
	card := a2a.Card{
		Name:     *name,
		URL:      baseURL,
		Version:  "0.1.0",
		Security: []map[string][]string{}, // open (P0)
	}

	srv := &http.Server{Addr: *addr, Handler: a2a.CardHandler(card, log)}
	go func() {
		log.Info().Str("addr", *addr).Msg("agent listening")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("agent server exited")
		}
	}()

	disco := discovery.New(*registryURL)
	info := domain.AgentInfo{
		Name:    *name,
		Role:    *role,
		BaseURL: baseURL,
		CardURL: baseURL + "/.well-known/agent-card.json",
	}
	ctx := context.Background()
	var regErr error
	for i := 0; i < 10; i++ {
		if regErr = disco.Register(ctx, info); regErr == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if regErr != nil {
		log.Error().Err(regErr).Msg("could not register with registry")
	} else {
		log.Info().Str("registry", *registryURL).Str("role", *role).Msg("registered with registry")
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	log.Info().Msg("agent stopped")
}
```

- [ ] **Step 2: Build all binaries**

Run: `make build`
Expected: `bin/registry` and `bin/agent` produced, exits 0.

- [ ] **Step 3: Commit**

```bash
git add cmd/agent/main.go
git commit -m "feat(cmd): base agent binary (identity, card, self-registration)"
```

---

## Task 9: End-to-end integration test

**Files:**
- Create: `internal/integration/p0_test.go`

- [ ] **Step 1: Write the failing test**

```go
package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/discovery"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/registry"
)

func TestP0_RegisterDiscoverAndFetchCard(t *testing.T) {
	reg := httptest.NewServer(registry.New(zerolog.Nop()).Handler())
	defer reg.Close()

	card := a2a.Card{Name: "greeter-open", Version: "0.1.0", Security: []map[string][]string{}}
	agent := httptest.NewServer(a2a.CardHandler(card, zerolog.Nop()))
	defer agent.Close()

	disco := discovery.New(reg.URL)
	ctx := context.Background()

	info := domain.AgentInfo{
		Name:    "greeter-open",
		Role:    "greeter",
		BaseURL: agent.URL,
		CardURL: agent.URL + "/.well-known/agent-card.json",
	}
	if err := disco.Register(ctx, info); err != nil {
		t.Fatalf("register: %v", err)
	}

	peers, err := disco.Search(ctx, "greeter")
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(peers) != 1 {
		t.Fatalf("want 1 peer, got %d", len(peers))
	}

	resp, err := http.Get(peers[0].CardURL)
	if err != nil {
		t.Fatalf("fetch card: %v", err)
	}
	defer resp.Body.Close()

	var got a2a.Card
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode card: %v", err)
	}
	if got.Name != "greeter-open" {
		t.Fatalf("card name = %q, want greeter-open", got.Name)
	}
}
```

- [ ] **Step 2: Run test to verify it passes**

Run: `go test ./internal/integration/ -v`
Expected: PASS. (All the pieces already exist; this test wires them together and guards the P0 contract.)

- [ ] **Step 3: Run the full suite with coverage**

Run: `make check`
Expected: `gofmt`/`vet` clean, all tests PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/integration/p0_test.go
git commit -m "test(integration): P0 register -> search -> fetch card"
```

---

## Task 10: Demo script

**Files:**
- Create: `scripts/demo/p0-discovery.sh`

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# P0 demo: start the registry, start two agents that self-register, then
# search the registry and fetch a discovered agent's card. Proves discovery
# works with no agent knowing another agent's address in advance.
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
./bin/agent --name authority-1  --role authority --addr 127.0.0.1:18102 --registry "http://$REG_ADDR" & pids+=("$!")
sleep 1

echo "== search role=greeter =="
curl -s "http://$REG_ADDR/search?role=greeter"; echo

echo "== fetch the greeter's agent card =="
CARD_URL=$(curl -s "http://$REG_ADDR/search?role=greeter" | \
  python3 -c 'import sys,json; print(json.load(sys.stdin)[0]["cardURL"])')
curl -s "$CARD_URL"; echo

echo "== all agents =="
curl -s "http://$REG_ADDR/search"; echo

echo "P0 demo OK"
```

- [ ] **Step 2: Make it executable and run it**

Run:
```bash
chmod +x scripts/demo/p0-discovery.sh
./scripts/demo/p0-discovery.sh
```
Expected: prints a JSON array containing `greeter-open`, then the greeter's card JSON (`"name":"greeter-open"`), then both agents, then `P0 demo OK`.

- [ ] **Step 3: Commit**

```bash
git add scripts/demo/p0-discovery.sh
git commit -m "chore(demo): P0 discovery end-to-end script"
```

---

## Self-review

**Spec coverage (P0 scope of the spec):**
- Registry service with register/search → Tasks 4, 7. ✓
- `Discovery` port + client adapter (swap seam) → Tasks 3, 5. ✓
- Base agent, role-configured, self-registers → Task 8. ✓
- A2A Agent Card served at `/.well-known/agent-card.json`, `security: []` for open → Tasks 6, 8. ✓
- Real identity keys (Ed25519) + thumbprint groundwork for later DPoP/mandate → Task 2. ✓
- Provable: integration test + demo script → Tasks 9, 10. ✓
- Hexagonal layout, injected `zerolog` with `component`, `make check` → throughout. ✓
- Deferred to later plans (correctly absent here): greet messaging (P1), SCITT/transparency (P2), mandate/OAuth2 (P3), nonce/DPoP proofs (P4), UI (P5).

**Placeholder scan:** none — every step has concrete code or an exact command with expected output.

**Type consistency check:**
- `domain.AgentInfo{Name, Role, BaseURL, CardURL}` — identical in Tasks 3, 4, 5, 8, 9. ✓
- `domain.Discovery{Register(ctx, AgentInfo) error, Search(ctx, string) ([]AgentInfo, error)}` — client asserts `var _ domain.Discovery` (Task 5); registry HTTP shape matches (Task 4). ✓
- `crypto.JWK{Kty, Crv, X}`, `PublicJWK`, `Thumbprint`, `LoadOrCreateEd25519` — defined Task 2, used Task 8. ✓
- `a2a.Card{Name, Description, URL, Version, Security}` + `a2a.CardHandler(card, log)` — identical in Tasks 6, 8, 9. ✓
- Registry routes `POST /register` (204) and `GET /search?role=` (200 JSON) — producer (Task 4) and consumer (Task 5) agree. ✓
