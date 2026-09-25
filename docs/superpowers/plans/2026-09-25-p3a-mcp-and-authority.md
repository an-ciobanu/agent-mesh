# agent-mesh P3a — MCP Layer + Authority (mandate issuance) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A minimal MCP tool layer (JSON-RPC 2.0 server + client) and an authority agent that issues scope-bound, COSE_Sign1-signed mandates through an `issue_mandate` MCP tool; a caller can obtain a mandate over MCP and verify the authority's signature.

**Architecture:** Builds on P0–P2. Adds `internal/comms/mcp` (a generic `tools/call` server + client); `domain.MandateClaims`; an `internal/authority` package that issues mandates as COSE_Sign1 (reusing `crypto.SignCOSE1`) and exposes them as an MCP tool; a `cmd/authority` binary (MCP `/mcp` + Agent Card + `GET /pubkey`, registers as role `authority`); and a `meshctl mandate-check` subcommand. The mandate is a COSE_Sign1 over `MandateClaims`, self-verifying (embeds the authority key) exactly like the P2 transparency statements/receipts.

**Tech Stack:** Go 1.23, existing deps (`veraison/go-cose`, `rs/zerolog`); no new dependencies.

**Scope:** P3a only — the MCP layer + authority/mandate issuance. The mandate-gated greeter, the requirements resolver following the card extension, and the `Mandate` guard are **P3b** (next plan). Nonce/DPoP (P4) and UI (P5) are later. This phase issues mandates but does NOT yet bind them to the caller's key (sender-constraint via DPoP is P4) — a mandate here authorizes `subject→audience→scope` for a time window, attested by the authority. See the design spec.

**Baseline:** P0+P1+P2 merged on `master`. Reuse: `crypto.SignCOSE1/VerifyCOSE1`, `crypto.PublicJWK/Thumbprint`, `crypto.LoadOrCreateEd25519`; `domain.{AgentInfo,Discovery,LocalANSName}`; `a2a.{Card,CardHandler}`; `comms/discovery.{New,Search}`; `cmd/{agent,registry,transparency,meshctl}`. Do all work on a branch off `master` (e.g. `p3a-mcp-authority`).

---

## File structure (this plan)

```
internal/comms/mcp/server.go                 # NEW: MCP tools/call server (Register + Handler)
internal/comms/mcp/client.go                 # NEW: MCP tools/call client (Call)
internal/comms/mcp/mcp_test.go               # NEW: round-trip + error paths
internal/domain/mandate.go                   # NEW: MandateClaims
internal/authority/authority.go              # NEW: IssueMandate + issue_mandate MCP tool
internal/authority/authority_test.go         # NEW
cmd/authority/main.go                        # NEW: authority binary (/mcp, card, /pubkey, register)
cmd/meshctl/main.go                          # MODIFY: add `mandate-check` subcommand
internal/integration/p3a_test.go             # NEW: issue_mandate over MCP -> verify mandate
scripts/demo/p3a-mandate.sh                  # NEW: runnable demo
```

Conventions unchanged: hexagonal Go; injected `zerolog.Logger` tagged `component`; no `fmt.Println`/`log` in library code (cmd/* stdout fine); `make check` green before every commit; **no AI `Co-Authored-By:` trailer**.

---

## Task 1: MCP layer — server + client

**Files:**
- Create: `internal/comms/mcp/server.go`
- Create: `internal/comms/mcp/client.go`
- Test: `internal/comms/mcp/mcp_test.go`

- [ ] **Step 1: Write the failing test**

```go
package mcp

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
)

func TestMCPToolCallRoundTrip(t *testing.T) {
	s := NewServer(zerolog.Nop())
	s.Register("echo", func(_ context.Context, args json.RawMessage) (json.RawMessage, error) {
		// Echo the args back as the result payload.
		return args, nil
	})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	out, err := NewClient().Call(context.Background(), ts.URL+"/mcp", "echo", map[string]string{"hello": "world"})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got["hello"] != "world" {
		t.Fatalf("echo result = %v", got)
	}
}

func TestMCPUnknownToolErrors(t *testing.T) {
	ts := httptest.NewServer(NewServer(zerolog.Nop()).Handler())
	defer ts.Close()
	if _, err := NewClient().Call(context.Background(), ts.URL+"/mcp", "nope", nil); err == nil {
		t.Fatal("expected error for unknown tool")
	}
}

func TestMCPToolErrorSurfacesToClient(t *testing.T) {
	s := NewServer(zerolog.Nop())
	s.Register("boom", func(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
		return nil, context.DeadlineExceeded
	})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	if _, err := NewClient().Call(context.Background(), ts.URL+"/mcp", "boom", nil); err == nil {
		t.Fatal("expected the tool error to surface to the client")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/comms/mcp/ -v`
Expected: FAIL — `undefined: NewServer`.

- [ ] **Step 3: Write `internal/comms/mcp/server.go`**

```go
// Package mcp is a minimal MCP (Model Context Protocol) tools layer: a
// JSON-RPC 2.0 tools/call server and client, used for agent capability tools.
package mcp

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog"
)

// MethodToolsCall is the MCP JSON-RPC method for invoking a tool.
const MethodToolsCall = "tools/call"

// ToolFunc handles one tool invocation: it receives the raw JSON arguments and
// returns a raw JSON payload (delivered to the client as the tool's text result).
type ToolFunc func(ctx context.Context, args json.RawMessage) (json.RawMessage, error)

// Server dispatches MCP tools/call requests to registered tools.
type Server struct {
	tools map[string]ToolFunc
	log   zerolog.Logger
}

// NewServer returns an MCP server with no tools registered.
func NewServer(log zerolog.Logger) *Server {
	return &Server{tools: make(map[string]ToolFunc), log: log.With().Str("component", "mcp").Logger()}
}

// Register adds a tool under name.
func (s *Server) Register(name string, fn ToolFunc) { s.tools[name] = fn }

// Handler serves POST /mcp.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /mcp", s.handleCall)
	return mux
}

type callParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type rpcRequest struct {
	JSONRPC string     `json:"jsonrpc"`
	ID      int        `json:"id"`
	Method  string     `json:"method"`
	Params  callParams `json:"params"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type toolResult struct {
	Content []contentBlock `json:"content"`
	IsError bool           `json:"isError"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Result  *toolResult `json:"result,omitempty"`
	Error   *rpcError   `json:"error,omitempty"`
}

func (s *Server) handleCall(w http.ResponseWriter, r *http.Request) {
	var req rpcRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, 0, -32700, "parse error")
		return
	}
	if req.Method != MethodToolsCall {
		s.writeError(w, req.ID, -32601, "method not found")
		return
	}
	fn, ok := s.tools[req.Params.Name]
	if !ok {
		s.writeError(w, req.ID, -32601, "unknown tool: "+req.Params.Name)
		return
	}
	out, err := fn(r.Context(), req.Params.Arguments)
	if err != nil {
		s.log.Warn().Err(err).Str("tool", req.Params.Name).Msg("tool returned error")
		s.writeResult(w, req.ID, &toolResult{Content: []contentBlock{{Type: "text", Text: err.Error()}}, IsError: true})
		return
	}
	s.log.Info().Str("tool", req.Params.Name).Msg("tool call ok")
	s.writeResult(w, req.ID, &toolResult{Content: []contentBlock{{Type: "text", Text: string(out)}}, IsError: false})
}

func (s *Server) writeResult(w http.ResponseWriter, id int, res *toolResult) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(rpcResponse{JSONRPC: "2.0", ID: id, Result: res}); err != nil {
		s.log.Error().Err(err).Msg("encode result")
	}
}

func (s *Server) writeError(w http.ResponseWriter, id, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}); err != nil {
		s.log.Error().Err(err).Msg("encode error")
	}
}
```

- [ ] **Step 4: Write `internal/comms/mcp/client.go`**

```go
package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Client invokes MCP tools over HTTP.
type Client struct {
	http *http.Client
}

// NewClient returns an MCP client with a bounded timeout.
func NewClient() *Client {
	return &Client{http: &http.Client{Timeout: 5 * time.Second}}
}

// Call invokes tool at endpoint with args and returns the tool's JSON payload.
func (c *Client) Call(ctx context.Context, endpoint, tool string, args any) (json.RawMessage, error) {
	argsJSON, err := json.Marshal(args)
	if err != nil {
		return nil, fmt.Errorf("marshal args: %w", err)
	}
	body, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0", ID: 1, Method: MethodToolsCall,
		Params: callParams{Name: tool, Arguments: argsJSON},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mcp request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mcp: unexpected status %d", resp.StatusCode)
	}

	var out rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if out.Error != nil {
		return nil, fmt.Errorf("mcp error: %s (code %d)", out.Error.Message, out.Error.Code)
	}
	if out.Result == nil || len(out.Result.Content) == 0 {
		return nil, fmt.Errorf("mcp: empty result")
	}
	if out.Result.IsError {
		return nil, fmt.Errorf("tool %q failed: %s", tool, out.Result.Content[0].Text)
	}
	return json.RawMessage(out.Result.Content[0].Text), nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/comms/mcp/ -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/comms/mcp/server.go internal/comms/mcp/client.go internal/comms/mcp/mcp_test.go
git commit -m "feat(mcp): minimal JSON-RPC tools/call server and client"
```

---

## Task 2: Domain — MandateClaims

**Files:**
- Create: `internal/domain/mandate.go`

- [ ] **Step 1: Write the file**

```go
package domain

// MandateClaims is the JSON payload inside a signed mandate (a COSE_Sign1). A
// mandate authorizes SubjectAns to interact with AudienceAns within Scope for a
// validity window, attested by AuthorityAns. Binding the mandate to the caller's
// key (sender-constraint via DPoP) is deferred to a later phase.
type MandateClaims struct {
	MandateID    string `json:"mandateId"`
	SubjectAns   string `json:"subjectAns"`
	AudienceAns  string `json:"audienceAns"`
	Scope        string `json:"scope"`
	NotBefore    string `json:"notBefore"`
	NotAfter     string `json:"notAfter"`
	AuthorityAns string `json:"authorityAns"`
}
```

- [ ] **Step 2: Verify it compiles**

Run: `go build ./internal/domain/`
Expected: exits 0.

- [ ] **Step 3: Commit**

```bash
git add internal/domain/mandate.go
git commit -m "feat(domain): MandateClaims"
```

---

## Task 3: Authority — issue mandates + MCP tool

**Files:**
- Create: `internal/authority/authority.go`
- Test: `internal/authority/authority_test.go`

- [ ] **Step 1: Write the failing test**

```go
package authority

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

func TestIssueMandateProducesVerifiableCOSE(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	ans := domain.LocalANSName("authority-1")
	a := New(ans, priv, time.Hour, zerolog.Nop())

	cose, err := a.IssueMandate(domain.LocalANSName("visitor"), domain.LocalANSName("greeter-mandate"), "greet")
	if err != nil {
		t.Fatal(err)
	}
	payload, signer, err := crypto.VerifyCOSE1(cose)
	if err != nil {
		t.Fatalf("verify mandate: %v", err)
	}
	if !signer.Equal(priv.Public()) {
		t.Fatal("mandate not signed by the authority key")
	}
	var claims domain.MandateClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.SubjectAns != domain.LocalANSName("visitor") ||
		claims.AudienceAns != domain.LocalANSName("greeter-mandate") ||
		claims.Scope != "greet" || claims.AuthorityAns != ans || claims.MandateID == "" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if claims.NotBefore == "" || claims.NotAfter == "" {
		t.Fatal("mandate missing validity window")
	}
}

func TestIssueMandateRejectsMissingFields(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	a := New(domain.LocalANSName("authority-1"), priv, time.Hour, zerolog.Nop())
	if _, err := a.IssueMandate("", domain.LocalANSName("x"), "greet"); err == nil {
		t.Fatal("expected error for empty subject")
	}
}

func TestMCPToolIssuesMandate(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	a := New(domain.LocalANSName("authority-1"), priv, time.Hour, zerolog.Nop())
	tool := a.MCPTool()

	args, _ := json.Marshal(map[string]string{
		"subjectAns":  domain.LocalANSName("visitor"),
		"audienceAns": domain.LocalANSName("greeter-mandate"),
		"scope":       "greet",
	})
	out, err := tool(context.Background(), args)
	if err != nil {
		t.Fatal(err)
	}
	var res struct {
		MandateCOSE []byte `json:"mandateCose"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatal(err)
	}
	if _, _, err := crypto.VerifyCOSE1(res.MandateCOSE); err != nil {
		t.Fatalf("tool mandate does not verify: %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/authority/ -v`
Expected: FAIL — `undefined: New`.

- [ ] **Step 3: Write the implementation**

```go
// Package authority issues scope-bound, COSE-signed mandates.
package authority

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

// Authority issues mandates signed with its Ed25519 identity key.
type Authority struct {
	ans  string
	priv ed25519.PrivateKey
	ttl  time.Duration
	log  zerolog.Logger
}

// New returns an authority named ans that signs mandates valid for ttl.
func New(ans string, priv ed25519.PrivateKey, ttl time.Duration, log zerolog.Logger) *Authority {
	return &Authority{ans: ans, priv: priv, ttl: ttl, log: log.With().Str("component", "authority").Logger()}
}

// IssueMandate builds a mandate authorizing subject->audience for scope and
// returns it as a COSE_Sign1 signed by the authority.
func (a *Authority) IssueMandate(subjectAns, audienceAns, scope string) ([]byte, error) {
	if subjectAns == "" || audienceAns == "" || scope == "" {
		return nil, fmt.Errorf("subjectAns, audienceAns and scope are required")
	}
	now := time.Now().UTC()
	claims := domain.MandateClaims{
		MandateID:    "mandate-" + randHex(8),
		SubjectAns:   subjectAns,
		AudienceAns:  audienceAns,
		Scope:        scope,
		NotBefore:    now.Format(time.RFC3339),
		NotAfter:     now.Add(a.ttl).Format(time.RFC3339),
		AuthorityAns: a.ans,
	}
	b, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("marshal mandate claims: %w", err)
	}
	cose, err := crypto.SignCOSE1(a.priv, b)
	if err != nil {
		return nil, fmt.Errorf("sign mandate: %w", err)
	}
	a.log.Info().Str("mandateId", claims.MandateID).Str("subjectAns", subjectAns).
		Str("audienceAns", audienceAns).Str("scope", scope).Msg("mandate issued")
	return cose, nil
}

type issueArgs struct {
	SubjectAns  string `json:"subjectAns"`
	AudienceAns string `json:"audienceAns"`
	Scope       string `json:"scope"`
}

type issueResult struct {
	MandateCOSE []byte `json:"mandateCose"` // JSON-encodes as base64
}

// MCPTool returns the issue_mandate MCP tool handler.
func (a *Authority) MCPTool() mcp.ToolFunc {
	return func(_ context.Context, args json.RawMessage) (json.RawMessage, error) {
		var in issueArgs
		if err := json.Unmarshal(args, &in); err != nil {
			return nil, fmt.Errorf("invalid arguments: %w", err)
		}
		cose, err := a.IssueMandate(in.SubjectAns, in.AudienceAns, in.Scope)
		if err != nil {
			return nil, err
		}
		return json.Marshal(issueResult{MandateCOSE: cose})
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/authority/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/authority/authority.go internal/authority/authority_test.go
git commit -m "feat(authority): issue COSE-signed mandates via issue_mandate MCP tool"
```

---

## Task 4: Authority binary

**Files:**
- Create: `cmd/authority/main.go`

- [ ] **Step 1: Write the binary**

```go
// Command authority runs an agent-mesh mandate authority: it serves an Agent
// Card, an MCP issue_mandate tool, and its public key, and registers with the
// discovery registry as role "authority".
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/authority"
	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/discovery"
	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

func main() {
	name := flag.String("name", "authority-1", "authority name")
	addr := flag.String("addr", "127.0.0.1:18110", "listen address")
	registryURL := flag.String("registry", "http://127.0.0.1:18090", "registry base URL")
	keyDir := flag.String("keys", "", "identity key directory (default: ./data/<name>)")
	ttl := flag.Duration("ttl", time.Hour, "mandate validity window")
	flag.Parse()

	log := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Str("agent", *name).Logger()

	dir := *keyDir
	if dir == "" {
		dir = filepath.Join("data", *name)
	}
	priv, err := crypto.LoadOrCreateEd25519(filepath.Join(dir, "id_ed25519.seed"))
	if err != nil {
		log.Fatal().Err(err).Msg("load identity key")
	}
	ans := domain.LocalANSName(*name)
	auth := authority.New(ans, priv, *ttl, log)

	mcpSrv := mcp.NewServer(log)
	mcpSrv.Register("issue_mandate", auth.MCPTool())

	baseURL := "http://" + *addr
	card := a2a.Card{Name: *name, URL: baseURL + "/mcp", Version: "0.1.0", Security: []map[string][]string{}}

	mux := http.NewServeMux()
	mux.Handle("/.well-known/agent-card.json", a2a.CardHandler(card, log))
	mux.Handle("/mcp", mcpSrv.Handler())
	mux.HandleFunc("GET /pubkey", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(crypto.PublicJWK(priv.Public().(ed25519.PublicKey))); err != nil {
			log.Error().Err(err).Msg("pubkey: encode")
		}
	})

	srv := &http.Server{Addr: *addr, Handler: mux}
	go func() {
		log.Info().Str("addr", *addr).Str("ans", ans).Msg("authority listening")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("authority server exited")
		}
	}()

	disco := discovery.New(*registryURL)
	info := domain.AgentInfo{
		Name: *name, Role: "authority", BaseURL: baseURL,
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
		log.Info().Str("registry", *registryURL).Msg("registered with registry")
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	log.Info().Msg("authority stopped")
}
```

- [ ] **Step 2: Build**

Run: `go build ./cmd/authority/`
Expected: exits 0.

- [ ] **Step 3: Commit**

```bash
git add cmd/authority/main.go
git commit -m "feat(cmd): authority binary (issue_mandate MCP tool, card, pubkey)"
```

---

## Task 5: `meshctl mandate-check` subcommand

**Files:**
- Modify: `cmd/meshctl/main.go`

- [ ] **Step 1: Add the dispatch case**

In the `switch os.Args[1]` block, add:

```go
	case "mandate-check":
		runMandateCheck(os.Args[2:])
```

And update the usage line to:

```go
		fmt.Fprintln(os.Stderr, "commands: greet, tl-check, mandate-check")
```

- [ ] **Step 2: Append `runMandateCheck`**

```go
func runMandateCheck(args []string) {
	fs := flag.NewFlagSet("mandate-check", flag.ExitOnError)
	registryURL := fs.String("registry", "http://127.0.0.1:18090", "registry base URL")
	subject := fs.String("subject", "visitor", "subject name")
	audience := fs.String("audience", "greeter-mandate", "audience name")
	scope := fs.String("scope", "greet", "requested scope")
	_ = fs.Parse(args)

	log := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()
	ctx := context.Background()

	peers, err := discovery.New(*registryURL).Search(ctx, "authority")
	if err != nil {
		log.Fatal().Err(err).Msg("discover authority")
	}
	if len(peers) == 0 {
		log.Fatal().Msg("no authority registered")
	}
	authURL := peers[0].BaseURL + "/mcp"

	raw, err := mcp.NewClient().Call(ctx, authURL, "issue_mandate", map[string]string{
		"subjectAns":  domain.LocalANSName(*subject),
		"audienceAns": domain.LocalANSName(*audience),
		"scope":       *scope,
	})
	if err != nil {
		log.Fatal().Err(err).Msg("issue_mandate")
	}
	var res struct {
		MandateCOSE []byte `json:"mandateCose"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		log.Fatal().Err(err).Msg("parse issue_mandate result")
	}

	payload, authPub, err := crypto.VerifyCOSE1(res.MandateCOSE)
	if err != nil {
		log.Fatal().Err(err).Msg("verify mandate")
	}
	var claims domain.MandateClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		log.Fatal().Err(err).Msg("parse mandate claims")
	}

	fmt.Printf("mandate %s: subject=%s audience=%s scope=%s (valid %s..%s)\n",
		claims.MandateID, claims.SubjectAns, claims.AudienceAns, claims.Scope, claims.NotBefore, claims.NotAfter)
	fmt.Printf("signed by authority %s (key %s)\n", claims.AuthorityAns, crypto.Thumbprint(crypto.PublicJWK(authPub)))
	fmt.Println("mandate issued and verified OK")
}
```

- [ ] **Step 3: Add the import**

Ensure `cmd/meshctl/main.go` imports include:

```go
	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
```

(`context`, `flag`, `fmt`, `os`, `encoding/json`, `github.com/rs/zerolog`, and the agent-mesh `comms/discovery`, `crypto`, `domain` packages are already imported from earlier phases. Add `encoding/json` if it is not yet imported — the P2a `tl-check` command did not need it, so it likely must be added.)

- [ ] **Step 4: Build**

Run: `make build`
Expected: all five binaries (`agent`, `registry`, `transparency`, `authority`, `meshctl`) build; exits 0.

- [ ] **Step 5: Commit**

```bash
git add cmd/meshctl/main.go
git commit -m "feat(meshctl): mandate-check subcommand (issue + verify a mandate)"
```

---

## Task 6: End-to-end integration test

**Files:**
- Create: `internal/integration/p3a_test.go`

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

	"github.com/an-ciobanu/agent-mesh/internal/authority"
	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

func TestP3A_IssueMandateOverMCP(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	ans := domain.LocalANSName("authority-1")
	auth := authority.New(ans, priv, time.Hour, zerolog.Nop())

	srv := mcp.NewServer(zerolog.Nop())
	srv.Register("issue_mandate", auth.MCPTool())
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	raw, err := mcp.NewClient().Call(context.Background(), ts.URL+"/mcp", "issue_mandate", map[string]string{
		"subjectAns":  domain.LocalANSName("visitor"),
		"audienceAns": domain.LocalANSName("greeter-mandate"),
		"scope":       "greet",
	})
	if err != nil {
		t.Fatalf("issue_mandate: %v", err)
	}
	var res struct {
		MandateCOSE []byte `json:"mandateCose"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatal(err)
	}

	payload, signer, err := crypto.VerifyCOSE1(res.MandateCOSE)
	if err != nil {
		t.Fatalf("verify mandate: %v", err)
	}
	if !signer.Equal(priv.Public()) {
		t.Fatal("mandate not signed by the authority key")
	}
	var claims domain.MandateClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.AudienceAns != domain.LocalANSName("greeter-mandate") || claims.Scope != "greet" || claims.AuthorityAns != ans {
		t.Fatalf("unexpected claims: %+v", claims)
	}

	// A malformed request (missing scope) surfaces as an MCP tool error.
	if _, err := mcp.NewClient().Call(context.Background(), ts.URL+"/mcp", "issue_mandate", map[string]string{
		"subjectAns": domain.LocalANSName("visitor"), "audienceAns": domain.LocalANSName("x"),
	}); err == nil {
		t.Fatal("expected an error when scope is missing")
	}
}
```

- [ ] **Step 2: Run test**

Run: `go test ./internal/integration/ -run P3A -v`
Expected: PASS.

- [ ] **Step 3: Full suite + check**

Run: `make check`
Expected: gofmt/vet clean, all tests PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/integration/p3a_test.go
git commit -m "test(integration): P3a issue_mandate over MCP -> verify mandate"
```

---

## Task 7: Demo script

**Files:**
- Create: `scripts/demo/p3a-mandate.sh`

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# P3a demo: start the registry and an authority; meshctl discovers the authority
# and requests a mandate over MCP (issue_mandate), then verifies the authority's
# COSE signature on it.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

make build

REG_ADDR="127.0.0.1:18090"
AUTH_ADDR="127.0.0.1:18110"
pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

./bin/registry --addr "$REG_ADDR" & pids+=("$!")
sleep 0.5
./bin/authority --name authority-1 --addr "$AUTH_ADDR" --registry "http://$REG_ADDR" & pids+=("$!")
sleep 1

echo "== meshctl mandate-check =="
OUT=$(./bin/meshctl mandate-check --registry "http://$REG_ADDR" --subject visitor --audience greeter-mandate --scope greet)
echo "$OUT"
echo "$OUT" | grep -q "mandate issued and verified OK"

echo "P3a demo OK"
```

- [ ] **Step 2: Make executable and run**

Run:
```bash
chmod +x scripts/demo/p3a-mandate.sh
./scripts/demo/p3a-mandate.sh
```
Expected: prints the mandate summary line, `signed by authority ans://v1.0.0.authority-1.mesh.local (key …)`, `mandate issued and verified OK`, then `P3a demo OK`.

- [ ] **Step 3: Commit**

```bash
git add scripts/demo/p3a-mandate.sh
git commit -m "chore(demo): P3a mandate issuance over MCP"
```

---

## Self-review

**Spec coverage (P3a scope):**
- MCP layer (server + client, `tools/call`) — the "MCP for capability tools" substrate → Task 1. ✓
- Authority issues scope-bound, COSE-signed mandates via an `issue_mandate` MCP tool → Tasks 2, 3. ✓
- Authority is a real agent: Agent Card, `/mcp`, `/pubkey`, registers as role `authority` → Task 4. ✓
- Provable: integration test (issue over MCP → verify signature + claims; missing-field error) + demo + `meshctl mandate-check` → Tasks 5, 6, 7. ✓
- Deferred correctly (absent): the mandate-gated greeter, the resolver following the card extension, and the `Mandate` guard (all P3b); DPoP sender-constraint / mandate→key binding (P4). Noted in Scope.

**Placeholder scan:** none — every step has concrete code or an exact command with expected output.

**Type consistency check:**
- `mcp.NewServer(log) *Server` + `Register(name, ToolFunc)` + `Handler()`; `mcp.NewClient() *Client` + `Call(ctx, endpoint, tool, args) (json.RawMessage, error)`; `mcp.ToolFunc = func(ctx, json.RawMessage) (json.RawMessage, error)`; `mcp.MethodToolsCall` — defined Task 1; used by authority (Task 3 `MCPTool`), cmd/authority (Task 4), meshctl (Task 5), integration (Task 6). ✓
- `domain.MandateClaims{MandateID,SubjectAns,AudienceAns,Scope,NotBefore,NotAfter,AuthorityAns}` — defined Task 2; produced/parsed in authority (Task 3), meshctl (Task 5), integration (Task 6). ✓
- `authority.New(ans string, priv ed25519.PrivateKey, ttl time.Duration, log) *Authority` + `IssueMandate(subject,audience,scope) ([]byte, error)` + `MCPTool() mcp.ToolFunc` — defined Task 3; used in Task 4 and tests. ✓
- The `issue_mandate` result shape `{"mandateCose": <base64 COSE bytes>}` is produced by `authority.issueResult` (Task 3) and parsed identically by meshctl (Task 5) and the integration test (Task 6) via an inline `struct{ MandateCOSE []byte }`. Go encodes/decodes `[]byte` as base64 consistently. ✓
- The mandate is a `crypto.SignCOSE1` object verified by `crypto.VerifyCOSE1` (Task 3/5/6) — same self-verifying COSE pattern as P2 statements/receipts; the authority key is embedded and returned to the verifier. ✓
- `cmd/authority` mounts `a2a.CardHandler` (P0/P1), `mcp.Server.Handler()` (Task 1), and a `/pubkey` handler on one mux; each sub-handler matches the full request path, so method-scoped patterns inside them still apply. ✓
