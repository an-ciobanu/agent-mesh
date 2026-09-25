# P8 — ACP Seller Agent + Buyer Commerce Driver Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an ACP (Agentic Commerce Protocol) seller agent and teach the existing greet agents to discover and buy from it automatically — authorized by an authority-issued COSE spend-mandate and settled by a real Stripe test-mode charge.

**Architecture:** The seller advertises an ACP capability + its trusted authority on its Agent Card; a buyer collides with it, fetches the catalog, obtains a spend-mandate for the chosen item from the named authority (reusing the P6 authority), and drives ACP `checkout_sessions` create/complete. The seller verifies the spend-mandate fail-closed (pinned authority key, sibling to the mandate/nonce guards), then settles through a `PaymentPrimitive` seam — `StripePaymentIntent` today, SPT drop-in later. Discovery + dispatch stay automatic (route by the card's advertised protocol; no per-seller code).

**Tech Stack:** Go 1.x, `net/http`, `github.com/veraison/go-cose` (existing COSE), `github.com/rs/zerolog`, Stripe REST (raw HTTP, test mode), the existing `internal/{events,policy,authority,comms/*,orchestrator}` packages and vanilla-JS `web/index.html`.

**Spec:** `docs/superpowers/specs/2026-09-25-p8-acp-seller-design.md`

**Module path:** `github.com/an-ciobanu/agent-mesh`

---

## Conventions for every task

- **TDD:** write the failing test first, watch it fail, implement minimally, watch it pass, commit.
- **Run the full gate before each commit:** `make check` (fmt + vet + lint + coverage) then `go test ./...`. If `make check` is slow, at minimum run `go test ./<changed-package>/...` for the red/green steps and `go build ./...` before commit.
- **Commits:** no `Co-Authored-By` / AI trailer, and do **not** use `git commit -s` (agent-mesh overrides the workspace DCO rule). Conventional-commit style messages (`feat:`, `test:`).
- **Fail closed:** every guard/verify path returns an error on any failure; never “accept on doubt”.
- **Secrets:** `STRIPE_SECRET_KEY` lives only in `data/stripe.env` (already gitignored via `data/`). Never log the key; log `pi_…` + status only.
- **Identity note (scope):** ACP calls in P8 do **not** carry the `X-ANS-Request-JWS` identity header that greets use. The buyer’s `callerAns` is self-asserted in the complete body and the spend-mandate binds `subjectAns` to it — consistent with the existing “CallerAns is self-asserted; key-to-name binding deferred” posture (see `internal/domain/greet.go`). Do not add JWS to ACP in this phase.

---

## Task 1: Domain types — spend-mandate claims + purchase request

**Files:**
- Modify: `internal/domain/mandate.go`
- Create: `internal/domain/commerce.go`
- Test: `internal/domain/commerce_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/domain/commerce_test.go`:
```go
package domain

import (
	"encoding/json"
	"testing"
)

func TestSpendMandateClaimsJSONRoundTrip(t *testing.T) {
	in := SpendMandateClaims{
		MandateID:    "spend-abc",
		SubjectAns:   "ans://v1.0.0.Ada.mesh.local",
		AudienceAns:  "ans://v1.0.0.shop-acp.mesh.local",
		ItemID:       "widget",
		MaxAmount:    1200,
		Currency:     "usd",
		Scope:        ScopePurchase,
		NotBefore:    "2026-09-25T00:00:00Z",
		NotAfter:     "2026-09-25T01:00:00Z",
		AuthorityAns: "ans://v1.0.0.authority-1.mesh.local",
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out SpendMandateClaims
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out != in {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", out, in)
	}
	if ScopePurchase != "purchase" {
		t.Fatalf("ScopePurchase = %q, want %q", ScopePurchase, "purchase")
	}
}

func TestPurchaseRequestFields(t *testing.T) {
	r := PurchaseRequest{CallerAns: "a", ItemID: "widget", Amount: 1200, Currency: "usd", SpendMandate: []byte{1, 2}}
	if r.Amount != 1200 || r.ItemID != "widget" || len(r.SpendMandate) != 2 {
		t.Fatalf("unexpected fields: %+v", r)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/domain/ -run 'SpendMandate|PurchaseRequest' -v`
Expected: FAIL — `undefined: SpendMandateClaims` / `ScopePurchase` / `PurchaseRequest`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/domain/commerce.go`:
```go
package domain

// ScopePurchase is the mandate scope that authorizes a purchase (distinct from
// the greet scope). A spend-mandate must carry this scope to admit a checkout.
const ScopePurchase = "purchase"

// SpendMandateClaims is the JSON payload inside a signed spend-mandate (a
// COSE_Sign1). It authorizes SubjectAns to buy the specific ItemID from
// AudienceAns for at most MaxAmount (smallest currency unit) in Currency, within
// a validity window, attested by AuthorityAns. It is the AP2-style proof of
// consent that the seller verifies before charging.
type SpendMandateClaims struct {
	MandateID    string `json:"mandateId"`
	SubjectAns   string `json:"subjectAns"`
	AudienceAns  string `json:"audienceAns"`
	ItemID       string `json:"itemId"`
	MaxAmount    int64  `json:"maxAmount"`
	Currency     string `json:"currency"`
	Scope        string `json:"scope"`
	NotBefore    string `json:"notBefore"`
	NotAfter     string `json:"notAfter"`
	AuthorityAns string `json:"authorityAns"`
}

// PurchaseRequest is the verified content the ACP seller's spend guard checks: a
// caller (self-asserted), the session's item/amount/currency, and the presented
// spend-mandate (a COSE_Sign1 over SpendMandateClaims).
type PurchaseRequest struct {
	CallerAns    string
	ItemID       string
	Amount       int64
	Currency     string
	SpendMandate []byte
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/domain/ -run 'SpendMandate|PurchaseRequest' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/domain/commerce.go internal/domain/commerce_test.go
git commit -m "feat(domain): add spend-mandate claims and purchase request types"
```

---

## Task 2: Authority — issue spend-mandates

**Files:**
- Modify: `internal/authority/authority.go`
- Modify: `cmd/authority/main.go:53-54`
- Test: `internal/authority/authority_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/authority/authority_test.go`:
```go
func TestIssueSpendMandateVerifiesAndBinds(t *testing.T) {
	priv, err := crypto.GenerateEd25519()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	ans := domain.LocalANSName("authority-1")
	a := authority.New(ans, priv, time.Hour, zerolog.Nop())

	cose, err := a.IssueSpendMandate(
		domain.LocalANSName("Ada"),
		domain.LocalANSName("shop-acp"),
		"widget", 1200, "usd",
	)
	if err != nil {
		t.Fatalf("issue spend mandate: %v", err)
	}
	payload, signer, err := crypto.VerifyCOSE1(cose)
	if err != nil {
		t.Fatalf("verify cose: %v", err)
	}
	if !signer.Equal(priv.Public().(ed25519.PublicKey)) {
		t.Fatalf("mandate not signed by the authority key")
	}
	var claims domain.SpendMandateClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	if claims.SubjectAns != domain.LocalANSName("Ada") ||
		claims.AudienceAns != domain.LocalANSName("shop-acp") ||
		claims.ItemID != "widget" || claims.MaxAmount != 1200 ||
		claims.Currency != "usd" || claims.Scope != domain.ScopePurchase ||
		claims.AuthorityAns != ans {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestSpendMCPToolRoundTrip(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	a := authority.New(domain.LocalANSName("authority-1"), priv, time.Hour, zerolog.Nop())
	args, _ := json.Marshal(map[string]any{
		"subjectAns": domain.LocalANSName("Ada"), "audienceAns": domain.LocalANSName("shop-acp"),
		"itemId": "widget", "maxAmount": 1200, "currency": "usd",
	})
	out, err := a.SpendMCPTool()(context.Background(), args)
	if err != nil {
		t.Fatalf("spend tool: %v", err)
	}
	var res struct {
		MandateCOSE []byte `json:"mandateCose"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if len(res.MandateCOSE) == 0 {
		t.Fatalf("empty mandate")
	}
}
```
Ensure the test file imports include: `context`, `crypto/ed25519`, `encoding/json`, `time`, `github.com/rs/zerolog`, and the `authority`, `crypto`, `domain` packages (match the existing imports already used in this test file; add any missing).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/authority/ -run 'SpendMandate|SpendMCPTool' -v`
Expected: FAIL — `a.IssueSpendMandate undefined` / `a.SpendMCPTool undefined`.

- [ ] **Step 3: Write minimal implementation**

Append to `internal/authority/authority.go` (after `IssueMandate`):
```go
// IssueSpendMandate builds a spend-mandate authorizing subject to buy itemID from
// audience for at most maxAmount (smallest currency unit) in currency, and returns
// it as a COSE_Sign1 signed by the authority. Scope is fixed to ScopePurchase.
func (a *Authority) IssueSpendMandate(subjectAns, audienceAns, itemID string, maxAmount int64, currency string) ([]byte, error) {
	if subjectAns == "" || audienceAns == "" || itemID == "" || currency == "" {
		return nil, fmt.Errorf("subjectAns, audienceAns, itemID and currency are required")
	}
	if maxAmount <= 0 {
		return nil, fmt.Errorf("maxAmount must be > 0")
	}
	now := time.Now().UTC()
	claims := domain.SpendMandateClaims{
		MandateID:    "spend-" + randHex(8),
		SubjectAns:   subjectAns,
		AudienceAns:  audienceAns,
		ItemID:       itemID,
		MaxAmount:    maxAmount,
		Currency:     currency,
		Scope:        domain.ScopePurchase,
		NotBefore:    now.Format(time.RFC3339),
		NotAfter:     now.Add(a.ttl).Format(time.RFC3339),
		AuthorityAns: a.ans,
	}
	b, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("marshal spend claims: %w", err)
	}
	cose, err := crypto.SignCOSE1(a.priv, b)
	if err != nil {
		return nil, fmt.Errorf("sign spend mandate: %w", err)
	}
	a.log.Info().Str("mandateId", claims.MandateID).Str("subjectAns", subjectAns).
		Str("audienceAns", audienceAns).Str("itemId", itemID).Int64("maxAmount", maxAmount).
		Str("currency", currency).Msg("spend mandate issued")
	return cose, nil
}

type spendArgs struct {
	SubjectAns  string `json:"subjectAns"`
	AudienceAns string `json:"audienceAns"`
	ItemID      string `json:"itemId"`
	MaxAmount   int64  `json:"maxAmount"`
	Currency    string `json:"currency"`
}

// SpendMCPTool returns the issue_spend_mandate MCP tool handler.
func (a *Authority) SpendMCPTool() mcp.ToolFunc {
	return func(_ context.Context, args json.RawMessage) (json.RawMessage, error) {
		var in spendArgs
		if err := json.Unmarshal(args, &in); err != nil {
			return nil, fmt.Errorf("invalid arguments: %w", err)
		}
		cose, err := a.IssueSpendMandate(in.SubjectAns, in.AudienceAns, in.ItemID, in.MaxAmount, in.Currency)
		if err != nil {
			return nil, err
		}
		return json.Marshal(issueResult{MandateCOSE: cose})
	}
}
```
(`issueResult`, `randHex`, and all imports already exist in `authority.go`.)

Then register the tool in `cmd/authority/main.go` immediately after the existing `mcpSrv.Register("issue_mandate", auth.MCPTool())` (around line 54):
```go
	mcpSrv.Register("issue_spend_mandate", auth.SpendMCPTool())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/authority/ -run 'SpendMandate|SpendMCPTool' -v && go build ./...`
Expected: PASS + build ok.

- [ ] **Step 5: Commit**

```bash
git add internal/authority/authority.go internal/authority/authority_test.go cmd/authority/main.go
git commit -m "feat(authority): issue spend-mandates via issue_spend_mandate MCP tool"
```

---

## Task 3: Spend guard (fail-closed spend-mandate verification)

**Files:**
- Create: `internal/policy/spend.go`
- Test: `internal/policy/spend_test.go`

Mirrors `internal/policy/mandate.go` (pinned authority key authenticates the issuer; every check fails closed) but verifies a `SpendMandateClaims` against a purchase.

- [ ] **Step 1: Write the failing test**

Create `internal/policy/spend_test.go`:
```go
package policy_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
)

func signSpend(t *testing.T, priv ed25519.PrivateKey, c domain.SpendMandateClaims) []byte {
	t.Helper()
	b, _ := json.Marshal(c)
	cose, err := crypto.SignCOSE1(priv, b)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return cose
}

func validClaims(now time.Time) domain.SpendMandateClaims {
	return domain.SpendMandateClaims{
		MandateID:    "spend-1",
		SubjectAns:   domain.LocalANSName("Ada"),
		AudienceAns:  domain.LocalANSName("shop-acp"),
		ItemID:       "widget",
		MaxAmount:    1500,
		Currency:     "usd",
		Scope:        domain.ScopePurchase,
		NotBefore:    now.Add(-time.Minute).Format(time.RFC3339),
		NotAfter:     now.Add(time.Hour).Format(time.RFC3339),
		AuthorityAns: domain.LocalANSName("authority-1"),
	}
}

func newGuard(t *testing.T) (*policy.Spend, ed25519.PrivateKey) {
	t.Helper()
	authPriv, _ := crypto.GenerateEd25519()
	g := policy.NewSpend(
		domain.LocalANSName("shop-acp"),
		domain.LocalANSName("authority-1"),
		authPriv.Public().(ed25519.PublicKey),
		zerolog.Nop(),
	)
	return g, authPriv
}

func req(mandate []byte) domain.PurchaseRequest {
	return domain.PurchaseRequest{
		CallerAns: domain.LocalANSName("Ada"), ItemID: "widget",
		Amount: 1200, Currency: "usd", SpendMandate: mandate,
	}
}

func TestSpendAcceptsValidMandate(t *testing.T) {
	g, authPriv := newGuard(t)
	m := signSpend(t, authPriv, validClaims(time.Now().UTC()))
	if err := g.Verify(context.Background(), req(m)); err != nil {
		t.Fatalf("valid mandate rejected: %v", err)
	}
}

func TestSpendRejectsMissingMandate(t *testing.T) {
	g, _ := newGuard(t)
	if err := g.Verify(context.Background(), req(nil)); err == nil {
		t.Fatal("expected rejection for missing mandate")
	}
}

func TestSpendRejectsWrongAuthorityKey(t *testing.T) {
	g, _ := newGuard(t)
	other, _ := crypto.GenerateEd25519()
	m := signSpend(t, other, validClaims(time.Now().UTC()))
	if err := g.Verify(context.Background(), req(m)); err == nil {
		t.Fatal("expected rejection: mandate signed by untrusted key")
	}
}

func TestSpendRejectsItemMismatch(t *testing.T) {
	g, authPriv := newGuard(t)
	c := validClaims(time.Now().UTC())
	c.ItemID = "gadget"
	m := signSpend(t, authPriv, c)
	if err := g.Verify(context.Background(), req(m)); err == nil {
		t.Fatal("expected rejection: item mismatch")
	}
}

func TestSpendRejectsAmountOverMax(t *testing.T) {
	g, authPriv := newGuard(t)
	c := validClaims(time.Now().UTC())
	c.MaxAmount = 1000 // request Amount is 1200
	m := signSpend(t, authPriv, c)
	if err := g.Verify(context.Background(), req(m)); err == nil {
		t.Fatal("expected rejection: amount exceeds maxAmount")
	}
}

func TestSpendRejectsWrongAudience(t *testing.T) {
	g, authPriv := newGuard(t)
	c := validClaims(time.Now().UTC())
	c.AudienceAns = domain.LocalANSName("someone-else")
	m := signSpend(t, authPriv, c)
	if err := g.Verify(context.Background(), req(m)); err == nil {
		t.Fatal("expected rejection: audience mismatch")
	}
}

func TestSpendRejectsExpired(t *testing.T) {
	g, authPriv := newGuard(t)
	c := validClaims(time.Now().UTC())
	c.NotAfter = time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339)
	m := signSpend(t, authPriv, c)
	if err := g.Verify(context.Background(), req(m)); err == nil {
		t.Fatal("expected rejection: expired mandate")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/ -run TestSpend -v`
Expected: FAIL — `undefined: policy.Spend` / `policy.NewSpend`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/policy/spend.go`:
```go
package policy

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/events"
)

// Spend verifies a purchase spend-mandate: a COSE_Sign1 over
// domain.SpendMandateClaims, signed by the specific authority this seller trusts
// (its Ed25519 key pinned at construction), naming this seller as the audience,
// the caller as the subject, the session's item, a price within maxAmount, the
// matching currency, ScopePurchase, and a currently-valid window.
//
// As with the greet Mandate guard, self-verifying COSE proves only that SOME key
// signed the mandate; pinning the authority key is what authenticates the issuer.
type Spend struct {
	selfAns      string
	authorityAns string
	authorityPub ed25519.PublicKey
	leeway       time.Duration
	now          func() time.Time
	log          zerolog.Logger
}

// NewSpend builds a spend guard for seller selfAns that trusts only spend-mandates
// signed by authorityPub (the authority named authorityAns).
func NewSpend(selfAns, authorityAns string, authorityPub ed25519.PublicKey, log zerolog.Logger) *Spend {
	return &Spend{
		selfAns:      selfAns,
		authorityAns: authorityAns,
		authorityPub: authorityPub,
		leeway:       60 * time.Second,
		now:          time.Now,
		log:          log.With().Str("component", "policy").Logger(),
	}
}

// Verify enforces the spend-mandate. Every failure returns an error (fail closed).
func (s *Spend) Verify(ctx context.Context, req domain.PurchaseRequest) error {
	if len(req.SpendMandate) == 0 {
		return fmt.Errorf("spend mandate required")
	}
	payload, signer, err := crypto.VerifyCOSE1(req.SpendMandate)
	if err != nil {
		events.Emit(ctx, "spend.verify", events.StatusFail, map[string]string{"error": err.Error()})
		return fmt.Errorf("spend mandate signature invalid: %w", err)
	}
	events.Emit(ctx, "spend.verify", events.StatusOK, map[string]string{"alg": "EdDSA", "result": "COSE_Sign1 signature valid (self-verifying)"})
	if !signer.Equal(s.authorityPub) {
		events.Emit(ctx, "authority.pin", events.StatusFail, map[string]string{"authority": s.authorityAns})
		return fmt.Errorf("spend mandate not signed by the trusted authority")
	}
	events.Emit(ctx, "authority.pin", events.StatusOK, map[string]string{"authority": s.authorityAns, "result": "issuer key matches the pinned authority — issuer authenticated"})

	var claims domain.SpendMandateClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return fmt.Errorf("spend claims malformed: %w", err)
	}
	if claims.AuthorityAns != s.authorityAns {
		return fmt.Errorf("spend authority %q is not the trusted authority %q", claims.AuthorityAns, s.authorityAns)
	}
	if claims.AudienceAns != s.selfAns {
		return fmt.Errorf("spend audience %q is not this seller %q", claims.AudienceAns, s.selfAns)
	}
	if claims.SubjectAns != req.CallerAns {
		return fmt.Errorf("spend subject %q does not match caller %q", claims.SubjectAns, req.CallerAns)
	}
	if claims.Scope != domain.ScopePurchase {
		return fmt.Errorf("spend scope %q is not %q", claims.Scope, domain.ScopePurchase)
	}
	if claims.ItemID != req.ItemID {
		return fmt.Errorf("spend item %q does not match session item %q", claims.ItemID, req.ItemID)
	}
	if claims.Currency != req.Currency {
		return fmt.Errorf("spend currency %q does not match session currency %q", claims.Currency, req.Currency)
	}
	if req.Amount > claims.MaxAmount {
		return fmt.Errorf("price %d exceeds authorized maxAmount %d", req.Amount, claims.MaxAmount)
	}
	now := s.now()
	nb, err := time.Parse(time.RFC3339, claims.NotBefore)
	if err != nil {
		return fmt.Errorf("spend notBefore invalid: %w", err)
	}
	na, err := time.Parse(time.RFC3339, claims.NotAfter)
	if err != nil {
		return fmt.Errorf("spend notAfter invalid: %w", err)
	}
	if now.Before(nb.Add(-s.leeway)) {
		return fmt.Errorf("spend mandate not yet valid")
	}
	if now.After(na.Add(s.leeway)) {
		return fmt.Errorf("spend mandate expired")
	}
	s.log.Info().Str("mandateId", claims.MandateID).Str("callerAns", req.CallerAns).
		Str("itemId", claims.ItemID).Msg("spend mandate accepted")
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/policy/ -run TestSpend -v`
Expected: PASS (all 7 sub-tests).

- [ ] **Step 5: Commit**

```bash
git add internal/policy/spend.go internal/policy/spend_test.go
git commit -m "feat(policy): fail-closed spend-mandate guard for ACP purchases"
```

---

## Task 4: Stripe test-mode PaymentIntent client

**Files:**
- Create: `internal/stripe/client.go`
- Test: `internal/stripe/client_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/stripe/client_test.go`:
```go
package stripe_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/an-ciobanu/agent-mesh/internal/stripe"
)

func TestCreatePaymentIntentEncodesAndParses(t *testing.T) {
	var gotAuth, gotIdem, gotBody, gotContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotIdem = r.Header.Get("Idempotency-Key")
		gotContentType = r.Header.Get("Content-Type")
		b := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(b)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"pi_test_123","status":"succeeded"}`))
	}))
	defer srv.Close()

	cli := stripe.NewClientWithBase("sk_test_abc", srv.URL)
	pi, err := cli.CreatePaymentIntent(context.Background(), stripe.PaymentIntentRequest{
		Amount: 1200, Currency: "usd", Description: "agent-mesh ACP",
		IdempotencyKey: "greet-1", Metadata: map[string]string{"source": "agent-mesh"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if pi.ID != "pi_test_123" || pi.Status != "succeeded" {
		t.Fatalf("unexpected PI: %+v", pi)
	}
	if gotAuth != "Bearer sk_test_abc" {
		t.Fatalf("auth = %q", gotAuth)
	}
	if gotIdem != "greet-1" {
		t.Fatalf("idempotency = %q", gotIdem)
	}
	if !strings.Contains(gotContentType, "application/x-www-form-urlencoded") {
		t.Fatalf("content-type = %q", gotContentType)
	}
	for _, want := range []string{"amount=1200", "currency=usd", "confirm=true",
		"payment_method=pm_card_visa", "payment_method_types%5B%5D=card", "metadata%5Bsource%5D=agent-mesh"} {
		if !strings.Contains(gotBody, want) {
			t.Fatalf("body missing %q; got %q", want, gotBody)
		}
	}
}

func TestCreatePaymentIntentReturnsAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPaymentRequired)
		_, _ = w.Write([]byte(`{"error":{"message":"card declined","code":"card_declined"}}`))
	}))
	defer srv.Close()
	cli := stripe.NewClientWithBase("sk_test_abc", srv.URL)
	_, err := cli.CreatePaymentIntent(context.Background(), stripe.PaymentIntentRequest{Amount: 100, Currency: "usd", IdempotencyKey: "x"})
	if err == nil || !strings.Contains(err.Error(), "card declined") {
		t.Fatalf("expected card declined error, got %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/stripe/ -v`
Expected: FAIL — package/symbols undefined.

- [ ] **Step 3: Write minimal implementation**

Create `internal/stripe/client.go`:
```go
// Package stripe is a minimal Stripe REST client for the demo's funding leg: it
// creates a test-mode PaymentIntent and confirms it with a test payment method.
// It deliberately implements only what the ACP seller needs; it is the concrete
// funding rail behind the PaymentPrimitive seam (SPT can replace it later).
package stripe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL is Stripe's API root.
const DefaultBaseURL = "https://api.stripe.com"

// Client calls the Stripe REST API with a secret key.
type Client struct {
	secret string
	base   string
	http   *http.Client
}

// NewClient returns a client for the live Stripe API root.
func NewClient(secretKey string) *Client { return NewClientWithBase(secretKey, DefaultBaseURL) }

// NewClientWithBase returns a client pointed at base (used by tests).
func NewClientWithBase(secretKey, base string) *Client {
	return &Client{secret: secretKey, base: strings.TrimRight(base, "/"), http: &http.Client{Timeout: 15 * time.Second}}
}

// PaymentIntentRequest is the demo's charge input.
type PaymentIntentRequest struct {
	Amount         int64
	Currency       string
	Description    string
	IdempotencyKey string
	Metadata       map[string]string
}

// PaymentIntent is the subset of the Stripe response the demo uses.
type PaymentIntent struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

type apiError struct {
	Error struct {
		Message string `json:"message"`
		Code    string `json:"code"`
		Type    string `json:"type"`
	} `json:"error"`
}

// CreatePaymentIntent creates and confirms a test-mode PaymentIntent using the
// pm_card_visa test payment method. Returns the PaymentIntent id and status.
func (c *Client) CreatePaymentIntent(ctx context.Context, in PaymentIntentRequest) (PaymentIntent, error) {
	form := url.Values{}
	form.Set("amount", strconv.FormatInt(in.Amount, 10))
	form.Set("currency", in.Currency)
	form.Set("payment_method", "pm_card_visa")
	form.Add("payment_method_types[]", "card")
	form.Set("confirm", "true")
	if in.Description != "" {
		form.Set("description", in.Description)
	}
	for k, v := range in.Metadata {
		form.Set("metadata["+k+"]", v)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/v1/payment_intents", strings.NewReader(form.Encode()))
	if err != nil {
		return PaymentIntent{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if in.IdempotencyKey != "" {
		req.Header.Set("Idempotency-Key", in.IdempotencyKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return PaymentIntent{}, fmt.Errorf("stripe request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		var ae apiError
		if json.Unmarshal(body, &ae) == nil && ae.Error.Message != "" {
			return PaymentIntent{}, fmt.Errorf("stripe: %s (code %s, status %d)", ae.Error.Message, ae.Error.Code, resp.StatusCode)
		}
		return PaymentIntent{}, fmt.Errorf("stripe: unexpected status %d", resp.StatusCode)
	}
	var pi PaymentIntent
	if err := json.Unmarshal(body, &pi); err != nil {
		return PaymentIntent{}, fmt.Errorf("decode payment intent: %w", err)
	}
	if pi.ID == "" {
		return PaymentIntent{}, fmt.Errorf("stripe: empty payment intent id")
	}
	return pi, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/stripe/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/stripe/client.go internal/stripe/client_test.go
git commit -m "feat(stripe): minimal test-mode PaymentIntent client"
```

---

## Task 5: Payment seam + catalog

**Files:**
- Create: `internal/commerce/acp/payment.go`
- Create: `internal/commerce/acp/catalog.go`
- Test: `internal/commerce/acp/payment_test.go`
- Test: `internal/commerce/acp/catalog_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/commerce/acp/payment_test.go`:
```go
package acp_test

import (
	"context"
	"testing"

	"github.com/an-ciobanu/agent-mesh/internal/commerce/acp"
)

func TestFakePaymentSucceeds(t *testing.T) {
	var p acp.PaymentPrimitive = acp.FakePayment{}
	res, err := p.Charge(context.Background(), acp.ChargeRequest{
		Amount: 1200, Currency: "usd", ItemID: "widget", BuyerAns: "ada", IdempotencyKey: "k1",
	})
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	if res.Provider != "fake" || res.Status != "succeeded" || res.Ref == "" {
		t.Fatalf("unexpected result: %+v", res)
	}
}
```

Create `internal/commerce/acp/catalog_test.go`:
```go
package acp_test

import (
	"testing"

	"github.com/an-ciobanu/agent-mesh/internal/commerce/acp"
)

func TestDefaultCatalogIsPricedInCurrency(t *testing.T) {
	items := acp.DefaultCatalog("usd")
	if len(items) < 2 {
		t.Fatalf("want >=2 items, got %d", len(items))
	}
	seen := map[string]bool{}
	for _, it := range items {
		if it.ID == "" || it.Amount <= 0 || it.Currency != "usd" {
			t.Fatalf("bad item: %+v", it)
		}
		if seen[it.ID] {
			t.Fatalf("duplicate item id %q", it.ID)
		}
		seen[it.ID] = true
	}
}

func TestLowestPricedPicksCheapest(t *testing.T) {
	items := []acp.Item{{ID: "a", Amount: 900, Currency: "usd"}, {ID: "b", Amount: 300, Currency: "usd"}, {ID: "c", Amount: 500, Currency: "usd"}}
	it, ok := acp.LowestPriced(items)
	if !ok || it.ID != "b" {
		t.Fatalf("want b, got %+v ok=%v", it, ok)
	}
	if _, ok := acp.LowestPriced(nil); ok {
		t.Fatal("empty catalog should return ok=false")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/commerce/acp/ -v`
Expected: FAIL — package/symbols undefined.

- [ ] **Step 3: Write minimal implementation**

Create `internal/commerce/acp/catalog.go`:
```go
// Package acp implements the demo's Agentic Commerce Protocol seller (server) and
// buyer driver (client): catalog + checkout_sessions create/complete, gated by an
// authority-issued spend-mandate and settled through a PaymentPrimitive seam.
package acp

// Item is one thing an ACP seller sells.
type Item struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Amount   int64  `json:"amount"` // smallest currency unit (e.g. cents)
	Currency string `json:"currency"`
}

// DefaultCatalog is the demo's fixed 3-item catalog priced in currency.
func DefaultCatalog(currency string) []Item {
	return []Item{
		{ID: "sticker", Name: "Mesh Sticker", Amount: 500, Currency: currency},
		{ID: "mug", Name: "Mesh Mug", Amount: 1200, Currency: currency},
		{ID: "hoodie", Name: "Mesh Hoodie", Amount: 4200, Currency: currency},
	}
}

// LowestPriced returns the cheapest item (deterministic buyer choice), or ok=false
// when the catalog is empty.
func LowestPriced(items []Item) (Item, bool) {
	if len(items) == 0 {
		return Item{}, false
	}
	best := items[0]
	for _, it := range items[1:] {
		if it.Amount < best.Amount {
			best = it
		}
	}
	return best, true
}
```

Create `internal/commerce/acp/payment.go`:
```go
package acp

import (
	"context"

	"github.com/an-ciobanu/agent-mesh/internal/stripe"
)

// ChargeRequest is the funding-leg input, independent of the concrete provider.
type ChargeRequest struct {
	Amount         int64
	Currency       string
	ItemID         string
	BuyerAns       string
	IdempotencyKey string
}

// ChargeResult is a provider-neutral funding result.
type ChargeResult struct {
	Provider string // "stripe" | "fake"
	Ref      string // e.g. "pi_..."
	Status   string // e.g. "succeeded"
}

// PaymentPrimitive is the funding seam: today a Stripe test-mode PaymentIntent,
// later a Shared Payment Token redemption — the seller code above it is unchanged.
type PaymentPrimitive interface {
	Charge(ctx context.Context, r ChargeRequest) (ChargeResult, error)
}

// StripePaymentIntent settles via a real test-mode Stripe PaymentIntent.
type StripePaymentIntent struct {
	Client *stripe.Client
}

// Charge creates and confirms a PaymentIntent for the requested amount.
func (s StripePaymentIntent) Charge(ctx context.Context, r ChargeRequest) (ChargeResult, error) {
	pi, err := s.Client.CreatePaymentIntent(ctx, stripe.PaymentIntentRequest{
		Amount:         r.Amount,
		Currency:       r.Currency,
		Description:    "agent-mesh ACP purchase: " + r.ItemID,
		IdempotencyKey: r.IdempotencyKey,
		Metadata:       map[string]string{"source": "agent-mesh", "item": r.ItemID, "buyer": r.BuyerAns},
	})
	if err != nil {
		return ChargeResult{}, err
	}
	return ChargeResult{Provider: "stripe", Ref: pi.ID, Status: pi.Status}, nil
}

// FakePayment settles locally with no network — used by tests and offline demos.
type FakePayment struct{}

// Charge returns a deterministic successful result.
func (FakePayment) Charge(_ context.Context, r ChargeRequest) (ChargeResult, error) {
	ref := "pi_fake_" + r.IdempotencyKey
	if r.IdempotencyKey == "" {
		ref = "pi_fake_" + r.ItemID
	}
	return ChargeResult{Provider: "fake", Ref: ref, Status: "succeeded"}, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/commerce/acp/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/commerce/acp/payment.go internal/commerce/acp/catalog.go internal/commerce/acp/payment_test.go internal/commerce/acp/catalog_test.go
git commit -m "feat(acp): payment seam (stripe + fake) and demo catalog"
```

---

## Task 6: ACP seller service (catalog + checkout_sessions create/complete)

**Files:**
- Create: `internal/commerce/acp/seller.go`
- Test: `internal/commerce/acp/seller_test.go`

The seller installs an events scope from the `X-ANS-Greet-Id` header on every ACP call (mirroring `GreetService.HandleMessageSend`), verifies the spend-mandate on complete via the `policy.Spend` guard, then charges via the `PaymentPrimitive`.

- [ ] **Step 1: Write the failing test**

Create `internal/commerce/acp/seller_test.go`:
```go
package acp_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/commerce/acp"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/events"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
)

func newSellerServer(t *testing.T) (*httptest.Server, ed25519.PrivateKey) {
	t.Helper()
	authPriv, _ := crypto.GenerateEd25519()
	guard := policy.NewSpend(
		domain.LocalANSName("shop-acp"),
		domain.LocalANSName("authority-1"),
		authPriv.Public().(ed25519.PublicKey),
		zerolog.Nop(),
	)
	seller := acp.NewSeller(acp.SellerConfig{
		SelfAns:   domain.LocalANSName("shop-acp"),
		AgentName: "shop-acp",
		Currency:  "usd",
		Catalog:   acp.DefaultCatalog("usd"),
		Guard:     guard,
		Payment:   acp.FakePayment{},
		Events:    events.Nop{},
		Log:       zerolog.Nop(),
	})
	mux := http.NewServeMux()
	seller.Mount(mux)
	return httptest.NewServer(mux), authPriv
}

func spendMandateFor(t *testing.T, authPriv ed25519.PrivateKey, itemID string, maxAmount int64) []byte {
	t.Helper()
	now := time.Now().UTC()
	c := domain.SpendMandateClaims{
		MandateID: "spend-x", SubjectAns: domain.LocalANSName("Ada"),
		AudienceAns: domain.LocalANSName("shop-acp"), ItemID: itemID, MaxAmount: maxAmount,
		Currency: "usd", Scope: domain.ScopePurchase,
		NotBefore: now.Add(-time.Minute).Format(time.RFC3339), NotAfter: now.Add(time.Hour).Format(time.RFC3339),
		AuthorityAns: domain.LocalANSName("authority-1"),
	}
	b, _ := json.Marshal(c)
	cose, err := crypto.SignCOSE1(authPriv, b)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return cose
}

func postJSON(t *testing.T, url string, body any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(acp.HeaderGreetID, "greet-test")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post %s: %v", url, err)
	}
	return resp
}

func TestSellerCatalog(t *testing.T) {
	srv, _ := newSellerServer(t)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/acp/catalog")
	if err != nil {
		t.Fatalf("get catalog: %v", err)
	}
	defer resp.Body.Close()
	var out struct{ Items []acp.Item `json:"items"` }
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Items) == 0 {
		t.Fatal("empty catalog")
	}
}

func TestSellerCheckoutHappyPath(t *testing.T) {
	srv, authPriv := newSellerServer(t)
	defer srv.Close()

	// create session for "sticker" (500)
	resp := postJSON(t, srv.URL+"/acp/checkout_sessions", map[string]string{"itemId": "sticker"})
	var sess struct {
		SessionID string `json:"sessionId"`
		Amount    int64  `json:"amount"`
		Currency  string `json:"currency"`
		Status    string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&sess); err != nil {
		t.Fatalf("decode session: %v", err)
	}
	resp.Body.Close()
	if sess.SessionID == "" || sess.Amount != 500 || sess.Status != "ready_for_payment" {
		t.Fatalf("unexpected session: %+v", sess)
	}

	// complete with a valid spend-mandate
	m := spendMandateFor(t, authPriv, "sticker", 500)
	resp = postJSON(t, srv.URL+"/acp/checkout_sessions/"+sess.SessionID+"/complete",
		map[string]any{"callerAns": domain.LocalANSName("Ada"), "spendMandate": m})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("complete status = %d", resp.StatusCode)
	}
	var rec struct {
		Status     string `json:"status"`
		Provider   string `json:"provider"`
		PaymentRef string `json:"paymentRef"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rec); err != nil {
		t.Fatalf("decode receipt: %v", err)
	}
	resp.Body.Close()
	if rec.Status != "completed" || rec.PaymentRef == "" || rec.Provider != "fake" {
		t.Fatalf("unexpected receipt: %+v", rec)
	}
}

func TestSellerCompleteRejectsBadMandate(t *testing.T) {
	srv, authPriv := newSellerServer(t)
	defer srv.Close()
	resp := postJSON(t, srv.URL+"/acp/checkout_sessions", map[string]string{"itemId": "mug"})
	var sess struct{ SessionID string `json:"sessionId"` }
	_ = json.NewDecoder(resp.Body).Decode(&sess)
	resp.Body.Close()

	// mandate is for the wrong item -> guard rejects, no charge
	m := spendMandateFor(t, authPriv, "sticker", 5000)
	resp = postJSON(t, srv.URL+"/acp/checkout_sessions/"+sess.SessionID+"/complete",
		map[string]any{"callerAns": domain.LocalANSName("Ada"), "spendMandate": m})
	if resp.StatusCode == http.StatusOK {
		t.Fatal("expected non-200 for item-mismatch mandate")
	}
	resp.Body.Close()
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/commerce/acp/ -run TestSeller -v`
Expected: FAIL — `acp.NewSeller` / `acp.SellerConfig` / `acp.HeaderGreetID` undefined.

- [ ] **Step 3: Write minimal implementation**

Create `internal/commerce/acp/seller.go`:
```go
package acp

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/events"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
)

// HeaderGreetID correlates a buyer's ACP calls (catalog/create/complete) with the
// seller's emitted events. It mirrors a2a.HeaderGreetID; duplicated here to avoid
// importing the a2a package into the commerce layer.
const HeaderGreetID = "X-ANS-Greet-Id"

// SellerConfig configures an ACP seller service.
type SellerConfig struct {
	SelfAns   string
	AgentName string
	Currency  string
	Catalog   []Item
	Guard     *policy.Spend
	Payment   PaymentPrimitive
	Events    events.Emitter
	Log       zerolog.Logger
}

type session struct {
	id       string
	itemID   string
	amount   int64
	currency string
}

// Seller serves the ACP catalog + checkout_sessions endpoints.
type Seller struct {
	cfg SellerConfig
	mu  sync.Mutex
	ses map[string]session
	log zerolog.Logger
}

// NewSeller builds a seller service.
func NewSeller(cfg SellerConfig) *Seller {
	if cfg.Events == nil {
		cfg.Events = events.Nop{}
	}
	return &Seller{cfg: cfg, ses: map[string]session{}, log: cfg.Log.With().Str("component", "acp-seller").Logger()}
}

// Mount registers the seller's routes on mux.
func (s *Seller) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /acp/catalog", s.handleCatalog)
	mux.HandleFunc("POST /acp/checkout_sessions", s.handleCreate)
	mux.HandleFunc("POST /acp/checkout_sessions/{id}/complete", s.handleComplete)
}

func (s *Seller) scope(r *http.Request) (ctx interface{ Done() <-chan struct{} }, gctx contextT) {
	return nil, contextT{}
}

func (s *Seller) handleCatalog(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": s.cfg.Catalog})
}

func (s *Seller) handleCreate(w http.ResponseWriter, r *http.Request) {
	gctx := events.WithScope(r.Context(), s.cfg.Events, r.Header.Get(HeaderGreetID), s.cfg.AgentName, events.RoleResponder)
	var in struct {
		ItemID string `json:"itemId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	var item Item
	found := false
	for _, it := range s.cfg.Catalog {
		if it.ID == in.ItemID {
			item, found = it, true
			break
		}
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown item"})
		return
	}
	id := "cs_" + events.NewGreetID()[:16]
	s.mu.Lock()
	s.ses[id] = session{id: id, itemID: item.ID, amount: item.Amount, currency: item.Currency}
	s.mu.Unlock()
	events.Emit(gctx, "session.create", events.StatusOK, map[string]string{
		"sessionId": id, "item": item.ID, "amount": strconv.FormatInt(item.Amount, 10), "currency": item.Currency,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"sessionId": id, "itemId": item.ID, "amount": item.Amount, "currency": item.Currency, "status": "ready_for_payment",
	})
}

func (s *Seller) handleComplete(w http.ResponseWriter, r *http.Request) {
	gctx := events.WithScope(r.Context(), s.cfg.Events, r.Header.Get(HeaderGreetID), s.cfg.AgentName, events.RoleResponder)
	id := r.PathValue("id")
	s.mu.Lock()
	sess, ok := s.ses[id]
	s.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown session"})
		return
	}
	var in struct {
		CallerAns    string `json:"callerAns"`
		SpendMandate []byte `json:"spendMandate"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	if err := s.cfg.Guard.Verify(gctx, domain.PurchaseRequest{
		CallerAns: in.CallerAns, ItemID: sess.itemID, Amount: sess.amount, Currency: sess.currency, SpendMandate: in.SpendMandate,
	}); err != nil {
		s.log.Warn().Err(err).Str("session", id).Msg("spend rejected")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "purchase not authorized: " + err.Error()})
		return
	}
	res, err := s.cfg.Payment.Charge(gctx, ChargeRequest{
		Amount: sess.amount, Currency: sess.currency, ItemID: sess.itemID,
		BuyerAns: in.CallerAns, IdempotencyKey: id,
	})
	if err != nil {
		events.Emit(gctx, "charge", events.StatusFail, map[string]string{"error": err.Error()})
		s.log.Error().Err(err).Str("session", id).Msg("charge failed")
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "charge failed: " + err.Error()})
		return
	}
	events.Emit(gctx, "charge", events.StatusOK, map[string]string{"provider": res.Provider, "ref": res.Ref, "status": res.Status})
	events.Emit(gctx, "receipt", events.StatusOK, map[string]string{"paymentRef": res.Ref, "status": res.Status})
	s.mu.Lock()
	delete(s.ses, id)
	s.mu.Unlock()
	s.log.Info().Str("session", id).Str("paymentRef", res.Ref).Str("status", res.Status).Msg("purchase completed")
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "completed", "provider": res.Provider, "paymentRef": res.Ref,
		"itemId": sess.itemID, "amount": sess.amount, "currency": sess.currency,
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

var _ = strings.TrimSpace // keep strings import if unused after edits
```
> **Implementation note:** delete the placeholder `scope`/`contextT` helper stub — it was only shown to illustrate intent. Do **not** include `func (s *Seller) scope(...)` or `contextT` in the final file; use `events.WithScope` inline as the handlers above do. Also remove the `var _ = strings.TrimSpace` line and the `strings` import if `strings` ends up unused. (This step's real code is the handlers; keep only what compiles.)

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/commerce/acp/ -run TestSeller -v && go vet ./internal/commerce/acp/`
Expected: PASS + vet clean (fix any unused import flagged by vet/compiler).

- [ ] **Step 5: Commit**

```bash
git add internal/commerce/acp/seller.go internal/commerce/acp/seller_test.go
git commit -m "feat(acp): seller service — catalog + checkout_sessions with spend-gate and charge"
```

---

## Task 7: Buyer ACP driver + buy trigger

**Files:**
- Create: `internal/commerce/acp/driver.go`
- Modify: `internal/comms/a2a/trigger.go`
- Test: `internal/commerce/acp/driver_test.go`
- Test: `internal/comms/a2a/trigger_test.go` (add a buy case)

The driver reads the ACP extension params from the card, fetches the catalog, picks the cheapest item, acquires a spend-mandate from the named authority over MCP, then drives create + complete. All HTTP calls carry the greet id from the ctx scope so the seller's events correlate.

- [ ] **Step 1: Write the failing test**

Create `internal/commerce/acp/driver_test.go`:
```go
package acp_test

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/commerce/acp"
	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
)

// stubDiscovery returns a fixed set for a role.
type stubDiscovery struct{ byRole map[string][]domain.AgentInfo }

func (s stubDiscovery) Register(context.Context, domain.AgentInfo) error { return nil }
func (s stubDiscovery) Search(_ context.Context, role string) ([]domain.AgentInfo, error) {
	return s.byRole[role], nil
}

func TestBuyPeerHappyPath(t *testing.T) {
	// authority MCP server (issue_spend_mandate)
	authPriv, _ := crypto.GenerateEd25519()
	authAns := domain.LocalANSName("authority-1")
	authMCP := mcp.NewServer(zerolog.Nop())
	authMCP.Register("issue_spend_mandate", func(_ context.Context, args []byte) ([]byte, error) {
		// delegate to the real authority for a correctly-bound mandate
		return newAuthorityTool(t, authPriv, authAns)(context.Background(), args)
	})
	authSrv := httptest.NewServer(authMCP.Handler())
	defer authSrv.Close()

	// seller server, trusting authPriv's key
	guard := policy.NewSpend(domain.LocalANSName("shop-acp"), authAns, authPriv.Public().(ed25519.PublicKey), zerolog.Nop())
	seller := acp.NewSeller(acp.SellerConfig{
		SelfAns: domain.LocalANSName("shop-acp"), AgentName: "shop-acp", Currency: "usd",
		Catalog: acp.DefaultCatalog("usd"), Guard: guard, Payment: acp.FakePayment{}, Log: zerolog.Nop(),
	})
	sMux := http.NewServeMux()
	seller.Mount(sMux)
	sellerSrv := httptest.NewServer(sMux)
	defer sellerSrv.Close()

	disco := stubDiscovery{byRole: map[string][]domain.AgentInfo{
		"authority": {{Name: "authority-1", Role: "authority", BaseURL: authSrv.URL, CardURL: authSrv.URL + "/.well-known/agent-card.json"}},
	}}
	peer := domain.AgentInfo{Name: "shop-acp", Role: "seller", BaseURL: sellerSrv.URL, CardURL: sellerSrv.URL + "/.well-known/agent-card.json"}
	card := a2a.Card{Name: "shop-acp", Capabilities: &a2a.Capabilities{Extensions: []a2a.Extension{{
		URI: a2a.ExtACPURI, Params: map[string]any{
			"catalogPath": "/acp/catalog", "checkoutPath": "/acp/checkout_sessions",
			"authorityRole": "authority", "authorityAns": authAns, "currency": "usd",
		},
	}}}}

	res, err := acp.BuyPeer(context.Background(), http.DefaultClient, mcp.NewClient(), disco, domain.LocalANSName("Ada"), peer, card)
	if err != nil {
		t.Fatalf("buy: %v", err)
	}
	if res.Status != "succeeded" || res.PaymentRef == "" {
		t.Fatalf("unexpected buy result: %+v", res)
	}
}
```
Add this test helper (new file `internal/commerce/acp/helpers_test.go`) so the driver test can mint a correctly-bound mandate through the real authority:
```go
package acp_test

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/authority"
	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
)

func newAuthorityTool(t *testing.T, priv ed25519.PrivateKey, ans string) mcp.ToolFunc {
	t.Helper()
	return authority.New(ans, priv, time.Hour, zerolog.Nop()).SpendMCPTool()
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/commerce/acp/ -run TestBuyPeer -v`
Expected: FAIL — `acp.BuyPeer` / `a2a.ExtACPURI` undefined.

- [ ] **Step 3a: Add the ACP extension URI**

In `internal/comms/a2a/card.go`, after the `ExtNonceURI` const (line 18), add:
```go
// ExtACPURI identifies the agent-mesh "ACP seller" A2A capabilities extension. A
// seller that advertises it sells over the Agentic Commerce Protocol: its params
// carry the catalog/checkout paths, the authority that issues valid
// spend-mandates, and the seller's currency.
const ExtACPURI = "https://agent-mesh.local/ext/acp/v1"
```

- [ ] **Step 3b: Write the buyer driver**

Create `internal/commerce/acp/driver.go`:
```go
package acp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/events"
)

// BuyResult is what a completed purchase returns to the caller.
type BuyResult struct {
	PaymentRef string
	Status     string
	ItemID     string
}

// BuyPeer drives a full ACP purchase against an already-discovered seller peer
// whose card advertises the ACP extension: fetch catalog, pick the cheapest item,
// acquire a spend-mandate from the named authority (over MCP), then create and
// complete a checkout session. Nothing about the seller or authority is hardcoded;
// everything is read from the card. Steps are emitted through ctx (no-op if no
// scope). disco is used only to discover the authority.
func BuyPeer(ctx context.Context, httpc *http.Client, mcpCli *mcp.Client, disco domain.Discovery, callerAns string, peer domain.AgentInfo, card a2a.Card) (BuyResult, error) {
	ext, ok := acpExtension(card)
	if !ok {
		return BuyResult{}, fmt.Errorf("peer %q does not advertise ACP", peer.Name)
	}
	events.Emit(ctx, "requirement", events.StatusInfo, map[string]string{"type": "acp"})
	events.Emit(ctx, "card.read", events.StatusOK, map[string]string{"peer": peer.Name, "url": card.URL})

	catalogPath := strParam(ext.Params, "catalogPath", "/acp/catalog")
	checkoutPath := strParam(ext.Params, "checkoutPath", "/acp/checkout_sessions")
	authorityRole := strParam(ext.Params, "authorityRole", "authority")
	authorityAns := strParam(ext.Params, "authorityAns", "")
	greetID := events.GreetIDFromContext(ctx)

	// 1. catalog
	items, err := fetchCatalog(ctx, httpc, greetID, peer.BaseURL+catalogPath)
	if err != nil {
		return BuyResult{}, err
	}
	events.Emit(ctx, "catalog.fetch", events.StatusOK, map[string]string{"items": strconv.Itoa(len(items))})
	item, ok := LowestPriced(items)
	if !ok {
		return BuyResult{}, fmt.Errorf("seller %q has an empty catalog", peer.Name)
	}
	events.Emit(ctx, "item.select", events.StatusOK, map[string]string{
		"item": item.ID, "amount": strconv.FormatInt(item.Amount, 10), "currency": item.Currency,
	})

	// 2. spend-mandate from the named authority
	audienceAns := domain.LocalANSName(peer.Name)
	authority, ok, err := pickAuthority(ctx, disco, authorityRole, authorityAns)
	if err != nil {
		return BuyResult{}, err
	}
	if !ok {
		return BuyResult{}, fmt.Errorf("no authority %q under role %q", authorityAns, authorityRole)
	}
	mandate, err := acquireSpendMandate(ctx, mcpCli, authority.BaseURL+"/mcp", callerAns, audienceAns, item)
	if err != nil {
		events.Emit(ctx, "spend.acquire", events.StatusFail, map[string]string{"error": err.Error(), "authority": authority.Name})
		return BuyResult{}, err
	}
	events.Emit(ctx, "spend.acquire", events.StatusOK, map[string]string{
		"authority": authority.Name, "item": item.ID, "maxAmount": strconv.FormatInt(item.Amount, 10), "currency": item.Currency, "tool": "issue_spend_mandate (MCP)",
	})

	// 3. create checkout session
	sessionID, amount, err := createSession(ctx, httpc, greetID, peer.BaseURL+checkoutPath, item.ID)
	if err != nil {
		return BuyResult{}, err
	}
	events.Emit(ctx, "checkout.create", events.StatusOK, map[string]string{"sessionId": sessionID, "amount": strconv.FormatInt(amount, 10)})

	// 4. complete
	events.Emit(ctx, "checkout.complete", events.StatusInfo, map[string]string{"sessionId": sessionID})
	res, err := completeSession(ctx, httpc, greetID, peer.BaseURL+checkoutPath+"/"+sessionID+"/complete", callerAns, mandate)
	if err != nil {
		events.Emit(ctx, "purchase.rejected", events.StatusFail, map[string]string{"error": err.Error()})
		return BuyResult{}, err
	}
	events.Emit(ctx, "receipt", events.StatusOK, map[string]string{"paymentRef": res.PaymentRef, "status": res.Status, "provider": res.Provider})
	return BuyResult{PaymentRef: res.PaymentRef, Status: res.Status, ItemID: item.ID}, nil
}

func acpExtension(card a2a.Card) (a2a.Extension, bool) {
	if card.Capabilities == nil {
		return a2a.Extension{}, false
	}
	for _, e := range card.Capabilities.Extensions {
		if e.URI == a2a.ExtACPURI {
			return e, true
		}
	}
	return a2a.Extension{}, false
}

func pickAuthority(ctx context.Context, disco domain.Discovery, role, wantAns string) (domain.AgentInfo, bool, error) {
	peers, err := disco.Search(ctx, role)
	if err != nil {
		return domain.AgentInfo{}, false, fmt.Errorf("discover authority role %q: %w", role, err)
	}
	if len(peers) == 0 {
		return domain.AgentInfo{}, false, nil
	}
	if wantAns == "" {
		return peers[0], true, nil
	}
	for _, p := range peers {
		if domain.LocalANSName(p.Name) == wantAns {
			return p, true, nil
		}
	}
	return domain.AgentInfo{}, false, nil
}

func acquireSpendMandate(ctx context.Context, mcpCli *mcp.Client, authURL, subjectAns, audienceAns string, item Item) ([]byte, error) {
	raw, err := mcpCli.Call(ctx, authURL, "issue_spend_mandate", map[string]any{
		"subjectAns": subjectAns, "audienceAns": audienceAns,
		"itemId": item.ID, "maxAmount": item.Amount, "currency": item.Currency,
	})
	if err != nil {
		return nil, fmt.Errorf("issue_spend_mandate: %w", err)
	}
	var out struct {
		MandateCOSE []byte `json:"mandateCose"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("parse issue_spend_mandate: %w", err)
	}
	if len(out.MandateCOSE) == 0 {
		return nil, fmt.Errorf("authority returned an empty spend mandate")
	}
	return out.MandateCOSE, nil
}

func fetchCatalog(ctx context.Context, httpc *http.Client, greetID, url string) ([]Item, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	setGreet(req, greetID)
	resp, err := httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch catalog: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("catalog: status %d", resp.StatusCode)
	}
	var out struct {
		Items []Item `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode catalog: %w", err)
	}
	return out.Items, nil
}

func createSession(ctx context.Context, httpc *http.Client, greetID, url, itemID string) (string, int64, error) {
	body, _ := json.Marshal(map[string]string{"itemId": itemID})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	setGreet(req, greetID)
	resp, err := httpc.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("create session: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("create session: status %d", resp.StatusCode)
	}
	var out struct {
		SessionID string `json:"sessionId"`
		Amount    int64  `json:"amount"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", 0, fmt.Errorf("decode session: %w", err)
	}
	if out.SessionID == "" {
		return "", 0, fmt.Errorf("seller returned no session id")
	}
	return out.SessionID, out.Amount, nil
}

type completeResult struct {
	Provider   string `json:"provider"`
	PaymentRef string `json:"paymentRef"`
	Status     string `json:"status"`
}

func completeSession(ctx context.Context, httpc *http.Client, greetID, url, callerAns string, mandate []byte) (completeResult, error) {
	body, _ := json.Marshal(map[string]any{"callerAns": callerAns, "spendMandate": mandate})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	setGreet(req, greetID)
	resp, err := httpc.Do(req)
	if err != nil {
		return completeResult{}, fmt.Errorf("complete: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if e.Error != "" {
			return completeResult{}, fmt.Errorf("%s", e.Error)
		}
		return completeResult{}, fmt.Errorf("complete: status %d", resp.StatusCode)
	}
	var out completeResult
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return completeResult{}, fmt.Errorf("decode receipt: %w", err)
	}
	return out, nil
}

func setGreet(req *http.Request, greetID string) {
	if greetID != "" {
		req.Header.Set(HeaderGreetID, greetID)
	}
}

func strParam(params map[string]any, key, def string) string {
	if params != nil {
		if v, ok := params[key].(string); ok && v != "" {
			return v
		}
	}
	return def
}
```
> Note: the local variable `authority` in `BuyPeer` shadows no import (the driver does not import the `authority` package). Keep the name or rename to `auth` if the linter objects.

- [ ] **Step 3c: Add the buy trigger to a2a**

In `internal/comms/a2a/trigger.go`, add a `BuyFunc` type, a field on `TriggerService`, a setter, and a `HandleBuy` handler. Apply these edits:

Add after the `GreetFunc` type (line 15):
```go
// BuyFunc makes this agent buy from a seller identified by name, using ACP. It
// returns the payment reference, the funding status, and any error. The greet id
// is supplied so events correlate across both agents.
type BuyFunc func(greetID, toName string) (paymentRef, status string, err error)
```
Add a `buy` field to the `TriggerService` struct:
```go
type TriggerService struct {
	self  string
	greet GreetFunc
	buy   BuyFunc
	log   zerolog.Logger
	em    events.Emitter
}
```
Add a setter and handler at the end of the file:
```go
// SetBuy installs the ACP buy handler (mounted at POST /trigger/buy).
func (t *TriggerService) SetBuy(fn BuyFunc) { t.buy = fn }

type buyReq struct {
	ToName string `json:"toName,omitempty"`
}

type buyResp struct {
	GreetID    string `json:"greetId"`
	PaymentRef string `json:"paymentRef,omitempty"`
	Status     string `json:"status,omitempty"`
	Error      string `json:"error,omitempty"`
}

// HandleBuy handles POST /trigger/buy.
func (t *TriggerService) HandleBuy(w http.ResponseWriter, r *http.Request) {
	if t.buy == nil {
		http.Error(w, "buy not enabled", http.StatusNotFound)
		return
	}
	var req buyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ToName == "" {
		http.Error(w, "toName required", http.StatusBadRequest)
		return
	}
	greetID := events.NewGreetID()
	ref, status, err := t.buy(greetID, req.ToName)
	resp := buyResp{GreetID: greetID, PaymentRef: ref, Status: status}
	if err != nil {
		resp.Error = err.Error()
		t.log.Warn().Err(err).Str("toName", req.ToName).Msg("trigger buy failed")
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
```

- [ ] **Step 3d: Add a trigger buy test**

Append to `internal/comms/a2a/trigger_test.go`:
```go
func TestHandleBuyRoutesToBuyFunc(t *testing.T) {
	trig := a2a.NewTriggerService("Ada", func(string, string, string, string) (string, bool, error) {
		return "", false, nil
	}, zerolog.Nop(), events.Nop{})
	trig.SetBuy(func(greetID, toName string) (string, string, error) {
		if toName != "shop-acp" {
			t.Fatalf("toName = %q", toName)
		}
		return "pi_fake_1", "succeeded", nil
	})
	srv := httptest.NewServer(http.HandlerFunc(trig.HandleBuy))
	defer srv.Close()
	resp, err := http.Post(srv.URL, "application/json", strings.NewReader(`{"toName":"shop-acp"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	var out struct {
		GreetID, PaymentRef, Status, Error string
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.GreetID == "" || out.PaymentRef != "pi_fake_1" || out.Status != "succeeded" || out.Error != "" {
		t.Fatalf("unexpected: %+v", out)
	}
}
```
(Match/extend the existing imports at the top of `trigger_test.go`: `encoding/json`, `net/http`, `net/http/httptest`, `strings`, `testing`, `github.com/rs/zerolog`, and the `a2a`, `events` packages.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/commerce/acp/ ./internal/comms/a2a/ -v && go build ./...`
Expected: PASS + build ok.

- [ ] **Step 5: Commit**

```bash
git add internal/commerce/acp/driver.go internal/commerce/acp/driver_test.go internal/commerce/acp/helpers_test.go internal/comms/a2a/card.go internal/comms/a2a/trigger.go internal/comms/a2a/trigger_test.go
git commit -m "feat(acp): buyer driver and POST /trigger/buy"
```

---

## Task 8: cmd/agent — ACP seller mode + buyer buy trigger

**Files:**
- Modify: `cmd/agent/main.go`

Adds a seller mode (`--acp`) and, on trigger-enabled greeters, wires the buy handler.

- [ ] **Step 1: Add flags**

In `cmd/agent/main.go` after the existing flag block (around line 48), add:
```go
	acpSeller := flag.Bool("acp", false, "run as an ACP seller (serves /acp/* instead of a greet policy)")
	acpCurrency := flag.String("acp-currency", "usd", "ACP catalog currency (when --acp)")
	payment := flag.String("payment", "stripe", "ACP funding backend: stripe | fake (when --acp)")
	stripeKeyEnv := flag.String("stripe-key-env", "STRIPE_SECRET_KEY", "env var holding the Stripe test secret key (when --acp --payment=stripe)")
```

- [ ] **Step 2: Branch into seller mode before the policy switch**

Immediately after `disco := discovery.New(*registryURL)` and `ctx := context.Background()` (around line 74), insert a seller short-circuit. When `--acp` is set the agent runs as a seller and returns from `main` via its own server/registration loop (do not fall through to the greet-policy switch). Add:

```go
	if *acpSeller {
		runACPSeller(ctx, acpSellerParams{
			name: *name, role: *role, addr: *addr, baseURL: baseURL, selfAns: selfAns,
			registryURL: *registryURL, currency: *acpCurrency, payment: *payment,
			stripeKeyEnv: *stripeKeyEnv, authorityRole: *authorityRole, authorityName: *authorityName,
			priv: priv, em: em, log: log, disco: disco,
		})
		return
	}
```

- [ ] **Step 3: Implement `runACPSeller`**

Append to `cmd/agent/main.go`:
```go
type acpSellerParams struct {
	name, role, addr, baseURL, selfAns, registryURL string
	currency, payment, stripeKeyEnv                 string
	authorityRole, authorityName                    string
	priv                                            ed25519.PrivateKey
	em                                              events.Emitter
	log                                             zerolog.Logger
	disco                                           *discovery.Client
}

// runACPSeller runs the agent as an ACP seller: it resolves and pins the authority
// that issues valid spend-mandates, builds a spend guard and a payment backend,
// serves the ACP endpoints, and registers as its role. It blocks until signalled.
func runACPSeller(ctx context.Context, p acpSellerParams) {
	authPeer, authPub := resolveAuthority(ctx, p.disco, authclient.New(), p.authorityRole, p.authorityName, p.log)
	authorityAns := domain.LocalANSName(authPeer.Name)
	guard := policy.NewSpend(p.selfAns, authorityAns, authPub, p.log)

	var pay acp.PaymentPrimitive
	switch p.payment {
	case "fake":
		pay = acp.FakePayment{}
		p.log.Info().Msg("ACP payment backend: fake (no network)")
	case "stripe":
		key := os.Getenv(p.stripeKeyEnv)
		if key == "" {
			p.log.Fatal().Str("env", p.stripeKeyEnv).Msg("ACP seller: Stripe secret key missing (fail closed)")
		}
		pay = acp.StripePaymentIntent{Client: stripe.NewClient(key)}
		p.log.Info().Msg("ACP payment backend: stripe (test mode)")
	default:
		p.log.Fatal().Str("payment", p.payment).Msg("unknown --payment (want: stripe | fake)")
	}

	seller := acp.NewSeller(acp.SellerConfig{
		SelfAns: p.selfAns, AgentName: p.name, Currency: p.currency,
		Catalog: acp.DefaultCatalog(p.currency), Guard: guard, Payment: pay,
		Events: p.em, Log: p.log,
	})

	card := a2a.Card{
		Name: p.name, Version: "0.1.0", Security: []map[string][]string{},
		Capabilities: &a2a.Capabilities{Extensions: []a2a.Extension{{
			URI:         a2a.ExtACPURI,
			Description: "buy over the Agentic Commerce Protocol; present a spend-mandate from the named authority",
			Required:    true,
			Params: map[string]any{
				"catalogPath": "/acp/catalog", "checkoutPath": "/acp/checkout_sessions",
				"authorityRole": p.authorityRole, "authorityAns": authorityAns, "currency": p.currency,
			},
		}}},
	}

	mux := http.NewServeMux()
	mux.Handle("/.well-known/agent-card.json", a2a.CardHandler(card, p.log))
	seller.Mount(mux)

	srv := &http.Server{Addr: p.addr, Handler: mux}
	go func() {
		p.log.Info().Str("addr", p.addr).Str("ans", p.selfAns).Msg("ACP seller listening")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			p.log.Fatal().Err(err).Msg("acp seller server exited")
		}
	}()

	info := domain.AgentInfo{Name: p.name, Role: p.role, BaseURL: p.baseURL, CardURL: p.baseURL + "/.well-known/agent-card.json"}
	for i := 0; i < 10; i++ {
		if err := p.disco.Register(ctx, info); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	p.log.Info().Msg("acp seller stopped")
}
```
Add imports to `cmd/agent/main.go`: `"github.com/an-ciobanu/agent-mesh/internal/commerce/acp"` and `"github.com/an-ciobanu/agent-mesh/internal/stripe"`.

- [ ] **Step 4: Wire the buy handler on trigger-enabled greeters**

In the existing `if *allowTrigger {` block, after `trig := a2a.NewTriggerService(...)` and the greet mount (around line 166-167), add a buy function and mount `/trigger/buy`:
```go
		buyFn := func(greetID, toName string) (string, string, error) {
			gctx := events.WithScope(context.Background(), em, greetID, *name, events.RoleInitiator)
			peers, serr := disco.Search(gctx, "seller")
			if serr != nil {
				return "", "", fmt.Errorf("discover sellers: %w", serr)
			}
			var peer domain.AgentInfo
			found := false
			for _, pr := range peers {
				if pr.Name == toName {
					peer, found = pr, true
					break
				}
			}
			if !found {
				return "", "", fmt.Errorf("no seller named %q", toName)
			}
			card, cerr := res.FetchCard(gctx, peer.CardURL)
			if cerr != nil {
				return "", "", fmt.Errorf("read seller card: %w", cerr)
			}
			result, berr := acp.BuyPeer(gctx, http.DefaultClient, mcpCli, disco, selfAns, peer, card)
			if berr != nil {
				return "", "", berr
			}
			return result.PaymentRef, result.Status, nil
		}
		trig.SetBuy(buyFn)
		mux.HandleFunc("POST /trigger/buy", trig.HandleBuy)
		log.Info().Msg("buy endpoint enabled (POST /trigger/buy)")
```
(`res`, `mcpCli`, `disco`, `selfAns`, `em`, `*name` are already in scope in that block. `res.FetchCard` returns `a2a.Card` — confirm the resolver signature and adapt the variable name if needed.)

- [ ] **Step 5: Build + commit**

Run: `go build ./... && go vet ./cmd/agent/`
Expected: build ok, vet clean.
```bash
git add cmd/agent/main.go
git commit -m "feat(agent): ACP seller mode and buyer /trigger/buy wiring"
```

---

## Task 9: Orchestrator wiring — roster, driver, supervisor, env

**Files:**
- Modify: `internal/orchestrator/roster.go`
- Modify: `internal/orchestrator/driver.go`
- Modify: `internal/orchestrator/supervisor.go`
- Create: `internal/orchestrator/stripeenv.go`
- Test: `internal/orchestrator/roster_test.go`, `internal/orchestrator/driver_test.go`, `internal/orchestrator/stripeenv_test.go`

- [ ] **Step 1: Write failing tests**

Append to `internal/orchestrator/roster_test.go`:
```go
func TestDefaultRosterIncludesACPSeller(t *testing.T) {
	r := orchestrator.DefaultRoster()
	var sellers int
	for _, a := range r.Agents {
		if a.Type == "acp" {
			sellers++
			if a.Color != orchestrator.ColorACP {
				t.Fatalf("seller %q color = %q, want %q", a.Name, a.Color, orchestrator.ColorACP)
			}
			if a.Policy != "acp" || a.Role != "seller" {
				t.Fatalf("seller %q policy/role = %q/%q", a.Name, a.Policy, a.Role)
			}
			if a.Authority == "" {
				t.Fatalf("seller %q has no authority", a.Name)
			}
		}
	}
	if sellers == 0 {
		t.Fatal("expected at least one ACP seller in the default roster")
	}
}
```
Create `internal/orchestrator/stripeenv_test.go`:
```go
package orchestrator_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/an-ciobanu/agent-mesh/internal/orchestrator"
)

func TestLoadStripeEnvParsesKeyValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stripe.env")
	if err := os.WriteFile(path, []byte("# comment\nSTRIPE_SECRET_KEY=sk_test_xyz\n\nOTHER=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := orchestrator.LoadStripeEnv(path)
	if env["STRIPE_SECRET_KEY"] != "sk_test_xyz" || env["OTHER"] != "1" {
		t.Fatalf("unexpected env: %+v", env)
	}
	if got := orchestrator.LoadStripeEnv(filepath.Join(dir, "missing.env")); len(got) != 0 {
		t.Fatalf("missing file should yield empty map, got %+v", got)
	}
}
```
Append to `internal/orchestrator/driver_test.go` a case asserting a seller target is routed to `/trigger/buy` (spin up an `httptest` server recording the path; construct an `AgentBook` whose `from` is a greeter and `to` is a seller — mirror the existing driver test's book setup):
```go
func TestCollideRoutesSellerToBuy(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]string{"greetId": "g1"})
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	roster := orchestrator.Roster{Agents: []orchestrator.Agent{
		{Name: "Ada", Role: "greeter-open", Policy: "open", Type: "simple", Addr: addr},
		{Name: "shop-acp", Role: "seller", Policy: "acp", Type: "acp", Addr: "127.0.0.1:1"},
	}}
	book := orchestrator.NewAgentBook(roster, 19999)
	d := orchestrator.NewDriver(book)
	if _, err := d.Collide(context.Background(), "Ada", "shop-acp"); err != nil {
		t.Fatalf("collide: %v", err)
	}
	if gotPath != "/trigger/buy" {
		t.Fatalf("path = %q, want /trigger/buy", gotPath)
	}
}
```
(Add imports `context`, `encoding/json`, `net/http`, `net/http/httptest` to the driver test if not present. Note the seller's `from` initiator is `Ada`, whose `Addr` is the test server, because `Collide` calls the *initiator's* trigger endpoint.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/orchestrator/ -run 'ACPSeller|StripeEnv|SellerToBuy' -v`
Expected: FAIL — `ColorACP` / `LoadStripeEnv` undefined; driver still posts `/trigger/greet`.

- [ ] **Step 3a: Roster**

In `internal/orchestrator/roster.go`:

Add the color constant to the `const` block:
```go
	ColorACP       = "#a774ff" // ACP seller -> purple
```
Add a `Protocol` field to `Agent` (keep it `json:"-"` since the browser uses `Type`):
```go
	Protocol  string `json:"-"` // for sellers: "acp"
```
Extend `mkAgent`'s switch with a seller case:
```go
	case "acp":
		a.Type, a.Color = "acp", ColorACP
```
Add a `mkSeller` helper after `mkMandate`:
```go
// mkSeller builds an ACP seller that trusts the named authority for spend-mandates.
func mkSeller(name, addr, authority string) Agent {
	a := mkAgent(name, "seller", "acp", addr)
	a.Protocol = "acp"
	a.Authority = authority
	return a
}
```
Add one seller to `DefaultRoster` (append inside the `[]Agent{...}` literal):
```go
		mkSeller("Shopa", "127.0.0.1:18207", "authority-1"),
```
> `Greeters()` already excludes only `Policy == "authority"`, so the seller is (correctly) included in the collidable set and spawned by the greeter loop; the supervisor branches on policy to build seller args (Step 3c).

- [ ] **Step 3b: Driver**

In `internal/orchestrator/driver.go`, replace the body of `Collide` that builds and posts the greet request with protocol-aware routing. After the `if toAgent.Policy == "authority"` guard, add:
```go
	if fromAgent.Policy == "authority" || fromAgent.Type == "acp" {
		return "", fmt.Errorf("%q cannot initiate", from)
	}
	if toAgent.Type == "acp" {
		return d.post(ctx, fromAgent.BaseURL()+"/trigger/buy", map[string]string{"toName": toAgent.Name})
	}
	return d.post(ctx, fromAgent.BaseURL()+"/trigger/greet",
		map[string]string{"toRole": toAgent.Role, "toName": toAgent.Name, "text": "hi " + toAgent.Name})
```
Add a `post` helper (replaces the inline request/response handling; both trigger endpoints return `{greetId,error}`):
```go
func (d *Driver) post(ctx context.Context, url string, payload map[string]string) (string, error) {
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("trigger: %w", err)
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
Remove the now-dead inline body of the old `Collide` (the `body, _ := json.Marshal(...)` down to the final `return out.GreetID, nil`) so only the routing + `post` remain. Keep the `bytes`, `encoding/json`, `net/http` imports.

- [ ] **Step 3c: Supervisor — seller args + env injection**

In `internal/orchestrator/supervisor.go`:

Add a `stripeEnv map[string]string` field to `Supervisor` and a setter, or pass it via `NewSupervisor`. Minimal approach — add a field and a setter:
```go
// (add to the Supervisor struct)
	stripeEnv []string // extra "K=V" env entries passed to seller processes
```
Add a setter:
```go
// WithChildEnv sets extra environment entries ("K=V") passed to spawned agents.
func (s *Supervisor) WithChildEnv(env []string) { s.stripeEnv = env }
```
Teach `greeterArgs` to build seller args when the agent is a seller:
```go
	if a.Policy == "acp" {
		return []string{
			"--name", a.Name, "--role", a.Role, "--addr", a.Addr,
			"--registry", regURL, "--acp", "--payment", "stripe",
			"--authority-role", "authority", "--authority-name", a.Authority,
			"--events",
		}
	}
```
(Place this branch at the top of `greeterArgs`, before the existing greeter args are assembled.)

Pass the env to seller child processes. In `spawn`, after `cmd := exec.CommandContext(...)`, add:
```go
	if len(s.stripeEnv) > 0 {
		cmd.Env = append(os.Environ(), s.stripeEnv...)
	}
```
Add `"os"` to the supervisor imports.
> Sellers do not need `--allow-trigger` or `--transparency`: they are ACP responders, not greet initiators, and P8 does not seal purchases (see spec §1 out-of-scope). Buyers keep their existing `--allow-trigger` and gain `/trigger/buy` from Task 8.

- [ ] **Step 3d: Env loader**

Create `internal/orchestrator/stripeenv.go`:
```go
package orchestrator

import (
	"bufio"
	"os"
	"strings"
)

// LoadStripeEnv reads KEY=VALUE lines from path (blank lines and #comments
// ignored) into a map. A missing or unreadable file yields an empty map — the
// seller then fails closed at startup when the Stripe key is absent.
func LoadStripeEnv(path string) map[string]string {
	out := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}
```

- [ ] **Step 3e: Wire env into the orchestrator command**

In `cmd/orchestrator/main.go`, after building `sup` and before `sup.Start(ctx)`, load and inject the env. Add a flag near the others:
```go
	stripeEnvPath := flag.String("stripe-env", "data/stripe.env", "path to KEY=VALUE file with STRIPE_SECRET_KEY for ACP sellers")
```
And after `sup := orchestrator.NewSupervisor(...)`:
```go
	if env := orchestrator.LoadStripeEnv(*stripeEnvPath); len(env) > 0 {
		var kv []string
		for k, v := range env {
			kv = append(kv, k+"="+v)
		}
		sup.WithChildEnv(kv)
		log.Info().Str("path", *stripeEnvPath).Msg("loaded Stripe env for ACP sellers")
	} else {
		log.Warn().Str("path", *stripeEnvPath).Msg("no Stripe env found; ACP sellers will fail to start (add data/stripe.env)")
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/orchestrator/ -v && go build ./...`
Expected: PASS + build ok.

- [ ] **Step 5: Commit**

```bash
git add internal/orchestrator/roster.go internal/orchestrator/roster_test.go internal/orchestrator/driver.go internal/orchestrator/driver_test.go internal/orchestrator/supervisor.go internal/orchestrator/stripeenv.go internal/orchestrator/stripeenv_test.go cmd/orchestrator/main.go
git commit -m "feat(orchestrator): ACP seller in roster, buy routing, Stripe env injection"
```

---

## Task 10: UI — ACP seller colour, steps, collision routing

**Files:**
- Modify: `web/index.html`

The UI is verified with headless Chrome (unit tests are not practical for the canvas). Make these edits, then verify visually.

- [ ] **Step 1: Colours + labels**

In the `:root` CSS block (lines 10-13) add:
```css
    --acp: #a774ff;      /* acp seller    = purple */
```
Update the `COL` and `LABEL` maps (lines 173-174):
```js
const COL = { simple:'#f4523b', nonce:'#f2c94c', token:'#4aa3ff', authority:'#8b93a7', acp:'#a774ff' };
const LABEL = { simple:'simple', nonce:'nonce', token:'token', authority:'authority', acp:'acp seller' };
```
Update `POLICY2TYPE` (line 177) to map the seller policy/role to the `acp` UI type:
```js
const POLICY2TYPE = { open:'simple', mandate:'token', nonce:'nonce', authority:'authority', simple:'simple', token:'token', acp:'acp', seller:'acp' };
```

- [ ] **Step 2: STEP ledger entries**

Add these entries to the `STEP` map (inside the object literal around lines 289-308), so the purchase flow renders with plain-English titles:
```js
  'catalog.fetch':     {title:'fetch catalog · GET /acp/catalog',   explain:'buyer reads the seller\'s items and prices — discovered, not hardcoded',   kind:'msg'},
  'item.select':       {title:'select item',                        explain:'buyer picks the cheapest item to purchase',                               kind:'note'},
  'spend.acquire':     {title:'acquire spend-mandate · MCP issue_spend_mandate', explain:'buyer obtains an authority-signed mandate for THIS item and price',    kind:'msg'},
  'checkout.create':   {title:'create checkout · POST /acp/checkout_sessions',   explain:'buyer opens a checkout session for the chosen item',                  kind:'msg'},
  'checkout.complete': {title:'complete checkout · POST …/complete', explain:'buyer submits the spend-mandate to pay',                                   kind:'msg'},
  'session.create':    {title:'open checkout session',              explain:'seller prices the session and awaits payment',                            kind:'chk'},
  'spend.verify':      {title:'verify spend-mandate',               explain:'seller checks the mandate signature (self-verifying COSE)',                kind:'chk'},
  'charge':            {title:'charge · Stripe PaymentIntent',      explain:'seller settles a real test-mode charge for the item price',               kind:'msg'},
  'receipt':           {title:'receipt',                            explain:'payment succeeded — the transaction is complete',                         kind:'msg'},
  'purchase.rejected': {title:'purchase rejected',                  explain:'seller refused to charge — fail closed',                                  kind:'msg'},
```

- [ ] **Step 3: Ledger peer resolution**

In `modelFromEvents` (lines 310-324), extend the `msg`-kind peer logic so the new steps point at the right peer. Replace the peer block:
```js
    if (meta.kind === 'msg') {
      if (e.step === 'mandate.acquire' || e.step === 'spend.acquire') peer = (e.detail && e.detail.authority) || 'authority';
      else if (e.step === 'charge') peer = 'Stripe';
      else peer = (actor === it.from) ? it.to : it.from;
    }
```

- [ ] **Step 4: Collision routing (buyer initiates, seller/authority never do)**

Replace the collision-initiation block inside `step()` (lines 419-422) with logic that lets a plain greeter buy from a seller and prevents sellers/authorities from initiating:
```js
        if (!cooldown.get(k) || t-cooldown.get(k) > 2500){ cooldown.set(k,t);
          const canInit = x => x.type==='simple' || x.type==='nonce' || x.type==='token';
          let ini=-1, tgt=-1;
          if (canInit(agents[i])) { ini=i; tgt=j; }
          else if (canInit(agents[j])) { ini=j; tgt=i; }
          // a greeter target is fine (greet); a seller target is fine (buy);
          // authorities are never a target.
          if (ini>=0 && agents[tgt].type!=='authority'){
            agents[ini].flash=1; agents[tgt].flash=1; collide(agents[ini].name, agents[tgt].name);
          }
        }
```

- [ ] **Step 5: Verdict on receipt (log rows)**

The SSE assembly in `startEvents` sets `verdict` from `greet.reply`/`greet.rejected`. Add purchase equivalents so buy rows show accepted/rejected. After line 222 (`if (e.step === 'greet.rejected')...`) add:
```js
    if (e.step === 'receipt')          it.verdict = 'accepted';
    if (e.step === 'purchase.rejected'){ it.verdict = 'rejected'; it.reason = (e.detail && e.detail.error) || it.reason; }
```
Mirror this in the server-side hub (Step 6).

- [ ] **Step 6: Hub verdict/type (server)**

In `internal/orchestrator/hub.go` `Ingest`, extend the `switch e.Step` (lines 57-73) with:
```go
	case "receipt":
		it.Verdict = "accepted"
	case "purchase.rejected":
		it.Verdict = "rejected"
		if r := e.Detail["error"]; r != "" {
			it.Reason = r
		}
```
(`requirement` already sets `it.Type` from `detail.type`, so the buyer's `requirement{type:"acp"}` tags the interaction correctly.)

- [ ] **Step 7: Verify with headless Chrome**

Build and run the demo (this needs `data/stripe.env` with a real `sk_test_…`, or run a seller with `--payment fake` for a pure-UI check — see the run script note in Task 11). With the mesh running on `http://127.0.0.1:18080`:
```bash
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new \
  --screenshot=/tmp/p8-ui.png --window-size=1400,900 --virtual-time-budget=8000 \
  http://127.0.0.1:18080
```
Confirm: a purple `acp seller` circle is present; a greeter→seller collision produces an `acp` interaction row; opening it shows the ledger (catalog.fetch → item.select → spend.acquire → session.create → spend.verify → authority.pin → charge → receipt) with real JSON. (Inject `#drawer{transition:none!important}` if capturing the drawer mid-animation, as in P5.)

- [ ] **Step 8: Commit**

```bash
git add web/index.html internal/orchestrator/hub.go
git commit -m "feat(ui): render ACP purchases — purple seller, purchase ledger, buy routing"
```

---

## Task 11: Integration test — end-to-end ACP purchase

**Files:**
- Create: `internal/integration/p8_test.go`
- Modify: `scripts/demo/p5-ui.sh` (or create `scripts/demo/p8-ui.sh`) — optional runner note

Uses the supervisor to spawn a real mesh with the seller running `--payment fake` (no network), then drives a buy via the driver and asserts a completed purchase. This mirrors `p5_test.go`/`p6_test.go` (short-guarded, real processes).

- [ ] **Step 1: Write the failing test**

Create `internal/integration/p8_test.go`:
```go
package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/orchestrator"
)

// TestP8_ACPPurchaseEndToEnd spawns a real mesh with an ACP seller (fake payment),
// collides a greeter into it, and asserts the interaction completes with a receipt.
func TestP8_ACPPurchaseEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: spawns real processes")
	}
	// Build binaries into a temp bin dir (reuse the helper the other p*_test.go use;
	// if a shared buildMesh(t) helper exists, call it — otherwise replicate its
	// `go build` of ./cmd/{registry,transparency,authority,agent} into t.TempDir()).
	binDir := buildMeshBinaries(t) // see note below

	roster := orchestrator.Roster{Agents: []orchestrator.Agent{
		mkAuthority("authority-1", "127.0.0.1:19410"),
		mkOpen("Ada", "127.0.0.1:19420"),
		mkACPSeller("Shopa", "127.0.0.1:19421", "authority-1"),
	}}

	log := zerolog.Nop()
	hub := orchestrator.NewHub(log)
	sup := orchestrator.NewSupervisor(binDir, "127.0.0.1:19490", "127.0.0.1:19491", roster, hub, log)
	sup.WithChildEnv([]string{"PAYMENT_FAKE=1"}) // not required; seller args set --payment fake (see note)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("start mesh: %v", err)
	}
	defer sup.Stop()

	book := orchestrator.NewAgentBook(roster, 19500)
	driver := orchestrator.NewDriver(book)
	greetID, err := driver.Collide(ctx, "Ada", "Shopa")
	if err != nil {
		t.Fatalf("collide: %v", err)
	}

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		it, ok := hub.Interaction(greetID)
		if ok && it.Verdict == "accepted" {
			return // success
		}
		time.Sleep(150 * time.Millisecond)
	}
	it, _ := hub.Interaction(greetID)
	t.Fatalf("purchase did not complete; verdict=%q reason=%q events=%d", it.Verdict, it.Reason, len(it.Events))
}
```
> **Notes for the implementer:**
> - Reuse the existing integration harness. Read `internal/integration/p6_test.go` first: use its exact `buildMesh`/binary-build helper and its `mk*` roster helpers (or add `mkACPSeller` mirroring `mkMandate`). Do **not** invent a second build helper if one exists — call it.
> - The seller must run with `--payment fake` so the test needs no network/Stripe key. This is already produced by the supervisor's seller-args branch **only if** you make the payment backend configurable for tests. Two clean options — pick one and implement it in Task 9 Step 3c if not already:
>   1. Have `greeterArgs` emit `--payment fake` when an env override (e.g. `AGENT_MESH_TEST_PAYMENT=fake`) is set, or
>   2. Add a `Supervisor` field `SellerPayment string` (default `"stripe"`) and a `WithSellerPayment("fake")` setter used by the test.
>   The `WithSellerPayment` setter is the least magical — prefer it, and have `greeterArgs` use `s.sellerPayment` (defaulting to `"stripe"`). Update Task 9 accordingly and set it in this test via `sup.WithSellerPayment("fake")`. Remove the `PAYMENT_FAKE`/`WithChildEnv` line above once done.
> - `mkACPSeller` for the test roster: `orchestrator.Agent{Name:"Shopa", Role:"seller", Policy:"acp", Type:"acp", Color:orchestrator.ColorACP, Addr:addr, Protocol:"acp", Authority:"authority-1"}`.

- [ ] **Step 2: Adjust Task 9 supervisor for a test payment override**

Implement `WithSellerPayment` on `Supervisor` (default `"stripe"`), and in the seller branch of `greeterArgs` use `s.sellerPayment` instead of the hardcoded `"stripe"`:
```go
// (field) sellerPayment string
// (setter)
func (s *Supervisor) WithSellerPayment(mode string) { s.sellerPayment = mode }
// (in greeterArgs seller branch)
payment := s.sellerPayment
if payment == "" {
	payment = "stripe"
}
// ... "--payment", payment, ...
```

- [ ] **Step 3: Run the test to verify it passes**

Run: `go test ./internal/integration/ -run TestP8_ACP -v`
Expected: PASS (spawns real processes; not run under `-short`).
Also run the whole suite: `go test ./... && go test ./... -short`.
Expected: all PASS.

- [ ] **Step 4: Runner note (optional)**

Add `scripts/demo/p8-ui.sh` mirroring `scripts/demo/p5-ui.sh` but reminding the operator to create `data/stripe.env` with `STRIPE_SECRET_KEY=sk_test_…`. Keep it a thin wrapper: `make build` + `go build -o bin/orchestrator ./cmd/orchestrator` + run + open the browser.

- [ ] **Step 5: Commit**

```bash
git add internal/integration/p8_test.go internal/orchestrator/supervisor.go scripts/demo/p8-ui.sh
git commit -m "test(integration): end-to-end ACP purchase; supervisor test payment override"
```

---

## Self-Review

**1. Spec coverage**

| Spec section | Task(s) |
| --- | --- |
| §4.1 SpendMandateClaims | Task 1 |
| §4.2 reuse COSE | Tasks 2, 3 (SignCOSE1/VerifyCOSE1) |
| §4.3 authority issue_spend_mandate | Task 2 |
| §4.4 internal/stripe client | Task 4 |
| §4.5 PaymentPrimitive seam | Task 5 |
| §4.6 spend guard (fail closed) | Task 3 |
| §4.7 ACP seller HTTP surface | Tasks 6, 8 |
| §4.8 buyer ACP driver + dispatch | Tasks 7, 8 |
| §4.9 orchestrator wiring | Task 9 |
| §4.10 UI | Task 10 |
| §5 card ACP capability | Tasks 7 (const), 8 (card build) |
| §6 data flow | Tasks 6–8 end-to-end; Task 11 verifies |
| §7 testing (unit + short-guarded integration + opt-in real Stripe) | every task's tests; Task 11 integration; Task 4 real-Stripe is opt-in via `NewClient` + a live key (documented, not a CI test) |
| §8 risks (SPT gated, MCP read-only, secret handling, idempotency) | Task 4 idempotency; Task 9 env; conventions header |
| §9 defaults (purple, cheapest pick, mandate+charge, create+complete, reuse authority) | Tasks 5,6,9,10 |

**Deviation from spec (intentional, noted):** §4.7 mentions sealing the completed purchase to the transparency log. This plan **defers sealing** to keep P8 focused (it is listed in spec §1 as the audit capstone but is not core to the ACP/mandate/charge story). If desired, add a follow-up task: seller signs a `purchase.completed` COSE statement and seals via `transparency.New(url).Seal`, emitting a `seal` event (the UI `STEP['seal']` entry already exists). Flag this to the user at execution time.

**2. Placeholder scan:** No `TODO`/`TBD`. The one illustrative stub (`scope`/`contextT` in Task 6) is explicitly called out to be deleted with the reason given; the real handler code is complete. `buildMeshBinaries`/`mk*` in Task 11 explicitly defer to the existing `p6_test.go` harness rather than inventing new helpers.

**3. Type consistency:** `SpendMandateClaims`, `PurchaseRequest`, `ScopePurchase` (Task 1) are used identically in Tasks 2/3/6. `policy.NewSpend`/`Spend.Verify` (Task 3) match usage in Tasks 6/8. `acp.PaymentPrimitive`/`ChargeRequest`/`ChargeResult`/`FakePayment`/`StripePaymentIntent` (Task 5) match Tasks 6/8. `acp.NewSeller`/`SellerConfig`/`Seller.Mount`/`HeaderGreetID` (Task 6) match Tasks 8/driver tests. `acp.BuyPeer`/`BuyResult` (Task 7) match Task 8. `a2a.ExtACPURI` (Task 7) match Task 8. `a2a.BuyFunc`/`TriggerService.SetBuy`/`HandleBuy` (Task 7) match Task 8. `orchestrator.ColorACP`/`Agent.Protocol`/`mkSeller`/`LoadStripeEnv`/`Supervisor.WithChildEnv`/`WithSellerPayment` (Task 9) match Tasks 10/11. `stripe.NewClient`/`NewClientWithBase`/`CreatePaymentIntent`/`PaymentIntentRequest`/`PaymentIntent` (Task 4) match Task 5.
