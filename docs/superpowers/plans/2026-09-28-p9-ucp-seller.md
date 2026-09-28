# P9 — UCP Seller Agent + Buyer Commerce Driver Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the Universal Commerce Protocol (UCP) as a second commerce protocol so a greet agent, colliding with a UCP seller, automatically speaks UCP (not ACP) — discovering it from the card, verifying the seller's signed checkout terms, obtaining two AP2 mandates, tokenizing through the seller's handler, and completing with a real Stripe test-mode charge.

**Architecture:** Mirror P8's seller/driver/seam split but model UCP's distinct shape: `/.well-known/ucp` discovery + a `/tokenize` handler, bidirectional cryptographic proof (seller signs terms; buyer presents CheckoutMandate + PaymentMandate), and create→update→complete. The buyer's `/trigger/buy` dispatches ACP vs UCP by reading the card. The payment seam + catalog types are first promoted to a shared `internal/commerce` package that both protocols reuse.

**Tech Stack:** Go, `net/http`, existing `internal/{crypto (COSE Ed25519 + JWK), events, policy, authority, comms/*, orchestrator, stripe}`, vanilla-JS `web/index.html`.

**Spec:** `docs/superpowers/specs/2026-09-28-p9-ucp-seller-design.md`
**Module path:** `github.com/an-ciobanu/agent-mesh`

---

## Conventions for every task

- **TDD:** failing test → watch it fail → implement → watch it pass → commit.
- **Gate before each commit:** `go build ./...` + `go test ./...` (and `make check` where practical). The refactor task (Task 1) MUST leave the entire suite green, including the ACP integration test.
- **Commits:** no `Co-Authored-By`/AI trailer; NO `git commit -s`. Plain `git commit -m`. Conventional-commit style.
- **Fail closed:** every verify path returns an error on any failure.
- **Secrets:** unchanged from P8 — `STRIPE_SECRET_KEY` only via `data/stripe.env`; never logged.
- **Identity note (scope):** as in P8, UCP HTTP calls do not carry the greet `X-ANS-Request-JWS` header; `callerAns` is self-asserted and the mandates bind `subjectAns` to it. The new element is the *seller* signing its terms (verified by the buyer).

**Key existing APIs to reuse (verified against the codebase):**
- `crypto.SignCOSE1(priv, payload) ([]byte, error)`, `crypto.VerifyCOSE1(data) (payload []byte, signer ed25519.PublicKey, err error)`
- `crypto.JWK`, `crypto.PublicJWK(pub) JWK`, `crypto.PublicKeyFromJWK(j JWK) (ed25519.PublicKey, error)`
- `events.WithScope(ctx, em, greetID, agent, role)`, `events.Emit(ctx, step, status, detail)`, `events.NewGreetID()`, `events.RoleResponder/RoleInitiator`, `events.StatusOK/Fail/Info`, `events.Nop{}`
- `mcp.Client.Call(ctx, endpoint, tool, args) (json.RawMessage, error)`, `mcp.Server.Register(name, ToolFunc)`, `mcp.ToolFunc = func(context.Context, json.RawMessage)(json.RawMessage,error)`
- `domain.Discovery.Search(ctx, role)`, `domain.LocalANSName(name)`, `domain.AgentInfo{Name,Role,BaseURL,CardURL}`
- `a2a.Card`, `a2a.Capabilities`, `a2a.Extension{URI,Description,Required,Params}`, `a2a.CardHandler(card, log)`, `a2a.ExtACPURI`
- `resolveAuthority(ctx, disco, authclient.New(), role, name, log) (domain.AgentInfo, ed25519.PublicKey)` (in `cmd/agent/main.go`)

---

## Task 1: Extract shared `internal/commerce` package (refactor)

Move the payment seam + catalog types out of `internal/commerce/acp` into a new shared `internal/commerce` package so UCP can reuse them without depending on `acp`.

**Files:**
- Create: `internal/commerce/payment.go`, `internal/commerce/catalog.go`, `internal/commerce/commerce.go`
- Create tests: `internal/commerce/payment_test.go`, `internal/commerce/catalog_test.go`
- Delete: `internal/commerce/acp/payment.go`, `internal/commerce/acp/catalog.go`, `internal/commerce/acp/payment_test.go`, `internal/commerce/acp/catalog_test.go`
- Modify: `internal/commerce/acp/seller.go`, `internal/commerce/acp/driver.go`, `internal/commerce/acp/seller_test.go`, `internal/commerce/acp/driver_test.go`, `internal/commerce/acp/helpers_test.go`, `cmd/agent/main.go`

- [ ] **Step 1: Create the shared package files**

`internal/commerce/payment.go`:
```go
// Package commerce holds the protocol-agnostic commerce primitives shared by the
// ACP and UCP sellers/drivers: the payment seam, the catalog types, and small
// shared constants. Protocol-specific logic lives in the acp/ and ucp/ subpackages.
package commerce

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
		Description:    "agent-mesh purchase: " + r.ItemID,
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

`internal/commerce/catalog.go`:
```go
package commerce

// Item is one thing a seller sells.
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

`internal/commerce/commerce.go`:
```go
package commerce

// HeaderGreetID correlates a buyer's commerce calls with the seller's emitted
// events. It mirrors a2a.HeaderGreetID; duplicated here to avoid importing the a2a
// package into the commerce layer.
const HeaderGreetID = "X-ANS-Greet-Id"

// BuyResult is what a completed purchase returns to the caller, for any protocol.
type BuyResult struct {
	PaymentRef string
	Status     string
	ItemID     string
}
```

- [ ] **Step 2: Move the tests**

Create `internal/commerce/payment_test.go` and `internal/commerce/catalog_test.go` by copying the bodies of the current `internal/commerce/acp/payment_test.go` and `internal/commerce/acp/catalog_test.go`, changing `package acp_test` → `package commerce_test`, the import `.../internal/commerce/acp` → `.../internal/commerce`, and every `acp.` → `commerce.`. Then delete the four ACP files:
```bash
git rm internal/commerce/acp/payment.go internal/commerce/acp/catalog.go internal/commerce/acp/payment_test.go internal/commerce/acp/catalog_test.go
```

- [ ] **Step 3: Re-point the `acp` package**

In `internal/commerce/acp/seller.go`:
- Add import `"github.com/an-ciobanu/agent-mesh/internal/commerce"`.
- Delete the local `const HeaderGreetID = ...` (now `commerce.HeaderGreetID`).
- `SellerConfig.Catalog` → `[]commerce.Item`; `SellerConfig.Payment` → `commerce.PaymentPrimitive`.
- Replace `Item` → `commerce.Item`, `ChargeRequest` → `commerce.ChargeRequest`, and `HeaderGreetID` → `commerce.HeaderGreetID` throughout.

In `internal/commerce/acp/driver.go`:
- Add import `"github.com/an-ciobanu/agent-mesh/internal/commerce"`.
- Delete the local `BuyResult` type; the function returns `commerce.BuyResult`.
- Replace `Item` → `commerce.Item`, `LowestPriced` → `commerce.LowestPriced`, `HeaderGreetID` → `commerce.HeaderGreetID`, and `BuyResult{...}` → `commerce.BuyResult{...}`.

In `internal/commerce/acp/{seller_test.go,driver_test.go,helpers_test.go}`: replace `acp.Item`→`commerce.Item`, `acp.DefaultCatalog`→`commerce.DefaultCatalog`, `acp.FakePayment`→`commerce.FakePayment`, `acp.BuyResult`→`commerce.BuyResult`, `acp.HeaderGreetID`→`commerce.HeaderGreetID`, and `acp.LowestPriced`→`commerce.LowestPriced` wherever they appear; add the `commerce` import.

In `cmd/agent/main.go` `runACPSeller`: add the `commerce` import and replace `acp.PaymentPrimitive`→`commerce.PaymentPrimitive`, `acp.FakePayment`→`commerce.FakePayment`, `acp.StripePaymentIntent`→`commerce.StripePaymentIntent`, `acp.DefaultCatalog`→`commerce.DefaultCatalog`.

- [ ] **Step 4: Build, run the FULL suite, verify green**

Run: `go build ./... && go test ./...`
Expected: all PASS, including `internal/commerce` (new), `internal/commerce/acp`, and `internal/integration` (the ACP p8 test). Fix any missed reference the compiler flags.

- [ ] **Step 5: Commit**
```bash
git add -A internal/commerce cmd/agent/main.go
git commit -m "refactor(commerce): extract shared payment seam + catalog into internal/commerce"
```

---

## Task 2: Domain — AP2 mandate claims + UCP completion input

**Files:** Modify `internal/domain/commerce.go`; Test `internal/domain/commerce_test.go`.

- [ ] **Step 1: Write the failing test** (append to `internal/domain/commerce_test.go`)
```go
func TestAP2ClaimsAndScopes(t *testing.T) {
	if ScopeCheckout != "checkout" || ScopePayment != "payment" {
		t.Fatalf("scopes wrong: %q %q", ScopeCheckout, ScopePayment)
	}
	c := CheckoutMandateClaims{MandateID: "c1", SubjectAns: "s", AudienceAns: "a", CheckoutID: "cs_1", ItemID: "mug", Amount: 1200, Currency: "usd", Scope: ScopeCheckout, NotBefore: "n", NotAfter: "x", AuthorityAns: "auth"}
	var c2 CheckoutMandateClaims
	b, _ := json.Marshal(c)
	if err := json.Unmarshal(b, &c2); err != nil || c2 != c {
		t.Fatalf("checkout claims round trip: %v %+v", err, c2)
	}
	p := PaymentMandateClaims{MandateID: "p1", SubjectAns: "s", AudienceAns: "a", Amount: 1200, Currency: "usd", Scope: ScopePayment, NotBefore: "n", NotAfter: "x", AuthorityAns: "auth"}
	var p2 PaymentMandateClaims
	pb, _ := json.Marshal(p)
	if err := json.Unmarshal(pb, &p2); err != nil || p2 != p {
		t.Fatalf("payment claims round trip: %v %+v", err, p2)
	}
	comp := UCPCompletion{CallerAns: "s", CheckoutID: "cs_1", ItemID: "mug", Amount: 1200, Currency: "usd", CheckoutMandate: []byte{1}, PaymentMandate: []byte{2}}
	if comp.Amount != 1200 || len(comp.CheckoutMandate) != 1 || len(comp.PaymentMandate) != 1 {
		t.Fatalf("bad completion: %+v", comp)
	}
}
```
(`encoding/json` is already imported in `commerce_test.go`.)

- [ ] **Step 2: Run it — FAIL** (`go test ./internal/domain/ -run AP2 -v`) — undefined symbols.

- [ ] **Step 3: Append to `internal/domain/commerce.go`**
```go
// ScopeCheckout / ScopePayment are the two AP2 mandate scopes UCP uses: a
// CheckoutMandate authorizes a specific cart/checkout state; a PaymentMandate
// authorizes the payment for it.
const (
	ScopeCheckout = "checkout"
	ScopePayment  = "payment"
)

// CheckoutMandateClaims is the JSON payload of a signed AP2 CheckoutMandate: the
// user (SubjectAns) authorizes buying ItemID from AudienceAns in a specific
// checkout (CheckoutID) for at most Amount in Currency, attested by AuthorityAns.
type CheckoutMandateClaims struct {
	MandateID    string `json:"mandateId"`
	SubjectAns   string `json:"subjectAns"`
	AudienceAns  string `json:"audienceAns"`
	CheckoutID   string `json:"checkoutId"`
	ItemID       string `json:"itemId"`
	Amount       int64  `json:"amount"`
	Currency     string `json:"currency"`
	Scope        string `json:"scope"`
	NotBefore    string `json:"notBefore"`
	NotAfter     string `json:"notAfter"`
	AuthorityAns string `json:"authorityAns"`
}

// PaymentMandateClaims is the JSON payload of a signed AP2 PaymentMandate: the
// user authorizes paying at most Amount in Currency to AudienceAns.
type PaymentMandateClaims struct {
	MandateID    string `json:"mandateId"`
	SubjectAns   string `json:"subjectAns"`
	AudienceAns  string `json:"audienceAns"`
	Amount       int64  `json:"amount"`
	Currency     string `json:"currency"`
	Scope        string `json:"scope"`
	NotBefore    string `json:"notBefore"`
	NotAfter     string `json:"notAfter"`
	AuthorityAns string `json:"authorityAns"`
}

// UCPCompletion is the server-authoritative content the UCP guard verifies: the
// caller, the session's checkout/item/amount/currency, and the two presented AP2
// mandates (COSE_Sign1 over the claim types above).
type UCPCompletion struct {
	CallerAns       string
	CheckoutID      string
	ItemID          string
	Amount          int64
	Currency        string
	CheckoutMandate []byte
	PaymentMandate  []byte
}
```

- [ ] **Step 4: Run it — PASS** (`go test ./internal/domain/ -run AP2 -v`).
- [ ] **Step 5: Commit**
```bash
git add internal/domain/commerce.go internal/domain/commerce_test.go
git commit -m "feat(domain): AP2 checkout/payment mandate claims and UCP completion"
```

---

## Task 3: Authority — checkout + payment mandate tools

**Files:** Modify `internal/authority/authority.go`, `cmd/authority/main.go`; Test `internal/authority/authority_test.go`.

- [ ] **Step 1: Append tests** (`internal/authority/authority_test.go`)
```go
func TestIssueCheckoutAndPaymentMandates(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	ans := domain.LocalANSName("authority-1")
	a := authority.New(ans, priv, time.Hour, zerolog.Nop())

	cm, err := a.IssueCheckoutMandate(domain.LocalANSName("Ada"), domain.LocalANSName("shop-ucp"), "cs_9", "mug", 1200, "usd")
	if err != nil {
		t.Fatalf("checkout mandate: %v", err)
	}
	cp, _, err := crypto.VerifyCOSE1(cm)
	if err != nil {
		t.Fatalf("verify checkout: %v", err)
	}
	var cc domain.CheckoutMandateClaims
	_ = json.Unmarshal(cp, &cc)
	if cc.Scope != domain.ScopeCheckout || cc.CheckoutID != "cs_9" || cc.ItemID != "mug" || cc.Amount != 1200 || cc.AuthorityAns != ans {
		t.Fatalf("bad checkout claims: %+v", cc)
	}

	pm, err := a.IssuePaymentMandate(domain.LocalANSName("Ada"), domain.LocalANSName("shop-ucp"), 1200, "usd")
	if err != nil {
		t.Fatalf("payment mandate: %v", err)
	}
	pp, _, _ := crypto.VerifyCOSE1(pm)
	var pc domain.PaymentMandateClaims
	_ = json.Unmarshal(pp, &pc)
	if pc.Scope != domain.ScopePayment || pc.Amount != 1200 || pc.AuthorityAns != ans {
		t.Fatalf("bad payment claims: %+v", pc)
	}
}

func TestUCPMandateMCPTools(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	a := authority.New(domain.LocalANSName("authority-1"), priv, time.Hour, zerolog.Nop())
	cArgs, _ := json.Marshal(map[string]any{"subjectAns": "s", "audienceAns": "a", "checkoutId": "cs_1", "itemId": "mug", "amount": 1200, "currency": "usd"})
	if out, err := a.CheckoutMandateMCPTool()(context.Background(), cArgs); err != nil || len(out) == 0 {
		t.Fatalf("checkout tool: %v", err)
	}
	pArgs, _ := json.Marshal(map[string]any{"subjectAns": "s", "audienceAns": "a", "amount": 1200, "currency": "usd"})
	if out, err := a.PaymentMandateMCPTool()(context.Background(), pArgs); err != nil || len(out) == 0 {
		t.Fatalf("payment tool: %v", err)
	}
}
```

- [ ] **Step 2: Run — FAIL** (`go test ./internal/authority/ -run 'CheckoutAndPayment|UCPMandateMCP' -v`).

- [ ] **Step 3: Append to `internal/authority/authority.go`** (reuses `SignCOSE1`, `randHex`, `issueResult`, `a.ttl`, imports already present)
```go
// IssueCheckoutMandate signs an AP2 CheckoutMandate authorizing subject to buy
// itemID from audience in checkoutID for at most amount in currency.
func (a *Authority) IssueCheckoutMandate(subjectAns, audienceAns, checkoutID, itemID string, amount int64, currency string) ([]byte, error) {
	if subjectAns == "" || audienceAns == "" || checkoutID == "" || itemID == "" || currency == "" {
		return nil, fmt.Errorf("subjectAns, audienceAns, checkoutID, itemID and currency are required")
	}
	if amount <= 0 {
		return nil, fmt.Errorf("amount must be > 0")
	}
	now := time.Now().UTC()
	claims := domain.CheckoutMandateClaims{
		MandateID: "checkout-" + randHex(8), SubjectAns: subjectAns, AudienceAns: audienceAns,
		CheckoutID: checkoutID, ItemID: itemID, Amount: amount, Currency: currency,
		Scope: domain.ScopeCheckout, NotBefore: now.Format(time.RFC3339), NotAfter: now.Add(a.ttl).Format(time.RFC3339),
		AuthorityAns: a.ans,
	}
	b, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("marshal checkout claims: %w", err)
	}
	cose, err := crypto.SignCOSE1(a.priv, b)
	if err != nil {
		return nil, fmt.Errorf("sign checkout mandate: %w", err)
	}
	a.log.Info().Str("mandateId", claims.MandateID).Str("checkoutId", checkoutID).Str("itemId", itemID).Int64("amount", amount).Msg("checkout mandate issued")
	return cose, nil
}

// IssuePaymentMandate signs an AP2 PaymentMandate authorizing subject to pay at
// most amount in currency to audience.
func (a *Authority) IssuePaymentMandate(subjectAns, audienceAns string, amount int64, currency string) ([]byte, error) {
	if subjectAns == "" || audienceAns == "" || currency == "" {
		return nil, fmt.Errorf("subjectAns, audienceAns and currency are required")
	}
	if amount <= 0 {
		return nil, fmt.Errorf("amount must be > 0")
	}
	now := time.Now().UTC()
	claims := domain.PaymentMandateClaims{
		MandateID: "payment-" + randHex(8), SubjectAns: subjectAns, AudienceAns: audienceAns,
		Amount: amount, Currency: currency, Scope: domain.ScopePayment,
		NotBefore: now.Format(time.RFC3339), NotAfter: now.Add(a.ttl).Format(time.RFC3339), AuthorityAns: a.ans,
	}
	b, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("marshal payment claims: %w", err)
	}
	cose, err := crypto.SignCOSE1(a.priv, b)
	if err != nil {
		return nil, fmt.Errorf("sign payment mandate: %w", err)
	}
	a.log.Info().Str("mandateId", claims.MandateID).Int64("amount", amount).Msg("payment mandate issued")
	return cose, nil
}

type checkoutMandateArgs struct {
	SubjectAns  string `json:"subjectAns"`
	AudienceAns string `json:"audienceAns"`
	CheckoutID  string `json:"checkoutId"`
	ItemID      string `json:"itemId"`
	Amount      int64  `json:"amount"`
	Currency    string `json:"currency"`
}

type paymentMandateArgs struct {
	SubjectAns  string `json:"subjectAns"`
	AudienceAns string `json:"audienceAns"`
	Amount      int64  `json:"amount"`
	Currency    string `json:"currency"`
}

// CheckoutMandateMCPTool returns the issue_checkout_mandate MCP tool.
func (a *Authority) CheckoutMandateMCPTool() mcp.ToolFunc {
	return func(_ context.Context, args json.RawMessage) (json.RawMessage, error) {
		var in checkoutMandateArgs
		if err := json.Unmarshal(args, &in); err != nil {
			return nil, fmt.Errorf("invalid arguments: %w", err)
		}
		cose, err := a.IssueCheckoutMandate(in.SubjectAns, in.AudienceAns, in.CheckoutID, in.ItemID, in.Amount, in.Currency)
		if err != nil {
			return nil, err
		}
		return json.Marshal(issueResult{MandateCOSE: cose})
	}
}

// PaymentMandateMCPTool returns the issue_payment_mandate MCP tool.
func (a *Authority) PaymentMandateMCPTool() mcp.ToolFunc {
	return func(_ context.Context, args json.RawMessage) (json.RawMessage, error) {
		var in paymentMandateArgs
		if err := json.Unmarshal(args, &in); err != nil {
			return nil, fmt.Errorf("invalid arguments: %w", err)
		}
		cose, err := a.IssuePaymentMandate(in.SubjectAns, in.AudienceAns, in.Amount, in.Currency)
		if err != nil {
			return nil, err
		}
		return json.Marshal(issueResult{MandateCOSE: cose})
	}
}
```
Then in `cmd/authority/main.go`, after the existing `mcpSrv.Register("issue_spend_mandate", ...)` line, add:
```go
	mcpSrv.Register("issue_checkout_mandate", auth.CheckoutMandateMCPTool())
	mcpSrv.Register("issue_payment_mandate", auth.PaymentMandateMCPTool())
```

- [ ] **Step 4: Run — PASS** (`go test ./internal/authority/ -run 'CheckoutAndPayment|UCPMandateMCP' -v && go build ./...`).
- [ ] **Step 5: Commit**
```bash
git add internal/authority/authority.go internal/authority/authority_test.go cmd/authority/main.go
git commit -m "feat(authority): issue AP2 checkout and payment mandates"
```

---

## Task 4: UCP guard (verify both AP2 mandates, fail-closed)

**Files:** Create `internal/policy/ucp.go`; Test `internal/policy/ucp_test.go`.

- [ ] **Step 1: Write the failing test** (`internal/policy/ucp_test.go`)
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

func signJSON(t *testing.T, priv ed25519.PrivateKey, v any) []byte {
	t.Helper()
	b, _ := json.Marshal(v)
	cose, err := crypto.SignCOSE1(priv, b)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return cose
}

func ucpGuard(t *testing.T) (*policy.UCP, ed25519.PrivateKey) {
	t.Helper()
	authPriv, _ := crypto.GenerateEd25519()
	g := policy.NewUCP(domain.LocalANSName("shop-ucp"), domain.LocalANSName("authority-1"), authPriv.Public().(ed25519.PublicKey), zerolog.Nop())
	return g, authPriv
}

func goodCheckout(now time.Time) domain.CheckoutMandateClaims {
	return domain.CheckoutMandateClaims{
		MandateID: "c", SubjectAns: domain.LocalANSName("Ada"), AudienceAns: domain.LocalANSName("shop-ucp"),
		CheckoutID: "cs_1", ItemID: "mug", Amount: 1200, Currency: "usd", Scope: domain.ScopeCheckout,
		NotBefore: now.Add(-time.Minute).Format(time.RFC3339), NotAfter: now.Add(time.Hour).Format(time.RFC3339), AuthorityAns: domain.LocalANSName("authority-1"),
	}
}
func goodPayment(now time.Time) domain.PaymentMandateClaims {
	return domain.PaymentMandateClaims{
		MandateID: "p", SubjectAns: domain.LocalANSName("Ada"), AudienceAns: domain.LocalANSName("shop-ucp"),
		Amount: 1200, Currency: "usd", Scope: domain.ScopePayment,
		NotBefore: now.Add(-time.Minute).Format(time.RFC3339), NotAfter: now.Add(time.Hour).Format(time.RFC3339), AuthorityAns: domain.LocalANSName("authority-1"),
	}
}
func completion(cm, pm []byte) domain.UCPCompletion {
	return domain.UCPCompletion{CallerAns: domain.LocalANSName("Ada"), CheckoutID: "cs_1", ItemID: "mug", Amount: 1200, Currency: "usd", CheckoutMandate: cm, PaymentMandate: pm}
}

func TestUCPAcceptsValidPair(t *testing.T) {
	g, ap := ucpGuard(t)
	now := time.Now().UTC()
	if err := g.Verify(context.Background(), completion(signJSON(t, ap, goodCheckout(now)), signJSON(t, ap, goodPayment(now)))); err != nil {
		t.Fatalf("valid pair rejected: %v", err)
	}
}

func TestUCPRejectsWrongAuthorityKey(t *testing.T) {
	g, _ := ucpGuard(t)
	other, _ := crypto.GenerateEd25519()
	now := time.Now().UTC()
	if err := g.Verify(context.Background(), completion(signJSON(t, other, goodCheckout(now)), signJSON(t, other, goodPayment(now)))); err == nil {
		t.Fatal("expected rejection: untrusted issuer")
	}
}

func TestUCPRejectsCheckoutIDMismatch(t *testing.T) {
	g, ap := ucpGuard(t)
	now := time.Now().UTC()
	c := goodCheckout(now)
	c.CheckoutID = "cs_other"
	if err := g.Verify(context.Background(), completion(signJSON(t, ap, c), signJSON(t, ap, goodPayment(now)))); err == nil {
		t.Fatal("expected rejection: checkoutId mismatch")
	}
}

func TestUCPRejectsPaymentUnderAmount(t *testing.T) {
	g, ap := ucpGuard(t)
	now := time.Now().UTC()
	p := goodPayment(now)
	p.Amount = 1000 // completion amount is 1200
	if err := g.Verify(context.Background(), completion(signJSON(t, ap, goodCheckout(now)), signJSON(t, ap, p))); err == nil {
		t.Fatal("expected rejection: payment authorizes less than amount")
	}
}

func TestUCPRejectsWrongPaymentScope(t *testing.T) {
	g, ap := ucpGuard(t)
	now := time.Now().UTC()
	// swap: present a checkout-scoped mandate where the payment mandate is expected
	if err := g.Verify(context.Background(), completion(signJSON(t, ap, goodCheckout(now)), signJSON(t, ap, goodCheckout(now)))); err == nil {
		t.Fatal("expected rejection: payment mandate has wrong scope")
	}
}

func TestUCPRejectsMissingMandates(t *testing.T) {
	g, _ := ucpGuard(t)
	if err := g.Verify(context.Background(), completion(nil, nil)); err == nil {
		t.Fatal("expected rejection: missing mandates")
	}
}
```

- [ ] **Step 2: Run — FAIL** (`go test ./internal/policy/ -run TestUCP -v`).

- [ ] **Step 3: Create `internal/policy/ucp.go`**
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

// UCP verifies a UCP purchase's two AP2 mandates: a CheckoutMandate (binds the
// cart state) and a PaymentMandate (binds the payment), both COSE_Sign1 signed by
// the pinned authority. Every check fails closed. As elsewhere, pinning the
// authority key authenticates the issuer.
type UCP struct {
	selfAns      string
	authorityAns string
	authorityPub ed25519.PublicKey
	leeway       time.Duration
	now          func() time.Time
	log          zerolog.Logger
}

// NewUCP builds a UCP guard for seller selfAns trusting authorityPub (authorityAns).
func NewUCP(selfAns, authorityAns string, authorityPub ed25519.PublicKey, log zerolog.Logger) *UCP {
	return &UCP{selfAns: selfAns, authorityAns: authorityAns, authorityPub: authorityPub, leeway: 60 * time.Second, now: time.Now, log: log.With().Str("component", "policy").Logger()}
}

// Verify checks both mandates against the completion. Fail closed.
func (u *UCP) Verify(ctx context.Context, c domain.UCPCompletion) error {
	if len(c.CheckoutMandate) == 0 || len(c.PaymentMandate) == 0 {
		return fmt.Errorf("both checkout and payment mandates are required")
	}

	// --- CheckoutMandate ---
	cPayload, cSigner, err := crypto.VerifyCOSE1(c.CheckoutMandate)
	if err != nil {
		events.Emit(ctx, "checkout.mandate.verify", events.StatusFail, map[string]string{"error": err.Error()})
		return fmt.Errorf("checkout mandate signature invalid: %w", err)
	}
	events.Emit(ctx, "checkout.mandate.verify", events.StatusOK, map[string]string{"alg": "EdDSA", "result": "COSE_Sign1 signature valid (self-verifying)"})
	if !cSigner.Equal(u.authorityPub) {
		events.Emit(ctx, "authority.pin", events.StatusFail, map[string]string{"authority": u.authorityAns})
		return fmt.Errorf("checkout mandate not signed by the trusted authority")
	}
	events.Emit(ctx, "authority.pin", events.StatusOK, map[string]string{"authority": u.authorityAns, "result": "issuer key matches the pinned authority — issuer authenticated"})
	var cc domain.CheckoutMandateClaims
	if err := json.Unmarshal(cPayload, &cc); err != nil {
		return fmt.Errorf("checkout claims malformed: %w", err)
	}
	if cc.AuthorityAns != u.authorityAns {
		return fmt.Errorf("checkout authority %q is not trusted %q", cc.AuthorityAns, u.authorityAns)
	}
	if cc.AudienceAns != u.selfAns {
		return fmt.Errorf("checkout audience %q is not this seller %q", cc.AudienceAns, u.selfAns)
	}
	if cc.SubjectAns != c.CallerAns {
		return fmt.Errorf("checkout subject %q does not match caller %q", cc.SubjectAns, c.CallerAns)
	}
	if cc.Scope != domain.ScopeCheckout {
		return fmt.Errorf("checkout scope %q is not %q", cc.Scope, domain.ScopeCheckout)
	}
	if cc.CheckoutID != c.CheckoutID {
		return fmt.Errorf("checkout mandate checkoutId %q does not match session %q", cc.CheckoutID, c.CheckoutID)
	}
	if cc.ItemID != c.ItemID {
		return fmt.Errorf("checkout item %q does not match session %q", cc.ItemID, c.ItemID)
	}
	if cc.Currency != c.Currency {
		return fmt.Errorf("checkout currency %q does not match session %q", cc.Currency, c.Currency)
	}
	if c.Amount > cc.Amount {
		return fmt.Errorf("amount %d exceeds checkout-authorized %d", c.Amount, cc.Amount)
	}
	if err := u.windowValid(cc.NotBefore, cc.NotAfter); err != nil {
		return fmt.Errorf("checkout mandate %w", err)
	}

	// --- PaymentMandate ---
	pPayload, pSigner, err := crypto.VerifyCOSE1(c.PaymentMandate)
	if err != nil {
		events.Emit(ctx, "payment.mandate.verify", events.StatusFail, map[string]string{"error": err.Error()})
		return fmt.Errorf("payment mandate signature invalid: %w", err)
	}
	if !pSigner.Equal(u.authorityPub) {
		events.Emit(ctx, "payment.mandate.verify", events.StatusFail, map[string]string{"error": "untrusted issuer"})
		return fmt.Errorf("payment mandate not signed by the trusted authority")
	}
	var pc domain.PaymentMandateClaims
	if err := json.Unmarshal(pPayload, &pc); err != nil {
		return fmt.Errorf("payment claims malformed: %w", err)
	}
	if pc.AuthorityAns != u.authorityAns {
		return fmt.Errorf("payment authority %q is not trusted %q", pc.AuthorityAns, u.authorityAns)
	}
	if pc.AudienceAns != u.selfAns {
		return fmt.Errorf("payment audience %q is not this seller %q", pc.AudienceAns, u.selfAns)
	}
	if pc.SubjectAns != c.CallerAns {
		return fmt.Errorf("payment subject %q does not match caller %q", pc.SubjectAns, c.CallerAns)
	}
	if pc.Scope != domain.ScopePayment {
		return fmt.Errorf("payment scope %q is not %q", pc.Scope, domain.ScopePayment)
	}
	if pc.Currency != c.Currency {
		return fmt.Errorf("payment currency %q does not match session %q", pc.Currency, c.Currency)
	}
	if c.Amount > pc.Amount {
		return fmt.Errorf("amount %d exceeds payment-authorized %d", c.Amount, pc.Amount)
	}
	if err := u.windowValid(pc.NotBefore, pc.NotAfter); err != nil {
		return fmt.Errorf("payment mandate %w", err)
	}
	events.Emit(ctx, "payment.mandate.verify", events.StatusOK, map[string]string{"alg": "EdDSA", "result": "payment authorization valid"})

	u.log.Info().Str("callerAns", c.CallerAns).Str("checkoutId", c.CheckoutID).Msg("UCP mandates accepted")
	return nil
}

func (u *UCP) windowValid(notBefore, notAfter string) error {
	nb, err := time.Parse(time.RFC3339, notBefore)
	if err != nil {
		return fmt.Errorf("notBefore invalid: %w", err)
	}
	na, err := time.Parse(time.RFC3339, notAfter)
	if err != nil {
		return fmt.Errorf("notAfter invalid: %w", err)
	}
	now := u.now()
	if now.Before(nb.Add(-u.leeway)) {
		return fmt.Errorf("not yet valid")
	}
	if now.After(na.Add(u.leeway)) {
		return fmt.Errorf("expired")
	}
	return nil
}
```

- [ ] **Step 4: Run — PASS** (`go test ./internal/policy/ -run TestUCP -v`).
- [ ] **Step 5: Commit**
```bash
git add internal/policy/ucp.go internal/policy/ucp_test.go
git commit -m "feat(policy): fail-closed UCP guard verifying both AP2 mandates"
```

---

## Task 5: UCP seller service

**Files:** Create `internal/commerce/ucp/seller.go`; Test `internal/commerce/ucp/seller_test.go`.

The seller serves `/.well-known/ucp`, catalog, create/update sessions (signing terms), `/tokenize`, and complete (verify both mandates + token, then charge). `seller.go` and the buyer `driver.go` (Task 6) are the SAME `package ucp`, so they share the unexported `checkoutTerms` type.

- [ ] **Step 1: Write the failing test** (`internal/commerce/ucp/seller_test.go`)
```go
package ucp_test

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

	"github.com/an-ciobanu/agent-mesh/internal/commerce"
	"github.com/an-ciobanu/agent-mesh/internal/commerce/ucp"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/events"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
)

func newUCPSeller(t *testing.T) (*httptest.Server, ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	authPriv, _ := crypto.GenerateEd25519()
	sellerPriv, _ := crypto.GenerateEd25519()
	guard := policy.NewUCP(domain.LocalANSName("shop-ucp"), domain.LocalANSName("authority-1"), authPriv.Public().(ed25519.PublicKey), zerolog.Nop())
	seller := ucp.NewSeller(ucp.SellerConfig{
		SelfAns: domain.LocalANSName("shop-ucp"), AgentName: "shop-ucp", Currency: "usd",
		Catalog: commerce.DefaultCatalog("usd"), Guard: guard, Payment: commerce.FakePayment{},
		SignKey: sellerPriv, AuthorityRole: "authority", AuthorityAns: domain.LocalANSName("authority-1"),
		Events: events.Nop{}, Log: zerolog.Nop(),
	})
	mux := http.NewServeMux()
	seller.Mount(mux)
	return httptest.NewServer(mux), authPriv, sellerPriv.Public().(ed25519.PublicKey)
}

func post(t *testing.T, url string, body any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(commerce.HeaderGreetID, "g-test")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post %s: %v", url, err)
	}
	return resp
}

func mint(t *testing.T, authPriv ed25519.PrivateKey, v any) []byte {
	t.Helper()
	b, _ := json.Marshal(v)
	c, err := crypto.SignCOSE1(authPriv, b)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return c
}

func TestUCPProfileAdvertisesHandlerAndKey(t *testing.T) {
	srv, _, sellerPub := newUCPSeller(t)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/.well-known/ucp")
	defer resp.Body.Close()
	var prof struct {
		Handlers []struct {
			ID           string `json:"id"`
			TokenizePath string `json:"tokenizePath"`
		} `json:"handlers"`
		AP2        struct{ AuthorityAns string `json:"authorityAns"` } `json:"ap2"`
		SigningKey crypto.JWK                                          `json:"signingKey"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&prof); err != nil {
		t.Fatalf("decode profile: %v", err)
	}
	if len(prof.Handlers) == 0 || prof.Handlers[0].TokenizePath == "" || prof.AP2.AuthorityAns == "" {
		t.Fatalf("profile incomplete: %+v", prof)
	}
	got, err := crypto.PublicKeyFromJWK(prof.SigningKey)
	if err != nil || !got.Equal(sellerPub) {
		t.Fatalf("profile signingKey mismatch: %v", err)
	}
}

func TestUCPHappyPath(t *testing.T) {
	srv, authPriv, sellerPub := newUCPSeller(t)
	defer srv.Close()

	// create session
	resp := post(t, srv.URL+"/ucp/checkout_sessions", map[string]string{"itemId": "sticker"})
	var sess struct {
		CheckoutID        string `json:"checkoutId"`
		ItemID            string `json:"itemId"`
		Amount            int64  `json:"amount"`
		Currency          string `json:"currency"`
		CheckoutSignature []byte `json:"checkoutSignature"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&sess)
	resp.Body.Close()
	if sess.CheckoutID == "" || sess.Amount != 500 || len(sess.CheckoutSignature) == 0 {
		t.Fatalf("bad session: %+v", sess)
	}
	// seller signed the terms with its key
	payload, signer, err := crypto.VerifyCOSE1(sess.CheckoutSignature)
	if err != nil || !signer.Equal(sellerPub) {
		t.Fatalf("checkout signature not from seller: %v", err)
	}
	var terms struct {
		CheckoutID string `json:"checkoutId"`
		Amount     int64  `json:"amount"`
	}
	_ = json.Unmarshal(payload, &terms)
	if terms.CheckoutID != sess.CheckoutID || terms.Amount != sess.Amount {
		t.Fatalf("signed terms mismatch: %+v", terms)
	}

	// update session (adds shipping) -> new amount + new signature
	resp = post(t, srv.URL+"/ucp/checkout_sessions/"+sess.CheckoutID, map[string]any{})
	var upd struct {
		Amount            int64  `json:"amount"`
		CheckoutSignature []byte `json:"checkoutSignature"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&upd)
	resp.Body.Close()
	if upd.Amount <= sess.Amount || len(upd.CheckoutSignature) == 0 {
		t.Fatalf("update did not raise amount / re-sign: %+v", upd)
	}

	// tokenize (allowance = updated amount)
	resp = post(t, srv.URL+"/ucp/tokenize", map[string]any{
		"binding":    map[string]string{"checkoutId": sess.CheckoutID},
		"allowance":  map[string]any{"maxAmount": upd.Amount, "currency": "usd"},
		"credential": map[string]string{"type": "card"},
	})
	var tok struct{ Token string `json:"token"` }
	_ = json.NewDecoder(resp.Body).Decode(&tok)
	resp.Body.Close()
	if tok.Token == "" {
		t.Fatal("no token issued")
	}

	// mandates over the updated amount
	now := time.Now().UTC()
	cm := mint(t, authPriv, domain.CheckoutMandateClaims{
		MandateID: "c", SubjectAns: domain.LocalANSName("Ada"), AudienceAns: domain.LocalANSName("shop-ucp"),
		CheckoutID: sess.CheckoutID, ItemID: "sticker", Amount: upd.Amount, Currency: "usd", Scope: domain.ScopeCheckout,
		NotBefore: now.Add(-time.Minute).Format(time.RFC3339), NotAfter: now.Add(time.Hour).Format(time.RFC3339), AuthorityAns: domain.LocalANSName("authority-1"),
	})
	pm := mint(t, authPriv, domain.PaymentMandateClaims{
		MandateID: "p", SubjectAns: domain.LocalANSName("Ada"), AudienceAns: domain.LocalANSName("shop-ucp"),
		Amount: upd.Amount, Currency: "usd", Scope: domain.ScopePayment,
		NotBefore: now.Add(-time.Minute).Format(time.RFC3339), NotAfter: now.Add(time.Hour).Format(time.RFC3339), AuthorityAns: domain.LocalANSName("authority-1"),
	})

	// complete
	resp = post(t, srv.URL+"/ucp/checkout_sessions/"+sess.CheckoutID+"/complete", map[string]any{
		"callerAns": domain.LocalANSName("Ada"), "checkoutMandate": cm, "paymentMandate": pm, "paymentToken": tok.Token,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("complete status=%d", resp.StatusCode)
	}
	var rec struct {
		Status     string `json:"status"`
		PaymentRef string `json:"paymentRef"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&rec)
	resp.Body.Close()
	if rec.Status != "completed" || rec.PaymentRef == "" {
		t.Fatalf("bad receipt: %+v", rec)
	}
}

func TestUCPCompleteRejectsBadMandate(t *testing.T) {
	srv, authPriv, _ := newUCPSeller(t)
	defer srv.Close()
	resp := post(t, srv.URL+"/ucp/checkout_sessions", map[string]string{"itemId": "mug"})
	var sess struct {
		CheckoutID string `json:"checkoutId"`
		Amount     int64  `json:"amount"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&sess)
	resp.Body.Close()
	// tokenize so token isn't the failing check
	resp = post(t, srv.URL+"/ucp/tokenize", map[string]any{"binding": map[string]string{"checkoutId": sess.CheckoutID}, "allowance": map[string]any{"maxAmount": sess.Amount, "currency": "usd"}, "credential": map[string]string{"type": "card"}})
	var tok struct{ Token string `json:"token"` }
	_ = json.NewDecoder(resp.Body).Decode(&tok)
	resp.Body.Close()
	now := time.Now().UTC()
	// checkout mandate for the WRONG checkout id
	cm := mint(t, authPriv, domain.CheckoutMandateClaims{MandateID: "c", SubjectAns: domain.LocalANSName("Ada"), AudienceAns: domain.LocalANSName("shop-ucp"), CheckoutID: "cs_wrong", ItemID: "mug", Amount: sess.Amount, Currency: "usd", Scope: domain.ScopeCheckout, NotBefore: now.Add(-time.Minute).Format(time.RFC3339), NotAfter: now.Add(time.Hour).Format(time.RFC3339), AuthorityAns: domain.LocalANSName("authority-1")})
	pm := mint(t, authPriv, domain.PaymentMandateClaims{MandateID: "p", SubjectAns: domain.LocalANSName("Ada"), AudienceAns: domain.LocalANSName("shop-ucp"), Amount: sess.Amount, Currency: "usd", Scope: domain.ScopePayment, NotBefore: now.Add(-time.Minute).Format(time.RFC3339), NotAfter: now.Add(time.Hour).Format(time.RFC3339), AuthorityAns: domain.LocalANSName("authority-1")})
	resp = post(t, srv.URL+"/ucp/checkout_sessions/"+sess.CheckoutID+"/complete", map[string]any{"callerAns": domain.LocalANSName("Ada"), "checkoutMandate": cm, "paymentMandate": pm, "paymentToken": tok.Token})
	if resp.StatusCode == http.StatusOK {
		t.Fatal("expected non-200 for checkoutId-mismatch mandate")
	}
	resp.Body.Close()
}
```

- [ ] **Step 2: Run — FAIL** (`go test ./internal/commerce/ucp/ -run TestUCP -v`) — undefined `ucp.*`.

- [ ] **Step 3: Create `internal/commerce/ucp/seller.go`**
```go
// Package ucp implements the demo's Universal Commerce Protocol seller (server)
// and buyer driver (client): /.well-known/ucp discovery + a tokenize handler,
// seller-signed checkout terms, and a create->update->complete session gated by
// two authority-issued AP2 mandates and settled through a commerce.PaymentPrimitive.
package ucp

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/commerce"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/events"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
)

// shippingFee is added to a session's total on update (the fulfillment step).
const shippingFee int64 = 300

// checkoutTerms is the exact structure the seller COSE-signs (checkoutSignature)
// and the buyer verifies. Shared by seller.go and driver.go (same package).
type checkoutTerms struct {
	CheckoutID string `json:"checkoutId"`
	ItemID     string `json:"itemId"`
	Amount     int64  `json:"amount"`
	Currency   string `json:"currency"`
}

// SellerConfig configures a UCP seller service.
type SellerConfig struct {
	SelfAns       string
	AgentName     string
	Currency      string
	Catalog       []commerce.Item
	Guard         *policy.UCP
	Payment       commerce.PaymentPrimitive
	SignKey       ed25519.PrivateKey
	AuthorityRole string
	AuthorityAns  string
	Events        events.Emitter
	Log           zerolog.Logger
}

type ucpSession struct {
	checkoutID string
	itemID     string
	amount     int64
	currency   string
}

type tokenRec struct {
	checkoutID string
	maxAmount  int64
	currency   string
	expiresAt  time.Time
}

// Seller serves the UCP surface.
type Seller struct {
	cfg     SellerConfig
	signPub ed25519.PublicKey
	mu      sync.Mutex
	ses     map[string]ucpSession
	toks    map[string]tokenRec
	log     zerolog.Logger
}

// NewSeller builds a UCP seller.
func NewSeller(cfg SellerConfig) *Seller {
	if cfg.Events == nil {
		cfg.Events = events.Nop{}
	}
	return &Seller{
		cfg:     cfg,
		signPub: cfg.SignKey.Public().(ed25519.PublicKey),
		ses:     map[string]ucpSession{},
		toks:    map[string]tokenRec{},
		log:     cfg.Log.With().Str("component", "ucp-seller").Logger(),
	}
}

// Mount registers the UCP routes.
func (s *Seller) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/ucp", s.handleProfile)
	mux.HandleFunc("GET /ucp/catalog", s.handleCatalog)
	mux.HandleFunc("POST /ucp/checkout_sessions", s.handleCreate)
	mux.HandleFunc("POST /ucp/checkout_sessions/{id}", s.handleUpdate)
	mux.HandleFunc("POST /ucp/tokenize", s.handleTokenize)
	mux.HandleFunc("POST /ucp/checkout_sessions/{id}/complete", s.handleComplete)
}

func (s *Seller) handleProfile(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ucp_version": "2026-04-08",
		"handlers": []map[string]any{{
			"id": "stripe_payments", "type": "com.stripe.payments", "tokenizePath": "/ucp/tokenize",
			"instruments": []map[string]any{{"type": "card", "tokenization": "required"}},
		}},
		"checkout": map[string]string{"catalogPath": "/ucp/catalog", "sessionsPath": "/ucp/checkout_sessions"},
		"ap2":      map[string]any{"required": true, "authorityRole": s.cfg.AuthorityRole, "authorityAns": s.cfg.AuthorityAns},
		"signingKey": crypto.PublicJWK(s.signPub),
	})
}

func (s *Seller) handleCatalog(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": s.cfg.Catalog})
}

// sign returns a COSE_Sign1 over the session's current terms.
func (s *Seller) sign(sess ucpSession) ([]byte, error) {
	b, err := json.Marshal(checkoutTerms{CheckoutID: sess.checkoutID, ItemID: sess.itemID, Amount: sess.amount, Currency: sess.currency})
	if err != nil {
		return nil, err
	}
	return crypto.SignCOSE1(s.cfg.SignKey, b)
}

func (s *Seller) handleCreate(w http.ResponseWriter, r *http.Request) {
	gctx := events.WithScope(r.Context(), s.cfg.Events, r.Header.Get(commerce.HeaderGreetID), s.cfg.AgentName, events.RoleResponder)
	var in struct {
		ItemID string `json:"itemId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	var item commerce.Item
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
	sess := ucpSession{checkoutID: id, itemID: item.ID, amount: item.Amount, currency: item.Currency}
	s.mu.Lock()
	s.ses[id] = sess
	s.mu.Unlock()
	sig, err := s.sign(sess)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "sign terms"})
		return
	}
	events.Emit(gctx, "session.create", events.StatusOK, map[string]string{"checkoutId": id, "item": item.ID, "amount": strconv.FormatInt(item.Amount, 10), "signed": "terms COSE-signed"})
	writeJSON(w, http.StatusOK, map[string]any{"checkoutId": id, "itemId": item.ID, "amount": item.Amount, "currency": item.Currency, "status": "created", "checkoutSignature": sig})
}

func (s *Seller) handleUpdate(w http.ResponseWriter, r *http.Request) {
	gctx := events.WithScope(r.Context(), s.cfg.Events, r.Header.Get(commerce.HeaderGreetID), s.cfg.AgentName, events.RoleResponder)
	id := r.PathValue("id")
	s.mu.Lock()
	sess, ok := s.ses[id]
	if ok {
		sess.amount += shippingFee // fulfillment surcharge
		s.ses[id] = sess
	}
	s.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown session"})
		return
	}
	sig, err := s.sign(sess)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "sign terms"})
		return
	}
	events.Emit(gctx, "session.update", events.StatusOK, map[string]string{"checkoutId": id, "amount": strconv.FormatInt(sess.amount, 10), "fulfillment": "standard shipping added"})
	writeJSON(w, http.StatusOK, map[string]any{"checkoutId": id, "itemId": sess.itemID, "amount": sess.amount, "currency": sess.currency, "status": "updated", "checkoutSignature": sig})
}

func (s *Seller) handleTokenize(w http.ResponseWriter, r *http.Request) {
	gctx := events.WithScope(r.Context(), s.cfg.Events, r.Header.Get(commerce.HeaderGreetID), s.cfg.AgentName, events.RoleResponder)
	var in struct {
		Binding   struct{ CheckoutID string `json:"checkoutId"` } `json:"binding"`
		Allowance struct {
			MaxAmount int64  `json:"maxAmount"`
			Currency  string `json:"currency"`
		} `json:"allowance"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Binding.CheckoutID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	token := "utok_" + hex.EncodeToString(b)
	exp := time.Now().Add(time.Hour)
	s.mu.Lock()
	s.toks[token] = tokenRec{checkoutID: in.Binding.CheckoutID, maxAmount: in.Allowance.MaxAmount, currency: in.Allowance.Currency, expiresAt: exp}
	s.mu.Unlock()
	events.Emit(gctx, "token.issue", events.StatusOK, map[string]string{"checkoutId": in.Binding.CheckoutID, "maxAmount": strconv.FormatInt(in.Allowance.MaxAmount, 10), "handler": "stripe_payments"})
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "expiresAt": exp.UTC().Format(time.RFC3339)})
}

func (s *Seller) handleComplete(w http.ResponseWriter, r *http.Request) {
	gctx := events.WithScope(r.Context(), s.cfg.Events, r.Header.Get(commerce.HeaderGreetID), s.cfg.AgentName, events.RoleResponder)
	id := r.PathValue("id")
	s.mu.Lock()
	sess, ok := s.ses[id]
	s.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown session"})
		return
	}
	var in struct {
		CallerAns       string `json:"callerAns"`
		CheckoutMandate []byte `json:"checkoutMandate"`
		PaymentMandate  []byte `json:"paymentMandate"`
		PaymentToken    string `json:"paymentToken"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	if err := s.cfg.Guard.Verify(gctx, domain.UCPCompletion{
		CallerAns: in.CallerAns, CheckoutID: id, ItemID: sess.itemID, Amount: sess.amount, Currency: sess.currency,
		CheckoutMandate: in.CheckoutMandate, PaymentMandate: in.PaymentMandate,
	}); err != nil {
		s.log.Warn().Err(err).Str("checkout", id).Msg("ucp mandates rejected")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "purchase not authorized: " + err.Error()})
		return
	}
	// validate the token: issued by us, bound to this checkout, covers the amount, unexpired.
	s.mu.Lock()
	tok, tok0k := s.toks[in.PaymentToken]
	s.mu.Unlock()
	if !tok0k || tok.checkoutID != id || tok.currency != sess.currency || tok.maxAmount < sess.amount || time.Now().After(tok.expiresAt) {
		events.Emit(gctx, "token.verify", events.StatusFail, map[string]string{"error": "invalid or insufficient payment token"})
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid payment token"})
		return
	}
	events.Emit(gctx, "token.verify", events.StatusOK, map[string]string{"token": in.PaymentToken, "result": "bound to checkout, allowance covers amount"})

	res, err := s.cfg.Payment.Charge(gctx, commerce.ChargeRequest{Amount: sess.amount, Currency: sess.currency, ItemID: sess.itemID, BuyerAns: in.CallerAns, IdempotencyKey: id})
	if err != nil {
		events.Emit(gctx, "charge", events.StatusFail, map[string]string{"error": err.Error()})
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "charge failed: " + err.Error()})
		return
	}
	events.Emit(gctx, "charge", events.StatusOK, map[string]string{"provider": res.Provider, "ref": res.Ref, "status": res.Status})
	events.Emit(gctx, "receipt", events.StatusOK, map[string]string{"paymentRef": res.Ref, "status": res.Status})
	s.mu.Lock()
	delete(s.ses, id)
	delete(s.toks, in.PaymentToken)
	s.mu.Unlock()
	s.log.Info().Str("checkout", id).Str("paymentRef", res.Ref).Msg("ucp purchase completed")
	writeJSON(w, http.StatusOK, map[string]any{"status": "completed", "provider": res.Provider, "paymentRef": res.Ref, "itemId": sess.itemID, "amount": sess.amount, "currency": sess.currency})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
```

- [ ] **Step 4: Run — PASS** (`go test ./internal/commerce/ucp/ -run TestUCP -v && go vet ./internal/commerce/ucp/`). Fix any unused import.
- [ ] **Step 5: Commit**
```bash
git add internal/commerce/ucp/seller.go internal/commerce/ucp/seller_test.go
git commit -m "feat(ucp): seller — discovery, signed terms, session create/update, tokenize, complete"
```

---

## Task 6: UCP buyer driver

**Files:** Create `internal/commerce/ucp/driver.go`; Test `internal/commerce/ucp/driver_test.go`, `internal/commerce/ucp/helpers_test.go`.

- [ ] **Step 1: Write the failing test** (`internal/commerce/ucp/driver_test.go`)
```go
package ucp_test

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/commerce"
	"github.com/an-ciobanu/agent-mesh/internal/commerce/ucp"
	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
)

type stubDisco struct{ byRole map[string][]domain.AgentInfo }

func (s stubDisco) Register(context.Context, domain.AgentInfo) error { return nil }
func (s stubDisco) Search(_ context.Context, role string) ([]domain.AgentInfo, error) {
	return s.byRole[role], nil
}

func TestUCPBuyPeerHappyPath(t *testing.T) {
	authPriv, _ := crypto.GenerateEd25519()
	authAns := domain.LocalANSName("authority-1")
	authMCP := mcp.NewServer(zerolog.Nop())
	authMCP.Register("issue_checkout_mandate", newCheckoutTool(t, authPriv, authAns))
	authMCP.Register("issue_payment_mandate", newPaymentTool(t, authPriv, authAns))
	authSrv := httptest.NewServer(authMCP.Handler())
	defer authSrv.Close()

	sellerPriv, _ := crypto.GenerateEd25519()
	guard := policy.NewUCP(domain.LocalANSName("shop-ucp"), authAns, authPriv.Public().(ed25519.PublicKey), zerolog.Nop())
	seller := ucp.NewSeller(ucp.SellerConfig{
		SelfAns: domain.LocalANSName("shop-ucp"), AgentName: "shop-ucp", Currency: "usd",
		Catalog: commerce.DefaultCatalog("usd"), Guard: guard, Payment: commerce.FakePayment{},
		SignKey: sellerPriv, AuthorityRole: "authority", AuthorityAns: authAns, Log: zerolog.Nop(),
	})
	sMux := http.NewServeMux()
	seller.Mount(sMux)
	sellerSrv := httptest.NewServer(sMux)
	defer sellerSrv.Close()

	disco := stubDisco{byRole: map[string][]domain.AgentInfo{
		"authority": {{Name: "authority-1", Role: "authority", BaseURL: authSrv.URL}},
	}}
	peer := domain.AgentInfo{Name: "shop-ucp", Role: "seller", BaseURL: sellerSrv.URL, CardURL: sellerSrv.URL + "/.well-known/agent-card.json"}
	card := a2a.Card{Name: "shop-ucp", Capabilities: &a2a.Capabilities{Extensions: []a2a.Extension{{
		URI: a2a.ExtUCPURI, Params: map[string]any{"profilePath": "/.well-known/ucp"},
	}}}}

	res, err := ucp.BuyPeer(context.Background(), http.DefaultClient, mcp.NewClient(), disco, domain.LocalANSName("Ada"), peer, card)
	if err != nil {
		t.Fatalf("buy: %v", err)
	}
	if res.Status != "completed" || res.PaymentRef == "" {
		t.Fatalf("unexpected result: %+v", res)
	}
}
```
`internal/commerce/ucp/helpers_test.go`:
```go
package ucp_test

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/authority"
	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
)

func newCheckoutTool(t *testing.T, priv ed25519.PrivateKey, ans string) mcp.ToolFunc {
	t.Helper()
	return authority.New(ans, priv, time.Hour, zerolog.Nop()).CheckoutMandateMCPTool()
}
func newPaymentTool(t *testing.T, priv ed25519.PrivateKey, ans string) mcp.ToolFunc {
	t.Helper()
	return authority.New(ans, priv, time.Hour, zerolog.Nop()).PaymentMandateMCPTool()
}
```

- [ ] **Step 2: Run — FAIL** (`go test ./internal/commerce/ucp/ -run TestUCPBuyPeer -v`) — undefined `ucp.BuyPeer` / `a2a.ExtUCPURI` (ExtUCPURI is added in Task 7; add it now if the compiler needs it — Step 3a).

- [ ] **Step 3a: Add `a2a.ExtUCPURI`** (in `internal/comms/a2a/card.go`, after `ExtACPURI`):
```go
// ExtUCPURI identifies the agent-mesh "UCP seller" A2A capabilities extension. A
// seller that advertises it sells over the Universal Commerce Protocol; its params
// point at the /.well-known/ucp discovery profile.
const ExtUCPURI = "https://agent-mesh.local/ext/ucp/v1"
```

- [ ] **Step 3b: Create `internal/commerce/ucp/driver.go`**
```go
package ucp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/an-ciobanu/agent-mesh/internal/commerce"
	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/events"
)

type ucpProfile struct {
	Handlers []struct {
		ID           string `json:"id"`
		TokenizePath string `json:"tokenizePath"`
	} `json:"handlers"`
	Checkout struct {
		CatalogPath  string `json:"catalogPath"`
		SessionsPath string `json:"sessionsPath"`
	} `json:"checkout"`
	AP2 struct {
		AuthorityRole string `json:"authorityRole"`
		AuthorityAns  string `json:"authorityAns"`
	} `json:"ap2"`
	SigningKey crypto.JWK `json:"signingKey"`
}

// BuyPeer drives a full UCP purchase against an already-discovered seller whose
// card advertises the UCP extension: read /.well-known/ucp, pick the cheapest item,
// create a session and verify the seller-signed terms, update it, obtain the two
// AP2 mandates from the named authority, tokenize, and complete. Card-driven; no
// hardcoding. Steps emit through ctx.
func BuyPeer(ctx context.Context, httpc *http.Client, mcpCli *mcp.Client, disco domain.Discovery, callerAns string, peer domain.AgentInfo, card a2a.Card) (commerce.BuyResult, error) {
	ext, ok := ucpExtension(card)
	if !ok {
		return commerce.BuyResult{}, fmt.Errorf("peer %q does not advertise UCP", peer.Name)
	}
	events.Emit(ctx, "requirement", events.StatusInfo, map[string]string{"type": "ucp"})
	events.Emit(ctx, "card.read", events.StatusOK, map[string]string{"peer": peer.Name, "url": card.URL})
	greetID := events.GreetIDFromContext(ctx)
	profilePath := strParam(ext.Params, "profilePath", "/.well-known/ucp")

	var prof ucpProfile
	if err := getJSON(ctx, httpc, greetID, peer.BaseURL+profilePath, &prof); err != nil {
		return commerce.BuyResult{}, fmt.Errorf("read ucp profile: %w", err)
	}
	if len(prof.Handlers) == 0 {
		return commerce.BuyResult{}, fmt.Errorf("seller %q advertises no UCP handler", peer.Name)
	}
	sellerPub, err := crypto.PublicKeyFromJWK(prof.SigningKey)
	if err != nil {
		return commerce.BuyResult{}, fmt.Errorf("seller signing key: %w", err)
	}
	events.Emit(ctx, "profile.read", events.StatusOK, map[string]string{"handler": prof.Handlers[0].ID, "authority": prof.AP2.AuthorityAns})

	var cat struct {
		Items []commerce.Item `json:"items"`
	}
	if err := getJSON(ctx, httpc, greetID, peer.BaseURL+prof.Checkout.CatalogPath, &cat); err != nil {
		return commerce.BuyResult{}, err
	}
	item, ok := commerce.LowestPriced(cat.Items)
	if !ok {
		return commerce.BuyResult{}, fmt.Errorf("seller %q has an empty catalog", peer.Name)
	}
	events.Emit(ctx, "catalog.fetch", events.StatusOK, map[string]string{"items": strconv.Itoa(len(cat.Items))})
	events.Emit(ctx, "item.select", events.StatusOK, map[string]string{"item": item.ID, "amount": strconv.FormatInt(item.Amount, 10)})

	// create session
	var sess struct {
		CheckoutID        string `json:"checkoutId"`
		ItemID            string `json:"itemId"`
		Amount            int64  `json:"amount"`
		Currency          string `json:"currency"`
		CheckoutSignature []byte `json:"checkoutSignature"`
	}
	if err := postJSON(ctx, httpc, greetID, peer.BaseURL+prof.Checkout.SessionsPath, map[string]string{"itemId": item.ID}, &sess); err != nil {
		return commerce.BuyResult{}, err
	}
	events.Emit(ctx, "session.create", events.StatusOK, map[string]string{"checkoutId": sess.CheckoutID, "amount": strconv.FormatInt(sess.Amount, 10)})
	if err := verifyTerms(sess.CheckoutSignature, sellerPub, sess.CheckoutID, sess.Amount); err != nil {
		events.Emit(ctx, "terms.verify", events.StatusFail, map[string]string{"error": err.Error()})
		return commerce.BuyResult{}, err
	}
	events.Emit(ctx, "terms.verify", events.StatusOK, map[string]string{"result": "seller signature over terms valid — terms authentic"})

	// update session (fulfillment) -> new amount + new signature
	var upd struct {
		Amount            int64  `json:"amount"`
		Currency          string `json:"currency"`
		CheckoutSignature []byte `json:"checkoutSignature"`
	}
	if err := postJSON(ctx, httpc, greetID, peer.BaseURL+prof.Checkout.SessionsPath+"/"+sess.CheckoutID, map[string]any{}, &upd); err != nil {
		return commerce.BuyResult{}, err
	}
	if err := verifyTerms(upd.CheckoutSignature, sellerPub, sess.CheckoutID, upd.Amount); err != nil {
		events.Emit(ctx, "terms.verify", events.StatusFail, map[string]string{"error": err.Error()})
		return commerce.BuyResult{}, err
	}
	events.Emit(ctx, "session.update", events.StatusOK, map[string]string{"checkoutId": sess.CheckoutID, "amount": strconv.FormatInt(upd.Amount, 10)})
	amount, currency := upd.Amount, upd.Currency

	// mandates from the named authority
	audienceAns := domain.LocalANSName(peer.Name)
	auth, ok, err := pickAuthority(ctx, disco, prof.AP2.AuthorityRole, prof.AP2.AuthorityAns)
	if err != nil {
		return commerce.BuyResult{}, err
	}
	if !ok {
		return commerce.BuyResult{}, fmt.Errorf("no authority %q under role %q", prof.AP2.AuthorityAns, prof.AP2.AuthorityRole)
	}
	cm, err := acquireMandate(ctx, mcpCli, auth.BaseURL+"/mcp", "issue_checkout_mandate", map[string]any{
		"subjectAns": callerAns, "audienceAns": audienceAns, "checkoutId": sess.CheckoutID, "itemId": item.ID, "amount": amount, "currency": currency,
	})
	if err != nil {
		events.Emit(ctx, "checkout.acquire", events.StatusFail, map[string]string{"error": err.Error()})
		return commerce.BuyResult{}, err
	}
	events.Emit(ctx, "checkout.acquire", events.StatusOK, map[string]string{"authority": auth.Name, "tool": "issue_checkout_mandate (MCP)"})
	pm, err := acquireMandate(ctx, mcpCli, auth.BaseURL+"/mcp", "issue_payment_mandate", map[string]any{
		"subjectAns": callerAns, "audienceAns": audienceAns, "amount": amount, "currency": currency,
	})
	if err != nil {
		events.Emit(ctx, "payment.acquire", events.StatusFail, map[string]string{"error": err.Error()})
		return commerce.BuyResult{}, err
	}
	events.Emit(ctx, "payment.acquire", events.StatusOK, map[string]string{"authority": auth.Name, "tool": "issue_payment_mandate (MCP)"})

	// tokenize via the handler
	var tok struct {
		Token string `json:"token"`
	}
	if err := postJSON(ctx, httpc, greetID, peer.BaseURL+prof.Handlers[0].TokenizePath, map[string]any{
		"binding":    map[string]string{"checkoutId": sess.CheckoutID},
		"allowance":  map[string]any{"maxAmount": amount, "currency": currency},
		"credential": map[string]string{"type": "card"},
	}, &tok); err != nil {
		return commerce.BuyResult{}, err
	}
	if tok.Token == "" {
		return commerce.BuyResult{}, fmt.Errorf("handler returned no token")
	}
	events.Emit(ctx, "tokenize", events.StatusOK, map[string]string{"handler": prof.Handlers[0].ID, "token": tok.Token})

	// complete
	events.Emit(ctx, "checkout.complete", events.StatusInfo, map[string]string{"checkoutId": sess.CheckoutID})
	var rec struct {
		Provider   string `json:"provider"`
		PaymentRef string `json:"paymentRef"`
		Status     string `json:"status"`
	}
	if err := postJSONExpect(ctx, httpc, greetID, peer.BaseURL+prof.Checkout.SessionsPath+"/"+sess.CheckoutID+"/complete", map[string]any{
		"callerAns": callerAns, "checkoutMandate": cm, "paymentMandate": pm, "paymentToken": tok.Token,
	}, &rec); err != nil {
		events.Emit(ctx, "purchase.rejected", events.StatusFail, map[string]string{"error": err.Error()})
		return commerce.BuyResult{}, err
	}
	events.Emit(ctx, "receipt", events.StatusOK, map[string]string{"paymentRef": rec.PaymentRef, "status": rec.Status, "provider": rec.Provider})
	return commerce.BuyResult{PaymentRef: rec.PaymentRef, Status: rec.Status, ItemID: item.ID}, nil
}

func ucpExtension(card a2a.Card) (a2a.Extension, bool) {
	if card.Capabilities == nil {
		return a2a.Extension{}, false
	}
	for _, e := range card.Capabilities.Extensions {
		if e.URI == a2a.ExtUCPURI {
			return e, true
		}
	}
	return a2a.Extension{}, false
}

func verifyTerms(sig []byte, sellerPub ed25519.PublicKey, checkoutID string, amount int64) error {
	if len(sig) == 0 {
		return fmt.Errorf("missing checkout signature")
	}
	payload, signer, err := crypto.VerifyCOSE1(sig)
	if err != nil {
		return fmt.Errorf("checkout signature invalid: %w", err)
	}
	if !signer.Equal(sellerPub) {
		return fmt.Errorf("checkout signature not from the advertised seller key")
	}
	var terms checkoutTerms
	if err := json.Unmarshal(payload, &terms); err != nil {
		return fmt.Errorf("signed terms malformed: %w", err)
	}
	if terms.CheckoutID != checkoutID || terms.Amount != amount {
		return fmt.Errorf("signed terms do not match session (id/amount)")
	}
	return nil
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

func acquireMandate(ctx context.Context, mcpCli *mcp.Client, authURL, tool string, args map[string]any) ([]byte, error) {
	raw, err := mcpCli.Call(ctx, authURL, tool, args)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", tool, err)
	}
	var out struct {
		MandateCOSE []byte `json:"mandateCose"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("parse %s: %w", tool, err)
	}
	if len(out.MandateCOSE) == 0 {
		return nil, fmt.Errorf("authority returned an empty mandate from %s", tool)
	}
	return out.MandateCOSE, nil
}

func getJSON(ctx context.Context, httpc *http.Client, greetID, url string, out any) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	setGreet(req, greetID)
	resp, err := httpc.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func postJSON(ctx context.Context, httpc *http.Client, greetID, url string, body, out any) error {
	return postJSONExpect(ctx, httpc, greetID, url, body, out)
}

func postJSONExpect(ctx context.Context, httpc *http.Client, greetID, url string, body, out any) error {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	setGreet(req, greetID)
	resp, err := httpc.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if e.Error != "" {
			return fmt.Errorf("%s", e.Error)
		}
		return fmt.Errorf("POST %s: status %d", url, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func setGreet(req *http.Request, greetID string) {
	if greetID != "" {
		req.Header.Set(commerce.HeaderGreetID, greetID)
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

- [ ] **Step 4: Run — PASS** (`go test ./internal/commerce/ucp/ -v && go build ./... && go vet ./internal/commerce/ucp/`).
- [ ] **Step 5: Commit**
```bash
git add internal/commerce/ucp/driver.go internal/commerce/ucp/driver_test.go internal/commerce/ucp/helpers_test.go internal/comms/a2a/card.go
git commit -m "feat(ucp): buyer driver (discovery, verify terms, dual mandates, tokenize, complete)"
```

---

## Task 7: cmd/agent — UCP seller mode + protocol dispatch

**Files:** Modify `cmd/agent/main.go`.

- [ ] **Step 1: Add the `--ucp` flag** (alongside the `--acp` flags)
```go
	ucpSeller := flag.Bool("ucp", false, "run as a UCP seller (serves /.well-known/ucp + /ucp/* instead of a greet policy)")
```

- [ ] **Step 2: Seller short-circuit** — next to the existing `if *acpSeller { ... }`, add:
```go
	if *ucpSeller {
		runUCPSeller(ctx, acpSellerParams{
			name: *name, role: *role, addr: *addr, baseURL: baseURL, selfAns: selfAns,
			registryURL: *registryURL, currency: *acpCurrency, payment: *payment,
			stripeKeyEnv: *stripeKeyEnv, authorityRole: *authorityRole, authorityName: *authorityName,
			priv: priv, em: em, log: log, disco: disco,
		})
		return
	}
```
(Reuses the existing `acpSellerParams` struct and `--acp-currency`/`--payment`/`--stripe-key-env` flags.)

- [ ] **Step 3: Implement `runUCPSeller`** (append to `cmd/agent/main.go`; import `"github.com/an-ciobanu/agent-mesh/internal/commerce/ucp"`)
```go
// runUCPSeller runs the agent as a UCP seller: resolves+pins the authority, builds
// a UCP guard and a payment backend, uses its own identity key to sign checkout
// terms, serves the UCP endpoints, and registers as its role.
func runUCPSeller(ctx context.Context, p acpSellerParams) {
	authPeer, authPub := resolveAuthority(ctx, p.disco, authclient.New(), p.authorityRole, p.authorityName, p.log)
	authorityAns := domain.LocalANSName(authPeer.Name)
	guard := policy.NewUCP(p.selfAns, authorityAns, authPub, p.log)

	var pay commerce.PaymentPrimitive
	switch p.payment {
	case "fake":
		pay = commerce.FakePayment{}
		p.log.Info().Msg("UCP payment backend: fake (no network)")
	case "stripe":
		key := os.Getenv(p.stripeKeyEnv)
		if key == "" {
			p.log.Fatal().Str("env", p.stripeKeyEnv).Msg("UCP seller: Stripe secret key missing (fail closed)")
		}
		pay = commerce.StripePaymentIntent{Client: stripe.NewClient(key)}
		p.log.Info().Msg("UCP payment backend: stripe (test mode)")
	default:
		p.log.Fatal().Str("payment", p.payment).Msg("unknown --payment (want: stripe | fake)")
	}

	seller := ucp.NewSeller(ucp.SellerConfig{
		SelfAns: p.selfAns, AgentName: p.name, Currency: p.currency,
		Catalog: commerce.DefaultCatalog(p.currency), Guard: guard, Payment: pay,
		SignKey: p.priv, AuthorityRole: p.authorityRole, AuthorityAns: authorityAns,
		Events: p.em, Log: p.log,
	})

	card := a2a.Card{
		Name: p.name, Version: "0.1.0", Security: []map[string][]string{},
		Capabilities: &a2a.Capabilities{Extensions: []a2a.Extension{{
			URI:         a2a.ExtUCPURI,
			Description: "buy over the Universal Commerce Protocol; see /.well-known/ucp",
			Required:    true,
			Params:      map[string]any{"profilePath": "/.well-known/ucp", "authorityRole": p.authorityRole, "authorityAns": authorityAns, "currency": p.currency},
		}}},
	}

	mux := http.NewServeMux()
	mux.Handle("/.well-known/agent-card.json", a2a.CardHandler(card, p.log))
	seller.Mount(mux)

	srv := &http.Server{Addr: p.addr, Handler: mux}
	go func() {
		p.log.Info().Str("addr", p.addr).Str("ans", p.selfAns).Msg("UCP seller listening")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			p.log.Fatal().Err(err).Msg("ucp seller server exited")
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
	p.log.Info().Msg("ucp seller stopped")
}
```
> Note: `.well-known/ucp` is served by `seller.Mount`; the agent-card handler at `/.well-known/agent-card.json` coexists (different paths).

- [ ] **Step 4: Dispatch ACP vs UCP in `buyFn`** — replace the single `acp.BuyPeer(...)` call inside `buyFn` with card-based dispatch. Replace:
```go
			result, berr := acp.BuyPeer(gctx, http.DefaultClient, mcpCli, disco, selfAns, peer, card)
			if berr != nil {
				return "", "", berr
			}
			return result.PaymentRef, result.Status, nil
```
with:
```go
			var result commerce.BuyResult
			switch {
			case hasExt(card, a2a.ExtACPURI):
				result, berr = acp.BuyPeer(gctx, http.DefaultClient, mcpCli, disco, selfAns, peer, card)
			case hasExt(card, a2a.ExtUCPURI):
				result, berr = ucp.BuyPeer(gctx, http.DefaultClient, mcpCli, disco, selfAns, peer, card)
			default:
				return "", "", fmt.Errorf("seller %q advertises no known commerce protocol", toName)
			}
			if berr != nil {
				return "", "", berr
			}
			return result.PaymentRef, result.Status, nil
```
Change the `berr` declaration accordingly (declare `var berr error` before the switch, or use `result, berr := ...` in each case with `result` predeclared). Add a helper at file scope:
```go
func hasExt(card a2a.Card, uri string) bool {
	if card.Capabilities == nil {
		return false
	}
	for _, e := range card.Capabilities.Extensions {
		if e.URI == uri {
			return true
		}
	}
	return false
}
```
Ensure `commerce` is imported. `acp.BuyPeer` now returns `commerce.BuyResult` (from Task 1), so both branches assign the same type.

- [ ] **Step 5: Build + commit**

Run: `go build ./... && go vet ./cmd/agent/`
```bash
git add cmd/agent/main.go
git commit -m "feat(agent): UCP seller mode and ACP/UCP protocol dispatch in buy trigger"
```

---

## Task 8: Orchestrator wiring — roster, routing, supervisor, UI

**Files:** Modify `internal/orchestrator/roster.go`, `internal/orchestrator/driver.go`, `internal/orchestrator/supervisor.go`, `web/index.html`; Test `internal/orchestrator/roster_test.go`, `internal/orchestrator/driver_test.go`.

- [ ] **Step 1: Failing tests**

Append to `internal/orchestrator/roster_test.go`:
```go
func TestDefaultRosterIncludesUCPSeller(t *testing.T) {
	r := orchestrator.DefaultRoster()
	found := false
	for _, a := range r.Agents {
		if a.Type == "ucp" {
			found = true
			if a.Color != orchestrator.ColorUCP || a.Policy != "ucp" || a.Role != "seller" || a.Authority == "" {
				t.Fatalf("bad ucp seller: %+v", a)
			}
		}
	}
	if !found {
		t.Fatal("expected a UCP seller in the default roster")
	}
}
```
Append to `internal/orchestrator/driver_test.go` (mirror `TestCollideRoutesSellerToBuy`, but with a `ucp`-typed target):
```go
func TestCollideRoutesUCPSellerToBuy(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]string{"greetId": "g1"})
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()
	roster := orchestrator.Roster{Agents: []orchestrator.Agent{
		{Name: "Ada", Role: "greeter-open", Policy: "open", Type: "simple", Addr: addr},
		{Name: "shop-ucp", Role: "seller", Policy: "ucp", Type: "ucp", Addr: "127.0.0.1:1"},
	}}
	book := orchestrator.NewAgentBook(roster, 19998)
	d := orchestrator.NewDriver(book)
	if _, err := d.Collide(context.Background(), "Ada", "shop-ucp"); err != nil {
		t.Fatalf("collide: %v", err)
	}
	if gotPath != "/trigger/buy" {
		t.Fatalf("path = %q, want /trigger/buy", gotPath)
	}
}
```

- [ ] **Step 2: Run — FAIL** (`go test ./internal/orchestrator/ -run 'UCPSeller|UCPSellerToBuy' -v`).

- [ ] **Step 3a: Roster** (`internal/orchestrator/roster.go`)
- Add to the color const block: `ColorUCP = "#3fb950" // UCP seller -> green`
- Add a `mkAgent` switch case:
```go
	case "ucp":
		a.Type, a.Color = "ucp", ColorUCP
```
- Add after `mkSeller`:
```go
// mkUCPSeller builds a UCP seller that trusts the named authority for AP2 mandates.
func mkUCPSeller(name, addr, authority string) Agent {
	a := mkAgent(name, "seller", "ucp", addr)
	a.Protocol = "ucp"
	a.Authority = authority
	return a
}
```
- In `DefaultRoster()` append: `mkUCPSeller("Ugo", "127.0.0.1:18208", "authority-1"),`

- [ ] **Step 3b: Driver routing** (`internal/orchestrator/driver.go`) — extend the seller checks to include `ucp`:
  - initiator guard: `if fromAgent.Policy == "authority" || fromAgent.Type == "acp" || fromAgent.Type == "ucp" {`
  - target routing: `if toAgent.Type == "acp" || toAgent.Type == "ucp" {` → `/trigger/buy`.

- [ ] **Step 3c: Supervisor** (`internal/orchestrator/supervisor.go`) — the seller branch of `greeterArgs` handles both policies. Replace the `if a.Policy == "acp" {` seller branch condition with `if a.Policy == "acp" || a.Policy == "ucp" {` and pick the flag:
```go
	if a.Policy == "acp" || a.Policy == "ucp" {
		payment := s.sellerPayment
		if payment == "" {
			payment = "stripe"
		}
		protoFlag := "--acp"
		if a.Policy == "ucp" {
			protoFlag = "--ucp"
		}
		return []string{
			"--name", a.Name, "--role", a.Role, "--addr", a.Addr,
			"--registry", "http://" + s.registry, protoFlag, "--payment", payment,
			"--authority-role", "authority", "--authority-name", a.Authority,
			"--events",
		}
	}
```

- [ ] **Step 3d: UI** (`web/index.html`)
- `:root` add `--ucp: #3fb950;`.
- `COL` add `ucp:'#3fb950'`; `LABEL` add `ucp:'ucp seller'`; `POLICY2TYPE` add `ucp:'ucp'` (the `seller` key already maps to `acp`; leave it — the roster now sends `type:"ucp"` directly for UCP sellers, and `POLICY2TYPE['ucp']='ucp'`).
- Add `STEP` entries:
```js
  'profile.read':        {title:'read UCP profile · /.well-known/ucp', explain:'buyer discovers the handler, endpoints, authority, and seller signing key', kind:'msg'},
  'terms.verify':        {title:'verify signed terms',                 explain:'buyer checks the seller cryptographically signed these exact terms',       kind:'chk'},
  'session.update':      {title:'update session · fulfillment',        explain:'seller adds shipping and re-signs the new total',                          kind:'msg'},
  'checkout.acquire':    {title:'acquire CheckoutMandate · MCP',       explain:'authority signs an AP2 mandate over this cart state',                      kind:'msg'},
  'payment.acquire':     {title:'acquire PaymentMandate · MCP',        explain:'authority signs an AP2 mandate authorizing the payment',                   kind:'msg'},
  'tokenize':            {title:'tokenize · handler',                  explain:'buyer exchanges a credential for a scoped token bound to this checkout',   kind:'msg'},
  'token.issue':         {title:'issue payment token',                 explain:'handler mints an opaque token with an allowance bound to the checkout',    kind:'chk'},
  'token.verify':        {title:'verify payment token',                explain:'seller confirms the token is its own, bound, and covers the amount',       kind:'chk'},
  'checkout.mandate.verify': {title:'verify CheckoutMandate',          explain:'seller checks the AP2 checkout mandate signature',                         kind:'chk'},
  'payment.mandate.verify':  {title:'verify PaymentMandate',           explain:'seller checks the AP2 payment mandate signature',                          kind:'chk'},
```
(If any of these keys already exist, replace rather than duplicate.)
- In `modelFromEvents`, extend the `msg`-kind peer block:
```js
    if (meta.kind === 'msg') {
      if (e.step === 'mandate.acquire' || e.step === 'spend.acquire' || e.step === 'checkout.acquire' || e.step === 'payment.acquire') peer = (e.detail && e.detail.authority) || 'authority';
      else if (e.step === 'charge') peer = 'Stripe';
      else if (e.step === 'tokenize') peer = 'handler';
      else peer = (actor === it.from) ? it.to : it.from;
    }
```
(Collision `canInit` already restricts initiators to simple/nonce/token, so UCP sellers are targets only — no change. The hub already sets verdict on `receipt`/`purchase.rejected`.)

- [ ] **Step 4: Run tests + build** (`go test ./internal/orchestrator/ -v && go build ./...`). Validate the JS with `node --check` on the extracted `<script>` (as in P8 Task 10) or careful review.

- [ ] **Step 5: Commit**
```bash
git add internal/orchestrator/roster.go internal/orchestrator/roster_test.go internal/orchestrator/driver.go internal/orchestrator/driver_test.go internal/orchestrator/supervisor.go web/index.html
git commit -m "feat(orchestrator+ui): UCP seller in roster, buy routing, green ledger"
```

---

## Task 9: Integration test — end-to-end UCP purchase

**Files:** Create `internal/integration/p9_test.go`.

- [ ] **Step 1: Write the test** — mirror `internal/integration/p8_test.go` exactly (same binary-build helper, `sup.WithSellerPayment("fake")`, port range 195xx to avoid clashes), swapping the seller for a UCP one and asserting a UCP-specific event is present.
```go
package integration

import (
	"context"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/orchestrator"
)

func mkUCPSellerT(name, addr, authority string) orchestrator.Agent {
	return orchestrator.Agent{Name: name, Role: "seller", Policy: "ucp", Type: "ucp", Color: orchestrator.ColorUCP, Addr: addr, Protocol: "ucp", Authority: authority}
}

func TestP9_UCPPurchaseEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: spawns real processes")
	}
	binDir := buildMeshBinaries(t) // REUSE the exact helper p8_test.go uses; match its name.

	roster := orchestrator.Roster{Agents: []orchestrator.Agent{
		mkAuthorityT("authority-1", "127.0.0.1:19510"), // reuse p8's authority helper name
		mkOpenT("Ada", "127.0.0.1:19501"),              // reuse p8's open-greeter helper name
		mkUCPSellerT("Ugo", "127.0.0.1:19502", "authority-1"),
	}}

	log := zerolog.Nop()
	hub := orchestrator.NewHub(log)
	sup := orchestrator.NewSupervisor(binDir, "127.0.0.1:19590", "127.0.0.1:19591", roster, hub, log)
	sup.WithSellerPayment("fake")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("start mesh: %v", err)
	}
	defer sup.Stop()

	book := orchestrator.NewAgentBook(roster, 19600)
	driver := orchestrator.NewDriver(book)
	greetID, err := driver.Collide(ctx, "Ada", "Ugo")
	if err != nil {
		t.Fatalf("collide: %v", err)
	}

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		it, ok := hub.Interaction(greetID)
		if ok && it.Verdict == "accepted" {
			// assert the UCP path actually ran
			for _, e := range it.Events {
				if e.Step == "terms.verify" || e.Step == "tokenize" {
					return
				}
			}
			t.Fatalf("accepted but no UCP-specific event; steps=%d", len(it.Events))
		}
		time.Sleep(150 * time.Millisecond)
	}
	it, _ := hub.Interaction(greetID)
	t.Fatalf("purchase did not complete; verdict=%q reason=%q events=%d", it.Verdict, it.Reason, len(it.Events))
}
```
> **Implementer:** open `internal/integration/p8_test.go` first and reuse its exact helper names for building binaries and constructing the authority/open-greeter agents (`buildMeshBinaries`, `mkAuthorityT`, `mkOpenT` are placeholders here — use whatever p8_test.go actually calls them; if p8 inlines them, inline the same way). Ports here are 195xx/196xx to avoid overlap with p0–p8.

- [ ] **Step 2: Run** (`go test ./internal/integration/ -run TestP9_UCP -v`) — expect PASS (real processes, ~6s). Then `go test ./... -short` (skips it) and `go test ./...` (full, all pass) and `go build ./... && go vet ./...`.
- [ ] **Step 3: Commit**
```bash
git add internal/integration/p9_test.go
git commit -m "test(integration): end-to-end UCP purchase with fake payment backend"
```

---

## Self-Review

**1. Spec coverage**

| Spec section | Task(s) |
| --- | --- |
| §4.1 shared `internal/commerce` refactor | Task 1 |
| §4.2 AP2 claim types + UCPCompletion | Task 2 |
| §4.3 authority two mandate tools | Task 3 |
| §4.4 UCP guard (both mandates, fail closed) | Task 4 |
| §4.5 UCP seller (profile, catalog, create/update, signed terms, tokenize, complete) | Task 5 |
| §4.6 UCP buyer driver (discover, verify terms, dual mandates, tokenize, complete) | Task 6 |
| §4.7 `ExtUCPURI` | Task 6 (added), Task 7 (advertised) |
| §4.8 cmd/agent UCP seller + ACP/UCP dispatch | Task 7 |
| §4.9 orchestrator roster/driver/supervisor + UI | Task 8 |
| §5 `/.well-known/ucp` profile | Task 5 (served), Task 6 (consumed) |
| §6 data flow | Tasks 5–7; Task 9 verifies end-to-end |
| §7 testing | each task's tests; Task 9 integration; Task 1 keeps ACP suite green |
| §8 risks (refactor blast radius, seller-hosted handler, live-by-default, secret/idempotency, one authority) | Task 1 gate; documented in code/spec |
| §9 defaults | Tasks 5/6/8 (update step, one authority, seller-hosted tokenize, green, shared commerce) |

**2. Placeholder scan:** No TODO/TBD in code. The only intentional placeholders are the integration-harness helper names in Task 9 (`buildMeshBinaries`/`mkAuthorityT`/`mkOpenT`), explicitly flagged to be replaced with p8_test.go's real names — the same approach P8's Task 11 used successfully.

**3. Type consistency:** `commerce.{Item,DefaultCatalog,LowestPriced,PaymentPrimitive,ChargeRequest,ChargeResult,StripePaymentIntent,FakePayment,HeaderGreetID,BuyResult}` (Task 1) are used consistently in Tasks 5/6/7 and in the re-pointed ACP code. `domain.{ScopeCheckout,ScopePayment,CheckoutMandateClaims,PaymentMandateClaims,UCPCompletion}` (Task 2) match Tasks 3/4/5. `authority.{IssueCheckoutMandate,IssuePaymentMandate,CheckoutMandateMCPTool,PaymentMandateMCPTool}` (Task 3) match Task 6's MCP tool names (`issue_checkout_mandate`/`issue_payment_mandate`) and the driver's calls. `policy.NewUCP`/`UCP.Verify` (Task 4) match Task 5's seller. `ucp.{NewSeller,SellerConfig,Seller.Mount,BuyPeer}` and the shared unexported `checkoutTerms` (Tasks 5/6) are one package. `a2a.ExtUCPURI` (Task 6) matches Tasks 7/8. `orchestrator.{ColorUCP,mkUCPSeller}` + `Agent.Type=="ucp"` routing (Task 8) match Task 9's roster. The `checkoutSignature`/mandate amounts use the **post-update** amount consistently (driver acquires mandates + tokenizes after the update; guard/seller compare against the current session amount).
