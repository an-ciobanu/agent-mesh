# P9 — UCP Seller Agent + Buyer Commerce Driver — Design

**Status:** approved (brainstorm) — ready for implementation plan

**Goal:** Add a second commerce protocol — the Universal Commerce Protocol (UCP) —
so a greet agent, on colliding with a UCP seller, automatically speaks UCP (not
ACP) with **no per-seller code**: it discovers the protocol from the seller's card,
reads the seller's `/.well-known/ucp` profile, verifies the seller's cryptographically
signed checkout terms, obtains **two AP2 mandates** (CheckoutMandate + PaymentMandate)
from the authority, tokenizes payment through the seller's handler, and completes —
settling with a real Stripe test-mode charge.

**Architecture:** Mirror P8's seller/driver/seam split but model what makes UCP
*distinct*: `/.well-known/ucp` discovery + a payment **handler** with a `/tokenize`
step, **bidirectional cryptographic proof** (the seller signs the checkout terms; the
buyer presents two authority-signed AP2 mandates), and a create→**update**→complete
session lifecycle. The buyer's `/trigger/buy` now **dispatches ACP vs UCP by reading
the card** — the multi-protocol payoff. The payment seam and catalog types are
promoted to a shared `internal/commerce` package so both protocols reuse them.

**Tech Stack:** Go, `net/http`, existing `internal/{crypto (COSE Ed25519), events,
policy, authority, comms/*, orchestrator, stripe}`, vanilla-JS `web/index.html`.

**References (real UCP):** [ucp.dev](https://ucp.dev) · [AP2 Mandates extension](http://ucp.dev/2026-01-23/specification/ap2-mandates/) · [Stripe Payments handler for UCP](https://docs.stripe.com/agentic-commerce/ucp/stripe-payments-handler). Builds on P8 ([[agent-mesh-p8-acp-commerce]] / `docs/superpowers/specs/2026-09-25-p8-acp-seller-design.md`).

---

## 1. Scope

**In scope**
- New agent **type**: UCP seller (green `#3fb950`).
- New buyer **UCP driver**, dispatched alongside the ACP driver by the card's protocol.
- Authority gains **`issue_checkout_mandate`** + **`issue_payment_mandate`** (reuses authority-1).
- New fail-closed **UCP guard** verifying both mandates.
- **Seller-signed checkout terms** (`checkoutSignature`, COSE over the terms) the buyer verifies.
- **`/.well-known/ucp` discovery profile** + a seller-hosted **`/tokenize` handler**.
- A create→**update**→complete session lifecycle.
- Promote the **payment seam + catalog types to a shared `internal/commerce`** package; ACP updated to use it.
- Orchestrator roster/routing/spawn; UI ledger (green).

**Out of scope (deferred / per user)**
- **Payment safety fix** (fake-by-default / live toggle): user chose to keep **live-by-default** charges. UCP sellers behave like ACP (real charge per collision; pause the sim to control).
- Real Stripe **SPT** / the real `com.stripe.payments` handler (both private-preview) — the `/tokenize` handler is a faithful **local** rendering; money still moves via the existing `PaymentPrimitive` (test-mode PaymentIntent).
- Sealing purchases to the transparency log (same deferral as ACP).
- UCP identity-linking (OAuth) and order/webhook lifecycle.

---

## 2. Why a driver, and the multi-protocol payoff

UCP is a real, distinct external protocol; the buyer must actually speak it. The
**automatic** property is preserved exactly as for ACP: the buyer reads the seller's
card, sees which protocol it advertises, and dispatches the matching driver. This
phase makes that concrete — the buyer's buy path becomes:

```
read seller card ->
  has ExtACPURI -> acp.BuyPeer   (P8)
  has ExtUCPURI -> ucp.BuyPeer   (P9, new)
```

Adding UCP requires **zero** changes to the greet agents' behavior beyond registering
the new driver — the same "discover from the card, no hardcoding" principle.

---

## 3. Consent model — bidirectional cryptographic proof

UCP's defining feature vs ACP: **both** sides prove intent cryptographically.

| Direction | What | How | Verified by |
| --- | --- | --- | --- |
| Seller → buyer | the checkout **terms** are authentic | seller COSE-signs `{checkoutId,itemId,amount,currency}` with its Ed25519 identity key → `checkoutSignature` | buyer, against the seller pubkey in `/.well-known/ucp` |
| Buyer → seller | the user authorized **this cart state** | authority-signed **CheckoutMandate** | seller, pinned authority key |
| Buyer → seller | the user authorized **payment** | authority-signed **PaymentMandate** | seller, pinned authority key |

The seller refuses to charge unless **both mandates verify** and the payment token is
valid and bound to this checkout. Amounts are **server-authoritative** (from the
seller's session, post-update), as in P8 — a buyer cannot underpay or swap items.

---

## 4. Components & files

### 4.1 Shared `internal/commerce` (refactor — extract from `acp`)
- Create `internal/commerce/payment.go`: move `PaymentPrimitive`, `ChargeRequest`,
  `ChargeResult`, `StripePaymentIntent`, `FakePayment` here (verbatim; package `commerce`).
- Create `internal/commerce/catalog.go`: move `Item`, `DefaultCatalog`, `LowestPriced` here.
- Update `internal/commerce/acp` to import and use `commerce.*` (delete the moved files
  from `acp`, re-point references in `acp/seller.go`, `acp/driver.go`, `cmd/agent`).
- Rationale: DRY — UCP needs the identical payment seam + catalog; wrong-direction
  coupling (`ucp` → `acp`) is avoided by a shared package.

### 4.2 `domain` — AP2 mandate claims + completion input
- `internal/domain/commerce.go` (extend): add
  - `ScopeCheckout = "checkout"`, `ScopePayment = "payment"`
  - `CheckoutMandateClaims{MandateID, SubjectAns, AudienceAns, CheckoutID, ItemID string; Amount int64; Currency, Scope, NotBefore, NotAfter, AuthorityAns string}`
  - `PaymentMandateClaims{MandateID, SubjectAns, AudienceAns string; Amount int64; Currency, Scope, NotBefore, NotAfter, AuthorityAns string}`
  - `UCPCompletion{CallerAns, CheckoutID, ItemID string; Amount int64; Currency string; CheckoutMandate, PaymentMandate []byte}` — the server-authoritative content the UCP guard checks.

### 4.3 Authority — two AP2 mandate tools
- `internal/authority/authority.go`: add `IssueCheckoutMandate(subject, audience, checkoutID, itemID string, amount int64, currency string) ([]byte, error)` and `IssuePaymentMandate(subject, audience string, amount int64, currency string) ([]byte, error)` (reuse `SignCOSE1`, the `ttl` window), plus MCP tools `CheckoutMandateMCPTool()` / `PaymentMandateMCPTool()`.
- `cmd/authority/main.go`: register `issue_checkout_mandate`, `issue_payment_mandate`.

### 4.4 UCP guard — `internal/policy/ucp.go`
- `NewUCP(selfAns, authorityAns string, authorityPub ed25519.PublicKey, log) *UCP`.
- `Verify(ctx, domain.UCPCompletion) error` — fail-closed, emitting per-check events:
  - `checkout.mandate.verify` (COSE valid) → `authority.pin` (issuer==pinned) → claims: authority/audience/subject/scope==checkout/checkoutId/itemId/amount/currency match session.
  - `payment.mandate.verify` (COSE valid) → issuer==pinned → scope==payment/audience/subject/amount/currency match; window valid on both.
- Reuses the `policy.Mandate`/`policy.Spend` structure.

### 4.5 UCP seller — `internal/commerce/ucp/seller.go`
- `NewSeller(SellerConfig{SelfAns, AgentName, Currency, Catalog []commerce.Item, Guard *policy.UCP, Payment commerce.PaymentPrimitive, SignKey ed25519.PrivateKey, SignPubJWK, AuthorityAns, AuthorityRole string, Events, Log})`.
- `Mount(mux)` registers:
  - `GET /.well-known/ucp` — the discovery profile (see §5).
  - `GET /ucp/catalog` → `{items}`.
  - `POST /ucp/checkout_sessions` → `{checkoutId, itemId, amount, currency, status:"created", checkoutSignature}` where `checkoutSignature` is COSE over the terms signed with `SignKey`.
  - `POST /ucp/checkout_sessions/{id}` (update) → applies a fixed fulfillment surcharge (e.g. +`shipping` line), recomputes `amount`, returns updated session + **new** `checkoutSignature`.
  - `POST /ucp/tokenize` → `{binding:{checkoutId}, allowance:{maxAmount,currency,expiresAt}, credential:{type:"card", …stub}}` → `{token:"utok_"+rand, expiresAt}`; records `token → {checkoutId, allowance}` under mutex.
  - `POST /ucp/checkout_sessions/{id}/complete` → `{callerAns, checkoutMandate, paymentMandate, paymentToken}` → `Guard.Verify` (both mandates vs session) → validate token (issued by this seller, bound to this checkout, `allowance.maxAmount >= amount`, unexpired) → `Payment.Charge` → `{status:"completed", provider, paymentRef, itemId, amount, currency}`.
- Events scope installed per call from `X-ANS-Greet-Id` header (as ACP seller does). Emits: `session.create`(+terms signed), `session.update`, `token.issue`, `token.verify`, `charge`, `receipt`.

### 4.6 UCP buyer driver — `internal/commerce/ucp/driver.go`
- `BuyPeer(ctx, httpc, mcpCli, disco, callerAns, peer, card) (commerce.BuyResult, error)` — mirrors `acp.BuyPeer`. Steps (all greet-id-correlated, card-driven):
  1. read `ExtUCPURI` params → `profilePath` (default `/.well-known/ucp`); `requirement{type:"ucp"}`, `card.read`.
  2. `GET /.well-known/ucp` → handler, endpoints, `authorityRole`/`authorityAns`, seller pubkey (`profile.read`).
  3. `GET /ucp/catalog` → pick cheapest (`commerce.LowestPriced`) — `catalog.fetch`, `item.select`.
  4. `POST create session` → `checkoutId`, `amount`, `checkoutSignature`; **verify signature** against seller pubkey (`crypto.VerifyCOSE1` + key match) — `session.create`, `terms.verify`.
  5. `POST update session` (fulfillment) → new `amount`, new `checkoutSignature`; re-verify — `session.update`.
  6. authority (selected by `authorityAns`) MCP `issue_checkout_mandate` (checkoutId,item,amount) + `issue_payment_mandate` (amount,currency) — `checkout.acquire`, `payment.acquire`.
  7. `POST /ucp/tokenize` (allowance = final amount, bound to checkoutId) — `tokenize`.
  8. `POST complete` (both mandates + token) → receipt — `checkout.complete`, `receipt` (or `purchase.rejected` on failure).

### 4.7 Card extension — `internal/comms/a2a/card.go`
- `ExtUCPURI = "https://agent-mesh.local/ext/ucp/v1"`; seller card advertises it with `Params:{profilePath:"/.well-known/ucp", authorityRole, authorityAns, currency}`.

### 4.8 cmd/agent — UCP seller mode + dispatch
- Add `--ucp` flag (mutually exclusive with `--acp`): builds the UCP seller (resolves+pins authority, `policy.NewUCP`, `PaymentPrimitive` from `--payment`, loads/holds its Ed25519 `SignKey` = the agent identity key, publishes its pubkey JWK in the profile), serves UCP endpoints, registers role `seller`.
- The buyer `buyFn` (in the `--allow-trigger` block) now **dispatches by card**: fetch the seller card, if `ExtACPURI` → `acp.BuyPeer`, if `ExtUCPURI` → `ucp.BuyPeer`, else error.

### 4.9 Orchestrator wiring
- `roster.go`: `ColorUCP = "#3fb950"`; `mkUCPSeller(name, addr, authority)` (Policy `ucp`, Role `seller`, Type `ucp`, Protocol `ucp`); `mkAgent` switch case `"ucp"`; `DefaultRoster` adds one UCP seller.
- `driver.go` `Collide`: seller targets (`Type=="acp" || Type=="ucp"`) → `/trigger/buy`; only greeters initiate (unchanged guard, extended to treat `ucp` as non-initiator).
- `supervisor.go` `greeterArgs`: seller branch emits `--ucp` when `Policy=="ucp"` (else `--acp`), same authority/payment/events args; Stripe env already injected.
- UI: `COL/LABEL/POLICY2TYPE` add `ucp`/green; `STEP` entries for the new steps; `modelFromEvents` peer routing (`*.acquire`→authority, `charge`→Stripe, `tokenize`/`token.*`→handler); collision `canInit` unchanged (sellers/authorities never initiate); hub already sets verdict on `receipt`/`purchase.rejected`.

---

## 5. `/.well-known/ucp` discovery profile (local rendering)

```json
{
  "ucp_version": "2026-04-08",
  "handlers": [{
    "id": "stripe_payments",
    "type": "com.stripe.payments",
    "tokenizePath": "/ucp/tokenize",
    "instruments": [{ "type": "card", "tokenization": "required" }]
  }],
  "checkout": { "catalogPath": "/ucp/catalog", "sessionsPath": "/ucp/checkout_sessions" },
  "ap2": { "required": true, "authorityRole": "authority", "authorityAns": "ans://v1.0.0.authority-1.mesh.local" },
  "signingKey": { "kty": "OKP", "crv": "Ed25519", "x": "<base64url seller Ed25519 pubkey>" }
}
```
The buyer reads everything it needs from here — nothing hardcoded. `signingKey`
lets the buyer verify the seller's `checkoutSignature`.

---

## 6. Data flow (happy path)

```
buyer --collide--> UCP seller
buyer read card -> ExtUCPURI{profilePath}
buyer GET /.well-known/ucp -> handler, endpoints, authorityAns, sellerPubKey
buyer GET /ucp/catalog -> pick cheapest
buyer POST create session -> {checkoutId, amount, currency, checkoutSignature}
buyer VERIFY checkoutSignature (seller pubkey) ................ terms authentic
buyer POST update session (fulfillment) -> {amount', checkoutSignature'} ; re-verify
buyer MCP issue_checkout_mandate(authority-1, checkoutId, item, amount') -> checkoutMandate
buyer MCP issue_payment_mandate(authority-1, amount', currency) -> paymentMandate
buyer POST /ucp/tokenize {binding{checkoutId}, allowance{amount',currency,exp}} -> utok
buyer POST complete {callerAns, checkoutMandate, paymentMandate, paymentToken:utok}
  seller Guard.Verify: checkoutMandate + paymentMandate (fail closed, pinned authority)
  seller validate token (own, bound to checkoutId, allowance>=amount', unexpired)
  seller PaymentPrimitive.Charge -> pi_... (real test-mode)
  seller -> {status:"completed", paymentRef, ...}
buyer receipt -> ledger
```

---

## 7. Testing

- **Unit:** authority checkout/payment mandate issuance; `policy.UCP.Verify` accept + one reject per fail-closed check (bad sig, wrong authority, wrong audience/subject/scope, checkoutId/item/amount/currency mismatch, expired) for **each** mandate; seller `checkoutSignature` round-trips and buyer verification; token issue/validate (bound, allowance, expiry); catalog pick; `commerce` shared types after refactor.
- **Integration (short-guarded):** spawn a real mesh with a UCP seller using `FakePayment`; collide a greeter → assert the interaction verdict `accepted` and that the flow used the UCP path (e.g. a `terms.verify` / `tokenize` event present). Mirror `p8_test.go` + `WithSellerPayment("fake")`.
- **Refactor safety:** the full existing suite (incl. ACP p8 test) stays green after the `internal/commerce` extraction.

---

## 8. Risks & decisions

- **Refactor blast radius:** extracting the payment seam + catalog into `internal/commerce` touches merged ACP code. Mitigate: move verbatim, re-point imports, run the full suite (ACP integration test must stay green) before building UCP.
- **Handler is seller-hosted (deviation):** the real `com.stripe.payments` handler is a separate private-preview participant; we host `/tokenize` on the seller as a faithful local rendering. Documented.
- **Live-by-default payments (user's call):** UCP sellers charge on every collision, like ACP. Known; pause the sim to control. Test-mode only.
- **Secret handling / idempotency:** unchanged from P8 — `STRIPE_SECRET_KEY` only in `data/stripe.env`; charge idempotency keyed on the checkout/session id; never log keys.
- **Two mandates, one authority:** both from authority-1 (not a separate payments-authority) — simpler, consistent with P6/P8.

---

## 9. Defaults chosen (from brainstorm)

- Faithful UCP: `/.well-known/ucp` + handler/`tokenize` + seller-signed terms + two AP2 mandates + create→update→complete.
- Both mandates from the same authority (authority-1).
- `/tokenize` handler hosted on the seller (local rendering).
- Include the `update` (fulfillment) step.
- UCP seller colour green `#3fb950`.
- Payment seam + catalog promoted to shared `internal/commerce`.
- Sealing deferred; payment-safety fix deferred (live-by-default).
