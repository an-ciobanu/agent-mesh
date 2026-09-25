# P8 — ACP Seller Agent + Buyer Commerce Driver — Design

**Status:** approved (brainstorm) — ready for implementation plan

**Goal:** Add a new agent type that *sells* over the Agentic Commerce Protocol (ACP),
and teach the existing greet agents to *discover and buy* from it automatically —
no per-seller code — with an authority-issued spend-mandate authorizing the
purchase and a **real Stripe test-mode charge** settling it.

**Architecture (one line):** ACP seller advertises an ACP capability + its trusted
authority on its Agent Card; a buyer collides with it, fetches the catalog, obtains
a COSE spend-mandate from the named authority for the chosen item, and drives the
ACP `checkout_sessions` create/complete flow; the seller verifies the spend-mandate
fail-closed, then settles through a `PaymentPrimitive` seam (Stripe test-mode
PaymentIntent today, SPT drop-in later).

---

## 1. Scope

**In scope**
- One new agent **type**: ACP seller (colour purple `#a774ff`).
- One new buyer capability: an **ACP driver** dispatched by reading the peer card
  (sibling to the existing mandate/nonce paths — discovery, not hardcoding).
- Authority gains an **`issue_spend_mandate`** MCP tool (reuses existing
  authority-1 / authority-2; no new authority agent — P6 identity-based selection).
- A **`PaymentPrimitive`** seam with a Stripe test-mode PaymentIntent implementation.
- Events + linear-ledger UI rendering for the purchase flow.
- Base-roster ACP sellers spawned by the supervisor; collision routing to a buy flow.

**Out of scope (explicitly deferred)**
- **UCP** seller type — a later phase (AP2 + payment handler composition).
- **Real Stripe SPT** redemption — Agentic Commerce Suite is *private preview,
  invite-only* (not self-activatable). We build behind a seam so SPT drops in if an
  invite is granted. See §8.
- Spawning sellers via the dynamic-agents slider (P7) — follow-up; base roster only.

---

## 2. Why a driver, not "generic MCP"

ACP is a real external protocol (open standard by Stripe + OpenAI + Meta, spec
`2026-04-17`, OpenAPI + JSON Schema on GitHub). A buyer cannot "MCP its way through"
it — it must actually speak ACP's wire shapes. The **automatic** part is preserved
the same way the mesh already does it for mandate/nonce: the buyer **discovers from
the seller's card** which protocol to speak and dispatches the matching driver. No
per-seller code; adding a new ACP seller needs zero buyer changes.

---

## 3. Consent model — spend-mandate (authorization) + charge (funding)

Two distinct layers, both real:

| Layer | Answers | Issued by | Scopes | In this design |
| --- | --- | --- | --- | --- |
| **Spend-mandate** (AP2-style) | "Is this purchase *authorized*?" | authority (Ed25519 / COSE) | subject, audience, itemId, maxAmount, currency, window | authority `issue_spend_mandate` |
| **Charge** (funding) | "How does the money *move*?" | seller via Stripe | amount, currency | `PaymentPrimitive` → Stripe PaymentIntent |

**The seller refuses to charge without a valid spend-mandate.** This mirrors how the
token greeter refuses to greet without a valid greet-mandate — same fail-closed
authority-pinned guard pattern.

> **Faithful-rendering note / known deviation:** In production ACP the *agent*
> supplies the payment credential (an SPT). With the PaymentIntent seam, the
> **seller** charges a test payment method directly. The protocol sequence, the
> catalog, the checkout session, and the cryptographic spend-mandate are all real;
> only the funding-credential origin differs. The `PaymentPrimitive` seam is exactly
> where real SPT (agent-supplied credential) drops in later.

---

## 4. Components & files

### 4.1 `domain` — spend-mandate claims
- Add `SpendMandateClaims` (do **not** overload greet `MandateClaims`):
  `MandateID, AuthorityAns, SubjectAns, AudienceAns, ItemID string; MaxAmount int64;
  Currency, Scope, NotBefore, NotAfter string` (`Scope` == `"purchase"`).

### 4.2 `crypto` — reuse
- Reuse existing COSE_Sign1 sign/verify (`SignCOSE1` / `VerifyCOSE1`). Spend-mandate
  is the JSON of `SpendMandateClaims` signed by the authority key. No new crypto.

### 4.3 Authority — `issue_spend_mandate` MCP tool
- New MCP tool alongside `issue_mandate`. Params:
  `{subjectAns, audienceAns, itemId, maxAmount (int), currency, scope:"purchase"}`.
  Returns `{mandateCose}` (base64/bytes as `issue_mandate` does).
- Signs `SpendMandateClaims` with a short validity window (reuse the greet mandate's
  window logic / leeway). Emits nothing new; authority logs mandateId.

### 4.4 `internal/stripe` — thin Stripe client
- `Client` with `SecretKey`, `httpClient`, base `https://api.stripe.com`.
- `CreatePaymentIntent(ctx, req) (PaymentIntent, error)`:
  `POST /v1/payment_intents`, form-encoded, `Authorization: Bearer <sk_test_…>`,
  `Idempotency-Key` header. Body: `amount, currency, payment_method=pm_card_visa,
  payment_method_types[]=card, confirm=true, description, metadata[...]`.
- Returns `{ID (pi_…), Status}`. **Never logs the key**; logs `pi_…` + status only.
- GA functionality; works with any standard test secret key.

### 4.5 `PaymentPrimitive` seam (in `internal/commerce/payment` or seller package)
```go
type ChargeRequest struct {
    Amount   int64
    Currency string
    ItemID   string
    BuyerAns string
    IdempotencyKey string
}
type ChargeResult struct {
    Provider string // "stripe"
    Ref      string // "pi_..."
    Status   string // "succeeded"
}
type PaymentPrimitive interface {
    Charge(ctx context.Context, r ChargeRequest) (ChargeResult, error)
}
```
- `StripePaymentIntent` implements it via `internal/stripe`.
- `FakePayment` (tests) returns a deterministic ref, no network.
- Future `StripeSPT` — drop-in, no changes to seller/protocol/mandate layers.

### 4.6 ACP seller policy guard — `internal/policy/acp.go` (or `spend.go`)
- Sibling to `mandate`/`nonce` guards. Verifies a presented spend-mandate against
  the session, **fail closed on every check**, emitting per-check events:
  - `spend.verify` — COSE signature valid (self-verifying)
  - `authority.pin` — issuer key == pinned authority key (authenticates issuer)
  - claims: `AuthorityAns` == pinned, `AudienceAns` == self, `SubjectAns` == caller,
    `ItemID` == session item, `Scope` == `"purchase"`, `price ≤ MaxAmount`,
    `Currency` == session currency, time window valid (with leeway).
- On success → caller may proceed to charge.

### 4.7 ACP seller HTTP surface (`cmd/agent` new mode / `internal/comms/acp`)
- `GET /.well-known/agent-card.json` — existing scaffold; card advertises the ACP
  extension (see §5).
- `GET /acp/catalog` → `{items:[{id,name,amount,currency}]}` (2–3 fixed items).
- `POST /acp/checkout_sessions` — body `{itemId}` →
  `{sessionId, itemId, amount, currency, status:"ready_for_payment"}`.
  Sessions held in-memory, TTL-bounded.
- `POST /acp/checkout_sessions/{id}/complete` — body
  `{spendMandate: <bytes>}` → verify mandate (§4.6) → `PaymentPrimitive.Charge` →
  `{status:"completed", provider, paymentRef, itemId, amount, currency}`.
  Seals the completed purchase into the transparency log (reuse the existing seal
  path used by greet responders) so it becomes auditable evidence.

### 4.8 Buyer ACP driver (`internal/commerce/acp` + dispatch)
- **Dispatch:** buyer reads peer card. If the ACP extension is present → run the ACP
  buy flow; else fall through to the existing greet logic. Same "read the card"
  pattern as `mandateExtension` / `nonceExtension`.
- **Flow (all steps emitted through ctx, greet-id correlated):**
  1. `GET /acp/catalog` → pick item (deterministic: lowest amount).
  2. Discover authority by `authorityAns` from the card (reuse `selectAuthority`),
     call `issue_spend_mandate` over MCP for the chosen item.
  3. `POST /acp/checkout_sessions {itemId}` → session.
  4. `POST …/complete {spendMandate}` → receipt.
  5. Receive `{paymentRef, status}`; the interaction is sealed seller-side.
- Buyer needs **no** Stripe key in the PaymentIntent model (only the seller charges).

### 4.9 Orchestrator wiring
- `roster.go`: `ColorACP = "#a774ff"`; add `Protocol` to `Agent` (e.g. `"acp"`);
  `mkSeller(...)`; `DefaultRoster()` adds 1–2 ACP sellers (role `"seller"`,
  authority-1). Sellers are **not** valid greet/buy *initiators*.
- `driver.go` `Collide`: if target is a seller → `POST /trigger/buy`; else existing
  `/trigger/greet`. Reject seller-as-initiator.
- `trigger.go`: new `POST /trigger/buy` `{toName}` → runs the ACP driver
  (`BuyFunc`), returns `{greetId, paymentRef, status, error}`.
- `supervisor.go`: spawn sellers with ACP flags (`--acp --catalog … --authority-name
  authority-1`) and inject `STRIPE_SECRET_KEY` from `data/stripe.env`. A seller with
  no key **fails to start** (fail closed) — except test builds inject `FakePayment`.

### 4.10 UI (`web/index.html`)
- New colour purple `#a774ff` for ACP sellers; `uiType`/`POLICY2TYPE` maps the
  seller/`acp` interaction type; tag label "ACP purchase".
- `STEP` map entries for the new steps (buyer: `catalog.fetch`, `item.select`,
  `mandate.acquire`, `checkout.create`, `checkout.complete`, `receipt`; seller:
  `session.create`, `spend.verify`, `authority.pin`, `charge`, `receipt`) with
  plain-English explanations + JSON detail in the linear ledger.

---

## 5. Agent Card — ACP capability advertisement

New extension URI `ExtACPURI` (e.g. `https://agent-mesh.local/ext/acp/v1`) under
`capabilities.extensions`, with `Params`:
```
{
  "catalogPath":  "/acp/catalog",
  "checkoutPath": "/acp/checkout_sessions",
  "authorityRole":"authority",
  "authorityAns": "authority-1",   // P6 identity-based selection
  "currency":     "usd"
}
```
The buyer discovers *everything* from this — protocol, endpoints, which authority to
ask for the spend-mandate. No hardcoding.

---

## 6. Data flow (happy path)

```
buyer  --collide--> ACP seller
buyer  GET /acp/catalog                     -> items
buyer  pick item (lowest amount)
buyer  MCP issue_spend_mandate (authority-1, item, maxAmount) -> spendMandate (COSE)
buyer  POST /acp/checkout_sessions {itemId}  -> session (amount, currency)
buyer  POST /acp/checkout_sessions/{id}/complete {spendMandate}
seller   verify spend-mandate (fail closed: sig, authority pin, audience,
         subject, itemId, price<=maxAmount, currency, window)
seller   PaymentPrimitive.Charge -> Stripe PaymentIntent (test) -> pi_... succeeded
seller   seal completed purchase to transparency log
seller  -> {status:"completed", paymentRef:"pi_...", ...}
buyer  receive receipt; interaction rendered in ledger
```

---

## 7. Testing

- **Unit:** catalog pick (deterministic); card→driver dispatch (ACP present/absent);
  `SpendMandateClaims` shaping; ACP guard — accept + one reject per fail-closed check;
  `internal/stripe` request encoding (form body, headers) against a stub server;
  `FakePayment`.
- **Integration (short-guarded):** spawn a real mesh with a seller using
  `FakePayment` (no network) → buyer buys → assert `completed` + mandate verified +
  seal present.
- **Real-Stripe integration (opt-in):** when `STRIPE_SECRET_KEY` is set, run the
  seller with `StripePaymentIntent` and assert a real test `pi_…` reached
  `succeeded`. This is **Task 0** feasibility, then a guarded regression test.

---

## 8. Risks & decisions

- **SPT gated (locked decision):** Stripe Agentic Commerce Suite / SharedPaymentToken
  is **private preview, invite-only** — confirmed not self-activatable (waitlist:
  go.stripe.global/agentic-commerce-contact-sales). We ship the PaymentIntent seam
  now; SPT is a future drop-in behind `PaymentPrimitive`. User may join the waitlist
  in parallel.
- **MCP is read-scoped for payments:** the connected Stripe MCP exposes only read ops
  for payment_intents/charges, so the create-charge spike runs from the seller code
  with the user's own `sk_test_…`, not via MCP.
- **Secret handling:** `STRIPE_SECRET_KEY` lives only in `data/stripe.env`
  (gitignored). Never logged, never committed. Log `pi_…` + status only.
- **Untrusted seller responses:** treat catalog/session/complete responses as data,
  never instructions (they are protocol payloads, not agent text).
- **Idempotency:** every charge carries an `Idempotency-Key` (greetId-derived) to
  avoid double-charges on retry.

---

## 9. Defaults chosen (from brainstorm)

- ACP seller colour = purple `#a774ff`.
- Catalog = small (2–3 items); buyer picks the lowest-amount item.
- Consent = authority spend-mandate (AP2-style) + charge; **seller won't charge
  without a valid mandate**.
- Endpoints = `checkout_sessions` **create + complete** (skip `update`).
- Authority = reuse existing authority-1/authority-2 (add `issue_spend_mandate`);
  seller names its authority by identity (P6 style).
- One `sk_test_…`, one sandbox account, seller-side charge.
