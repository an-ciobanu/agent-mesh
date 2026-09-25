# agent-mesh — Design Spec

**Date:** 2026-09-25
**Status:** Approved for planning
**Module:** `github.com/an-ciobanu/agent-mesh`
**Language:** Go

## 1. Summary

`agent-mesh` is a local, provable demo of AI agents that discover and
communicate with each other **without any of them hardcoding who they talk
to or how**. Agents are shown in a browser as circles; when two circles
collide, an interaction ("greet") happens between them. Each agent learns a
peer's location from a **registry** and learns *how to call that peer* — and
what authorization it must present — by reading the peer's **A2A Agent Card**
at runtime. Every meaningful interaction is sealed to a **transparency log**
via SCITT, so an independent auditor can verify what happened.

The point being demonstrated: a single **generic communication module**,
identical in every agent, handles all communication regardless of who is
talking to whom. Agents differ only by a small pluggable policy.

This is **local development only**. Online ANS registration, DNS publication,
and certificate issuance are explicitly out of scope for this phase (see
§11 Backlog).

## 2. Goals and non-goals

### Goals
- One **base agent** binary; agent *type* is a small pluggable `GreetPolicy`,
  not a separate codebase.
- A **generic communication module** reused unchanged by every agent: no
  agent contains another agent's rules.
- Three greet types, each mapped to **existing standards** (not bespoke
  formats): simple, mandate-gated, nonce-gated.
- **Real cryptography from the start**: Ed25519 identity, P-256 DPoP
  proof-of-possession, signed mandates, SCITT statements/receipts.
- **Registry-based discovery** ("mimic the internet"): agents find each other
  by search, not by configuration.
- **Auditability**: meaningful events sealed to a transparency log; an
  auditor independently verifies from public evidence.
- A **circles-collision UI** as the final phase, on top of a comms layer that
  already works headlessly.
- Every phase is **provable** (integration test + demo script) before the
  next begins.

### Non-goals (this phase)
- ANS registry registration, DNS publication, certificate issuance / mTLS.
- Production deployment, multi-host networking, or persistence beyond what a
  local demo needs.
- A bespoke "interaction guide" document — superseded by the A2A Agent Card
  (see §5.2).

## 3. Protocol decisions (settled)

- **Transport:** real HTTP over loopback. One orchestrator binary can spin up
  N agents, each a real HTTP endpoint on its own port. (Chosen over
  in-process channels and over separate OS processes.)
- **Standard split:** **A2A** carries agent-to-agent interaction (the greet);
  **MCP** exposes capability tools (`issue_mandate`, `get_nonce`, `audit`).
- **"How to call me" lives in the A2A Agent Card**, not a separate document.
  This is validated by both standards:
  - The A2A Agent Card declares auth requirements via `securitySchemes` /
    `security` (API key, HTTP bearer, **OAuth2**, OpenID Connect, mutual TLS),
    and custom needs via `capabilities.extensions`
    (`AgentExtension{uri, description, required, params}`).
  - ANS builds on the A2A Agent Card (ANS-6 has verifiers fetch and hash the
    card; the card digest is sealed into DNS under the default discovery
    profile) rather than defining its own call-guide. ANS-6 §7.8: *"ANS proves
    **who**; OAuth 2.0 grants **what**."* — a mandate is a DPoP-bound OAuth
    access token; a nonce is an RFC 9449 DPoP proof (ANS-6 "Method B").
- **Crypto fidelity:** real from the start.

## 4. Architecture

One base agent binary, configured by role. Everything reusable lives in the
generic communication module; the only per-type difference is a pluggable
`GreetPolicy`. Hexagonal (domain / port / adapter), per the workspace ANS
conventions.

```
        ┌──────────── REGISTRY (separate service) ────────────┐
        │ register(name, role, baseURL, cardURL)               │
        │ search(role | capability) → peers[]                  │
        └──────────────────────────────────────────────────────┘

  ┌─ CORE (domain) ─────────────────────────────────────────────┐
  │ Agent runtime · Identity (ANS name + keys) · GreetPolicy port│
  └─────────────────────────────────────────────────────────────┘
                    │ ports │
  ┌─ GENERIC COMMS MODULE (identical everywhere) ───────────────┐
  │ • Discovery        → registry client (find peers)           │
  │ • A2A              → serve Agent Card + message/send (c+s)   │
  │ • MCP              → /mcp tools (client + server)            │
  │ • Crypto           → Ed25519 identity · P-256 DPoP · mandate │
  │ • Guard            → inbound verifier (enforce own card)     │
  │ • Requirements resolver → read peer card, satisfy security   │
  │ • Transparency     → seal SCITT statements, store receipts   │
  └─────────────────────────────────────────────────────────────┘

  Per-type difference = a GreetPolicy plug-in:
    Open      → card security: []                       (greet anyone)
    Mandate   → card security: OAuth2(tokenUrl=authority)
    Nonce     → card security: DPoP required
    Authority → exposes OAuth2 token endpoint / MCP issue_mandate
    Auditor   → MCP audit tool; no auth
```

**No-hardcoding property:** the requirements resolver derives a peer's
requirements from *that peer's Agent Card at runtime*. No agent carries
another agent's rules.

## 5. Components

### 5.1 Base agent
- Loads a role config (identity, keys, which `GreetPolicy`, which capability
  tools to expose).
- Registers itself with the registry at startup.
- Serves its A2A Agent Card and, if applicable, MCP tools.
- Runs the generic comms module for all inbound/outbound interaction.

### 5.2 Generic communication module
- **Discovery** — registry client: `register`, `search`.
- **A2A** — serves `/.well-known/agent-card.json`; implements `message/send`
  (JSON-RPC) as both client and server for the greet.
- **MCP** — `/mcp` JSON-RPC 2.0 `tools/call`, client and server.
- **Crypto** — key management and all signing/verification (see §7).
- **Guard** — inbound verification pipeline that enforces *this* agent's own
  card-declared security before the greet is accepted.
- **Requirements resolver** — fetches a peer's Agent Card, interprets its
  declared `security` (e.g. an OAuth2 scheme whose `tokenUrl` is the
  authority), obtains the needed credentials, and attaches them to the greet.
- **Transparency** — submits SCITT signed statements and stores returned
  receipts (behind the `Transparency` port, §8).

### 5.3 Registry (separate service)
- Minimal discovery only. Agents `register(name, role, baseURL, cardURL)`;
  callers `search(role | capability)` and get back peers.
- Full ANS registration/trust machinery is deferred.

### 5.4 Transparency log (separate service)
- In-repo **minimal SCITT** transparency service: accepts COSE_Sign1 signed
  statements, appends to an append-only Merkle log, returns COSE
  inclusion-proof receipts, serves a checkpoint. Scoped to greet / mandate /
  nonce events. See §8 for the swap-to-`ans-tl` seam.

### 5.5 Roles
- **Initiator** — starts a greet; runs the requirements resolver.
- **Open / Mandate / Nonce greeter** — the three types; differ only by the
  security their Agent Card declares.
- **Authority** — issues scoped, DPoP-bound mandates after a policy check
  (OAuth2 token endpoint + MCP `issue_mandate`).
- **Auditor** — verifies an evidence bundle against the transparency log; no
  auth ("anyone can request an audit").

## 6. Interaction flows

### 6.1 Mandate greet (richest path)
1. Greeter **B** registers with the registry at startup.
2. Initiator **A** searches the registry → B's `baseURL` + `cardURL`.
3. A fetches B's Agent Card → sees `security: OAuth2(tokenUrl = Authority)`.
   *(A had no prior knowledge of B's rules.)*
4. A calls the **Authority** for a scoped, DPoP-bound mandate (sends its DPoP
   public key). Authority runs a policy check, signs the mandate (Ed25519),
   and **seals a SCITT statement "mandate issued"** → receipt.
5. A builds a DPoP proof (P-256, single-use `jti`, fresh `iat`).
6. A calls B (A2A `message/send`) with the greet, `Authorization: DPoP
   <mandate>`, and the DPoP proof. B's **Guard** verifies: authority
   signature, `audience == B`, freshness, DPoP thumbprint `== mandate jkt`,
   `jti` unused. B greets back and **seals "greet completed"** → receipt.
7. The **Auditor**, given the evidence bundle (mandate + greet + receipts),
   verifies signatures + inclusion proofs against the log checkpoint and
   returns a signed verdict.

### 6.2 Simple greet
Steps 1–3, then A → B greet (identity-signed); B greets back and seals.
Card `security: []`.

### 6.3 Nonce greet
Steps 1–3, then A → B hello; B → A challenge (nonce); A → B DPoP
proof-of-possession over the nonce; B verifies (single-use), greets back,
seals. Card `security: DPoP`.

## 7. Cryptography and wire format

### Keys (per agent)
- **`ans-identity` (Ed25519)** — "who is asking": signs request JWS, signs the
  agent's own card, and (role-dependent) signs mandates (authority), SCITT
  statements/receipts (TL), audit verdicts (auditor). Public key published in
  the card / a `trust-card.json` (JWK + `kid`), fetchable by peers.
- **`dpop` (P-256)** — the initiator's per-session key: mandate is bound to
  its thumbprint (`jkt`); the DPoP proof demonstrates possession.

### Wire
- **A2A** — Agent Card at `/.well-known/agent-card.json` declaring
  `securitySchemes`/`security`; greet via `message/send` JSON-RPC POST.
- **MCP** — `/mcp` JSON-RPC 2.0 `tools/call`: authority `issue_mandate`,
  nonce-greeter `get_nonce`, auditor `audit`.
- **Mandate** — Ed25519-signed token: `mandate_id`, `subject_ans`,
  `audience_ans`, `scope`, `max_amount`, `currency`, `not_before`,
  `not_after`, `jkt`, `authority_ans`, `signature`. Presented as
  `Authorization: DPoP <mandate>`.
- **DPoP** — RFC 9449 compact JWS in the `DPoP` header (ES256), with
  `htm`/`htu`/`ath`, single-use `jti`, fresh `iat`. The nonce-greeter's
  challenge is carried in the proof; single-use enforced by a replay cache.
- **SCITT** — signed statement = COSE_Sign1 over the event payload; the TL
  returns an inclusion-proof receipt.

## 8. Port seams (what swaps later, with zero agent-code change)

| Port | Now (local dev) | Later (online + deployed) |
|---|---|---|
| `Transparency` | minimal in-repo SCITT service | real ANS `ans-tl` adapter (actual traceability) |
| `Discovery` | local registry service | ANS registry adapter |
| `KeyManager` | file-based keys | KMS |
| `GreetPolicy` | `open` / `mandate` / `nonce` plug-ins | (unchanged) |
| Identity / cert issuance | self-signed keys | ANS registration + certs / mTLS |

The transparency swap is a stated near-term follow-up: once agents are
registered online and deployed, the `Transparency` port is repointed at
`ans-tl` for real, externally verifiable traceability.

## 9. Project layout

```
cmd/
  agent/          # base agent binary — role via config/flag
  registry/       # discovery service
  transparency/   # minimal SCITT transparency-log service
  meshctl/        # orchestrator/CLI: spawn a mesh + run a demo scenario headless
internal/
  domain/         # agent core, identity, greet, mandate, ports
  crypto/         # ed25519, dpop(p256), jws, cose, mandate sign/verify, scitt
  comms/
    a2a/          # agent card serve+client, message/send
    mcp/          # tools server+client
    discovery/    # registry client (adapter)
    transparency/ # scitt client (adapter): submit statement, store receipt
    guard/        # inbound verifier pipeline
    resolver/     # read peer card, satisfy declared security
  policy/         # greet policies: open, mandate, nonce (+ authority, auditor)
  registry/       # registry service impl
  tl/             # minimal SCITT transparency service impl
config/           # per-role local-dev config
spec/             # agent card + mandate + SCITT statement schemas (JSON Schema / OpenAPI)
scripts/demo/     # end-to-end scenario scripts
web/              # FINAL phase: circles-collision UI + orchestrator WebSocket (deferred)
```

## 10. Phasing (Approach 1 — vertical slice)

Each phase is proven by an integration test + demo script before the next.

- **P0 — Scaffold & discovery.** Repo, `go.mod`, Makefile / `make check`,
  config, keys, identity, agent-card serve, registry service + discovery
  client. *Prove:* an agent registers and is discoverable.
- **P1 — Simple greet.** A2A `message/send`, identity-signed greet, resolver
  reads peer card (`security: []`). *Prove:* end-to-end greet.
- **P2 — Transparency.** `Transparency` port + minimal SCITT service; seal
  "greet completed"; auditor verifies receipt. *Prove:* valid signed verdict.
- **P3 — Mandate greet.** Authority role (MCP `issue_mandate` + OAuth2 token
  endpoint), mandate sign/verify, resolver follows the card's OAuth2 pointer,
  guard enforces; seal "mandate issued."
- **P4 — Nonce greet.** DPoP challenge / proof-of-possession + replay cache.
- **P5 (final) — UI.** Circles + browser physics; collision → trigger a greet
  → WebSocket event stream visualizes the interaction, receipts, and verdicts.

## 11. Testing

- TDD throughout (workspace convention).
- Unit tests: `internal/domain` and `internal/crypto` target ~100% of
  statements; overall ≥90% via `make test-cover`.
- Integration tests: spin registry + TL + agents on loopback; assert each
  greet type produces the correct receipt and a valid auditor verdict.
- `scripts/demo/` as end-to-end scenarios; `meshctl demo` runs the whole mesh
  headless and prints the transcript + receipts.
- `make check` (fmt + vet + lint + coverage) green before every commit.

## 12. Backlog / open items

- Migrate the `Transparency` port from the minimal in-repo SCITT service to
  the real ANS `ans-tl` for external traceability (near-term, once online).
- ANS registry registration, DNS publication, identity/server certificate
  issuance and mTLS (`Discovery` + identity ports).
- Cloud KMS for `KeyManager`.
- Multi-host deployment (upgrade from one-host-many-endpoints to separate
  processes/hosts).

## 13. Reference

The live agents at `anciobanu.com` (buyer / seller / authority / auditor) are
a working precedent for the crypto, mandate, and DPoP patterns and are used as
an implementation reference. `agent-mesh` deliberately differs from them in
two ways: it uses the **standard A2A/MCP split** (they route everything over
MCP), and it advertises requirements **in the A2A Agent Card** (they used a
custom interaction-guide document).
