# agent-mesh

A local, visual demo of an **agent-identity + trust stack**. Agents are circles
that drift and bounce on a canvas; when two collide, a **real** agent-to-agent
interaction fires — discovered at runtime from each agent's [A2A](https://github.com/google/A2A)
Agent Card, with **nothing hardcoded** about the other agent's address, keys, or
capabilities. Every meaningful step is emitted as an event and rendered from each
agent's own point of view, and every accepted interaction is **sealed into a
transparency log** and **independently audited** by the caller.

It is a teaching/demo tool, not a product: everything runs on `127.0.0.1`, keys
are generated on first run, and payments use Stripe **test mode**.

---

## What happens on a collision

Depending on the two agents that touch, one of two real flows runs:

**A greet** (greeter → greeter), gated by the target's card:
- **open** — no requirement; just an identity-signed greet.
- **nonce** — the target requires a DPoP proof; the caller fetches a nonce from
  the target's `get_nonce` MCP tool and builds a P-256 proof.
- **token (mandate)** — the target requires a mandate; the caller discovers the
  authority named in the card, requests a mandate over MCP (`issue_mandate`), and
  presents it.

**A purchase** (greeter → seller), gated by the seller's card:
- **ACP** (Agentic Commerce Protocol) — catalog → checkout session → present an
  authority-issued **spend-mandate** → seller charges.
- **UCP** (Universal Commerce Protocol) — `/.well-known/ucp` discovery →
  seller-signed checkout terms → **two** AP2 mandates (checkout + payment) →
  tokenize → seller charges.

**In every case** the responder (and the authority, for each issued mandate)
**seals** a signed statement into the shared transparency log and returns an
inclusion **receipt**; the caller then runs an **audit** step that verifies, against
the log's own key, the issuer signature + the RFC-6962 inclusion proof + the
**log id** (the log's public-key thumbprint, pinned from the receipt). Payments
settle through a real Stripe **test-mode** PaymentIntent.

---

## Prerequisites

| Requirement | Notes |
| --- | --- |
| **Go 1.23+** | builds all binaries (`go version` to check) |
| **macOS or Linux** | developed on macOS; Linux works |
| **A browser** | for the P5 UI demo |
| **A Stripe test secret key** | **only** needed if you want the ACP/UCP sellers (`Shopa`, `Ugo`) to run. See [Stripe setup](#stripe-setup). Without it the two sellers fail to start; the rest of the mesh runs fine. |
| Node.js *(optional)* | only used to sanity-check the UI's inline JS during development |

No database, no external services (besides Stripe in test mode), no network
except `127.0.0.1` and (for commerce) `api.stripe.com`.

---

## Quick start (the visual demo)

```bash
# from the repo root
make build                       # compile every binary into ./bin
./bin/orchestrator               # starts the whole mesh + serves the UI
# then open http://127.0.0.1:18080
```

Or use the helper script, which builds, launches, and opens the browser for you:

```bash
./scripts/demo/p5-ui.sh
```

Press **Ctrl-C** to stop the orchestrator; it shuts down every child process it
spawned. (If a process is ever left behind, see [Troubleshooting](#troubleshooting).)

> **Heads-up on charges:** the orchestrator runs the two sellers with `--payment
> stripe`, so any collision between a bouncing agent and `Shopa`/`Ugo` makes a
> real **test-mode** Stripe charge. This is expected and costs no real money, but
> it will fill your Stripe **test** dashboard. To run without any sellers, simply
> don't provide `data/stripe.env` (the sellers won't start).

### Using the UI

- **Canvas** — agents drift and bounce; a collision triggers a real interaction.
- **Interaction stream** (right) — one row per interaction; click a row to open a
  drawer showing both agents' step-by-step events (discovery, gating, greet/charge,
  seal, audit), including the sealed receipt's entry index and **log id**.
- **agents slider** (top-right) — the **total** number of live agents. The 10 base
  agents are always present (the floor); the slider reveals up to **15** more from
  a fixed, deterministic pool (same cast every run), for a max of 25. It opens with
  5 extra already revealed.
- **speed slider** — 0.2×–3× drift speed.
- **Pause** button / **Spacebar** — freeze the physics to inspect the log.
- **legend** (bottom-left) — the agent types and their colors.

---

## Stripe setup

The ACP/UCP sellers settle with a Stripe test-mode PaymentIntent, so they need a
**test** secret key. Put it in a gitignored env file:

```bash
mkdir -p data
echo 'STRIPE_SECRET_KEY=sk_test_...' > data/stripe.env
```

- Use a key that starts with `sk_test_` — **never a live key.** The file lives under
  `data/`, which is gitignored; the key is never logged (only `pi_…` ids and status
  are).
- The orchestrator reads it via `--stripe-env` (default `data/stripe.env`) and
  injects it into the seller child processes. Without it, the orchestrator logs a
  warning and the two sellers fail to start (fail-closed); everything else runs.
- To exercise commerce **without** Stripe (offline), run a seller manually with
  `--payment fake` (see [Manual / component runs](#manual--component-runs)); the
  `fake` backend returns a deterministic fake payment ref and makes no network call.

---

## Ports

Everything binds `127.0.0.1`. Defaults:

| Port | Component |
| --- | --- |
| 18080 | orchestrator UI |
| 18090 | registry (discovery) |
| 18091 | transparency log |
| 18110 | authority-1 |
| 18111 | authority-2 |
| 18201 | Ada (open) |
| 18202 | Noah (open) |
| 18203 | Zoe (nonce) |
| 18204 | Chris (mandate → authority-1) |
| 18205 | Ema (open) |
| 18206 | Kai (mandate → authority-2) |
| 18207 | Shopa (ACP seller) |
| 18208 | Ugo (UCP seller) |
| 18300–18314 | dynamic agent pool (revealed by the slider) |

The orchestrator **pre-flight checks** all of these before starting and fails
loudly, naming each busy port, if a previous run is still holding one.

---

## The default roster

Always present (the 10 base agents):

| Agent | Type | Notes |
| --- | --- | --- |
| authority-1, authority-2 | authority | issue & seal mandates over MCP |
| Ada, Noah, Ema | open greeter | no gate |
| Zoe | nonce greeter | DPoP proof required |
| Chris | token greeter | trusts authority-1 |
| Kai | token greeter | trusts authority-2 |
| Shopa | ACP seller | trusts authority-1 |
| Ugo | UCP seller | trusts authority-1 |

The slider reveals a fixed, ordered pool of 15 greeters (8 open / 4 nonce / 3
token), identical every run: Luna, Milo, Priya, Theo, Nina, Omar, Sofia, Ravi,
Bao, Tess, Jonas, Iris, Leo, Mia, Zara.

---

## Components & CLI reference

Build all with `make build`; binaries land in `./bin`.

### orchestrator (`bin/orchestrator`)
Spawns the whole mesh (registry, transparency log, authorities, base agents,
initial pool agents) and serves the browser UI.

| Flag | Default | Purpose |
| --- | --- | --- |
| `--addr` | `127.0.0.1:18080` | UI listen address |
| `--bin` | `bin` | directory holding the built binaries |
| `--web` | `web` | directory holding `index.html` |
| `--registry` | `127.0.0.1:18090` | registry address |
| `--transparency` | `127.0.0.1:18091` | transparency log address |
| `--stripe-env` | `data/stripe.env` | KEY=VALUE file with `STRIPE_SECRET_KEY` for sellers |

### agent (`bin/agent`)
One mesh agent — greeter or seller. Key flags:

| Flag | Default | Purpose |
| --- | --- | --- |
| `--name` | *(required)* | unique agent name |
| `--role` | `greeter` | discovery role |
| `--addr` | `127.0.0.1:18101` | listen address |
| `--registry` | `http://127.0.0.1:18090` | registry base URL |
| `--transparency` | *(empty)* | TL base URL; enables sealing of accepted greets / purchases |
| `--policy` | `open` | greet policy: `open` \| `mandate` \| `nonce` |
| `--authority-role` / `--authority-name` | `authority` / *(first)* | which authority to trust (mandate) |
| `--scope` | `greet` | required mandate scope (mandate) |
| `--nonce-ttl` | `2m` | nonce validity window (nonce) |
| `--acp` / `--ucp` | `false` | run as an ACP / UCP seller instead of a greeter |
| `--acp-currency` | `usd` | seller catalog currency |
| `--payment` | `stripe` | seller funding backend: `stripe` \| `fake` |
| `--stripe-key-env` | `STRIPE_SECRET_KEY` | env var holding the Stripe test key |
| `--events` | `false` | emit per-step events as JSON lines to stdout |
| `--allow-trigger` | `false` | expose `POST /trigger/greet` (demo driver) |

### authority (`bin/authority`)
Issues scope-bound, COSE-signed mandates over MCP; seals each issuance when a TL
is configured.

| Flag | Default | Purpose |
| --- | --- | --- |
| `--name` | `authority-1` | authority name |
| `--addr` | `127.0.0.1:18110` | listen address |
| `--registry` | `http://127.0.0.1:18090` | registry base URL |
| `--ttl` | `1h` | mandate validity window |
| `--transparency` | *(empty)* | TL base URL; enables sealing of issued mandates |

### registry (`bin/registry`)
In-memory discovery service. `--addr` (default `127.0.0.1:18090`).

### transparency (`bin/transparency`)
Append-only Merkle transparency log; signs receipts and stamps its **log id**.
`--addr` (default `127.0.0.1:18091`), `--keys` (default `data/transparency`, where
its signing key persists). The log itself is in-memory (fresh each start).

### meshctl (`bin/meshctl`)
CLI for driving the mesh by hand:

- `meshctl greet   --from <name> --to-role <role> --text <msg> [--audit]`
- `meshctl tl-check --transparency <url>` — seal a statement and verify the receipt.
- `meshctl mandate-check --subject <s> --audience <a> --scope <sc>` — request &
  verify a mandate.

---

## Scripted CLI demos

Each script builds what it needs and runs a focused, headless slice of the stack
(no browser). Run from the repo root:

| Script | Shows |
| --- | --- |
| `scripts/demo/p0-discovery.sh` | registry + two self-registering agents; discovery by role. |
| `scripts/demo/p1-greet.sh` | an open greeter; a discovered, identity-signed greet end-to-end. |
| `scripts/demo/p2a-transparency.sh` | seal a COSE statement and verify the receipt + inclusion proof. |
| `scripts/demo/p2b-greet-audit.sh` | a sealing greeter; caller independently audits the sealed evidence. |
| `scripts/demo/p3a-mandate.sh` | request a mandate from an authority over MCP and verify its signature. |
| `scripts/demo/p3b-mandate-greet.sh` | a mandate-gated greeter; follow the card to the authority, then greet. |
| `scripts/demo/p4b-nonce-greet.sh` | a nonce-gated greeter; fetch a nonce, build a DPoP proof, then greet. |
| `scripts/demo/p5-ui.sh` | the full visual demo (this is the main one). |

---

## Build & test

```bash
make build        # compile every cmd into ./bin
make test         # go test ./...
make test-cover   # go test -cover ./...
make vet          # go vet ./...
make fmt          # gofmt -l -w .
make check        # fmt + vet + test (run before committing)
make tidy         # go mod tidy
```

The integration tests under `internal/integration` spawn real processes; they are
skipped by `go test -short`.

---

## Security & trust model

- **Identity** — every agent has an Ed25519 key (generated on first run, stored
  under `data/<name>/`). Greets, mandates, checkout terms, and log receipts are all
  COSE_Sign1 signatures.
- **Gating is discovered, not hardcoded** — a caller reads the target's Agent Card
  and satisfies whatever it advertises (open / nonce / mandate / ACP / UCP).
- **Mandates** are authority-issued, scope-bound, and time-bound; guards verify
  them **fail-closed** against a pinned authority key. Commerce amounts/items are
  **server-authoritative** (from the seller's session), so a buyer cannot underpay
  or swap items.
- **Transparency + audit** — the responder (and the authority, per issuance) seals
  a signed statement into the shared log and returns a receipt carrying the log's
  **log id**. The caller audits it against the log's own key: issuer signature,
  TL-signed receipt, **log-id pin** (receipt log id must equal the thumbprint of
  the fetched log key), and the inclusion proof. Sealing/auditing is best-effort —
  a log outage surfaces as a fail-status `seal`/`audit` event but never rolls back a
  completed interaction.
- **Single log for the demo.** One transparency log is shared by the whole mesh.
  The log id is carried in every receipt so multi-log becomes a configuration
  change, not a redesign.

---

## Data & secrets

- `data/` and `bin/` are **gitignored** — runtime keys, seeds, and secrets are
  never committed.
- `data/<name>/id_ed25519.seed` — each agent's identity key.
- `data/transparency/` — the transparency log's signing key.
- `data/stripe.env` — `STRIPE_SECRET_KEY=sk_test_…` (you create this).

To reset all identities and logs, delete `data/` (the transparency key and agent
identities regenerate on next start; note this changes their public keys).

---

## Troubleshooting

- **"ports already in use — a previous mesh may still be running"** — a prior run
  left a process holding a port. Find and stop it:
  ```bash
  ps -ax -o pid,command | grep -E 'bin/(orchestrator|registry|transparency|authority|agent)' | grep -v grep
  # then: kill <pid>   (or kill them all, e.g. via pkill -f 'bin/transparency')
  ```
  The orchestrator now refuses to start against a stale process rather than
  silently using it.
- **Audits show `verdict: "invalid"` / empty `logId`** — you're pointed at an old
  transparency process (from before the log-id change). Stop **all** mesh processes
  (above) and restart, so a fresh log stamps its log id into every receipt.
- **"Stripe secret key missing (fail closed)"** — a seller was started with
  `--payment stripe` but no key. Add `data/stripe.env`, or run the seller with
  `--payment fake`.
- **Sellers don't appear / "no Stripe env found"** — `data/stripe.env` is missing;
  add it (see [Stripe setup](#stripe-setup)). The rest of the mesh still runs.

---

## Manual / component runs

Start pieces by hand instead of via the orchestrator (each in its own terminal):

```bash
bin/registry --addr 127.0.0.1:18090
bin/transparency --addr 127.0.0.1:18091
bin/authority --name authority-1 --addr 127.0.0.1:18110 \
  --registry http://127.0.0.1:18090 --transparency http://127.0.0.1:18091
bin/agent --name Ada --role greeter-open --addr 127.0.0.1:18201 \
  --registry http://127.0.0.1:18090 --transparency http://127.0.0.1:18091 --policy open
# an offline seller (no Stripe):
bin/agent --name Shopa --role seller --addr 127.0.0.1:18207 \
  --registry http://127.0.0.1:18090 --transparency http://127.0.0.1:18091 \
  --acp --payment fake --authority-role authority --authority-name authority-1
# then drive it:
bin/meshctl greet --from visitor --to-role greeter-open --text "hi" --audit
```

---

## Project layout

```
cmd/            entrypoints: orchestrator, agent, authority, registry, transparency, meshctl
internal/
  orchestrator/ mesh supervisor, roster, agent book, hub, HTTP + SSE UI backend
  commerce/     shared payment seam + catalog; acp/ and ucp/ sellers + buyer drivers
  greet/        greet initiator (open / nonce / mandate)
  policy/       fail-closed guards (mandate, nonce, spend, UCP)
  authority/    mandate issuance + MCP tools
  audit/        evidence-bundle verifier (log-id pinned)
  attest/       shared "audit against the log" step
  tl/           transparency log (Merkle, receipts, log id)
  comms/        a2a, mcp, discovery, resolver, transparency client
  crypto/       Ed25519, COSE_Sign1, JWK/thumbprint, Merkle helpers
  domain/       DTOs and wire types
  events/       per-step event stream (JSON lines, greet-id correlated)
web/            index.html (the canvas UI)
scripts/demo/   p0–p5 headless + UI demos
docs/           design specs and implementation plans
```
