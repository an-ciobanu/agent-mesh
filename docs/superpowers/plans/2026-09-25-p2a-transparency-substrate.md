# agent-mesh P2a — Transparency Substrate (COSE + Merkle log + TL service) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A standalone SCITT-style transparency log: an agent seals a COSE_Sign1 signed statement, the log appends it to an RFC-6962 Merkle tree and returns a receipt (TL-signed COSE_Sign1 over the inclusion commitment), and anyone can independently verify the TL signature + inclusion proof.

**Architecture:** Builds on P0/P1. Adds real COSE_Sign1 (EdDSA) sign/verify and an RFC-6962 Merkle tree to `internal/crypto`; a `Transparency` port + `Receipt`/`EvidenceBundle` types to `internal/domain`; an append-only log and HTTP service in `internal/tl`; a `cmd/transparency` binary; and an HTTP `Transparency` client adapter in `internal/comms/transparency`. A `meshctl tl-check` subcommand + integration test prove seal→verify end-to-end.

**Tech Stack:** Go 1.23, `github.com/veraison/go-cose` (NEW — real COSE_Sign1; pulls `fxamacker/cbor/v2`), stdlib `crypto/ed25519`/`crypto/sha256`, `github.com/rs/zerolog`.

**Scope:** P2a only — the transparency substrate. Wiring sealing into the greeter, the auditor, and the signed verdict are **P2b** (next plan). Mandate/OAuth2 (P3), nonce/DPoP (P4), and UI (P5) are later. See `docs/superpowers/specs/2026-09-25-agent-mesh-design.md`.

**Baseline:** P0 + P1 merged on `master`. Existing: `internal/crypto` (JWK, PublicJWK, Thumbprint, GenerateEd25519, LoadOrCreateEd25519, SignJWS, VerifyJWS), `internal/domain`, `internal/registry`, `internal/comms/{discovery,a2a,resolver}`, `internal/policy`, `internal/greet`, `cmd/{agent,registry,meshctl}`. Do all P2a work on a branch off `master` (e.g. `p2a-transparency`).

---

## File structure (this plan)

```
internal/crypto/cose.go                     # NEW: SignCOSE1 / VerifyCOSE1 (EdDSA, embedded signer key)
internal/crypto/cose_test.go                # NEW
internal/crypto/merkle.go                    # NEW: RFC 6962 LeafHash / MerkleRoot / InclusionProof / VerifyInclusion
internal/crypto/merkle_test.go               # NEW
internal/domain/transparency.go              # NEW: Receipt, Transparency port, EvidenceBundle
internal/tl/log.go                           # NEW: in-memory append-only Merkle log
internal/tl/log_test.go                      # NEW
internal/tl/service.go                        # NEW: HTTP service (POST /entries, GET /pubkey, GET /checkpoint)
internal/tl/service_test.go                   # NEW
internal/comms/transparency/client.go         # NEW: HTTP Transparency client (Seal + FetchPubKey)
internal/comms/transparency/client_test.go    # NEW
cmd/transparency/main.go                      # NEW: transparency-log binary
cmd/meshctl/main.go                           # MODIFY: add `tl-check` subcommand
internal/integration/p2a_test.go              # NEW: seal -> verify TL sig + inclusion; tamper -> fail
scripts/demo/p2a-transparency.sh              # NEW: runnable demo
```

Conventions (unchanged): hexagonal Go; injected `zerolog.Logger` tagged `component`; no `fmt.Println`/`log` in library code (cmd/* may print to stdout); `make check` green before every commit; **no AI `Co-Authored-By:` trailer**.

---

## Task 1: Crypto — real COSE_Sign1 (EdDSA) with embedded signer key

**Files:**
- Create: `internal/crypto/cose.go`
- Test: `internal/crypto/cose_test.go`

- [ ] **Step 1: Add the go-cose dependency**

Run:
```bash
go get github.com/veraison/go-cose@v1.3.0
go mod tidy
```
Expected: `go.mod` gains `github.com/veraison/go-cose v1.3.0` (and `github.com/fxamacker/cbor/v2` as indirect); `go.sum` updated.

- [ ] **Step 2: Write the failing test**

```go
package crypto

import (
	"crypto/ed25519"
	"testing"
)

func TestSignVerifyCOSE1RoundTrip(t *testing.T) {
	priv, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"type":"greet.completed"}`)

	sig, err := SignCOSE1(priv, payload)
	if err != nil {
		t.Fatal(err)
	}
	got, signer, err := VerifyCOSE1(sig)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload = %s, want %s", got, payload)
	}
	if !signer.Equal(priv.Public().(ed25519.PublicKey)) {
		t.Fatal("returned signer key does not match")
	}
}

func TestVerifyCOSE1RejectsTamperedPayload(t *testing.T) {
	priv, _ := GenerateEd25519()
	sig, _ := SignCOSE1(priv, []byte(`{"a":1}`))
	// Flip a byte late in the COSE structure (within the payload region).
	sig[len(sig)-10] ^= 0xff
	if _, _, err := VerifyCOSE1(sig); err == nil {
		t.Fatal("expected verification failure on tampered COSE_Sign1")
	}
}

func TestVerifyCOSE1RejectsGarbage(t *testing.T) {
	if _, _, err := VerifyCOSE1([]byte("not cbor")); err == nil {
		t.Fatal("expected error for non-COSE bytes")
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/crypto/ -run COSE1 -v`
Expected: FAIL — `undefined: SignCOSE1`.

- [ ] **Step 4: Write the implementation**

Note: this targets `github.com/veraison/go-cose` v1.x. If the installed version's API differs in a minor way, adjust the calls but keep the contract exactly: `SignCOSE1` produces a COSE_Sign1 (EdDSA) over `payload` embedding the signer's raw Ed25519 public key in the protected header; `VerifyCOSE1` parses it, verifies with the embedded key, and returns `(payload, signerPublicKey, error)`. The tests above define the contract.

```go
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/veraison/go-cose"
)

// coseHeaderIssuerPub is the protected-header label under which the signer's raw
// Ed25519 public key is embedded, so a COSE_Sign1 is self-verifying. Binding
// that key to a registered identity is out of scope (deferred, like the JWS path).
const coseHeaderIssuerPub = "issuer_pub"

// SignCOSE1 produces a COSE_Sign1 (EdDSA) over payload, embedding the signer's
// public key in the protected header.
func SignCOSE1(priv ed25519.PrivateKey, payload []byte) ([]byte, error) {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("cose: private key is not ed25519")
	}
	signer, err := cose.NewSigner(cose.AlgorithmEdDSA, priv)
	if err != nil {
		return nil, fmt.Errorf("cose: new signer: %w", err)
	}
	msg := cose.NewSign1Message()
	msg.Payload = payload
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmEdDSA)
	msg.Headers.Protected[coseHeaderIssuerPub] = []byte(pub)
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return nil, fmt.Errorf("cose: sign: %w", err)
	}
	out, err := msg.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("cose: marshal: %w", err)
	}
	return out, nil
}

// VerifyCOSE1 parses a self-verifying COSE_Sign1 (from SignCOSE1), verifies its
// signature with the embedded public key, and returns the payload and that key.
func VerifyCOSE1(data []byte) ([]byte, ed25519.PublicKey, error) {
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(data); err != nil {
		return nil, nil, fmt.Errorf("cose: unmarshal: %w", err)
	}
	raw, ok := msg.Headers.Protected[coseHeaderIssuerPub]
	if !ok {
		return nil, nil, errors.New("cose: missing issuer_pub header")
	}
	pubBytes, ok := raw.([]byte)
	if !ok || len(pubBytes) != ed25519.PublicKeySize {
		return nil, nil, errors.New("cose: invalid issuer_pub header")
	}
	pub := ed25519.PublicKey(pubBytes)
	verifier, err := cose.NewVerifier(cose.AlgorithmEdDSA, pub)
	if err != nil {
		return nil, nil, fmt.Errorf("cose: new verifier: %w", err)
	}
	if err := msg.Verify(nil, verifier); err != nil {
		return nil, nil, fmt.Errorf("cose: verify: %w", err)
	}
	return msg.Payload, pub, nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/crypto/ -run COSE1 -v`
Expected: PASS. (If `TestVerifyCOSE1RejectsTamperedPayload` flips a byte that lands outside the signed region and still verifies, adjust the flip to target an earlier offset within the payload; the payload here is 9 bytes so `len-10` lands inside the CBOR-wrapped structure — verification must fail.)

- [ ] **Step 6: Full crypto suite + commit**

Run: `go test ./internal/crypto/ -v` → PASS.
```bash
git add go.mod go.sum internal/crypto/cose.go internal/crypto/cose_test.go
git commit -m "feat(crypto): real COSE_Sign1 (EdDSA) sign/verify with embedded key"
```

---

## Task 2: Crypto — RFC 6962 Merkle tree

**Files:**
- Create: `internal/crypto/merkle.go`
- Test: `internal/crypto/merkle_test.go`

- [ ] **Step 1: Write the failing test**

```go
package crypto

import (
	"bytes"
	"testing"
)

func leaves(n int) [][]byte {
	ls := make([][]byte, n)
	for i := 0; i < n; i++ {
		ls[i] = LeafHash([]byte{byte(i)})
	}
	return ls
}

func TestInclusionProofVerifiesForEverySize(t *testing.T) {
	for size := 1; size <= 9; size++ {
		ls := leaves(size)
		root := MerkleRoot(ls)
		for i := 0; i < size; i++ {
			proof := InclusionProof(ls, i)
			if !VerifyInclusion(ls[i], i, size, proof, root) {
				t.Fatalf("size=%d index=%d: inclusion proof failed to verify", size, i)
			}
		}
	}
}

func TestVerifyInclusionRejectsWrongLeaf(t *testing.T) {
	ls := leaves(5)
	root := MerkleRoot(ls)
	proof := InclusionProof(ls, 2)
	wrong := LeafHash([]byte("nope"))
	if VerifyInclusion(wrong, 2, 5, proof, root) {
		t.Fatal("expected verification to fail for a wrong leaf")
	}
}

func TestVerifyInclusionRejectsWrongRoot(t *testing.T) {
	ls := leaves(4)
	proof := InclusionProof(ls, 1)
	badRoot := LeafHash([]byte("bad root"))
	if VerifyInclusion(ls[1], 1, 4, proof, badRoot) {
		t.Fatal("expected verification to fail for a wrong root")
	}
}

func TestLeafHashIsDomainSeparated(t *testing.T) {
	// Leaf and node hashing use different prefixes (0x00 vs 0x01).
	if bytes.Equal(LeafHash([]byte("x")), LeafHash([]byte("y"))) {
		t.Fatal("distinct leaves must hash differently")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/crypto/ -run 'Inclusion|LeafHash' -v`
Expected: FAIL — `undefined: LeafHash`.

- [ ] **Step 3: Write the implementation**

```go
package crypto

import (
	"bytes"
	"crypto/sha256"
)

// LeafHash returns the RFC 6962 leaf hash: SHA-256(0x00 || data).
func LeafHash(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	return h.Sum(nil)
}

// nodeHash returns the RFC 6962 interior node hash: SHA-256(0x01 || left || right).
func nodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// MerkleRoot computes the RFC 6962 Merkle Tree Hash over the given leaf hashes.
func MerkleRoot(leaves [][]byte) []byte {
	switch len(leaves) {
	case 0:
		s := sha256.Sum256(nil)
		return s[:]
	case 1:
		return leaves[0]
	}
	k := largestPowerOfTwoLessThan(len(leaves))
	return nodeHash(MerkleRoot(leaves[:k]), MerkleRoot(leaves[k:]))
}

// InclusionProof returns the RFC 6962 audit path for the leaf at index.
func InclusionProof(leaves [][]byte, index int) [][]byte {
	if index < 0 || index >= len(leaves) || len(leaves) <= 1 {
		return nil
	}
	k := largestPowerOfTwoLessThan(len(leaves))
	if index < k {
		return append(InclusionProof(leaves[:k], index), MerkleRoot(leaves[k:]))
	}
	return append(InclusionProof(leaves[k:], index-k), MerkleRoot(leaves[:k]))
}

// VerifyInclusion checks that leaf at index, in a tree of the given size with the
// supplied audit path, reproduces root (RFC 6962 §2.1.1).
func VerifyInclusion(leaf []byte, index, size int, proof [][]byte, root []byte) bool {
	if index < 0 || index >= size {
		return false
	}
	computed := leaf
	fn, sn := index, size-1
	pi := 0
	for sn > 0 {
		if pi >= len(proof) {
			return false
		}
		if fn%2 == 1 || fn == sn {
			computed = nodeHash(proof[pi], computed)
			for fn%2 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			computed = nodeHash(computed, proof[pi])
		}
		pi++
		fn >>= 1
		sn >>= 1
	}
	return pi == len(proof) && bytes.Equal(computed, root)
}

// largestPowerOfTwoLessThan returns the largest power of two strictly less than n
// (n >= 2).
func largestPowerOfTwoLessThan(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/crypto/ -run 'Inclusion|LeafHash' -v`
Expected: PASS (all sizes 1..9, wrong-leaf, wrong-root).

- [ ] **Step 5: Commit**

```bash
git add internal/crypto/merkle.go internal/crypto/merkle_test.go
git commit -m "feat(crypto): RFC 6962 Merkle tree (root, inclusion proof, verify)"
```

---

## Task 3: Domain — Transparency port, Receipt, EvidenceBundle

**Files:**
- Create: `internal/domain/transparency.go`

- [ ] **Step 1: Write the file**

```go
package domain

import "context"

// Receipt is a transparency-log inclusion receipt for a submitted statement.
// Root and Proof JSON-encode as base64 (Go's default for []byte).
type Receipt struct {
	EntryIndex int      `json:"entryIndex"`
	TreeSize   int      `json:"treeSize"`
	Root       []byte   `json:"root"`
	Proof      [][]byte `json:"proof"`
	COSE       []byte   `json:"cose"` // TL-signed COSE_Sign1 over {entryIndex, treeSize, root}
}

// Transparency seals a signed statement into an append-only transparency log and
// returns a receipt proving its inclusion.
type Transparency interface {
	Seal(ctx context.Context, statement []byte) (Receipt, error)
}

// EvidenceBundle is what an auditor needs to verify an interaction: the signed
// statement (COSE_Sign1 bytes) and its transparency receipt.
type EvidenceBundle struct {
	Statement []byte  `json:"statement"`
	Receipt   Receipt `json:"receipt"`
}
```

- [ ] **Step 2: Verify it compiles**

Run: `go build ./internal/domain/`
Expected: exits 0.

- [ ] **Step 3: Commit**

```bash
git add internal/domain/transparency.go
git commit -m "feat(domain): Transparency port, Receipt, EvidenceBundle"
```

---

## Task 4: TL — append-only Merkle log

**Files:**
- Create: `internal/tl/log.go`
- Test: `internal/tl/log_test.go`

- [ ] **Step 1: Write the failing test**

```go
package tl

import (
	"testing"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
)

func TestAppendAndProveIsConsistent(t *testing.T) {
	l := NewLog()
	s1 := []byte("statement-one")
	i1, size1, root1, proof1 := l.AppendAndProve(s1)
	if i1 != 0 || size1 != 1 {
		t.Fatalf("first entry: index=%d size=%d", i1, size1)
	}
	if !crypto.VerifyInclusion(crypto.LeafHash(s1), i1, size1, proof1, root1) {
		t.Fatal("first entry inclusion proof does not verify")
	}

	s2 := []byte("statement-two")
	i2, size2, root2, proof2 := l.AppendAndProve(s2)
	if i2 != 1 || size2 != 2 {
		t.Fatalf("second entry: index=%d size=%d", i2, size2)
	}
	if !crypto.VerifyInclusion(crypto.LeafHash(s2), i2, size2, proof2, root2) {
		t.Fatal("second entry inclusion proof does not verify")
	}
	if l.Size() != 2 {
		t.Fatalf("Size = %d, want 2", l.Size())
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/tl/ -v`
Expected: FAIL — `undefined: NewLog`.

- [ ] **Step 3: Write the implementation**

```go
// Package tl is agent-mesh's minimal SCITT-style transparency log.
package tl

import (
	"sync"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
)

// Log is an in-memory, append-only RFC 6962 Merkle log of statement bytes.
type Log struct {
	mu         sync.RWMutex
	statements [][]byte
	leaves     [][]byte
}

// NewLog returns an empty log.
func NewLog() *Log { return &Log{} }

// AppendAndProve appends statement and returns, atomically, its entry index, the
// resulting tree size, the tree root, and the inclusion proof for the new entry.
func (l *Log) AppendAndProve(statement []byte) (index, size int, root []byte, proof [][]byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	dup := append([]byte(nil), statement...)
	l.statements = append(l.statements, dup)
	l.leaves = append(l.leaves, crypto.LeafHash(dup))
	index = len(l.leaves) - 1
	size = len(l.leaves)
	root = crypto.MerkleRoot(l.leaves)
	proof = crypto.InclusionProof(l.leaves, index)
	return index, size, root, proof
}

// Size returns the number of entries.
func (l *Log) Size() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.leaves)
}

// Root returns the current Merkle root.
func (l *Log) Root() []byte {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return crypto.MerkleRoot(l.leaves)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/tl/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/tl/log.go internal/tl/log_test.go
git commit -m "feat(tl): append-only RFC 6962 Merkle log"
```

---

## Task 5: TL — HTTP service

**Files:**
- Create: `internal/tl/service.go`
- Test: `internal/tl/service_test.go`

- [ ] **Step 1: Write the failing test**

```go
package tl

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

func TestServiceSealReturnsVerifiableReceipt(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	ts := httptest.NewServer(NewService(priv, zerolog.Nop()).Handler())
	defer ts.Close()

	// A signed statement (issuer distinct from the TL).
	issuer, _ := crypto.GenerateEd25519()
	statement, _ := crypto.SignCOSE1(issuer, []byte(`{"type":"greet.completed"}`))

	resp, err := http.Post(ts.URL+"/entries", "application/cose", bytes.NewReader(statement))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("seal status = %d", resp.StatusCode)
	}
	var rec domain.Receipt
	if err := json.NewDecoder(resp.Body).Decode(&rec); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// The receipt's COSE is signed by the TL and commits to the same root.
	claims, signer, err := crypto.VerifyCOSE1(rec.COSE)
	if err != nil {
		t.Fatalf("verify receipt cose: %v", err)
	}
	if !signer.Equal(priv.Public()) {
		t.Fatal("receipt not signed by the TL key")
	}
	var rc struct {
		EntryIndex int    `json:"entryIndex"`
		TreeSize   int    `json:"treeSize"`
		Root       []byte `json:"root"`
	}
	if err := json.Unmarshal(claims, &rc); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rc.Root, rec.Root) || rc.EntryIndex != rec.EntryIndex || rc.TreeSize != rec.TreeSize {
		t.Fatal("receipt COSE claims do not match receipt fields")
	}

	// The inclusion proof verifies against the receipt root.
	if !crypto.VerifyInclusion(crypto.LeafHash(statement), rec.EntryIndex, rec.TreeSize, rec.Proof, rec.Root) {
		t.Fatal("inclusion proof does not verify")
	}
}

func TestServiceRejectsEmptyStatement(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	ts := httptest.NewServer(NewService(priv, zerolog.Nop()).Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/entries", "application/cose", bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for empty statement, got %d", resp.StatusCode)
	}
}

func TestServicePubKeyReturnsTLKey(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	ts := httptest.NewServer(NewService(priv, zerolog.Nop()).Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/pubkey")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var jwk crypto.JWK
	if err := json.NewDecoder(resp.Body).Decode(&jwk); err != nil {
		t.Fatal(err)
	}
	if jwk != crypto.PublicJWK(priv.Public().(interface{ Public() any }).Public().(interface{}).(interface{})) {
		// placeholder; replaced below
	}
}
```

Note: fix the final assertion in `TestServicePubKeyReturnsTLKey` to compare against the TL's JWK directly — replace the broken last `if` with:

```go
	pub, _ := priv.Public().(interface{ Equal(x any) bool }) // not used; see below
```

Actually use this exact body for `TestServicePubKeyReturnsTLKey` instead of the version above:

```go
func TestServicePubKeyReturnsTLKey(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	ts := httptest.NewServer(NewService(priv, zerolog.Nop()).Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/pubkey")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var jwk crypto.JWK
	if err := json.NewDecoder(resp.Body).Decode(&jwk); err != nil {
		t.Fatal(err)
	}
	want := crypto.PublicJWK(priv.Public().(ed25519.PublicKey))
	if jwk != want {
		t.Fatalf("pubkey = %+v, want %+v", jwk, want)
	}
}
```

and add `"crypto/ed25519"` to the test imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/tl/ -run Service -v`
Expected: FAIL — `undefined: NewService`.

- [ ] **Step 3: Write the implementation**

```go
package tl

import (
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

// maxStatementBytes bounds a submitted statement.
const maxStatementBytes = 1 << 20

// Service is the transparency-log HTTP service. It signs receipts with its own
// Ed25519 key.
type Service struct {
	log  *Log
	priv ed25519.PrivateKey
	l    zerolog.Logger
}

// NewService returns a transparency service backed by a fresh empty log.
func NewService(priv ed25519.PrivateKey, log zerolog.Logger) *Service {
	return &Service{log: NewLog(), priv: priv, l: log.With().Str("component", "tl").Logger()}
}

// Handler returns the transparency-log routes.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /entries", s.handleAppend)
	mux.HandleFunc("GET /pubkey", s.handlePubKey)
	mux.HandleFunc("GET /checkpoint", s.handleCheckpoint)
	return mux
}

type receiptClaims struct {
	EntryIndex int    `json:"entryIndex"`
	TreeSize   int    `json:"treeSize"`
	Root       []byte `json:"root"`
}

func (s *Service) handleAppend(w http.ResponseWriter, r *http.Request) {
	statement, err := io.ReadAll(io.LimitReader(r.Body, maxStatementBytes))
	if err != nil {
		s.l.Warn().Err(err).Msg("append: read body")
		http.Error(w, "unreadable statement", http.StatusBadRequest)
		return
	}
	if len(statement) == 0 {
		http.Error(w, "empty statement", http.StatusBadRequest)
		return
	}

	index, size, root, proof := s.log.AppendAndProve(statement)

	claims, err := json.Marshal(receiptClaims{EntryIndex: index, TreeSize: size, Root: root})
	if err != nil {
		s.l.Error().Err(err).Msg("append: marshal receipt claims")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	receiptCOSE, err := crypto.SignCOSE1(s.priv, claims)
	if err != nil {
		s.l.Error().Err(err).Msg("append: sign receipt")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.l.Info().Int("entryIndex", index).Int("treeSize", size).Msg("statement sealed")
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(domain.Receipt{
		EntryIndex: index, TreeSize: size, Root: root, Proof: proof, COSE: receiptCOSE,
	}); err != nil {
		s.l.Error().Err(err).Msg("append: encode receipt")
	}
}

func (s *Service) handlePubKey(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(crypto.PublicJWK(s.priv.Public().(ed25519.PublicKey))); err != nil {
		s.l.Error().Err(err).Msg("pubkey: encode")
	}
}

func (s *Service) handleCheckpoint(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{"treeSize": s.log.Size(), "root": s.log.Root()}); err != nil {
		s.l.Error().Err(err).Msg("checkpoint: encode")
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/tl/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/tl/service.go internal/tl/service_test.go
git commit -m "feat(tl): transparency HTTP service (seal, pubkey, checkpoint)"
```

---

## Task 6: Transparency binary

**Files:**
- Create: `cmd/transparency/main.go`

- [ ] **Step 1: Write the binary**

```go
// Command transparency runs the agent-mesh transparency log.
package main

import (
	"flag"
	"net/http"
	"os"
	"path/filepath"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/tl"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:18091", "listen address")
	keyDir := flag.String("keys", "data/transparency", "directory for the TL signing key")
	flag.Parse()

	log := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()

	priv, err := crypto.LoadOrCreateEd25519(filepath.Join(*keyDir, "id_ed25519.seed"))
	if err != nil {
		log.Fatal().Err(err).Msg("load transparency key")
	}
	svc := tl.NewService(priv, log)

	log.Info().Str("addr", *addr).Msg("transparency log listening")
	if err := http.ListenAndServe(*addr, svc.Handler()); err != nil {
		log.Fatal().Err(err).Msg("transparency server exited")
	}
}
```

- [ ] **Step 2: Build**

Run: `go build ./cmd/transparency/`
Expected: exits 0.

- [ ] **Step 3: Commit**

```bash
git add cmd/transparency/main.go
git commit -m "feat(cmd): transparency-log binary"
```

---

## Task 7: Transparency client (port adapter)

**Files:**
- Create: `internal/comms/transparency/client.go`
- Test: `internal/comms/transparency/client_test.go`

- [ ] **Step 1: Write the failing test**

```go
package transparency

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/tl"
)

func TestClientSealAndFetchPubKey(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	ts := httptest.NewServer(tl.NewService(priv, zerolog.Nop()).Handler())
	defer ts.Close()

	c := New(ts.URL)
	ctx := context.Background()

	issuer, _ := crypto.GenerateEd25519()
	statement, _ := crypto.SignCOSE1(issuer, []byte(`{"type":"greet.completed"}`))

	rec, err := c.Seal(ctx, statement)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if rec.TreeSize != 1 || rec.EntryIndex != 0 {
		t.Fatalf("receipt index/size = %d/%d", rec.EntryIndex, rec.TreeSize)
	}
	if !crypto.VerifyInclusion(crypto.LeafHash(statement), rec.EntryIndex, rec.TreeSize, rec.Proof, rec.Root) {
		t.Fatal("inclusion proof does not verify")
	}

	tlPub, err := c.FetchPubKey(ctx)
	if err != nil {
		t.Fatalf("fetch pubkey: %v", err)
	}
	if !tlPub.Equal(priv.Public()) {
		t.Fatal("fetched pubkey does not match TL key")
	}
	// The receipt is signed by the TL key we fetched.
	_, signer, err := crypto.VerifyCOSE1(rec.COSE)
	if err != nil {
		t.Fatal(err)
	}
	if !signer.Equal(tlPub) {
		t.Fatal("receipt signer != fetched TL pubkey")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/comms/transparency/ -v`
Expected: FAIL — `undefined: New`.

- [ ] **Step 3: Write the implementation**

```go
// Package transparency is the HTTP client adapter for the domain.Transparency port.
package transparency

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

// Client talks to a transparency-log service over HTTP.
type Client struct {
	base string
	http *http.Client
}

// New returns a transparency client for the given TL base URL.
func New(base string) *Client {
	return &Client{base: base, http: &http.Client{Timeout: 5 * time.Second}}
}

// Seal submits a signed statement and returns its inclusion receipt.
func (c *Client) Seal(ctx context.Context, statement []byte) (domain.Receipt, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/entries", bytes.NewReader(statement))
	if err != nil {
		return domain.Receipt{}, fmt.Errorf("build seal request: %w", err)
	}
	req.Header.Set("Content-Type", "application/cose")
	resp, err := c.http.Do(req)
	if err != nil {
		return domain.Receipt{}, fmt.Errorf("seal request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return domain.Receipt{}, fmt.Errorf("seal: unexpected status %d", resp.StatusCode)
	}
	var rec domain.Receipt
	if err := json.NewDecoder(resp.Body).Decode(&rec); err != nil {
		return domain.Receipt{}, fmt.Errorf("decode receipt: %w", err)
	}
	return rec, nil
}

// FetchPubKey returns the transparency log's Ed25519 public key.
func (c *Client) FetchPubKey(ctx context.Context) (ed25519.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/pubkey", nil)
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
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" {
		return nil, fmt.Errorf("pubkey: not an Ed25519 OKP key")
	}
	raw, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("pubkey: decode x: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("pubkey: bad size %d", len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

var _ domain.Transparency = (*Client)(nil)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/comms/transparency/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/comms/transparency/client.go internal/comms/transparency/client_test.go
git commit -m "feat(transparency): HTTP client implementing Transparency port"
```

---

## Task 8: `meshctl tl-check` subcommand

**Files:**
- Modify: `cmd/meshctl/main.go`

- [ ] **Step 1: Add the subcommand dispatch**

In `cmd/meshctl/main.go`, in the `switch os.Args[1]` block, add a `tl-check` case alongside the existing `greet` case:

```go
	case "tl-check":
		runTLCheck(os.Args[2:])
```

Also update the usage line to mention it:

```go
		fmt.Fprintln(os.Stderr, "commands: greet, tl-check")
```

- [ ] **Step 2: Add the `runTLCheck` function**

Append to `cmd/meshctl/main.go`:

```go
func runTLCheck(args []string) {
	fs := flag.NewFlagSet("tl-check", flag.ExitOnError)
	tlURL := fs.String("transparency", "http://127.0.0.1:18091", "transparency log base URL")
	_ = fs.Parse(args)

	log := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()
	ctx := context.Background()

	// Sign a sample statement with an ephemeral issuer key and seal it.
	issuer, err := crypto.GenerateEd25519()
	if err != nil {
		log.Fatal().Err(err).Msg("generate issuer key")
	}
	statement, err := crypto.SignCOSE1(issuer, []byte(`{"type":"tl-check","note":"meshctl self-test"}`))
	if err != nil {
		log.Fatal().Err(err).Msg("sign statement")
	}

	tc := transparency.New(*tlURL)
	rec, err := tc.Seal(ctx, statement)
	if err != nil {
		log.Fatal().Err(err).Msg("seal statement")
	}
	tlPub, err := tc.FetchPubKey(ctx)
	if err != nil {
		log.Fatal().Err(err).Msg("fetch TL pubkey")
	}

	// Verify the receipt is TL-signed and the inclusion proof holds.
	_, signer, err := crypto.VerifyCOSE1(rec.COSE)
	if err != nil {
		log.Fatal().Err(err).Msg("verify receipt cose")
	}
	if !signer.Equal(tlPub) {
		log.Fatal().Msg("receipt not signed by the TL key")
	}
	if !crypto.VerifyInclusion(crypto.LeafHash(statement), rec.EntryIndex, rec.TreeSize, rec.Proof, rec.Root) {
		log.Fatal().Msg("inclusion proof failed to verify")
	}

	fmt.Printf("sealed entry %d of %d; receipt TL-signed and inclusion proof verified OK\n", rec.EntryIndex, rec.TreeSize)
}
```

- [ ] **Step 3: Add imports**

Ensure `cmd/meshctl/main.go` imports include (alongside the existing ones):

```go
	"github.com/an-ciobanu/agent-mesh/internal/comms/transparency"
```

(`context`, `flag`, `fmt`, `os`, `github.com/rs/zerolog`, and `github.com/an-ciobanu/agent-mesh/internal/crypto` are already imported by the P1 greet command.)

- [ ] **Step 4: Build**

Run: `make build`
Expected: all four binaries (`agent`, `registry`, `meshctl`, `transparency`) build; exits 0.

- [ ] **Step 5: Commit**

```bash
git add cmd/meshctl/main.go
git commit -m "feat(meshctl): tl-check subcommand (seal + verify a sample statement)"
```

---

## Task 9: End-to-end integration test

**Files:**
- Create: `internal/integration/p2a_test.go`

- [ ] **Step 1: Write the test**

```go
package integration

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	commstl "github.com/an-ciobanu/agent-mesh/internal/comms/transparency"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/tl"
)

func TestP2A_SealThenVerifyInclusion(t *testing.T) {
	tlPriv, _ := crypto.GenerateEd25519()
	ts := httptest.NewServer(tl.NewService(tlPriv, zerolog.Nop()).Handler())
	defer ts.Close()

	client := commstl.New(ts.URL)
	ctx := context.Background()

	issuer, _ := crypto.GenerateEd25519()
	statement, _ := crypto.SignCOSE1(issuer, []byte(`{"type":"greet.completed","greeting":"hello"}`))

	rec, err := client.Seal(ctx, statement)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	tlPub, err := client.FetchPubKey(ctx)
	if err != nil {
		t.Fatalf("fetch pubkey: %v", err)
	}

	// Receipt is signed by the TL and commits to the returned root.
	_, signer, err := crypto.VerifyCOSE1(rec.COSE)
	if err != nil {
		t.Fatalf("verify receipt: %v", err)
	}
	if !signer.Equal(tlPub) {
		t.Fatal("receipt signer != TL pubkey")
	}
	// Statement issuer signature verifies independently.
	if _, _, err := crypto.VerifyCOSE1(statement); err != nil {
		t.Fatalf("verify statement: %v", err)
	}
	// Inclusion proof holds for the real statement.
	if !crypto.VerifyInclusion(crypto.LeafHash(statement), rec.EntryIndex, rec.TreeSize, rec.Proof, rec.Root) {
		t.Fatal("inclusion proof failed to verify")
	}

	// Tamper: a modified statement must NOT verify against the same receipt.
	tampered := append([]byte(nil), statement...)
	tampered[len(tampered)-5] ^= 0xff
	if crypto.VerifyInclusion(crypto.LeafHash(tampered), rec.EntryIndex, rec.TreeSize, rec.Proof, rec.Root) {
		t.Fatal("tampered statement must not satisfy the inclusion proof")
	}
}
```

- [ ] **Step 2: Run test**

Run: `go test ./internal/integration/ -run P2A -v`
Expected: PASS.

- [ ] **Step 3: Full suite + check**

Run: `make check`
Expected: gofmt/vet clean, all tests PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/integration/p2a_test.go
git commit -m "test(integration): P2a seal -> verify TL signature + inclusion"
```

---

## Task 10: Demo script

**Files:**
- Create: `scripts/demo/p2a-transparency.sh`

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# P2a demo: start the transparency log, then use meshctl tl-check to seal a
# COSE_Sign1 statement and independently verify the TL-signed receipt + RFC 6962
# inclusion proof.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

make build

TL_ADDR="127.0.0.1:18091"
pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

./bin/transparency --addr "$TL_ADDR" & pids+=("$!")
sleep 0.7

echo "== checkpoint (empty log) =="
curl -s "http://$TL_ADDR/checkpoint"; echo

echo "== meshctl tl-check (seal + verify) =="
OUT=$(./bin/meshctl tl-check --transparency "http://$TL_ADDR")
echo "$OUT"
echo "$OUT" | grep -q "inclusion proof verified OK"

echo "== checkpoint (after one entry) =="
curl -s "http://$TL_ADDR/checkpoint"; echo

echo "P2a demo OK"
```

- [ ] **Step 2: Make executable and run**

Run:
```bash
chmod +x scripts/demo/p2a-transparency.sh
./scripts/demo/p2a-transparency.sh
```
Expected: prints the empty checkpoint (`treeSize:0`), then `sealed entry 0 of 1; receipt TL-signed and inclusion proof verified OK`, then a checkpoint with `treeSize:1`, then `P2a demo OK`.

- [ ] **Step 3: Commit**

```bash
git add scripts/demo/p2a-transparency.sh
git commit -m "chore(demo): P2a transparency seal + verify script"
```

---

## Self-review

**Spec coverage (P2a scope — the transparency substrate of spec §5.4 / §8):**
- Real COSE_Sign1 signed statements & receipts → Task 1. ✓
- Append-only Merkle log with inclusion-proof receipts (RFC 6962) → Tasks 2, 4, 5. ✓
- `Transparency` port (swap seam to `ans-tl` later) → Task 3, adapter Task 7. ✓
- Standalone TL service + binary (`GET /pubkey`, `/checkpoint`, `POST /entries`) → Tasks 5, 6. ✓
- Provable: integration test (seal → verify TL sig + inclusion; tamper fails) + demo → Tasks 9, 10; plus `meshctl tl-check` → Task 8. ✓
- Deferred to P2b (correctly absent here): sealing "greet completed" inside the greeter, the auditor, and the signed verdict. `EvidenceBundle` type is defined now (Task 3) as the seam P2b fills.

**Placeholder scan:** none — every step has concrete code or an exact command with expected output. (Task 5's test includes an explicit correction to `TestServicePubKeyReturnsTLKey`; the corrected body and the `crypto/ed25519` import are the version to use.)

**Type consistency check:**
- `crypto.SignCOSE1(ed25519.PrivateKey, []byte) ([]byte, error)` / `crypto.VerifyCOSE1([]byte) ([]byte, ed25519.PublicKey, error)` — defined Task 1; used in tl/service (receipt signing), tl/service_test, transparency client test, meshctl tl-check (Task 8), integration (Task 9). ✓
- `crypto.LeafHash/MerkleRoot/InclusionProof/VerifyInclusion` — defined Task 2; used in tl/log (Task 4), tests, meshctl tl-check, integration. ✓
- `domain.Receipt{EntryIndex, TreeSize, Root, Proof, COSE}`, `domain.Transparency.Seal(ctx, []byte) (Receipt, error)`, `domain.EvidenceBundle{Statement, Receipt}` — defined Task 3; the TL service returns `domain.Receipt` (Task 5), the client implements `domain.Transparency` with `var _` assertion (Task 7). ✓
- `tl.NewLog()` + `(*Log).AppendAndProve(...) (int,int,[]byte,[][]byte)` + `Size()`/`Root()` — defined Task 4; used by `tl.NewService` (Task 5). ✓
- `tl.NewService(ed25519.PrivateKey, zerolog.Logger) *Service` + `Handler()` — defined Task 5; used in Tasks 6, 7-test, 9. ✓
- `transparency.New(base) *Client` + `Seal`/`FetchPubKey` — defined Task 7; used in meshctl tl-check (Task 8) and integration (Task 9). ✓
- The `receiptClaims` JSON shape (`entryIndex`,`treeSize`,`root`) written by tl/service (Task 5) is parsed identically in tl/service_test and by verifiers; base64 `[]byte` encoding is consistent (Go default). ✓
