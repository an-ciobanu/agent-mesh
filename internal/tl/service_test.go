package tl

import (
	"bytes"
	"crypto/ed25519"
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
	want := crypto.PublicJWK(priv.Public().(ed25519.PublicKey))
	if jwk != want {
		t.Fatalf("pubkey = %+v, want %+v", jwk, want)
	}
}
