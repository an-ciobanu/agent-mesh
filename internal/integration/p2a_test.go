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
