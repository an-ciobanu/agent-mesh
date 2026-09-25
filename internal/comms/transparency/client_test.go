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
