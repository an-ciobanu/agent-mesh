package audit

import (
	"context"
	"crypto/ed25519"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	commstl "github.com/an-ciobanu/agent-mesh/internal/comms/transparency"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/tl"
)

// sealedBundle builds a real evidence bundle by signing a statement and sealing
// it against a live transparency service, returning the bundle and the TL key.
func sealedBundle(t *testing.T) (domain.EvidenceBundle, []byte, *httptest.Server) {
	t.Helper()
	tlPriv, _ := crypto.GenerateEd25519()
	ts := httptest.NewServer(tl.NewService(tlPriv, zerolog.Nop()).Handler())

	greeter, _ := crypto.GenerateEd25519()
	statement, err := crypto.SignCOSE1(greeter, []byte(`{"type":"greet.completed","greeting":"hi"}`))
	if err != nil {
		t.Fatal(err)
	}
	client := commstl.New(ts.URL)
	rec, err := client.Seal(context.Background(), statement)
	if err != nil {
		t.Fatal(err)
	}
	tlPub, err := client.FetchPubKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return domain.EvidenceBundle{Statement: statement, Receipt: rec}, tlPub, ts
}

func TestAuditorVerifiesValidBundle(t *testing.T) {
	bundle, tlPub, ts := sealedBundle(t)
	defer ts.Close()

	priv, _ := crypto.GenerateEd25519()
	a := New(domain.LocalANSName("auditor"), priv, zerolog.Nop())

	verdict, signed, err := a.Verify(context.Background(), bundle, tlPub)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Verdict != "valid" {
		t.Fatalf("verdict = %q, checks=%v", verdict.Verdict, verdict.Checks)
	}
	// The signed verdict is a COSE_Sign1 by the auditor key.
	_, signer, err := crypto.VerifyCOSE1(signed)
	if err != nil {
		t.Fatal(err)
	}
	if !signer.Equal(priv.Public()) {
		t.Fatal("signed verdict not signed by the auditor key")
	}
}

func TestAuditorRejectsTamperedStatement(t *testing.T) {
	bundle, tlPub, ts := sealedBundle(t)
	defer ts.Close()

	bundle.Statement = append([]byte(nil), bundle.Statement...)
	bundle.Statement[len(bundle.Statement)-5] ^= 0xff

	priv, _ := crypto.GenerateEd25519()
	verdict, _, err := New(domain.LocalANSName("auditor"), priv, zerolog.Nop()).Verify(context.Background(), bundle, tlPub)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Verdict != "invalid" {
		t.Fatalf("verdict = %q, want invalid", verdict.Verdict)
	}
}

func TestAuditorRejectsReceiptClaimsMismatch(t *testing.T) {
	bundle, tlPub, ts := sealedBundle(t)
	defer ts.Close()

	// Mutate a receipt FIELD while leaving the TL-signed Receipt.COSE untouched,
	// so the receipt signature still verifies but its claims no longer match.
	bundle.Receipt.EntryIndex++

	priv, _ := crypto.GenerateEd25519()
	verdict, _, err := New(domain.LocalANSName("auditor"), priv, zerolog.Nop()).
		Verify(context.Background(), bundle, tlPub)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Verdict != "invalid" {
		t.Fatalf("verdict = %q, want invalid (receipt claims mismatch)", verdict.Verdict)
	}
}

func TestAuditorRejectsBadInclusionProof(t *testing.T) {
	tlPriv, _ := crypto.GenerateEd25519()
	ts := httptest.NewServer(tl.NewService(tlPriv, zerolog.Nop()).Handler())
	defer ts.Close()

	client := commstl.New(ts.URL)

	greeter, _ := crypto.GenerateEd25519()
	statement1, err := crypto.SignCOSE1(greeter, []byte(`{"type":"greet.completed","greeting":"one"}`))
	if err != nil {
		t.Fatal(err)
	}
	rec1, err := client.Seal(context.Background(), statement1)
	if err != nil {
		t.Fatal(err)
	}

	statement2, err := crypto.SignCOSE1(greeter, []byte(`{"type":"greet.completed","greeting":"two"}`))
	if err != nil {
		t.Fatal(err)
	}
	rec2, err := client.Seal(context.Background(), statement2)
	if err != nil {
		t.Fatal(err)
	}
	_ = rec1 // entry 0's own receipt has an empty audit path (proof against a
	// size-1 tree); entry 1's receipt is proved against the size-2 tree and so
	// has a non-empty audit path, which is what this test needs to corrupt.

	tlPub, err := client.FetchPubKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	bundle := domain.EvidenceBundle{Statement: statement2, Receipt: rec2}
	if len(bundle.Receipt.Proof) == 0 {
		t.Fatal("expected a non-empty audit path for a size-2 tree")
	}
	bundle.Receipt.Proof = append([][]byte(nil), bundle.Receipt.Proof...)
	corrupted := append([]byte(nil), bundle.Receipt.Proof[0]...)
	corrupted[0] ^= 0xff
	bundle.Receipt.Proof[0] = corrupted

	priv, _ := crypto.GenerateEd25519()
	verdict, _, err := New(domain.LocalANSName("auditor"), priv, zerolog.Nop()).
		Verify(context.Background(), bundle, tlPub)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Verdict != "invalid" {
		t.Fatalf("verdict = %q, want invalid (bad inclusion proof)", verdict.Verdict)
	}
}

func TestAuditorRejectsWrongTLKey(t *testing.T) {
	bundle, _, ts := sealedBundle(t)
	defer ts.Close()

	other, _ := crypto.GenerateEd25519()
	wrongPub := other.Public().(ed25519.PublicKey)

	priv, _ := crypto.GenerateEd25519()
	verdict, _, err := New(domain.LocalANSName("auditor"), priv, zerolog.Nop()).
		Verify(context.Background(), bundle, wrongPub)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Verdict != "invalid" {
		t.Fatalf("verdict = %q, want invalid (receipt not signed by given TL key)", verdict.Verdict)
	}
}
