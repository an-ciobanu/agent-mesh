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
