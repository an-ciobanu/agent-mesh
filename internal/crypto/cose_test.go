package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/veraison/go-cose"
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

func TestVerifyCOSE1RejectsMissingIssuerPubHeader(t *testing.T) {
	priv, _ := GenerateEd25519()
	signer, err := cose.NewSigner(cose.AlgorithmEdDSA, priv)
	if err != nil {
		t.Fatal(err)
	}
	msg := cose.NewSign1Message()
	msg.Payload = []byte(`{"a":1}`)
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmEdDSA)
	// Deliberately do not set coseHeaderIssuerPub.
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatal(err)
	}
	data, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyCOSE1(data); err == nil || !strings.Contains(err.Error(), "missing issuer_pub") {
		t.Fatalf("expected missing issuer_pub error, got %v", err)
	}
}

func TestVerifyCOSE1RejectsWrongSizeIssuerPubHeader(t *testing.T) {
	priv, _ := GenerateEd25519()
	signer, err := cose.NewSigner(cose.AlgorithmEdDSA, priv)
	if err != nil {
		t.Fatal(err)
	}
	msg := cose.NewSign1Message()
	msg.Payload = []byte(`{"a":1}`)
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmEdDSA)
	msg.Headers.Protected[coseHeaderIssuerPub] = []byte{1, 2, 3} // too short for an Ed25519 key
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatal(err)
	}
	data, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyCOSE1(data); err == nil || !strings.Contains(err.Error(), "invalid issuer_pub") {
		t.Fatalf("expected invalid issuer_pub error, got %v", err)
	}
}
