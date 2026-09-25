package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

func TestSignVerifyJWSRoundTrip(t *testing.T) {
	priv, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"hello":"world"}`)

	compact, err := SignJWS(priv, payload)
	if err != nil {
		t.Fatal(err)
	}
	got, jwk, err := VerifyJWS(compact)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload = %s, want %s", got, payload)
	}
	if jwk != PublicJWK(priv.Public().(ed25519.PublicKey)) {
		t.Fatal("returned jwk does not match signer")
	}
}

func TestVerifyJWSRejectsTamperedPayload(t *testing.T) {
	priv, _ := GenerateEd25519()
	compact, _ := SignJWS(priv, []byte(`{"a":1}`))

	parts := strings.Split(compact, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"a":2}`))
	tampered := strings.Join(parts, ".")

	if _, _, err := VerifyJWS(tampered); err == nil {
		t.Fatal("expected verification failure on tampered payload")
	}
}

func TestVerifyJWSRejectsMalformed(t *testing.T) {
	if _, _, err := VerifyJWS("only.two"); err == nil {
		t.Fatal("expected error for malformed compact jws")
	}
}
