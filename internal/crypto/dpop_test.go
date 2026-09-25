package crypto

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func sampleClaims() DPoPClaims {
	return DPoPClaims{
		HTM:   "POST",
		HTU:   "http://127.0.0.1:9/a2a",
		IAT:   time.Now().Unix(),
		JTI:   "jti-123",
		Nonce: "nonce-abc",
	}
}

func TestDPoPProofRoundTrip(t *testing.T) {
	priv, err := GenerateDPoPKey()
	if err != nil {
		t.Fatal(err)
	}
	in := sampleClaims()
	proof, err := CreateDPoPProof(priv, in)
	if err != nil {
		t.Fatal(err)
	}
	got, thumb, err := VerifyDPoPProof(proof)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got != in {
		t.Fatalf("claims mismatch: %+v vs %+v", got, in)
	}
	if thumb == "" {
		t.Fatal("empty thumbprint")
	}
	if thumb != DPoPThumbprint(&priv.PublicKey) {
		t.Fatal("thumbprint not stable")
	}
}

func TestDPoPProofRejectsTamperedClaims(t *testing.T) {
	priv, _ := GenerateDPoPKey()
	proof, _ := CreateDPoPProof(priv, sampleClaims())
	parts := strings.Split(proof, ".")
	parts[1] = parts[1][:len(parts[1])-2] + "AA"
	if _, _, err := VerifyDPoPProof(strings.Join(parts, ".")); err == nil {
		t.Fatal("expected verification failure on tampered claims")
	}
}

func TestDPoPProofRejectsWrongKey(t *testing.T) {
	priv, _ := GenerateDPoPKey()
	other, _ := GenerateDPoPKey()
	proof, _ := CreateDPoPProof(priv, sampleClaims())
	otherProof, _ := CreateDPoPProof(other, sampleClaims())
	spliced := strings.Split(otherProof, ".")[0] + "." + strings.SplitN(proof, ".", 2)[1]
	if _, _, err := VerifyDPoPProof(spliced); err == nil {
		t.Fatal("expected verification failure when header key does not match signature")
	}
}

func TestDPoPProofRejectsMalformed(t *testing.T) {
	for _, bad := range []string{"", "a.b", "a.b.c.d", "!!!.!!!.!!!"} {
		if _, _, err := VerifyDPoPProof(bad); err == nil {
			t.Fatalf("expected error for malformed proof %q", bad)
		}
	}
}

func TestDPoPProofRejectsUnsupportedCurve(t *testing.T) {
	hdr := `{"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-384","x":"AA","y":"AA"}}`
	h := base64.RawURLEncoding.EncodeToString([]byte(hdr))
	proof := h + ".AA.AA"
	if _, _, err := VerifyDPoPProof(proof); err == nil {
		t.Fatal("expected error for unsupported curve in header jwk")
	}
}

func TestDPoPThumbprintDistinctKeys(t *testing.T) {
	a, _ := GenerateDPoPKey()
	b, _ := GenerateDPoPKey()
	if DPoPThumbprint(&a.PublicKey) == DPoPThumbprint(&b.PublicKey) {
		t.Fatal("distinct keys must have distinct thumbprints")
	}
}
