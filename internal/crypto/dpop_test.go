package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
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

// signCompact signs header+claims JSON as a compact ES256 JWS (white-box helper
// for crafting adversarial proofs).
func signCompact(t *testing.T, priv *ecdsa.PrivateKey, headerJSON, claimsJSON []byte) string {
	t.Helper()
	si := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(si))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := append(coord32(r), coord32(s)...)
	return si + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func validHeaderJSON(t *testing.T, priv *ecdsa.PrivateKey, typ, alg string) []byte {
	t.Helper()
	b, err := json.Marshal(dpopHeader{Typ: typ, Alg: alg, JWK: ecPublicJWK(&priv.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDPoPRejectsBadAlgOrTyp(t *testing.T) {
	priv, _ := GenerateDPoPKey()
	claims, _ := json.Marshal(sampleClaims())
	for _, h := range []struct{ typ, alg string }{
		{"dpop+jwt", "none"},
		{"dpop+jwt", "HS256"},
		{"JWT", "ES256"},
	} {
		proof := signCompact(t, priv, validHeaderJSON(t, priv, h.typ, h.alg), claims)
		if _, _, err := VerifyDPoPProof(proof); err == nil {
			t.Fatalf("expected rejection for typ=%q alg=%q", h.typ, h.alg)
		}
	}
}

func TestDPoPRejectsBadSignatureLength(t *testing.T) {
	priv, _ := GenerateDPoPKey()
	claims, _ := json.Marshal(sampleClaims())
	si := base64.RawURLEncoding.EncodeToString(validHeaderJSON(t, priv, "dpop+jwt", "ES256")) + "." + base64.RawURLEncoding.EncodeToString(claims)
	proof := si + "." + base64.RawURLEncoding.EncodeToString([]byte("short"))
	if _, _, err := VerifyDPoPProof(proof); err == nil {
		t.Fatal("expected rejection for a non-64-byte signature")
	}
}

func TestDPoPRejectsNonJSONHeader(t *testing.T) {
	priv, _ := GenerateDPoPKey()
	claims, _ := json.Marshal(sampleClaims())
	proof := signCompact(t, priv, []byte("not json"), claims)
	if _, _, err := VerifyDPoPProof(proof); err == nil {
		t.Fatal("expected rejection for a non-JSON header")
	}
}

func TestDPoPRejectsBadBase64Segments(t *testing.T) {
	priv, _ := GenerateDPoPKey()
	claims, _ := json.Marshal(sampleClaims())
	goodHeader := base64.RawURLEncoding.EncodeToString(validHeaderJSON(t, priv, "dpop+jwt", "ES256"))
	goodClaims := base64.RawURLEncoding.EncodeToString(claims)
	if _, _, err := VerifyDPoPProof(goodHeader + ".!!!." + "AAAA"); err == nil {
		t.Fatal("expected rejection for bad claims base64")
	}
	if _, _, err := VerifyDPoPProof(goodHeader + "." + goodClaims + ".!!!"); err == nil {
		t.Fatal("expected rejection for bad signature base64")
	}
	if _, _, err := VerifyDPoPProof("!!!." + goodClaims + ".AAAA"); err == nil {
		t.Fatal("expected rejection for bad header base64")
	}
}

func TestDPoPRejectsBadJWKCoordinates(t *testing.T) {
	priv, _ := GenerateDPoPKey()
	claims, _ := json.Marshal(sampleClaims())
	hdr := dpopHeader{Typ: "dpop+jwt", Alg: "ES256", JWK: ecPublicJWK(&priv.PublicKey)}
	hdr.JWK.X = "!!!" // invalid base64
	hb, _ := json.Marshal(hdr)
	proof := signCompact(t, priv, hb, claims)
	if _, _, err := VerifyDPoPProof(proof); err == nil {
		t.Fatal("expected rejection for an invalid JWK x coordinate")
	}
}

func TestDPoPRejectsNonJSONClaims(t *testing.T) {
	priv, _ := GenerateDPoPKey()
	proof := signCompact(t, priv, validHeaderJSON(t, priv, "dpop+jwt", "ES256"), []byte("not json"))
	if _, _, err := VerifyDPoPProof(proof); err == nil {
		t.Fatal("expected rejection for non-JSON claims")
	}
}

func TestCoord32Pads(t *testing.T) {
	b := coord32(big.NewInt(1))
	if len(b) != 32 || b[31] != 1 {
		t.Fatalf("coord32 did not left-pad to 32 bytes: %v", b)
	}
	for _, x := range b[:31] {
		if x != 0 {
			t.Fatal("coord32 padding not zero")
		}
	}
}
