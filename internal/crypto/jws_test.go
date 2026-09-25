package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
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

// TestVerifyJWSRejectsInvalidHeadersAndSegments exercises every rejection
// branch in VerifyJWS: bad alg, bad jwk kty/crv, a truncated key, and
// non-base64 garbage in each of the three compact-JWS segments.
func TestVerifyJWSRejectsInvalidHeadersAndSegments(t *testing.T) {
	priv, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)

	valid, err := SignJWS(priv, []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	validParts := strings.Split(valid, ".")
	if len(validParts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(validParts))
	}
	headerSeg, payloadSeg, sigSeg := validParts[0], validParts[1], validParts[2]
	validX := base64.RawURLEncoding.EncodeToString(pub)

	encodeHeader := func(alg, kty, crv, x string) string {
		hb, merr := json.Marshal(map[string]any{
			"alg": alg,
			"jwk": map[string]string{"kty": kty, "crv": crv, "x": x},
		})
		if merr != nil {
			t.Fatal(merr)
		}
		return base64.RawURLEncoding.EncodeToString(hb)
	}

	cases := []struct {
		name    string
		compact string
	}{
		{"alg none", encodeHeader("none", "OKP", "Ed25519", validX) + "." + payloadSeg + "." + sigSeg},
		{"alg HS256", encodeHeader("HS256", "OKP", "Ed25519", validX) + "." + payloadSeg + "." + sigSeg},
		{"kty RSA", encodeHeader("EdDSA", "RSA", "Ed25519", validX) + "." + payloadSeg + "." + sigSeg},
		{"crv P-256", encodeHeader("EdDSA", "OKP", "P-256", validX) + "." + payloadSeg + "." + sigSeg},
		{
			"truncated x (wrong key size)",
			encodeHeader("EdDSA", "OKP", "Ed25519", base64.RawURLEncoding.EncodeToString(pub[:10])) + "." + payloadSeg + "." + sigSeg,
		},
		{"garbage header segment", "not-valid-base64!!!" + "." + payloadSeg + "." + sigSeg},
		{"garbage payload segment", headerSeg + "." + "not-valid-base64!!!" + "." + sigSeg},
		{"garbage signature segment", headerSeg + "." + payloadSeg + "." + "not-valid-base64!!!"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := VerifyJWS(tc.compact); err == nil {
				t.Fatalf("expected VerifyJWS to reject case %q", tc.name)
			}
		})
	}
}
