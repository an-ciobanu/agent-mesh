package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestPublicJWKAndThumbprintDeterministic(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize) // all-zero seed -> deterministic key
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	jwk := PublicJWK(pub)
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" || jwk.X == "" {
		t.Fatalf("unexpected jwk: %+v", jwk)
	}

	tp1 := Thumbprint(jwk)
	tp2 := Thumbprint(PublicJWK(pub))
	if tp1 == "" || tp1 != tp2 {
		t.Fatalf("thumbprint not deterministic: %q vs %q", tp1, tp2)
	}
}

func TestLoadOrCreateEd25519Persists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id_ed25519.seed")

	k1, err := LoadOrCreateEd25519(path)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := LoadOrCreateEd25519(path)
	if err != nil {
		t.Fatal(err)
	}
	if !k1.Equal(k2) {
		t.Fatal("expected the same key when reloading from disk")
	}
}

func TestLoadOrCreateEd25519RejectsWrongLengthSeed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id_ed25519.seed")
	if err := os.WriteFile(path, make([]byte, 10), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadOrCreateEd25519(path); err == nil {
		t.Fatal("expected an error for a wrong-length seed file, got nil")
	}
}

func TestPublicKeyFromJWKRoundTrip(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	got, err := PublicKeyFromJWK(PublicJWK(pub))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(pub) {
		t.Fatal("round-tripped key does not match")
	}
}

func TestPublicKeyFromJWKRejectsWrongType(t *testing.T) {
	if _, err := PublicKeyFromJWK(JWK{Kty: "RSA", Crv: "Ed25519", X: "x"}); err == nil {
		t.Fatal("expected error for non-OKP key")
	}
	if _, err := PublicKeyFromJWK(JWK{Kty: "OKP", Crv: "P-256", X: "x"}); err == nil {
		t.Fatal("expected error for non-Ed25519 curve")
	}
}

func TestPublicKeyFromJWKRejectsBadX(t *testing.T) {
	if _, err := PublicKeyFromJWK(JWK{Kty: "OKP", Crv: "Ed25519", X: "!!!not base64!!!"}); err == nil {
		t.Fatal("expected error for invalid base64 x")
	}
	if _, err := PublicKeyFromJWK(JWK{Kty: "OKP", Crv: "Ed25519", X: "YWJj"}); err == nil {
		t.Fatal("expected error for wrong key size")
	}
}
