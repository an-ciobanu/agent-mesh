package crypto

import (
	"crypto/ed25519"
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
