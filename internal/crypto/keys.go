// Package crypto holds agent-mesh key management and signing primitives.
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// JWK is a minimal JSON Web Key for an Ed25519 public key (OKP).
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
}

// GenerateEd25519 returns a fresh Ed25519 private key.
func GenerateEd25519() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	return priv, nil
}

// LoadOrCreateEd25519 loads a 32-byte seed from path, or creates, persists,
// and returns a new key when the file does not yet exist.
func LoadOrCreateEd25519(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(b) != ed25519.SeedSize {
			return nil, fmt.Errorf("key file %s: want %d-byte seed, got %d", path, ed25519.SeedSize, len(b))
		}
		return ed25519.NewKeyFromSeed(b), nil
	case errors.Is(err, os.ErrNotExist):
		priv, gerr := GenerateEd25519()
		if gerr != nil {
			return nil, gerr
		}
		if mkErr := os.MkdirAll(filepath.Dir(path), 0o700); mkErr != nil {
			return nil, fmt.Errorf("create key dir: %w", mkErr)
		}
		if wErr := os.WriteFile(path, priv.Seed(), 0o600); wErr != nil {
			return nil, fmt.Errorf("write key file: %w", wErr)
		}
		return priv, nil
	default:
		return nil, fmt.Errorf("read key file %s: %w", path, err)
	}
}

// PublicJWK builds a JWK from an Ed25519 public key.
func PublicJWK(pub ed25519.PublicKey) JWK {
	return JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
	}
}

// PublicKeyFromJWK converts an Ed25519 OKP JWK to a public key. It is the
// inverse of PublicJWK.
func PublicKeyFromJWK(j JWK) (ed25519.PublicKey, error) {
	if j.Kty != "OKP" || j.Crv != "Ed25519" {
		return nil, fmt.Errorf("jwk: not an Ed25519 OKP key")
	}
	raw, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, fmt.Errorf("jwk: decode x: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("jwk: bad key size %d", len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// Thumbprint returns the RFC 7638 JWK thumbprint (base64url SHA-256 over the
// canonical JSON of the required members, in lexicographic order).
func Thumbprint(j JWK) string {
	canonical := fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q}`, j.Crv, j.Kty, j.X)
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
