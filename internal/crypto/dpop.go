package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// DPoPClaims are the RFC 9449 DPoP proof claims agent-mesh uses.
type DPoPClaims struct {
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	IAT   int64  `json:"iat"`
	JTI   string `json:"jti"`
	Nonce string `json:"nonce"`
}

// ecJWK is a P-256 public key in JWK form.
type ecJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type dpopHeader struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	JWK ecJWK  `json:"jwk"`
}

// GenerateDPoPKey returns a fresh P-256 key for DPoP proofs.
func GenerateDPoPKey() (*ecdsa.PrivateKey, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate dpop key: %w", err)
	}
	return k, nil
}

// coord32 left-pads a coordinate to the 32-byte P-256 field size.
func coord32(v *big.Int) []byte {
	b := v.Bytes()
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func ecPublicJWK(pub *ecdsa.PublicKey) ecJWK {
	return ecJWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(coord32(pub.X)),
		Y:   base64.RawURLEncoding.EncodeToString(coord32(pub.Y)),
	}
}

// DPoPThumbprint returns the RFC 7638 JWK thumbprint of a P-256 public key.
func DPoPThumbprint(pub *ecdsa.PublicKey) string {
	j := ecPublicJWK(pub)
	canonical := fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q,"y":%q}`, j.Crv, j.Kty, j.X, j.Y)
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// CreateDPoPProof builds a compact ES256 JWS DPoP proof over claims, embedding
// the signer's P-256 public key in the header (self-verifying).
func CreateDPoPProof(priv *ecdsa.PrivateKey, claims DPoPClaims) (string, error) {
	hb, err := json.Marshal(dpopHeader{Typ: "dpop+jwt", Alg: "ES256", JWK: ecPublicJWK(&priv.PublicKey)})
	if err != nil {
		return "", fmt.Errorf("marshal dpop header: %w", err)
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal dpop claims: %w", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign dpop proof: %w", err)
	}
	sig := append(coord32(r), coord32(s)...)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyDPoPProof verifies a compact ES256 DPoP proof against its embedded key
// and returns the claims plus the RFC 7638 thumbprint of that key. It verifies
// the signature and structural validity only; freshness, htm/htu and nonce are
// the caller's (policy's) responsibility.
func VerifyDPoPProof(compact string) (DPoPClaims, string, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return DPoPClaims{}, "", errors.New("dpop: malformed proof")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return DPoPClaims{}, "", fmt.Errorf("dpop: decode header: %w", err)
	}
	var hdr dpopHeader
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return DPoPClaims{}, "", fmt.Errorf("dpop: parse header: %w", err)
	}
	if hdr.Typ != "dpop+jwt" || hdr.Alg != "ES256" {
		return DPoPClaims{}, "", errors.New("dpop: unexpected header typ/alg")
	}
	pub, err := ecPublicKeyFromJWK(hdr.JWK)
	if err != nil {
		return DPoPClaims{}, "", err
	}
	cb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return DPoPClaims{}, "", fmt.Errorf("dpop: decode claims: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return DPoPClaims{}, "", fmt.Errorf("dpop: decode signature: %w", err)
	}
	if len(sig) != 64 {
		return DPoPClaims{}, "", errors.New("dpop: bad signature length")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return DPoPClaims{}, "", errors.New("dpop: signature verification failed")
	}
	var claims DPoPClaims
	if err := json.Unmarshal(cb, &claims); err != nil {
		return DPoPClaims{}, "", fmt.Errorf("dpop: parse claims: %w", err)
	}
	return claims, DPoPThumbprint(pub), nil
}

// ecPublicKeyFromJWK reconstructs a P-256 public key from its JWK. ecdsa.Verify
// safely rejects an off-curve or invalid point (returns false), so no explicit
// on-curve check is needed here.
func ecPublicKeyFromJWK(j ecJWK) (*ecdsa.PublicKey, error) {
	if j.Kty != "EC" || j.Crv != "P-256" {
		return nil, errors.New("dpop: not a P-256 EC key")
	}
	x, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, fmt.Errorf("dpop: decode x: %w", err)
	}
	y, err := base64.RawURLEncoding.DecodeString(j.Y)
	if err != nil {
		return nil, fmt.Errorf("dpop: decode y: %w", err)
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, nil
}
