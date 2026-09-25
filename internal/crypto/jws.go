package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type jwsHeader struct {
	Alg string `json:"alg"`
	JWK JWK    `json:"jwk"`
}

// SignJWS returns a compact JWS (EdDSA) over payload, embedding the signer's
// public JWK in the protected header so a verifier is self-contained.
func SignJWS(priv ed25519.PrivateKey, payload []byte) (string, error) {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return "", errors.New("jws: private key is not ed25519")
	}
	hb, err := json.Marshal(jwsHeader{Alg: "EdDSA", JWK: PublicJWK(pub)})
	if err != nil {
		return "", fmt.Errorf("jws: marshal header: %w", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	sig := ed25519.Sign(priv, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyJWS verifies a compact EdDSA JWS whose header carries the public JWK,
// returning the payload and the verifying key. Possession of the key is proven
// by the signature; binding that key to a registered identity is out of scope.
func VerifyJWS(compact string) ([]byte, JWK, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, JWK{}, errors.New("jws: expected 3 parts")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, JWK{}, fmt.Errorf("jws: decode header: %w", err)
	}
	var hdr jwsHeader
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, JWK{}, fmt.Errorf("jws: parse header: %w", err)
	}
	if hdr.Alg != "EdDSA" {
		return nil, JWK{}, fmt.Errorf("jws: unsupported alg %q", hdr.Alg)
	}
	if hdr.JWK.Kty != "OKP" || hdr.JWK.Crv != "Ed25519" {
		return nil, JWK{}, errors.New("jws: header jwk is not an Ed25519 OKP key")
	}
	pub, err := base64.RawURLEncoding.DecodeString(hdr.JWK.X)
	if err != nil {
		return nil, JWK{}, fmt.Errorf("jws: decode jwk x: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, JWK{}, fmt.Errorf("jws: bad public key size %d", len(pub))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, JWK{}, fmt.Errorf("jws: decode payload: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, JWK{}, fmt.Errorf("jws: decode signature: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte(parts[0]+"."+parts[1]), sig) {
		return nil, JWK{}, errors.New("jws: signature verification failed")
	}
	return payload, hdr.JWK, nil
}
