package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/veraison/go-cose"
)

// coseHeaderIssuerPub is the protected-header label under which the signer's raw
// Ed25519 public key is embedded, so a COSE_Sign1 is self-verifying. Binding
// that key to a registered identity is out of scope (deferred, like the JWS path).
const coseHeaderIssuerPub = "issuer_pub"

// SignCOSE1 produces a COSE_Sign1 (EdDSA) over payload, embedding the signer's
// public key in the protected header.
func SignCOSE1(priv ed25519.PrivateKey, payload []byte) ([]byte, error) {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("cose: private key is not ed25519")
	}
	signer, err := cose.NewSigner(cose.AlgorithmEdDSA, priv)
	if err != nil {
		return nil, fmt.Errorf("cose: new signer: %w", err)
	}
	msg := cose.NewSign1Message()
	msg.Payload = payload
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmEdDSA)
	msg.Headers.Protected[coseHeaderIssuerPub] = []byte(pub)
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return nil, fmt.Errorf("cose: sign: %w", err)
	}
	out, err := msg.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("cose: marshal: %w", err)
	}
	return out, nil
}

// VerifyCOSE1 parses a self-verifying COSE_Sign1 (from SignCOSE1), verifies its
// signature with the embedded public key, and returns the payload and that key.
func VerifyCOSE1(data []byte) ([]byte, ed25519.PublicKey, error) {
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(data); err != nil {
		return nil, nil, fmt.Errorf("cose: unmarshal: %w", err)
	}
	raw, ok := msg.Headers.Protected[coseHeaderIssuerPub]
	if !ok {
		return nil, nil, errors.New("cose: missing issuer_pub header")
	}
	pubBytes, ok := raw.([]byte)
	if !ok || len(pubBytes) != ed25519.PublicKeySize {
		return nil, nil, errors.New("cose: invalid issuer_pub header")
	}
	pub := ed25519.PublicKey(pubBytes)
	verifier, err := cose.NewVerifier(cose.AlgorithmEdDSA, pub)
	if err != nil {
		return nil, nil, fmt.Errorf("cose: new verifier: %w", err)
	}
	if err := msg.Verify(nil, verifier); err != nil {
		return nil, nil, fmt.Errorf("cose: verify: %w", err)
	}
	return msg.Payload, pub, nil
}
