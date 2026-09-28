// Package audit independently verifies transparency evidence bundles.
package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

// Auditor verifies evidence bundles and signs its verdicts.
type Auditor struct {
	auditorAns string
	priv       ed25519.PrivateKey
	log        zerolog.Logger
}

// New returns an auditor identified by auditorAns that signs verdicts with priv.
func New(auditorAns string, priv ed25519.PrivateKey, log zerolog.Logger) *Auditor {
	return &Auditor{auditorAns: auditorAns, priv: priv, log: log.With().Str("component", "audit").Logger()}
}

type receiptClaims struct {
	LogID      string `json:"logId"`
	EntryIndex int    `json:"entryIndex"`
	TreeSize   int    `json:"treeSize"`
	Root       []byte `json:"root"`
}

// Verify independently checks a bundle against the transparency log's public key
// and returns a verdict plus a COSE-signed copy of it. A verification failure is
// an "invalid" verdict, not a Go error; errors are reserved for internal faults
// (e.g. signing the verdict).
func (a *Auditor) Verify(_ context.Context, bundle domain.EvidenceBundle, tlPub ed25519.PublicKey) (domain.Verdict, []byte, error) {
	v := domain.Verdict{Verdict: "valid", AuditorAns: a.auditorAns}
	fail := func(reason string) (domain.Verdict, []byte, error) {
		v.Verdict = "invalid"
		v.Checks = append(v.Checks, "FAIL: "+reason)
		a.log.Warn().Str("reason", reason).Msg("audit failed")
		signed, err := a.sign(v)
		return v, signed, err
	}

	// 1. Statement issuer signature (self-asserted issuer key; thumbprint recorded).
	_, issuerPub, err := crypto.VerifyCOSE1(bundle.Statement)
	if err != nil {
		return fail("statement signature invalid: " + err.Error())
	}
	v.Checks = append(v.Checks, "OK: statement signed by "+crypto.Thumbprint(crypto.PublicJWK(issuerPub)))

	// 2. Receipt signed by the transparency log.
	claimsBytes, receiptSigner, err := crypto.VerifyCOSE1(bundle.Receipt.COSE)
	if err != nil {
		return fail("receipt signature invalid: " + err.Error())
	}
	if !receiptSigner.Equal(tlPub) {
		return fail("receipt not signed by the expected transparency-log key")
	}
	v.Checks = append(v.Checks, "OK: receipt signed by the transparency log")

	// 2b. The log id in the receipt must be the thumbprint of the log key we just
	// verified against — this pins the receipt to a specific, named log identity
	// (the "check the TL and log id from the peer's output" property).
	wantLogID := crypto.Thumbprint(crypto.PublicJWK(tlPub))
	if bundle.Receipt.LogID != wantLogID {
		return fail("receipt log id does not match the transparency-log key")
	}
	v.Checks = append(v.Checks, "OK: log id "+wantLogID+" matches the log key")

	// 3. Receipt COSE claims match the receipt fields.
	var rc receiptClaims
	if err := json.Unmarshal(claimsBytes, &rc); err != nil {
		return fail("receipt claims unparseable: " + err.Error())
	}
	if rc.LogID != bundle.Receipt.LogID || rc.EntryIndex != bundle.Receipt.EntryIndex || rc.TreeSize != bundle.Receipt.TreeSize || !bytes.Equal(rc.Root, bundle.Receipt.Root) {
		return fail("receipt claims do not match receipt fields")
	}
	v.Checks = append(v.Checks, "OK: receipt claims consistent")

	// 4. Inclusion proof against the receipt root.
	leaf := crypto.LeafHash(bundle.Statement)
	if !crypto.VerifyInclusion(leaf, bundle.Receipt.EntryIndex, bundle.Receipt.TreeSize, bundle.Receipt.Proof, bundle.Receipt.Root) {
		return fail("inclusion proof does not verify")
	}
	v.Checks = append(v.Checks, fmt.Sprintf("OK: included at entry %d of %d", bundle.Receipt.EntryIndex, bundle.Receipt.TreeSize))

	a.log.Info().Str("verdict", v.Verdict).Msg("audit complete")
	signed, err := a.sign(v)
	return v, signed, err
}

func (a *Auditor) sign(v domain.Verdict) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal verdict: %w", err)
	}
	signed, err := crypto.SignCOSE1(a.priv, b)
	if err != nil {
		return nil, fmt.Errorf("sign verdict: %w", err)
	}
	return signed, nil
}
