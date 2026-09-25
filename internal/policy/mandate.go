package policy

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/events"
)

// Mandate is a GreetPolicy that admits a caller only if it presents a valid
// mandate: a COSE_Sign1 over domain.MandateClaims, signed by the specific
// authority this greeter trusts (its Ed25519 key pinned at construction), naming
// this greeter as the audience, the caller as the subject, the required scope,
// and a currently-valid window.
//
// Self-verifying COSE proves only that SOME key signed the mandate; pinning the
// authority's key is what authenticates the issuer. Without it, any party could
// mint a mandate signed with its own key and pass.
type Mandate struct {
	selfAns      string
	authorityAns string
	authorityPub ed25519.PublicKey
	scope        string
	leeway       time.Duration
	now          func() time.Time
	log          zerolog.Logger
}

// NewMandate builds a mandate-gated policy for greeter selfAns that trusts only
// mandates signed by authorityPub (the authority named authorityAns), granting
// scope. A small clock-skew leeway is applied to the validity window.
func NewMandate(selfAns, authorityAns string, authorityPub ed25519.PublicKey, scope string, log zerolog.Logger) *Mandate {
	return &Mandate{
		selfAns:      selfAns,
		authorityAns: authorityAns,
		authorityPub: authorityPub,
		scope:        scope,
		leeway:       60 * time.Second,
		now:          time.Now,
		log:          log.With().Str("component", "policy").Logger(),
	}
}

// Authorize enforces the mandate. Every failure returns an error (fail closed).
func (m *Mandate) Authorize(ctx context.Context, req domain.GreetRequest) error {
	if len(req.Mandate) == 0 {
		return fmt.Errorf("mandate required")
	}
	payload, signer, err := crypto.VerifyCOSE1(req.Mandate)
	if err != nil {
		events.Emit(ctx, "mandate.verify", events.StatusFail, map[string]string{"error": err.Error()})
		return fmt.Errorf("mandate signature invalid: %w", err)
	}
	events.Emit(ctx, "mandate.verify", events.StatusOK, map[string]string{"alg": "EdDSA", "result": "COSE_Sign1 signature valid (self-verifying)"})
	if !signer.Equal(m.authorityPub) {
		events.Emit(ctx, "authority.pin", events.StatusFail, map[string]string{"authority": m.authorityAns})
		return fmt.Errorf("mandate not signed by the trusted authority")
	}
	events.Emit(ctx, "authority.pin", events.StatusOK, map[string]string{"authority": m.authorityAns, "result": "issuer key matches the pinned authority — issuer authenticated"})
	var claims domain.MandateClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return fmt.Errorf("mandate claims malformed: %w", err)
	}
	if claims.AuthorityAns != m.authorityAns {
		return fmt.Errorf("mandate authority %q is not the trusted authority %q", claims.AuthorityAns, m.authorityAns)
	}
	if claims.AudienceAns != m.selfAns {
		return fmt.Errorf("mandate audience %q is not this greeter %q", claims.AudienceAns, m.selfAns)
	}
	if claims.SubjectAns != req.CallerAns {
		return fmt.Errorf("mandate subject %q does not match caller %q", claims.SubjectAns, req.CallerAns)
	}
	if claims.Scope != m.scope {
		return fmt.Errorf("mandate scope %q is not %q", claims.Scope, m.scope)
	}
	now := m.now()
	nb, err := time.Parse(time.RFC3339, claims.NotBefore)
	if err != nil {
		return fmt.Errorf("mandate notBefore invalid: %w", err)
	}
	na, err := time.Parse(time.RFC3339, claims.NotAfter)
	if err != nil {
		return fmt.Errorf("mandate notAfter invalid: %w", err)
	}
	if now.Before(nb.Add(-m.leeway)) {
		return fmt.Errorf("mandate not yet valid")
	}
	if now.After(na.Add(m.leeway)) {
		return fmt.Errorf("mandate expired")
	}

	m.log.Info().Str("mandateId", claims.MandateID).Str("callerAns", req.CallerAns).Msg("mandate accepted")
	return nil
}

var _ domain.GreetPolicy = (*Mandate)(nil)
