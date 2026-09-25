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

// Spend verifies a purchase spend-mandate: a COSE_Sign1 over
// domain.SpendMandateClaims, signed by the specific authority this seller trusts
// (its Ed25519 key pinned at construction), naming this seller as the audience,
// the caller as the subject, the session's item, a price within maxAmount, the
// matching currency, ScopePurchase, and a currently-valid window.
//
// As with the greet Mandate guard, self-verifying COSE proves only that SOME key
// signed the mandate; pinning the authority key is what authenticates the issuer.
type Spend struct {
	selfAns      string
	authorityAns string
	authorityPub ed25519.PublicKey
	leeway       time.Duration
	now          func() time.Time
	log          zerolog.Logger
}

// NewSpend builds a spend guard for seller selfAns that trusts only spend-mandates
// signed by authorityPub (the authority named authorityAns).
func NewSpend(selfAns, authorityAns string, authorityPub ed25519.PublicKey, log zerolog.Logger) *Spend {
	return &Spend{
		selfAns:      selfAns,
		authorityAns: authorityAns,
		authorityPub: authorityPub,
		leeway:       60 * time.Second,
		now:          time.Now,
		log:          log.With().Str("component", "policy").Logger(),
	}
}

// Verify enforces the spend-mandate. Every failure returns an error (fail closed).
func (s *Spend) Verify(ctx context.Context, req domain.PurchaseRequest) error {
	if len(req.SpendMandate) == 0 {
		return fmt.Errorf("spend mandate required")
	}
	payload, signer, err := crypto.VerifyCOSE1(req.SpendMandate)
	if err != nil {
		events.Emit(ctx, "spend.verify", events.StatusFail, map[string]string{"error": err.Error()})
		return fmt.Errorf("spend mandate signature invalid: %w", err)
	}
	events.Emit(ctx, "spend.verify", events.StatusOK, map[string]string{"alg": "EdDSA", "result": "COSE_Sign1 signature valid (self-verifying)"})
	if !signer.Equal(s.authorityPub) {
		events.Emit(ctx, "authority.pin", events.StatusFail, map[string]string{"authority": s.authorityAns})
		return fmt.Errorf("spend mandate not signed by the trusted authority")
	}
	events.Emit(ctx, "authority.pin", events.StatusOK, map[string]string{"authority": s.authorityAns, "result": "issuer key matches the pinned authority — issuer authenticated"})

	var claims domain.SpendMandateClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return fmt.Errorf("spend claims malformed: %w", err)
	}
	if claims.AuthorityAns != s.authorityAns {
		return fmt.Errorf("spend authority %q is not the trusted authority %q", claims.AuthorityAns, s.authorityAns)
	}
	if claims.AudienceAns != s.selfAns {
		return fmt.Errorf("spend audience %q is not this seller %q", claims.AudienceAns, s.selfAns)
	}
	if claims.SubjectAns != req.CallerAns {
		return fmt.Errorf("spend subject %q does not match caller %q", claims.SubjectAns, req.CallerAns)
	}
	if claims.Scope != domain.ScopePurchase {
		return fmt.Errorf("spend scope %q is not %q", claims.Scope, domain.ScopePurchase)
	}
	if claims.ItemID != req.ItemID {
		return fmt.Errorf("spend item %q does not match session item %q", claims.ItemID, req.ItemID)
	}
	if claims.Currency != req.Currency {
		return fmt.Errorf("spend currency %q does not match session currency %q", claims.Currency, req.Currency)
	}
	if req.Amount > claims.MaxAmount {
		return fmt.Errorf("price %d exceeds authorized maxAmount %d", req.Amount, claims.MaxAmount)
	}
	now := s.now()
	nb, err := time.Parse(time.RFC3339, claims.NotBefore)
	if err != nil {
		return fmt.Errorf("spend notBefore invalid: %w", err)
	}
	na, err := time.Parse(time.RFC3339, claims.NotAfter)
	if err != nil {
		return fmt.Errorf("spend notAfter invalid: %w", err)
	}
	if now.Before(nb.Add(-s.leeway)) {
		return fmt.Errorf("spend mandate not yet valid")
	}
	if now.After(na.Add(s.leeway)) {
		return fmt.Errorf("spend mandate expired")
	}
	s.log.Info().Str("mandateId", claims.MandateID).Str("callerAns", req.CallerAns).
		Str("itemId", claims.ItemID).Msg("spend mandate accepted")
	return nil
}
