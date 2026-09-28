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

// UCP verifies a UCP purchase's two AP2 mandates: a CheckoutMandate (binds the
// cart state) and a PaymentMandate (binds the payment), both COSE_Sign1 signed by
// the pinned authority. Every check fails closed. Pinning the authority key
// authenticates the issuer.
type UCP struct {
	selfAns      string
	authorityAns string
	authorityPub ed25519.PublicKey
	leeway       time.Duration
	now          func() time.Time
	log          zerolog.Logger
}

// NewUCP builds a UCP guard for seller selfAns trusting authorityPub (authorityAns).
func NewUCP(selfAns, authorityAns string, authorityPub ed25519.PublicKey, log zerolog.Logger) *UCP {
	return &UCP{selfAns: selfAns, authorityAns: authorityAns, authorityPub: authorityPub, leeway: 60 * time.Second, now: time.Now, log: log.With().Str("component", "policy").Logger()}
}

// Verify checks both mandates against the completion. Fail closed.
func (u *UCP) Verify(ctx context.Context, c domain.UCPCompletion) error {
	if len(c.CheckoutMandate) == 0 || len(c.PaymentMandate) == 0 {
		return fmt.Errorf("both checkout and payment mandates are required")
	}

	cPayload, cSigner, err := crypto.VerifyCOSE1(c.CheckoutMandate)
	if err != nil {
		events.Emit(ctx, "checkout.mandate.verify", events.StatusFail, map[string]string{"error": err.Error()})
		return fmt.Errorf("checkout mandate signature invalid: %w", err)
	}
	events.Emit(ctx, "checkout.mandate.verify", events.StatusOK, map[string]string{"alg": "EdDSA", "result": "COSE_Sign1 signature valid (self-verifying)"})
	if !cSigner.Equal(u.authorityPub) {
		events.Emit(ctx, "authority.pin", events.StatusFail, map[string]string{"authority": u.authorityAns})
		return fmt.Errorf("checkout mandate not signed by the trusted authority")
	}
	events.Emit(ctx, "authority.pin", events.StatusOK, map[string]string{"authority": u.authorityAns, "result": "issuer key matches the pinned authority — issuer authenticated"})
	var cc domain.CheckoutMandateClaims
	if err := json.Unmarshal(cPayload, &cc); err != nil {
		return fmt.Errorf("checkout claims malformed: %w", err)
	}
	if cc.AuthorityAns != u.authorityAns {
		return fmt.Errorf("checkout authority %q is not trusted %q", cc.AuthorityAns, u.authorityAns)
	}
	if cc.AudienceAns != u.selfAns {
		return fmt.Errorf("checkout audience %q is not this seller %q", cc.AudienceAns, u.selfAns)
	}
	if cc.SubjectAns != c.CallerAns {
		return fmt.Errorf("checkout subject %q does not match caller %q", cc.SubjectAns, c.CallerAns)
	}
	if cc.Scope != domain.ScopeCheckout {
		return fmt.Errorf("checkout scope %q is not %q", cc.Scope, domain.ScopeCheckout)
	}
	if cc.CheckoutID != c.CheckoutID {
		return fmt.Errorf("checkout mandate checkoutId %q does not match session %q", cc.CheckoutID, c.CheckoutID)
	}
	if cc.ItemID != c.ItemID {
		return fmt.Errorf("checkout item %q does not match session %q", cc.ItemID, c.ItemID)
	}
	if cc.Currency != c.Currency {
		return fmt.Errorf("checkout currency %q does not match session %q", cc.Currency, c.Currency)
	}
	if c.Amount > cc.Amount {
		return fmt.Errorf("amount %d exceeds checkout-authorized %d", c.Amount, cc.Amount)
	}
	if err := u.windowValid(cc.NotBefore, cc.NotAfter); err != nil {
		return fmt.Errorf("checkout mandate %w", err)
	}

	pPayload, pSigner, err := crypto.VerifyCOSE1(c.PaymentMandate)
	if err != nil {
		events.Emit(ctx, "payment.mandate.verify", events.StatusFail, map[string]string{"error": err.Error()})
		return fmt.Errorf("payment mandate signature invalid: %w", err)
	}
	if !pSigner.Equal(u.authorityPub) {
		events.Emit(ctx, "payment.mandate.verify", events.StatusFail, map[string]string{"error": "untrusted issuer"})
		return fmt.Errorf("payment mandate not signed by the trusted authority")
	}
	var pc domain.PaymentMandateClaims
	if err := json.Unmarshal(pPayload, &pc); err != nil {
		return fmt.Errorf("payment claims malformed: %w", err)
	}
	if pc.AuthorityAns != u.authorityAns {
		return fmt.Errorf("payment authority %q is not trusted %q", pc.AuthorityAns, u.authorityAns)
	}
	if pc.AudienceAns != u.selfAns {
		return fmt.Errorf("payment audience %q is not this seller %q", pc.AudienceAns, u.selfAns)
	}
	if pc.SubjectAns != c.CallerAns {
		return fmt.Errorf("payment subject %q does not match caller %q", pc.SubjectAns, c.CallerAns)
	}
	if pc.Scope != domain.ScopePayment {
		return fmt.Errorf("payment scope %q is not %q", pc.Scope, domain.ScopePayment)
	}
	if pc.Currency != c.Currency {
		return fmt.Errorf("payment currency %q does not match session %q", pc.Currency, c.Currency)
	}
	if c.Amount > pc.Amount {
		return fmt.Errorf("amount %d exceeds payment-authorized %d", c.Amount, pc.Amount)
	}
	if err := u.windowValid(pc.NotBefore, pc.NotAfter); err != nil {
		return fmt.Errorf("payment mandate %w", err)
	}
	events.Emit(ctx, "payment.mandate.verify", events.StatusOK, map[string]string{"alg": "EdDSA", "result": "payment authorization valid"})

	u.log.Info().Str("callerAns", c.CallerAns).Str("checkoutId", c.CheckoutID).Msg("UCP mandates accepted")
	return nil
}

func (u *UCP) windowValid(notBefore, notAfter string) error {
	nb, err := time.Parse(time.RFC3339, notBefore)
	if err != nil {
		return fmt.Errorf("notBefore invalid: %w", err)
	}
	na, err := time.Parse(time.RFC3339, notAfter)
	if err != nil {
		return fmt.Errorf("notAfter invalid: %w", err)
	}
	now := u.now()
	if now.Before(nb.Add(-u.leeway)) {
		return fmt.Errorf("not yet valid")
	}
	if now.After(na.Add(u.leeway)) {
		return fmt.Errorf("expired")
	}
	return nil
}
