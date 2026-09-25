package policy

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/nonce"
)

// Nonce is a GreetPolicy that admits a caller only if it presents a valid DPoP
// proof-of-possession (RFC 9449, ES256) over a fresh, single-use nonce this
// greeter issued: the proof's signature must verify against its embedded key,
// its htm/htu must match this request, its iat must be fresh, and its nonce must
// be one the greeter issued and has not yet consumed.
//
// Single use is enforced on the nonce claim (via the store), not on the proof
// bytes: ECDSA signatures are malleable, so a byte-level dedupe would be
// bypassable; consuming the nonce defeats replay regardless of re-signing.
type Nonce struct {
	selfAns string
	store   *nonce.Store
	leeway  time.Duration
	now     func() time.Time
	log     zerolog.Logger
}

// NewNonce builds a nonce-gated policy for greeter selfAns backed by store.
func NewNonce(selfAns string, store *nonce.Store, log zerolog.Logger) *Nonce {
	return &Nonce{
		selfAns: selfAns,
		store:   store,
		leeway:  60 * time.Second,
		now:     time.Now,
		log:     log.With().Str("component", "policy").Logger(),
	}
}

// Authorize enforces the DPoP proof. Every failure returns an error (fail closed).
func (n *Nonce) Authorize(_ context.Context, req domain.GreetRequest) error {
	if req.DPoPProof == "" {
		return fmt.Errorf("DPoP proof required")
	}
	claims, thumb, err := crypto.VerifyDPoPProof(req.DPoPProof)
	if err != nil {
		return fmt.Errorf("DPoP proof invalid: %w", err)
	}
	if claims.HTM != req.HTTPMethod {
		return fmt.Errorf("DPoP htm %q does not match request method %q", claims.HTM, req.HTTPMethod)
	}
	if claims.HTU != req.HTTPURL {
		return fmt.Errorf("DPoP htu %q does not match request URL %q", claims.HTU, req.HTTPURL)
	}
	iat := time.Unix(claims.IAT, 0)
	now := n.now()
	if iat.After(now.Add(n.leeway)) || now.Sub(iat) > n.leeway {
		return fmt.Errorf("DPoP proof stale or not yet valid")
	}
	// Consuming the nonce enforces single use and freshness (the greeter issued
	// it, within the store's TTL).
	if !n.store.Consume(claims.Nonce) {
		return fmt.Errorf("DPoP nonce not recognized or already used")
	}
	n.log.Info().Str("callerAns", req.CallerAns).Str("dpopThumbprint", thumb).Msg("nonce proof accepted")
	return nil
}

var _ domain.GreetPolicy = (*Nonce)(nil)
