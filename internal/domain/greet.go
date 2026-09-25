package domain

import "context"

// GreetRequest is the verified content of an inbound greet.
type GreetRequest struct {
	CallerAns   string
	AudienceAns string
	Greeting    string

	// CallerKeyThumbprint is the RFC 7638 JWK thumbprint of the key that signed
	// the greet — proof that the caller possesses that key. It does NOT prove
	// CallerAns belongs to that key: in P1, CallerAns is self-asserted by the
	// caller. Binding CallerAns to a registered key is deferred to P2/P3.
	CallerKeyThumbprint string

	// Mandate is the caller-presented authorization: a COSE_Sign1 over
	// domain.MandateClaims, or nil if none was presented. A mandate-gated
	// GreetPolicy verifies and pins it to a trusted authority; an open policy
	// ignores it.
	Mandate []byte
}

// GreetPolicy decides whether an agent accepts a greet. Implementations are the
// per-type behavior (open, mandate-gated, nonce-gated); the comms layer stays
// identical across them.
type GreetPolicy interface {
	Authorize(ctx context.Context, req GreetRequest) error
}
