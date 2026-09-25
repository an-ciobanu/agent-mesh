package domain

import "context"

// GreetRequest is the verified content of an inbound greet.
type GreetRequest struct {
	CallerAns   string
	AudienceAns string
	Greeting    string
}

// GreetPolicy decides whether an agent accepts a greet. Implementations are the
// per-type behavior (open, mandate-gated, nonce-gated); the comms layer stays
// identical across them.
type GreetPolicy interface {
	Authorize(ctx context.Context, req GreetRequest) error
}
