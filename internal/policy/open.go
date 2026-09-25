// Package policy holds the per-type GreetPolicy implementations.
package policy

import (
	"context"

	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/events"
)

// Open accepts any greet from any caller that proved possession of a signing
// key.
type Open struct{}

// Authorize always succeeds. By the time Authorize runs, the caller has proved
// possession of the key that signed the greet and bound the greet to us (the
// audience match), and the payload's integrity is verified — but the caller's
// ANS name (CallerAns) is self-asserted in P1: nothing here checks that the
// signing key belongs to that name. Binding a name to a registered key is
// deferred to P2/P3. An open greeter imposes no further requirement regardless.
func (Open) Authorize(ctx context.Context, _ domain.GreetRequest) error {
	events.Emit(ctx, "gate", events.StatusOK, map[string]string{"policy": "open"})
	return nil
}

var _ domain.GreetPolicy = Open{}
