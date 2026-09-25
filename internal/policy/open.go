// Package policy holds the per-type GreetPolicy implementations.
package policy

import (
	"context"

	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

// Open accepts any greet from any identity-verified caller.
type Open struct{}

// Authorize always succeeds — the caller's identity was already verified by the
// transport layer; an open greeter imposes no further requirement.
func (Open) Authorize(_ context.Context, _ domain.GreetRequest) error {
	return nil
}

var _ domain.GreetPolicy = Open{}
