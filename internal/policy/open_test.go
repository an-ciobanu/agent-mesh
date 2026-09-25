package policy

import (
	"context"
	"testing"

	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

func TestOpenAuthorizeAcceptsAnyCaller(t *testing.T) {
	var p domain.GreetPolicy = Open{}
	err := p.Authorize(context.Background(), domain.GreetRequest{
		CallerAns:   "ans://v1.0.0.visitor.mesh.local",
		AudienceAns: "ans://v1.0.0.greeter-open.mesh.local",
		Greeting:    "hello",
	})
	if err != nil {
		t.Fatalf("Open.Authorize returned error: %v", err)
	}
}
