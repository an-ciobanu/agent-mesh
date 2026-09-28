package greet

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
	"github.com/an-ciobanu/agent-mesh/internal/comms/resolver"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/events"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
)

// startOpenGreeter stands up an in-process OPEN greeter (no mandate/nonce
// requirement), mirroring the harness used by TestInitiateGreetsDiscoveredOpenPeer
// in initiator_test.go, and returns its domain.AgentInfo plus a caller keypair.
func startOpenGreeter(t *testing.T) (domain.AgentInfo, ed25519.PrivateKey) {
	t.Helper()

	const name = "greeter-open-peer"
	self := domain.LocalANSName(name)
	svc := a2a.NewGreetService(self, policy.Open{}, zerolog.Nop())
	agent := httptest.NewServer(a2a.NewMux(a2a.Card{Name: name, Version: "0.1.0"}, svc, zerolog.Nop()))
	t.Cleanup(agent.Close)

	peer := domain.AgentInfo{
		Name:    name,
		Role:    "greeter",
		BaseURL: agent.URL,
		CardURL: agent.URL + "/.well-known/agent-card.json",
	}

	priv, _ := crypto.GenerateEd25519()
	return peer, priv
}

func TestGreetPeerOpenEmitsInitiatorEvents(t *testing.T) {
	peer, priv := startOpenGreeter(t)

	var buf bytes.Buffer
	ctx := events.WithScope(context.Background(), events.NewJSONEmitter(&buf), "g9", "chris", events.RoleInitiator)

	reply, _, _, err := GreetPeer(ctx, resolver.New(), a2a.NewClient(), mcp.NewClient(), nil,
		priv, domain.LocalANSName("chris"), peer, "hello")
	if err != nil {
		t.Fatalf("GreetPeer: %v", err)
	}
	if reply == "" {
		t.Fatalf("empty reply")
	}
	got := buf.String()
	for _, want := range []string{`"step":"card.read"`, `"step":"greet.send"`, `"step":"greet.reply"`, `"greetId":"g9"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s in events: %s", want, got)
		}
	}
}
