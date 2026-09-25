package integration

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/audit"
	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/discovery"
	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
	"github.com/an-ciobanu/agent-mesh/internal/comms/resolver"
	commstl "github.com/an-ciobanu/agent-mesh/internal/comms/transparency"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/greet"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
	"github.com/an-ciobanu/agent-mesh/internal/registry"
	"github.com/an-ciobanu/agent-mesh/internal/tl"
)

func TestP2B_GreetSealAudit(t *testing.T) {
	reg := httptest.NewServer(registry.New(zerolog.Nop()).Handler())
	defer reg.Close()

	tlPriv, _ := crypto.GenerateEd25519()
	tlSrv := httptest.NewServer(tl.NewService(tlPriv, zerolog.Nop()).Handler())
	defer tlSrv.Close()

	const name = "greeter-open"
	self := domain.LocalANSName(name)
	greeterPriv, _ := crypto.GenerateEd25519()
	svc := a2a.NewGreetService(self, policy.Open{}, zerolog.Nop(), a2a.WithSealing(greeterPriv, commstl.New(tlSrv.URL)))
	agent := httptest.NewServer(a2a.NewMux(a2a.Card{Name: name, Version: "0.1.0", Security: []map[string][]string{}}, svc, zerolog.Nop()))
	defer agent.Close()

	disco := discovery.New(reg.URL)
	ctx := context.Background()
	if err := disco.Register(ctx, domain.AgentInfo{
		Name: name, Role: "greeter", BaseURL: agent.URL, CardURL: agent.URL + "/.well-known/agent-card.json",
	}); err != nil {
		t.Fatal(err)
	}

	priv, _ := crypto.GenerateEd25519()
	_, evidence, _, err := greet.Initiate(ctx, disco, resolver.New(), a2a.NewClient(), mcp.NewClient(), priv, domain.LocalANSName("visitor"), "greeter", "hello there")
	if err != nil {
		t.Fatalf("greet: %v", err)
	}
	if evidence == nil {
		t.Fatal("expected sealed evidence")
	}

	tlPub, err := commstl.New(tlSrv.URL).FetchPubKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	auditorPriv, _ := crypto.GenerateEd25519()
	auditor := audit.New(domain.LocalANSName("auditor"), auditorPriv, zerolog.Nop())

	verdict, _, err := auditor.Verify(ctx, *evidence, tlPub)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Verdict != "valid" {
		t.Fatalf("verdict = %q, checks=%v", verdict.Verdict, verdict.Checks)
	}

	// Tamper: a corrupted statement must be judged invalid.
	bad := *evidence
	bad.Statement = append([]byte(nil), evidence.Statement...)
	bad.Statement[len(bad.Statement)-5] ^= 0xff
	badVerdict, _, err := auditor.Verify(ctx, bad, tlPub)
	if err != nil {
		t.Fatal(err)
	}
	if badVerdict.Verdict != "invalid" {
		t.Fatal("tampered evidence must be judged invalid")
	}
}
