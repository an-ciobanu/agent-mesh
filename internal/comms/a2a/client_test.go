package a2a

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	commstl "github.com/an-ciobanu/agent-mesh/internal/comms/transparency"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
	"github.com/an-ciobanu/agent-mesh/internal/tl"
)

func TestClientSendGreetRoundTrip(t *testing.T) {
	self := domain.LocalANSName("greeter-open")
	svc := NewGreetService(self, policy.Open{}, zerolog.Nop())
	ts := httptest.NewServer(NewMux(Card{Name: "greeter-open", Version: "0.1.0"}, svc, zerolog.Nop()))
	defer ts.Close()

	priv, _ := crypto.GenerateEd25519()
	reply, _, err := NewClient().SendGreet(context.Background(), ts.URL+"/a2a", priv, GreetPayload{
		CallerAns:   domain.LocalANSName("visitor"),
		AudienceAns: self,
		Greeting:    "hello there",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reply, self) {
		t.Fatalf("reply = %q, want it to contain %q", reply, self)
	}
}

func TestClientSendGreetSurfacesRPCError(t *testing.T) {
	self := domain.LocalANSName("greeter-open")
	svc := NewGreetService(self, policy.Open{}, zerolog.Nop())
	ts := httptest.NewServer(NewMux(Card{Name: "greeter-open", Version: "0.1.0"}, svc, zerolog.Nop()))
	defer ts.Close()

	priv, _ := crypto.GenerateEd25519()
	// Wrong audience -> handler returns a JSON-RPC error -> client must error.
	_, _, err := NewClient().SendGreet(context.Background(), ts.URL+"/a2a", priv, GreetPayload{
		CallerAns:   domain.LocalANSName("visitor"),
		AudienceAns: domain.LocalANSName("someone-else"),
		Greeting:    "hi",
	})
	if err == nil {
		t.Fatal("expected an error when the server rejects the greet")
	}
}

func TestClientSendGreetReturnsEvidenceWhenSealing(t *testing.T) {
	tlPriv, _ := crypto.GenerateEd25519()
	tlSrv := httptest.NewServer(tl.NewService(tlPriv, zerolog.Nop()).Handler())
	defer tlSrv.Close()

	self := domain.LocalANSName("greeter-open")
	greeterPriv, _ := crypto.GenerateEd25519()
	svc := NewGreetService(self, policy.Open{}, zerolog.Nop(), WithSealing(greeterPriv, commstl.New(tlSrv.URL)))
	ts := httptest.NewServer(NewMux(Card{Name: "greeter-open", Version: "0.1.0"}, svc, zerolog.Nop()))
	defer ts.Close()

	priv, _ := crypto.GenerateEd25519()
	reply, evidence, err := NewClient().SendGreet(context.Background(), ts.URL+"/a2a", priv, GreetPayload{
		CallerAns:   domain.LocalANSName("visitor"),
		AudienceAns: self,
		Greeting:    "hello there",
	})
	if err != nil {
		t.Fatal(err)
	}
	if reply == "" {
		t.Fatal("empty reply")
	}
	if evidence == nil {
		t.Fatal("expected sealed evidence from a sealing greeter")
	}
	if !crypto.VerifyInclusion(crypto.LeafHash(evidence.Statement), evidence.Receipt.EntryIndex, evidence.Receipt.TreeSize, evidence.Receipt.Proof, evidence.Receipt.Root) {
		t.Fatal("evidence inclusion proof does not verify")
	}
}
