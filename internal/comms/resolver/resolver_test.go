package resolver

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
)

func TestFetchCardReturnsPeerCard(t *testing.T) {
	self := domain.LocalANSName("greeter-open")
	svc := a2a.NewGreetService(self, policy.Open{}, zerolog.Nop())
	ts := httptest.NewServer(a2a.NewMux(a2a.Card{Name: "greeter-open", Version: "0.1.0"}, svc, zerolog.Nop()))
	defer ts.Close()

	card, err := New().FetchCard(context.Background(), ts.URL+"/.well-known/agent-card.json")
	if err != nil {
		t.Fatal(err)
	}
	if card.Name != "greeter-open" {
		t.Fatalf("card.Name = %q", card.Name)
	}
	if len(card.Security) != 0 {
		t.Fatalf("expected open card, got security %+v", card.Security)
	}
}

func TestFetchCardErrorsOnNotFound(t *testing.T) {
	ts := httptest.NewServer(a2a.NewMux(a2a.Card{Name: "x", Version: "0.1.0"},
		a2a.NewGreetService("x", policy.Open{}, zerolog.Nop()), zerolog.Nop()))
	defer ts.Close()

	if _, err := New().FetchCard(context.Background(), ts.URL+"/nope"); err == nil {
		t.Fatal("expected error for missing card")
	}
}
