package a2a

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

// capturePolicy records the GreetRequest it was asked to authorize.
type capturePolicy struct{ last domain.GreetRequest }

func (c *capturePolicy) Authorize(_ context.Context, req domain.GreetRequest) error {
	c.last = req
	return nil
}

func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func TestMandateHeaderReachesPolicy(t *testing.T) {
	pol := &capturePolicy{}
	svc := NewGreetService(domain.LocalANSName("greeter-mandate"), pol, zerolog.Nop())
	ts := httptest.NewServer(http.HandlerFunc(svc.HandleMessageSend))
	defer ts.Close()

	priv := testKey(t)
	mandate := []byte("pretend-cose-mandate-bytes")
	_, _, err := NewClient().SendGreet(context.Background(), ts.URL, priv, GreetPayload{
		CallerAns:   domain.LocalANSName("visitor"),
		AudienceAns: domain.LocalANSName("greeter-mandate"),
		Greeting:    "hi",
	}, WithMandate(mandate))
	if err != nil {
		t.Fatal(err)
	}
	if string(pol.last.Mandate) != string(mandate) {
		t.Fatalf("policy did not receive the mandate: got %q", pol.last.Mandate)
	}
}

func TestNoMandateHeaderMeansNilMandate(t *testing.T) {
	pol := &capturePolicy{}
	svc := NewGreetService(domain.LocalANSName("greeter"), pol, zerolog.Nop())
	ts := httptest.NewServer(http.HandlerFunc(svc.HandleMessageSend))
	defer ts.Close()

	priv := testKey(t)
	if _, _, err := NewClient().SendGreet(context.Background(), ts.URL, priv, GreetPayload{
		CallerAns:   domain.LocalANSName("visitor"),
		AudienceAns: domain.LocalANSName("greeter"),
		Greeting:    "hi",
	}); err != nil {
		t.Fatal(err)
	}
	if pol.last.Mandate != nil {
		t.Fatalf("expected nil mandate, got %q", pol.last.Mandate)
	}
}

func TestBadMandateEncodingFailsClosed(t *testing.T) {
	pol := &capturePolicy{}
	svc := NewGreetService(domain.LocalANSName("greeter"), pol, zerolog.Nop())
	ts := httptest.NewServer(http.HandlerFunc(svc.HandleMessageSend))
	defer ts.Close()

	priv := testKey(t)
	// Well-formed greet but a corrupt (non-base64) mandate header.
	_, _, err := NewClient().SendGreet(context.Background(), ts.URL, priv, GreetPayload{
		CallerAns:   domain.LocalANSName("visitor"),
		AudienceAns: domain.LocalANSName("greeter"),
		Greeting:    "hi",
	}, func(h http.Header) { h.Set(HeaderMandate, "!!!not base64!!!") })
	if err == nil {
		t.Fatal("expected the greet to be rejected for an invalid mandate encoding")
	}
	// The reject must happen before the policy runs (fail closed).
	if pol.last.CallerAns != "" || pol.last.Mandate != nil {
		t.Fatal("policy should not have been invoked on a bad mandate encoding")
	}
}
