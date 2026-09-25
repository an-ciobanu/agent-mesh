package stripe_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/an-ciobanu/agent-mesh/internal/stripe"
)

func TestCreatePaymentIntentEncodesAndParses(t *testing.T) {
	var gotAuth, gotIdem, gotBody, gotContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotIdem = r.Header.Get("Idempotency-Key")
		gotContentType = r.Header.Get("Content-Type")
		b := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(b)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"pi_test_123","status":"succeeded"}`))
	}))
	defer srv.Close()

	cli := stripe.NewClientWithBase("sk_test_abc", srv.URL)
	pi, err := cli.CreatePaymentIntent(context.Background(), stripe.PaymentIntentRequest{
		Amount: 1200, Currency: "usd", Description: "agent-mesh ACP",
		IdempotencyKey: "greet-1", Metadata: map[string]string{"source": "agent-mesh"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if pi.ID != "pi_test_123" || pi.Status != "succeeded" {
		t.Fatalf("unexpected PI: %+v", pi)
	}
	if gotAuth != "Bearer sk_test_abc" {
		t.Fatalf("auth = %q", gotAuth)
	}
	if gotIdem != "greet-1" {
		t.Fatalf("idempotency = %q", gotIdem)
	}
	if !strings.Contains(gotContentType, "application/x-www-form-urlencoded") {
		t.Fatalf("content-type = %q", gotContentType)
	}
	for _, want := range []string{"amount=1200", "currency=usd", "confirm=true",
		"payment_method=pm_card_visa", "payment_method_types%5B%5D=card", "metadata%5Bsource%5D=agent-mesh"} {
		if !strings.Contains(gotBody, want) {
			t.Fatalf("body missing %q; got %q", want, gotBody)
		}
	}
}

func TestCreatePaymentIntentReturnsAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPaymentRequired)
		_, _ = w.Write([]byte(`{"error":{"message":"card declined","code":"card_declined"}}`))
	}))
	defer srv.Close()
	cli := stripe.NewClientWithBase("sk_test_abc", srv.URL)
	_, err := cli.CreatePaymentIntent(context.Background(), stripe.PaymentIntentRequest{Amount: 100, Currency: "usd", IdempotencyKey: "x"})
	if err == nil || !strings.Contains(err.Error(), "card declined") {
		t.Fatalf("expected card declined error, got %v", err)
	}
}
