package acp

import (
	"context"

	"github.com/an-ciobanu/agent-mesh/internal/stripe"
)

// ChargeRequest is the funding-leg input, independent of the concrete provider.
type ChargeRequest struct {
	Amount         int64
	Currency       string
	ItemID         string
	BuyerAns       string
	IdempotencyKey string
}

// ChargeResult is a provider-neutral funding result.
type ChargeResult struct {
	Provider string // "stripe" | "fake"
	Ref      string // e.g. "pi_..."
	Status   string // e.g. "succeeded"
}

// PaymentPrimitive is the funding seam: today a Stripe test-mode PaymentIntent,
// later a Shared Payment Token redemption — the seller code above it is unchanged.
type PaymentPrimitive interface {
	Charge(ctx context.Context, r ChargeRequest) (ChargeResult, error)
}

// StripePaymentIntent settles via a real test-mode Stripe PaymentIntent.
type StripePaymentIntent struct {
	Client *stripe.Client
}

// Charge creates and confirms a PaymentIntent for the requested amount.
func (s StripePaymentIntent) Charge(ctx context.Context, r ChargeRequest) (ChargeResult, error) {
	pi, err := s.Client.CreatePaymentIntent(ctx, stripe.PaymentIntentRequest{
		Amount:         r.Amount,
		Currency:       r.Currency,
		Description:    "agent-mesh ACP purchase: " + r.ItemID,
		IdempotencyKey: r.IdempotencyKey,
		Metadata:       map[string]string{"source": "agent-mesh", "item": r.ItemID, "buyer": r.BuyerAns},
	})
	if err != nil {
		return ChargeResult{}, err
	}
	return ChargeResult{Provider: "stripe", Ref: pi.ID, Status: pi.Status}, nil
}

// FakePayment settles locally with no network — used by tests and offline demos.
type FakePayment struct{}

// Charge returns a deterministic successful result.
func (FakePayment) Charge(_ context.Context, r ChargeRequest) (ChargeResult, error) {
	ref := "pi_fake_" + r.IdempotencyKey
	if r.IdempotencyKey == "" {
		ref = "pi_fake_" + r.ItemID
	}
	return ChargeResult{Provider: "fake", Ref: ref, Status: "succeeded"}, nil
}
