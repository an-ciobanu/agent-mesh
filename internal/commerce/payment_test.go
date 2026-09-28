package commerce_test

import (
	"context"
	"testing"

	"github.com/an-ciobanu/agent-mesh/internal/commerce"
)

func TestFakePaymentSucceeds(t *testing.T) {
	var p commerce.PaymentPrimitive = commerce.FakePayment{}
	res, err := p.Charge(context.Background(), commerce.ChargeRequest{
		Amount: 1200, Currency: "usd", ItemID: "widget", BuyerAns: "ada", IdempotencyKey: "k1",
	})
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	if res.Provider != "fake" || res.Status != "succeeded" || res.Ref == "" {
		t.Fatalf("unexpected result: %+v", res)
	}
}
