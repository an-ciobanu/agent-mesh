package commerce_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/audit"
	"github.com/an-ciobanu/agent-mesh/internal/commerce"
	"github.com/an-ciobanu/agent-mesh/internal/comms/transparency"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/tl"
)

func TestSealPurchaseProducesAuditableEvidence(t *testing.T) {
	tlPriv, _ := crypto.GenerateEd25519()
	srv := httptest.NewServer(tl.NewService(tlPriv, zerolog.Nop()).Handler())
	defer srv.Close()

	sellerPriv, _ := crypto.GenerateEd25519()
	ev, err := commerce.SealPurchase(context.Background(), sellerPriv, transparency.New(srv.URL), commerce.PurchaseRecord{
		Protocol: "acp", CheckoutID: "cs_1", BuyerAns: "ada.local.agent", SellerAns: "shop.local.agent",
		ItemID: "sticker", Amount: 500, Currency: "usd", PaymentRef: "pi_test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Receipt.LogID == "" {
		t.Fatal("sealed purchase carries no log id")
	}

	tlPub, err := transparency.New(srv.URL).FetchPubKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	auditorPriv, _ := crypto.GenerateEd25519()
	verdict, _, err := audit.New(domain.LocalANSName("auditor"), auditorPriv, zerolog.Nop()).Verify(context.Background(), ev, tlPub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verdict.Verdict != "valid" {
		t.Fatalf("sealed purchase should audit valid, got %q: %v", verdict.Verdict, verdict.Checks)
	}
}
