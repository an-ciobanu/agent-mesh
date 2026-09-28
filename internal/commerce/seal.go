package commerce

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

// PurchaseRecord is the seller-signed statement sealed into the transparency log
// when a purchase completes. It carries ids and amounts only — never secrets or
// PII (paymentRef is the provider's public intent id, e.g. pi_...).
type PurchaseRecord struct {
	Protocol   string `json:"protocol"`
	CheckoutID string `json:"checkoutId"`
	BuyerAns   string `json:"buyerAns"`
	SellerAns  string `json:"sellerAns"`
	ItemID     string `json:"itemId"`
	Amount     int64  `json:"amount"`
	Currency   string `json:"currency"`
	PaymentRef string `json:"paymentRef"`
	TS         string `json:"ts"`
}

// SealPurchase signs the record with the seller's key and seals it into the
// transparency log, returning the evidence bundle (signed statement + inclusion
// receipt) for the seller to hand back to the buyer to audit.
func SealPurchase(ctx context.Context, priv ed25519.PrivateKey, tl domain.Transparency, rec PurchaseRecord) (domain.EvidenceBundle, error) {
	if rec.TS == "" {
		rec.TS = time.Now().UTC().Format(time.RFC3339)
	}
	body, err := json.Marshal(rec)
	if err != nil {
		return domain.EvidenceBundle{}, err
	}
	stmt, err := crypto.SignCOSE1(priv, body)
	if err != nil {
		return domain.EvidenceBundle{}, err
	}
	receipt, err := tl.Seal(ctx, stmt)
	if err != nil {
		return domain.EvidenceBundle{}, err
	}
	return domain.EvidenceBundle{Statement: stmt, Receipt: receipt}, nil
}
