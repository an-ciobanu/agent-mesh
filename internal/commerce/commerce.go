package commerce

import "github.com/an-ciobanu/agent-mesh/internal/domain"

// HeaderGreetID correlates a buyer's commerce calls with the seller's emitted
// events. It mirrors a2a.HeaderGreetID; duplicated here to avoid importing the a2a
// package into the commerce layer.
const HeaderGreetID = "X-ANS-Greet-Id"

// BuyResult is what a completed purchase returns to the caller, for any protocol.
// PurchaseEvidence is the seller-sealed purchase receipt (nil if the seller did
// not seal); MandateEvidence holds the authority-sealed issuance receipts for the
// mandates acquired during the purchase. Both are for the caller to audit against
// the transparency log.
type BuyResult struct {
	PaymentRef       string
	Status           string
	ItemID           string
	PurchaseEvidence *domain.EvidenceBundle
	MandateEvidence  []domain.EvidenceBundle
}
