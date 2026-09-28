package commerce

// HeaderGreetID correlates a buyer's commerce calls with the seller's emitted
// events. It mirrors a2a.HeaderGreetID; duplicated here to avoid importing the a2a
// package into the commerce layer.
const HeaderGreetID = "X-ANS-Greet-Id"

// BuyResult is what a completed purchase returns to the caller, for any protocol.
type BuyResult struct {
	PaymentRef string
	Status     string
	ItemID     string
}
