// Package acp implements the demo's Agentic Commerce Protocol seller (server) and
// buyer driver (client): catalog + checkout_sessions create/complete, gated by an
// authority-issued spend-mandate and settled through a PaymentPrimitive seam.
package acp

// Item is one thing an ACP seller sells.
type Item struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Amount   int64  `json:"amount"` // smallest currency unit (e.g. cents)
	Currency string `json:"currency"`
}

// DefaultCatalog is the demo's fixed 3-item catalog priced in currency.
func DefaultCatalog(currency string) []Item {
	return []Item{
		{ID: "sticker", Name: "Mesh Sticker", Amount: 500, Currency: currency},
		{ID: "mug", Name: "Mesh Mug", Amount: 1200, Currency: currency},
		{ID: "hoodie", Name: "Mesh Hoodie", Amount: 4200, Currency: currency},
	}
}

// LowestPriced returns the cheapest item (deterministic buyer choice), or ok=false
// when the catalog is empty.
func LowestPriced(items []Item) (Item, bool) {
	if len(items) == 0 {
		return Item{}, false
	}
	best := items[0]
	for _, it := range items[1:] {
		if it.Amount < best.Amount {
			best = it
		}
	}
	return best, true
}
