package acp_test

import (
	"testing"

	"github.com/an-ciobanu/agent-mesh/internal/commerce/acp"
)

func TestDefaultCatalogIsPricedInCurrency(t *testing.T) {
	items := acp.DefaultCatalog("usd")
	if len(items) < 2 {
		t.Fatalf("want >=2 items, got %d", len(items))
	}
	seen := map[string]bool{}
	for _, it := range items {
		if it.ID == "" || it.Amount <= 0 || it.Currency != "usd" {
			t.Fatalf("bad item: %+v", it)
		}
		if seen[it.ID] {
			t.Fatalf("duplicate item id %q", it.ID)
		}
		seen[it.ID] = true
	}
}

func TestLowestPricedPicksCheapest(t *testing.T) {
	items := []acp.Item{{ID: "a", Amount: 900, Currency: "usd"}, {ID: "b", Amount: 300, Currency: "usd"}, {ID: "c", Amount: 500, Currency: "usd"}}
	it, ok := acp.LowestPriced(items)
	if !ok || it.ID != "b" {
		t.Fatalf("want b, got %+v ok=%v", it, ok)
	}
	if _, ok := acp.LowestPriced(nil); ok {
		t.Fatal("empty catalog should return ok=false")
	}
}
