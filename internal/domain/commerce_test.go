package domain

import (
	"encoding/json"
	"testing"
)

func TestSpendMandateClaimsJSONRoundTrip(t *testing.T) {
	in := SpendMandateClaims{
		MandateID:    "spend-abc",
		SubjectAns:   "ans://v1.0.0.Ada.mesh.local",
		AudienceAns:  "ans://v1.0.0.shop-acp.mesh.local",
		ItemID:       "widget",
		MaxAmount:    1200,
		Currency:     "usd",
		Scope:        ScopePurchase,
		NotBefore:    "2026-09-25T00:00:00Z",
		NotAfter:     "2026-09-25T01:00:00Z",
		AuthorityAns: "ans://v1.0.0.authority-1.mesh.local",
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out SpendMandateClaims
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out != in {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", out, in)
	}
	if ScopePurchase != "purchase" {
		t.Fatalf("ScopePurchase = %q, want %q", ScopePurchase, "purchase")
	}
}

func TestPurchaseRequestFields(t *testing.T) {
	r := PurchaseRequest{CallerAns: "a", ItemID: "widget", Amount: 1200, Currency: "usd", SpendMandate: []byte{1, 2}}
	if r.Amount != 1200 || r.ItemID != "widget" || len(r.SpendMandate) != 2 {
		t.Fatalf("unexpected fields: %+v", r)
	}
}

func TestAP2ClaimsAndScopes(t *testing.T) {
	if ScopeCheckout != "checkout" || ScopePayment != "payment" {
		t.Fatalf("scopes wrong: %q %q", ScopeCheckout, ScopePayment)
	}
	c := CheckoutMandateClaims{MandateID: "c1", SubjectAns: "s", AudienceAns: "a", CheckoutID: "cs_1", ItemID: "mug", Amount: 1200, Currency: "usd", Scope: ScopeCheckout, NotBefore: "n", NotAfter: "x", AuthorityAns: "auth"}
	var c2 CheckoutMandateClaims
	b, _ := json.Marshal(c)
	if err := json.Unmarshal(b, &c2); err != nil || c2 != c {
		t.Fatalf("checkout claims round trip: %v %+v", err, c2)
	}
	p := PaymentMandateClaims{MandateID: "p1", SubjectAns: "s", AudienceAns: "a", Amount: 1200, Currency: "usd", Scope: ScopePayment, NotBefore: "n", NotAfter: "x", AuthorityAns: "auth"}
	var p2 PaymentMandateClaims
	pb, _ := json.Marshal(p)
	if err := json.Unmarshal(pb, &p2); err != nil || p2 != p {
		t.Fatalf("payment claims round trip: %v %+v", err, p2)
	}
	comp := UCPCompletion{CallerAns: "s", CheckoutID: "cs_1", ItemID: "mug", Amount: 1200, Currency: "usd", CheckoutMandate: []byte{1}, PaymentMandate: []byte{2}}
	if comp.Amount != 1200 || len(comp.CheckoutMandate) != 1 || len(comp.PaymentMandate) != 1 {
		t.Fatalf("bad completion: %+v", comp)
	}
}
