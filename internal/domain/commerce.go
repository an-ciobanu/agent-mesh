package domain

// ScopePurchase is the mandate scope that authorizes a purchase (distinct from
// the greet scope). A spend-mandate must carry this scope to admit a checkout.
const ScopePurchase = "purchase"

// SpendMandateClaims is the JSON payload inside a signed spend-mandate (a
// COSE_Sign1). It authorizes SubjectAns to buy the specific ItemID from
// AudienceAns for at most MaxAmount (smallest currency unit) in Currency, within
// a validity window, attested by AuthorityAns. It is the AP2-style proof of
// consent that the seller verifies before charging.
type SpendMandateClaims struct {
	MandateID    string `json:"mandateId"`
	SubjectAns   string `json:"subjectAns"`
	AudienceAns  string `json:"audienceAns"`
	ItemID       string `json:"itemId"`
	MaxAmount    int64  `json:"maxAmount"`
	Currency     string `json:"currency"`
	Scope        string `json:"scope"`
	NotBefore    string `json:"notBefore"`
	NotAfter     string `json:"notAfter"`
	AuthorityAns string `json:"authorityAns"`
}

// PurchaseRequest is the verified content the ACP seller's spend guard checks: a
// caller (self-asserted), the session's item/amount/currency, and the presented
// spend-mandate (a COSE_Sign1 over SpendMandateClaims).
type PurchaseRequest struct {
	CallerAns    string
	ItemID       string
	Amount       int64
	Currency     string
	SpendMandate []byte
}
