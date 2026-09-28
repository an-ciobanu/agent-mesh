// Package authority issues scope-bound, COSE-signed mandates.
package authority

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

// Authority issues mandates signed with its Ed25519 identity key.
type Authority struct {
	ans  string
	priv ed25519.PrivateKey
	ttl  time.Duration
	log  zerolog.Logger
}

// New returns an authority named ans that signs mandates valid for ttl.
// ttl must be > 0; a non-positive ttl produces immediately-expired mandates.
func New(ans string, priv ed25519.PrivateKey, ttl time.Duration, log zerolog.Logger) *Authority {
	return &Authority{ans: ans, priv: priv, ttl: ttl, log: log.With().Str("component", "authority").Logger()}
}

// IssueMandate builds a mandate authorizing subject->audience for scope and
// returns it as a COSE_Sign1 signed by the authority.
func (a *Authority) IssueMandate(subjectAns, audienceAns, scope string) ([]byte, error) {
	if subjectAns == "" || audienceAns == "" || scope == "" {
		return nil, fmt.Errorf("subjectAns, audienceAns and scope are required")
	}
	now := time.Now().UTC()
	claims := domain.MandateClaims{
		MandateID:    "mandate-" + randHex(8),
		SubjectAns:   subjectAns,
		AudienceAns:  audienceAns,
		Scope:        scope,
		NotBefore:    now.Format(time.RFC3339),
		NotAfter:     now.Add(a.ttl).Format(time.RFC3339),
		AuthorityAns: a.ans,
	}
	b, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("marshal mandate claims: %w", err)
	}
	cose, err := crypto.SignCOSE1(a.priv, b)
	if err != nil {
		return nil, fmt.Errorf("sign mandate: %w", err)
	}
	a.log.Info().Str("mandateId", claims.MandateID).Str("subjectAns", subjectAns).
		Str("audienceAns", audienceAns).Str("scope", scope).Msg("mandate issued")
	return cose, nil
}

// IssueSpendMandate builds a spend-mandate authorizing subject to buy itemID from
// audience for at most maxAmount (smallest currency unit) in currency, and returns
// it as a COSE_Sign1 signed by the authority. Scope is fixed to ScopePurchase.
func (a *Authority) IssueSpendMandate(subjectAns, audienceAns, itemID string, maxAmount int64, currency string) ([]byte, error) {
	if subjectAns == "" || audienceAns == "" || itemID == "" || currency == "" {
		return nil, fmt.Errorf("subjectAns, audienceAns, itemID and currency are required")
	}
	if maxAmount <= 0 {
		return nil, fmt.Errorf("maxAmount must be > 0")
	}
	now := time.Now().UTC()
	claims := domain.SpendMandateClaims{
		MandateID:    "spend-" + randHex(8),
		SubjectAns:   subjectAns,
		AudienceAns:  audienceAns,
		ItemID:       itemID,
		MaxAmount:    maxAmount,
		Currency:     currency,
		Scope:        domain.ScopePurchase,
		NotBefore:    now.Format(time.RFC3339),
		NotAfter:     now.Add(a.ttl).Format(time.RFC3339),
		AuthorityAns: a.ans,
	}
	b, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("marshal spend claims: %w", err)
	}
	cose, err := crypto.SignCOSE1(a.priv, b)
	if err != nil {
		return nil, fmt.Errorf("sign spend mandate: %w", err)
	}
	a.log.Info().Str("mandateId", claims.MandateID).Str("subjectAns", subjectAns).
		Str("audienceAns", audienceAns).Str("itemId", itemID).Int64("maxAmount", maxAmount).
		Str("currency", currency).Msg("spend mandate issued")
	return cose, nil
}

type spendArgs struct {
	SubjectAns  string `json:"subjectAns"`
	AudienceAns string `json:"audienceAns"`
	ItemID      string `json:"itemId"`
	MaxAmount   int64  `json:"maxAmount"`
	Currency    string `json:"currency"`
}

// SpendMCPTool returns the issue_spend_mandate MCP tool handler.
func (a *Authority) SpendMCPTool() mcp.ToolFunc {
	return func(_ context.Context, args json.RawMessage) (json.RawMessage, error) {
		var in spendArgs
		if err := json.Unmarshal(args, &in); err != nil {
			return nil, fmt.Errorf("invalid arguments: %w", err)
		}
		cose, err := a.IssueSpendMandate(in.SubjectAns, in.AudienceAns, in.ItemID, in.MaxAmount, in.Currency)
		if err != nil {
			return nil, err
		}
		return json.Marshal(issueResult{MandateCOSE: cose})
	}
}

type issueArgs struct {
	SubjectAns  string `json:"subjectAns"`
	AudienceAns string `json:"audienceAns"`
	Scope       string `json:"scope"`
}

type issueResult struct {
	MandateCOSE []byte `json:"mandateCose"` // JSON-encodes as base64
}

// MCPTool returns the issue_mandate MCP tool handler.
func (a *Authority) MCPTool() mcp.ToolFunc {
	return func(_ context.Context, args json.RawMessage) (json.RawMessage, error) {
		var in issueArgs
		if err := json.Unmarshal(args, &in); err != nil {
			return nil, fmt.Errorf("invalid arguments: %w", err)
		}
		cose, err := a.IssueMandate(in.SubjectAns, in.AudienceAns, in.Scope)
		if err != nil {
			return nil, err
		}
		return json.Marshal(issueResult{MandateCOSE: cose})
	}
}

// IssueCheckoutMandate signs an AP2 CheckoutMandate authorizing subject to buy
// itemID from audience in checkoutID for at most amount in currency.
func (a *Authority) IssueCheckoutMandate(subjectAns, audienceAns, checkoutID, itemID string, amount int64, currency string) ([]byte, error) {
	if subjectAns == "" || audienceAns == "" || checkoutID == "" || itemID == "" || currency == "" {
		return nil, fmt.Errorf("subjectAns, audienceAns, checkoutID, itemID and currency are required")
	}
	if amount <= 0 {
		return nil, fmt.Errorf("amount must be > 0")
	}
	now := time.Now().UTC()
	claims := domain.CheckoutMandateClaims{
		MandateID: "checkout-" + randHex(8), SubjectAns: subjectAns, AudienceAns: audienceAns,
		CheckoutID: checkoutID, ItemID: itemID, Amount: amount, Currency: currency,
		Scope: domain.ScopeCheckout, NotBefore: now.Format(time.RFC3339), NotAfter: now.Add(a.ttl).Format(time.RFC3339),
		AuthorityAns: a.ans,
	}
	b, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("marshal checkout claims: %w", err)
	}
	cose, err := crypto.SignCOSE1(a.priv, b)
	if err != nil {
		return nil, fmt.Errorf("sign checkout mandate: %w", err)
	}
	a.log.Info().Str("mandateId", claims.MandateID).Str("checkoutId", checkoutID).Str("itemId", itemID).Int64("amount", amount).Msg("checkout mandate issued")
	return cose, nil
}

// IssuePaymentMandate signs an AP2 PaymentMandate authorizing subject to pay at
// most amount in currency to audience.
func (a *Authority) IssuePaymentMandate(subjectAns, audienceAns string, amount int64, currency string) ([]byte, error) {
	if subjectAns == "" || audienceAns == "" || currency == "" {
		return nil, fmt.Errorf("subjectAns, audienceAns and currency are required")
	}
	if amount <= 0 {
		return nil, fmt.Errorf("amount must be > 0")
	}
	now := time.Now().UTC()
	claims := domain.PaymentMandateClaims{
		MandateID: "payment-" + randHex(8), SubjectAns: subjectAns, AudienceAns: audienceAns,
		Amount: amount, Currency: currency, Scope: domain.ScopePayment,
		NotBefore: now.Format(time.RFC3339), NotAfter: now.Add(a.ttl).Format(time.RFC3339), AuthorityAns: a.ans,
	}
	b, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("marshal payment claims: %w", err)
	}
	cose, err := crypto.SignCOSE1(a.priv, b)
	if err != nil {
		return nil, fmt.Errorf("sign payment mandate: %w", err)
	}
	a.log.Info().Str("mandateId", claims.MandateID).Int64("amount", amount).Msg("payment mandate issued")
	return cose, nil
}

type checkoutMandateArgs struct {
	SubjectAns  string `json:"subjectAns"`
	AudienceAns string `json:"audienceAns"`
	CheckoutID  string `json:"checkoutId"`
	ItemID      string `json:"itemId"`
	Amount      int64  `json:"amount"`
	Currency    string `json:"currency"`
}

type paymentMandateArgs struct {
	SubjectAns  string `json:"subjectAns"`
	AudienceAns string `json:"audienceAns"`
	Amount      int64  `json:"amount"`
	Currency    string `json:"currency"`
}

// CheckoutMandateMCPTool returns the issue_checkout_mandate MCP tool.
func (a *Authority) CheckoutMandateMCPTool() mcp.ToolFunc {
	return func(_ context.Context, args json.RawMessage) (json.RawMessage, error) {
		var in checkoutMandateArgs
		if err := json.Unmarshal(args, &in); err != nil {
			return nil, fmt.Errorf("invalid arguments: %w", err)
		}
		cose, err := a.IssueCheckoutMandate(in.SubjectAns, in.AudienceAns, in.CheckoutID, in.ItemID, in.Amount, in.Currency)
		if err != nil {
			return nil, err
		}
		return json.Marshal(issueResult{MandateCOSE: cose})
	}
}

// PaymentMandateMCPTool returns the issue_payment_mandate MCP tool.
func (a *Authority) PaymentMandateMCPTool() mcp.ToolFunc {
	return func(_ context.Context, args json.RawMessage) (json.RawMessage, error) {
		var in paymentMandateArgs
		if err := json.Unmarshal(args, &in); err != nil {
			return nil, fmt.Errorf("invalid arguments: %w", err)
		}
		cose, err := a.IssuePaymentMandate(in.SubjectAns, in.AudienceAns, in.Amount, in.Currency)
		if err != nil {
			return nil, err
		}
		return json.Marshal(issueResult{MandateCOSE: cose})
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	// rand.Read never returns an error on supported platforms (it aborts the
	// process if the OS entropy source fails); the mandate ID is an identifier,
	// not a security nonce (security comes from the COSE signature), so the
	// error is intentionally not handled.
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
