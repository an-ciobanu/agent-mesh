package authority_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/authority"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

func TestIssueMandateProducesVerifiableCOSE(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	ans := domain.LocalANSName("authority-1")
	a := authority.New(ans, priv, time.Hour, zerolog.Nop())

	cose, err := a.IssueMandate(domain.LocalANSName("visitor"), domain.LocalANSName("greeter-mandate"), "greet")
	if err != nil {
		t.Fatal(err)
	}
	payload, signer, err := crypto.VerifyCOSE1(cose)
	if err != nil {
		t.Fatalf("verify mandate: %v", err)
	}
	if !signer.Equal(priv.Public()) {
		t.Fatal("mandate not signed by the authority key")
	}
	var claims domain.MandateClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.SubjectAns != domain.LocalANSName("visitor") ||
		claims.AudienceAns != domain.LocalANSName("greeter-mandate") ||
		claims.Scope != "greet" || claims.AuthorityAns != ans || claims.MandateID == "" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if claims.NotBefore == "" || claims.NotAfter == "" {
		t.Fatal("mandate missing validity window")
	}
}

func TestIssueMandateRejectsMissingFields(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	a := authority.New(domain.LocalANSName("authority-1"), priv, time.Hour, zerolog.Nop())
	if _, err := a.IssueMandate("", domain.LocalANSName("x"), "greet"); err == nil {
		t.Fatal("expected error for empty subject")
	}
}

func TestMCPToolIssuesMandate(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	a := authority.New(domain.LocalANSName("authority-1"), priv, time.Hour, zerolog.Nop())
	tool := a.MCPTool()

	args, _ := json.Marshal(map[string]string{
		"subjectAns":  domain.LocalANSName("visitor"),
		"audienceAns": domain.LocalANSName("greeter-mandate"),
		"scope":       "greet",
	})
	out, err := tool(context.Background(), args)
	if err != nil {
		t.Fatal(err)
	}
	var res struct {
		MandateCOSE []byte `json:"mandateCose"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatal(err)
	}
	if _, _, err := crypto.VerifyCOSE1(res.MandateCOSE); err != nil {
		t.Fatalf("tool mandate does not verify: %v", err)
	}
}

func TestMCPToolRejectsMalformedArgs(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	a := authority.New(domain.LocalANSName("authority-1"), priv, time.Hour, zerolog.Nop())
	if _, err := a.MCPTool()(context.Background(), json.RawMessage("{")); err == nil {
		t.Fatal("expected error for malformed tool arguments")
	}
}

func TestMCPToolPropagatesIssuanceError(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	a := authority.New(domain.LocalANSName("authority-1"), priv, time.Hour, zerolog.Nop())
	args, _ := json.Marshal(map[string]string{"subjectAns": "", "audienceAns": domain.LocalANSName("x"), "scope": "greet"})
	if _, err := a.MCPTool()(context.Background(), args); err == nil {
		t.Fatal("expected issuance validation error to propagate through the tool")
	}
}

func TestIssueSpendMandateVerifiesAndBinds(t *testing.T) {
	priv, err := crypto.GenerateEd25519()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	ans := domain.LocalANSName("authority-1")
	a := authority.New(ans, priv, time.Hour, zerolog.Nop())

	cose, err := a.IssueSpendMandate(
		domain.LocalANSName("Ada"),
		domain.LocalANSName("shop-acp"),
		"widget", 1200, "usd",
	)
	if err != nil {
		t.Fatalf("issue spend mandate: %v", err)
	}
	payload, signer, err := crypto.VerifyCOSE1(cose)
	if err != nil {
		t.Fatalf("verify cose: %v", err)
	}
	if !signer.Equal(priv.Public().(ed25519.PublicKey)) {
		t.Fatalf("mandate not signed by the authority key")
	}
	var claims domain.SpendMandateClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	if claims.SubjectAns != domain.LocalANSName("Ada") ||
		claims.AudienceAns != domain.LocalANSName("shop-acp") ||
		claims.ItemID != "widget" || claims.MaxAmount != 1200 ||
		claims.Currency != "usd" || claims.Scope != domain.ScopePurchase ||
		claims.AuthorityAns != ans {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestSpendMCPToolRoundTrip(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	a := authority.New(domain.LocalANSName("authority-1"), priv, time.Hour, zerolog.Nop())
	args, _ := json.Marshal(map[string]any{
		"subjectAns": domain.LocalANSName("Ada"), "audienceAns": domain.LocalANSName("shop-acp"),
		"itemId": "widget", "maxAmount": 1200, "currency": "usd",
	})
	out, err := a.SpendMCPTool()(context.Background(), args)
	if err != nil {
		t.Fatalf("spend tool: %v", err)
	}
	var res struct {
		MandateCOSE []byte `json:"mandateCose"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if len(res.MandateCOSE) == 0 {
		t.Fatalf("empty mandate")
	}
}
