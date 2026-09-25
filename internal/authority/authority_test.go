package authority

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

func TestIssueMandateProducesVerifiableCOSE(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	ans := domain.LocalANSName("authority-1")
	a := New(ans, priv, time.Hour, zerolog.Nop())

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
	a := New(domain.LocalANSName("authority-1"), priv, time.Hour, zerolog.Nop())
	if _, err := a.IssueMandate("", domain.LocalANSName("x"), "greet"); err == nil {
		t.Fatal("expected error for empty subject")
	}
}

func TestMCPToolIssuesMandate(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	a := New(domain.LocalANSName("authority-1"), priv, time.Hour, zerolog.Nop())
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
	a := New(domain.LocalANSName("authority-1"), priv, time.Hour, zerolog.Nop())
	if _, err := a.MCPTool()(context.Background(), json.RawMessage("{")); err == nil {
		t.Fatal("expected error for malformed tool arguments")
	}
}

func TestMCPToolPropagatesIssuanceError(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	a := New(domain.LocalANSName("authority-1"), priv, time.Hour, zerolog.Nop())
	args, _ := json.Marshal(map[string]string{"subjectAns": "", "audienceAns": domain.LocalANSName("x"), "scope": "greet"})
	if _, err := a.MCPTool()(context.Background(), args); err == nil {
		t.Fatal("expected issuance validation error to propagate through the tool")
	}
}
