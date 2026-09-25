package integration

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/authority"
	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

func TestP3A_IssueMandateOverMCP(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	ans := domain.LocalANSName("authority-1")
	auth := authority.New(ans, priv, time.Hour, zerolog.Nop())

	srv := mcp.NewServer(zerolog.Nop())
	srv.Register("issue_mandate", auth.MCPTool())
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	raw, err := mcp.NewClient().Call(context.Background(), ts.URL+"/mcp", "issue_mandate", map[string]string{
		"subjectAns":  domain.LocalANSName("visitor"),
		"audienceAns": domain.LocalANSName("greeter-mandate"),
		"scope":       "greet",
	})
	if err != nil {
		t.Fatalf("issue_mandate: %v", err)
	}
	var res struct {
		MandateCOSE []byte `json:"mandateCose"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatal(err)
	}

	payload, signer, err := crypto.VerifyCOSE1(res.MandateCOSE)
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
	if claims.AudienceAns != domain.LocalANSName("greeter-mandate") || claims.Scope != "greet" || claims.AuthorityAns != ans {
		t.Fatalf("unexpected claims: %+v", claims)
	}

	// A malformed request (missing scope) surfaces as an MCP tool error.
	if _, err := mcp.NewClient().Call(context.Background(), ts.URL+"/mcp", "issue_mandate", map[string]string{
		"subjectAns": domain.LocalANSName("visitor"), "audienceAns": domain.LocalANSName("x"),
	}); err == nil {
		t.Fatal("expected an error when scope is missing")
	}
}
