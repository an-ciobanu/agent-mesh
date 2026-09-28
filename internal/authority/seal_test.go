package authority_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/audit"
	"github.com/an-ciobanu/agent-mesh/internal/authority"
	"github.com/an-ciobanu/agent-mesh/internal/comms/transparency"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/tl"
)

// TestMCPToolsSealIssuanceWhenTransparencyEnabled checks that, with a transparency
// log wired in, every mandate MCP tool returns evidence that audits valid — the
// caller can independently confirm the authority logged the issuance.
func TestMCPToolsSealIssuanceWhenTransparencyEnabled(t *testing.T) {
	tlPriv, _ := crypto.GenerateEd25519()
	srv := httptest.NewServer(tl.NewService(tlPriv, zerolog.Nop()).Handler())
	defer srv.Close()

	authPriv, _ := crypto.GenerateEd25519()
	a := authority.New(domain.LocalANSName("authority-1"), authPriv, time.Hour, zerolog.Nop()).
		WithTransparency(transparency.New(srv.URL))

	tlPub, err := transparency.New(srv.URL).FetchPubKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	auditorPriv, _ := crypto.GenerateEd25519()
	auditor := audit.New(domain.LocalANSName("auditor"), auditorPriv, zerolog.Nop())

	cases := []struct {
		name string
		tool func() ([]byte, error)
	}{
		{"issue_mandate", func() ([]byte, error) {
			return a.MCPTool()(context.Background(), json.RawMessage(`{"subjectAns":"ada.local.agent","audienceAns":"bob.local.agent","scope":"greet"}`))
		}},
		{"issue_spend_mandate", func() ([]byte, error) {
			return a.SpendMCPTool()(context.Background(), json.RawMessage(`{"subjectAns":"ada.local.agent","audienceAns":"shop.local.agent","itemId":"sticker","maxAmount":500,"currency":"usd"}`))
		}},
		{"issue_checkout_mandate", func() ([]byte, error) {
			return a.CheckoutMandateMCPTool()(context.Background(), json.RawMessage(`{"subjectAns":"ada.local.agent","audienceAns":"shop.local.agent","checkoutId":"cs_1","itemId":"sticker","amount":500,"currency":"usd"}`))
		}},
		{"issue_payment_mandate", func() ([]byte, error) {
			return a.PaymentMandateMCPTool()(context.Background(), json.RawMessage(`{"subjectAns":"ada.local.agent","audienceAns":"shop.local.agent","amount":500,"currency":"usd"}`))
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := tc.tool()
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			var out struct {
				MandateCOSE []byte                 `json:"mandateCose"`
				Evidence    *domain.EvidenceBundle `json:"evidence"`
			}
			if err := json.Unmarshal(raw, &out); err != nil {
				t.Fatal(err)
			}
			if len(out.MandateCOSE) == 0 {
				t.Fatal("no mandate returned")
			}
			if out.Evidence == nil {
				t.Fatal("expected issuance evidence when transparency is enabled")
			}
			verdict, _, err := auditor.Verify(context.Background(), *out.Evidence, tlPub)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if verdict.Verdict != "valid" {
				t.Fatalf("issuance evidence should audit valid, got %q: %v", verdict.Verdict, verdict.Checks)
			}
		})
	}
}

// TestMCPToolsOmitEvidenceWithoutTransparency confirms sealing is opt-in.
func TestMCPToolsOmitEvidenceWithoutTransparency(t *testing.T) {
	authPriv, _ := crypto.GenerateEd25519()
	a := authority.New(domain.LocalANSName("authority-1"), authPriv, time.Hour, zerolog.Nop())
	raw, err := a.MCPTool()(context.Background(), json.RawMessage(`{"subjectAns":"ada.local.agent","audienceAns":"bob.local.agent","scope":"greet"}`))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Evidence *domain.EvidenceBundle `json:"evidence"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.Evidence != nil {
		t.Fatal("evidence must be omitted when no transparency log is configured")
	}
}
