package ucp_test

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/authority"
	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
)

func newCheckoutTool(t *testing.T, priv ed25519.PrivateKey, ans string) mcp.ToolFunc {
	t.Helper()
	return authority.New(ans, priv, time.Hour, zerolog.Nop()).CheckoutMandateMCPTool()
}
func newPaymentTool(t *testing.T, priv ed25519.PrivateKey, ans string) mcp.ToolFunc {
	t.Helper()
	return authority.New(ans, priv, time.Hour, zerolog.Nop()).PaymentMandateMCPTool()
}
