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

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
