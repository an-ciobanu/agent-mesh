// Package nonce issues and single-use-tracks challenge nonces for DPoP
// proof-of-possession.
package nonce

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"sync"
	"time"

	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
)

// Store issues random single-use nonces, each valid for a bounded TTL.
type Store struct {
	mu     sync.Mutex
	issued map[string]time.Time // nonce -> expiry
	ttl    time.Duration
	now    func() time.Time
}

// NewStore returns a nonce store whose nonces expire after ttl.
func NewStore(ttl time.Duration) *Store {
	return &Store{issued: make(map[string]time.Time), ttl: ttl, now: time.Now}
}

// Issue creates, records, and returns a fresh single-use nonce.
func (s *Store) Issue() string {
	b := make([]byte, 32)
	// rand.Read never returns an error on supported platforms; the nonce's
	// unpredictability comes from crypto/rand.
	_, _ = rand.Read(b)
	n := base64.RawURLEncoding.EncodeToString(b)
	s.mu.Lock()
	s.issued[n] = s.now().Add(s.ttl)
	s.mu.Unlock()
	return n
}

// Consume returns true exactly once for a nonce that was issued and has not
// expired, removing it (single-use); it returns false otherwise.
func (s *Store) Consume(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.issued[nonce]
	if !ok {
		return false
	}
	delete(s.issued, nonce)
	return s.now().Before(exp)
}

type nonceResult struct {
	Nonce string `json:"nonce"`
}

// MCPTool returns the get_nonce MCP tool handler: each call issues a fresh nonce.
func (s *Store) MCPTool() mcp.ToolFunc {
	return func(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
		return json.Marshal(nonceResult{Nonce: s.Issue()})
	}
}
