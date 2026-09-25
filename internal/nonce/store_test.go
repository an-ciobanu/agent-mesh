package nonce

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestIssueThenConsumeOnce(t *testing.T) {
	s := NewStore(time.Minute)
	n := s.Issue()
	if n == "" {
		t.Fatal("empty nonce")
	}
	if !s.Consume(n) {
		t.Fatal("first consume should succeed")
	}
	if s.Consume(n) {
		t.Fatal("second consume must fail (single-use)")
	}
}

func TestConsumeUnknownFails(t *testing.T) {
	s := NewStore(time.Minute)
	if s.Consume("never-issued") {
		t.Fatal("consuming an unknown nonce must fail")
	}
}

func TestConsumeExpiredFails(t *testing.T) {
	s := NewStore(time.Minute)
	base := time.Now()
	s.now = func() time.Time { return base }
	n := s.Issue()
	s.now = func() time.Time { return base.Add(2 * time.Minute) }
	if s.Consume(n) {
		t.Fatal("expired nonce must not be consumable")
	}
}

func TestIssueDistinct(t *testing.T) {
	s := NewStore(time.Minute)
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		n := s.Issue()
		if seen[n] {
			t.Fatal("duplicate nonce issued")
		}
		seen[n] = true
	}
}

func TestGetNonceMCPTool(t *testing.T) {
	s := NewStore(time.Minute)
	out, err := s.MCPTool()(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var res struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatal(err)
	}
	if res.Nonce == "" {
		t.Fatal("get_nonce returned empty nonce")
	}
	if !s.Consume(res.Nonce) {
		t.Fatal("nonce from get_nonce should be consumable")
	}
}
