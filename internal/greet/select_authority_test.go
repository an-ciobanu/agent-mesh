package greet

import (
	"testing"

	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

func peers() []domain.AgentInfo {
	return []domain.AgentInfo{
		{Name: "authority-1", Role: "authority", BaseURL: "http://a1"},
		{Name: "authority-2", Role: "authority", BaseURL: "http://a2"},
	}
}

func TestSelectAuthorityByAns(t *testing.T) {
	got, ok := selectAuthority(peers(), domain.LocalANSName("authority-2"))
	if !ok || got.Name != "authority-2" {
		t.Fatalf("selectAuthority = %+v ok=%v; want authority-2", got, ok)
	}
}

func TestSelectAuthorityEmptyAnsFallsBackToFirst(t *testing.T) {
	got, ok := selectAuthority(peers(), "")
	if !ok || got.Name != "authority-1" {
		t.Fatalf("selectAuthority(\"\") = %+v ok=%v; want first (authority-1)", got, ok)
	}
}

func TestSelectAuthorityUnknownAnsFails(t *testing.T) {
	if _, ok := selectAuthority(peers(), domain.LocalANSName("authority-9")); ok {
		t.Fatalf("selectAuthority for unknown ANS should fail closed")
	}
}

func TestSelectAuthorityEmptyPeersFails(t *testing.T) {
	if _, ok := selectAuthority(nil, ""); ok {
		t.Fatalf("selectAuthority(nil) should be false")
	}
}
