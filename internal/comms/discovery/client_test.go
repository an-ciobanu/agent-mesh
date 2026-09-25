package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/registry"
)

func TestClientRegisterAndSearchRoundTrip(t *testing.T) {
	reg := httptest.NewServer(registry.New(zerolog.Nop()).Handler())
	defer reg.Close()

	c := New(reg.URL)
	ctx := context.Background()

	want := domain.AgentInfo{
		Name:    "authority-1",
		Role:    "authority",
		BaseURL: "http://127.0.0.1:18120",
		CardURL: "http://127.0.0.1:18120/.well-known/agent-card.json",
	}
	if err := c.Register(ctx, want); err != nil {
		t.Fatalf("register: %v", err)
	}

	got, err := c.Search(ctx, "authority")
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("search result = %+v, want [%+v]", got, want)
	}

	empty, err := c.Search(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("search empty: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("expected no results, got %+v", empty)
	}
}

func TestRegisterReturnsErrorOnServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	c := New(ts.URL)
	if err := c.Register(context.Background(), domain.AgentInfo{Name: "x", BaseURL: "http://x"}); err == nil {
		t.Fatal("expected an error when register gets a 500, got nil")
	}
}

func TestSearchReturnsErrorOnServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	c := New(ts.URL)
	if _, err := c.Search(context.Background(), "greeter"); err == nil {
		t.Fatal("expected an error when search gets a 500, got nil")
	}
}

func TestSearchReturnsErrorOnInvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}))
	defer ts.Close()

	c := New(ts.URL)
	if _, err := c.Search(context.Background(), "greeter"); err == nil {
		t.Fatal("expected a decode error for a non-JSON body, got nil")
	}
}
