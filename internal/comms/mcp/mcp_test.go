package mcp

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
)

func TestMCPToolCallRoundTrip(t *testing.T) {
	s := NewServer(zerolog.Nop())
	s.Register("echo", func(_ context.Context, args json.RawMessage) (json.RawMessage, error) {
		// Echo the args back as the result payload.
		return args, nil
	})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	out, err := NewClient().Call(context.Background(), ts.URL+"/mcp", "echo", map[string]string{"hello": "world"})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got["hello"] != "world" {
		t.Fatalf("echo result = %v", got)
	}
}

func TestMCPUnknownToolErrors(t *testing.T) {
	ts := httptest.NewServer(NewServer(zerolog.Nop()).Handler())
	defer ts.Close()
	if _, err := NewClient().Call(context.Background(), ts.URL+"/mcp", "nope", nil); err == nil {
		t.Fatal("expected error for unknown tool")
	}
}

func TestMCPToolErrorSurfacesToClient(t *testing.T) {
	s := NewServer(zerolog.Nop())
	s.Register("boom", func(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
		return nil, context.DeadlineExceeded
	})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	if _, err := NewClient().Call(context.Background(), ts.URL+"/mcp", "boom", nil); err == nil {
		t.Fatal("expected the tool error to surface to the client")
	}
}
