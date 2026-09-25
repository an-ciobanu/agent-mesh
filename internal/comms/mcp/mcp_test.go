package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestMCPParseErrorReturnsNullID(t *testing.T) {
	ts := httptest.NewServer(NewServer(zerolog.Nop()).Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader("{not json"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		ID    json.RawMessage `json:"id"`
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Error == nil || out.Error.Code != -32700 {
		t.Fatalf("expected parse error -32700, got %+v", out.Error)
	}
	if string(out.ID) != "null" {
		t.Fatalf("expected id null on parse error, got %s", out.ID)
	}
}

func TestMCPNonToolsCallMethodRejected(t *testing.T) {
	ts := httptest.NewServer(NewServer(zerolog.Nop()).Handler())
	defer ts.Close()

	body := `{"jsonrpc":"2.0","id":"abc","method":"tools/list","params":{}}`
	resp, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		ID    json.RawMessage `json:"id"`
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Error == nil || out.Error.Code != -32601 {
		t.Fatalf("expected method-not-found -32601, got %+v", out.Error)
	}
	// String ids must round-trip verbatim (JSON-RPC contract).
	if string(out.ID) != `"abc"` {
		t.Fatalf("expected id \"abc\" echoed back, got %s", out.ID)
	}
}

func TestMCPClientRejectsNon200(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer ts.Close()
	if _, err := NewClient().Call(context.Background(), ts.URL+"/mcp", "x", nil); err == nil {
		t.Fatal("expected error on non-200 status")
	}
}

func TestMCPClientRejectsEmptyResult(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[],"isError":false}}`))
	}))
	defer ts.Close()
	if _, err := NewClient().Call(context.Background(), ts.URL+"/mcp", "x", nil); err == nil {
		t.Fatal("expected error on empty result content")
	}
}

// The following tests were added beyond the reviewer's list to close the
// remaining coverage gap on Client.Call's error branches.

func TestMCPClientRejectsMalformedResponseBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{not json"))
	}))
	defer ts.Close()
	if _, err := NewClient().Call(context.Background(), ts.URL+"/mcp", "x", nil); err == nil {
		t.Fatal("expected error decoding a malformed response body")
	}
}

func TestMCPClientRejectsUnreachableEndpoint(t *testing.T) {
	ts := httptest.NewServer(NewServer(zerolog.Nop()).Handler())
	endpoint := ts.URL + "/mcp"
	ts.Close() // endpoint now refuses connections
	if _, err := NewClient().Call(context.Background(), endpoint, "x", nil); err == nil {
		t.Fatal("expected error calling an unreachable endpoint")
	}
}

func TestMCPClientRejectsInvalidEndpoint(t *testing.T) {
	if _, err := NewClient().Call(context.Background(), "://bad-url", "x", nil); err == nil {
		t.Fatal("expected error building a request for an invalid endpoint")
	}
}
