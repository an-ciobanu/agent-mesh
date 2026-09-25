package a2a

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
)

func signedGreet(t *testing.T, callerAns, audienceAns, greeting string) (body []byte, jws string) {
	t.Helper()
	priv, err := crypto.GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	pb, _ := json.Marshal(GreetPayload{CallerAns: callerAns, AudienceAns: audienceAns, Greeting: greeting})
	jws, err = crypto.SignJWS(priv, pb)
	if err != nil {
		t.Fatal(err)
	}
	rpc := rpcRequest{JSONRPC: "2.0", ID: 1, Method: MethodMessageSend,
		Params: messageParams{Message: Message{Role: "user", Parts: []Part{{Kind: "text", Text: greeting}}}}}
	body, _ = json.Marshal(rpc)
	return body, jws
}

func postGreet(t *testing.T, h http.Handler, body []byte, jws string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/a2a", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if jws != "" {
		req.Header.Set(HeaderRequestJWS, jws)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Result()
}

func TestGreetServiceAcceptsSignedGreet(t *testing.T) {
	self := domain.LocalANSName("greeter-open")
	svc := NewGreetService(self, policy.Open{}, zerolog.Nop())

	body, jws := signedGreet(t, domain.LocalANSName("visitor"), self, "hello there")
	resp := postGreet(t, http.HandlerFunc(svc.HandleMessageSend), body, jws)
	defer resp.Body.Close()

	var out rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Error != nil {
		t.Fatalf("unexpected rpc error: %+v", out.Error)
	}
	if out.Result == nil || len(out.Result.Parts) == 0 {
		t.Fatal("expected a reply message")
	}
	reply := out.Result.Parts[0].Text
	if !strings.Contains(reply, domain.LocalANSName("visitor")) || !strings.Contains(reply, self) {
		t.Fatalf("reply missing identities: %q", reply)
	}
}

func TestGreetServiceRejectsMissingJWS(t *testing.T) {
	self := domain.LocalANSName("greeter-open")
	svc := NewGreetService(self, policy.Open{}, zerolog.Nop())
	body, _ := signedGreet(t, domain.LocalANSName("visitor"), self, "hi")

	resp := postGreet(t, http.HandlerFunc(svc.HandleMessageSend), body, "")
	defer resp.Body.Close()
	var out rpcResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.Error == nil {
		t.Fatal("expected rpc error for missing identity proof")
	}
}

func TestGreetServiceRejectsAudienceMismatch(t *testing.T) {
	self := domain.LocalANSName("greeter-open")
	svc := NewGreetService(self, policy.Open{}, zerolog.Nop())
	// audience is someone else
	body, jws := signedGreet(t, domain.LocalANSName("visitor"), domain.LocalANSName("other"), "hi")

	resp := postGreet(t, http.HandlerFunc(svc.HandleMessageSend), body, jws)
	defer resp.Body.Close()
	var out rpcResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.Error == nil {
		t.Fatal("expected rpc error for audience mismatch")
	}
}

func TestGreetServiceRejectsWrongMethod(t *testing.T) {
	self := domain.LocalANSName("greeter-open")
	svc := NewGreetService(self, policy.Open{}, zerolog.Nop())
	rpc := rpcRequest{JSONRPC: "2.0", ID: 7, Method: "message/stream"}
	body, _ := json.Marshal(rpc)

	resp := postGreet(t, http.HandlerFunc(svc.HandleMessageSend), body, "")
	defer resp.Body.Close()
	var out rpcResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.Error == nil {
		t.Fatal("expected rpc error for wrong method")
	}
}

var _ = context.Background // context used indirectly via handler
