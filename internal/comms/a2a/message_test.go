package a2a

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	commstl "github.com/an-ciobanu/agent-mesh/internal/comms/transparency"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/events"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
	"github.com/an-ciobanu/agent-mesh/internal/tl"
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

// postSignedGreet builds a signed greet from callerName to audienceName, posts
// it to svc's HandleMessageSend, applying any headerMutators (e.g. to set
// X-ANS-Greet-Id) before sending, and returns the raw recorder. It reuses
// signedGreet for the wire body/JWS and does not alter it.
func postSignedGreet(t *testing.T, svc *GreetService, callerName, audienceName, greeting string, headerMutators ...func(http.Header)) *httptest.ResponseRecorder {
	t.Helper()
	body, jws := signedGreet(t, domain.LocalANSName(callerName), domain.LocalANSName(audienceName), greeting)
	req := httptest.NewRequest(http.MethodPost, "/a2a", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderRequestJWS, jws)
	for _, m := range headerMutators {
		m(req.Header)
	}
	rec := httptest.NewRecorder()
	svc.HandleMessageSend(rec, req)
	return rec
}

func TestHandleMessageSendEmitsResponderEvents(t *testing.T) {
	var buf bytes.Buffer
	em := events.NewJSONEmitter(&buf)

	svc := NewGreetService(domain.LocalANSName("ema"), policy.Open{},
		zerolog.Nop(), WithEvents(em, "ema", "greeter-open"))

	rr := postSignedGreet(t, svc, "chris", "ema", "hi", func(h http.Header) {
		h.Set(HeaderGreetID, "g42")
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}

	var sawJWS, sawGate bool
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var e events.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("bad event line %q: %v", line, err)
		}
		if e.GreetID != "g42" || e.Agent != "ema" || e.Role != events.RoleResponder {
			t.Fatalf("wrong scope on event: %+v", e)
		}
		switch e.Step {
		case "jws.verify":
			sawJWS = e.Status == events.StatusOK
		case "gate":
			sawGate = e.Status == events.StatusOK
		}
	}
	if !sawJWS || !sawGate {
		t.Fatalf("missing responder events: jws=%v gate=%v (%s)", sawJWS, sawGate, buf.String())
	}
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

func TestGreetServiceRejectsInvalidJWS(t *testing.T) {
	self := domain.LocalANSName("greeter-open")
	svc := NewGreetService(self, policy.Open{}, zerolog.Nop())
	body, _ := signedGreet(t, domain.LocalANSName("visitor"), self, "hi")

	resp := postGreet(t, http.HandlerFunc(svc.HandleMessageSend), body, "a.b.c")
	defer resp.Body.Close()
	var out rpcResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.Error == nil {
		t.Fatal("expected rpc error for an invalid (unparseable) identity proof")
	}
}

func TestGreetServiceRejectsNonJSONPayload(t *testing.T) {
	self := domain.LocalANSName("greeter-open")
	svc := NewGreetService(self, policy.Open{}, zerolog.Nop())

	priv, err := crypto.GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	jws, err := crypto.SignJWS(priv, []byte("not json"))
	if err != nil {
		t.Fatal(err)
	}
	rpc := rpcRequest{JSONRPC: "2.0", ID: 1, Method: MethodMessageSend,
		Params: messageParams{Message: Message{Role: "user", Parts: []Part{{Kind: "text", Text: "hi"}}}}}
	body, _ := json.Marshal(rpc)

	resp := postGreet(t, http.HandlerFunc(svc.HandleMessageSend), body, jws)
	defer resp.Body.Close()
	var out rpcResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.Error == nil {
		t.Fatal("expected rpc error when the signed payload is not valid greet JSON")
	}
}

func TestGreetServiceRejectsUnparseableBody(t *testing.T) {
	self := domain.LocalANSName("greeter-open")
	svc := NewGreetService(self, policy.Open{}, zerolog.Nop())

	resp := postGreet(t, http.HandlerFunc(svc.HandleMessageSend), []byte("{"), "")
	defer resp.Body.Close()
	var out rpcResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.Error == nil {
		t.Fatal("expected rpc error for an unparseable request body")
	}
}

var _ = context.Background // context used indirectly via handler

func TestGreetServiceSealsWhenConfigured(t *testing.T) {
	tlPriv, _ := crypto.GenerateEd25519()
	tlSrv := httptest.NewServer(tl.NewService(tlPriv, zerolog.Nop()).Handler())
	defer tlSrv.Close()

	self := domain.LocalANSName("greeter-open")
	greeterPriv, _ := crypto.GenerateEd25519()
	svc := NewGreetService(self, policy.Open{}, zerolog.Nop(), WithSealing(greeterPriv, commstl.New(tlSrv.URL)))

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
	if out.Evidence == nil {
		t.Fatal("expected sealed evidence in the response")
	}
	if !crypto.VerifyInclusion(crypto.LeafHash(out.Evidence.Statement), out.Evidence.Receipt.EntryIndex, out.Evidence.Receipt.TreeSize, out.Evidence.Receipt.Proof, out.Evidence.Receipt.Root) {
		t.Fatal("sealed evidence inclusion proof does not verify")
	}
}

// failingTP is a domain.Transparency stub whose Seal always errors, so tests
// can exercise the greeter's best-effort seal-failure path.
type failingTP struct{}

func (failingTP) Seal(ctx context.Context, statement []byte) (domain.Receipt, error) {
	return domain.Receipt{}, errors.New("boom")
}

func TestGreetServiceSucceedsWithoutEvidenceWhenSealFails(t *testing.T) {
	self := domain.LocalANSName("greeter-open")
	greeterPriv, _ := crypto.GenerateEd25519()
	svc := NewGreetService(self, policy.Open{}, zerolog.Nop(), WithSealing(greeterPriv, failingTP{}))

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
	if out.Result == nil {
		t.Fatal("expected the greet to still succeed when sealing fails")
	}
	if out.Evidence != nil {
		t.Fatal("expected no evidence when sealing fails")
	}
}
