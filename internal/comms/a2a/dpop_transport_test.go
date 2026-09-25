package a2a

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

func TestDPoPHeaderReachesPolicyWithBinding(t *testing.T) {
	pol := &capturePolicy{}
	svc := NewGreetService(domain.LocalANSName("greeter-nonce"), pol, zerolog.Nop())
	mux := http.NewServeMux()
	mux.HandleFunc("POST /a2a", svc.HandleMessageSend)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	priv := testKey(t)
	proof := "eyJ.header.sig" // opaque to the transport; the policy verifies it
	_, _, err := NewClient().SendGreet(context.Background(), ts.URL+"/a2a", priv, GreetPayload{
		CallerAns:   domain.LocalANSName("visitor"),
		AudienceAns: domain.LocalANSName("greeter-nonce"),
		Greeting:    "hi",
	}, WithDPoP(proof))
	if err != nil {
		t.Fatal(err)
	}
	if pol.last.DPoPProof != proof {
		t.Fatalf("policy did not receive the DPoP proof: got %q", pol.last.DPoPProof)
	}
	if pol.last.HTTPMethod != "POST" {
		t.Fatalf("HTTPMethod not bound: got %q", pol.last.HTTPMethod)
	}
	if !strings.HasSuffix(pol.last.HTTPURL, "/a2a") || !strings.HasPrefix(pol.last.HTTPURL, "http://") {
		t.Fatalf("HTTPURL not bound to the request: got %q", pol.last.HTTPURL)
	}
}

func TestNoDPoPHeaderMeansEmptyProof(t *testing.T) {
	pol := &capturePolicy{}
	svc := NewGreetService(domain.LocalANSName("greeter"), pol, zerolog.Nop())
	ts := httptest.NewServer(http.HandlerFunc(svc.HandleMessageSend))
	defer ts.Close()

	priv := testKey(t)
	if _, _, err := NewClient().SendGreet(context.Background(), ts.URL, priv, GreetPayload{
		CallerAns:   domain.LocalANSName("visitor"),
		AudienceAns: domain.LocalANSName("greeter"),
		Greeting:    "hi",
	}); err != nil {
		t.Fatal(err)
	}
	if pol.last.DPoPProof != "" {
		t.Fatalf("expected empty DPoP proof, got %q", pol.last.DPoPProof)
	}
}

func TestExtNonceURIDefined(t *testing.T) {
	if ExtNonceURI == "" || ExtNonceURI == ExtMandateURI {
		t.Fatal("ExtNonceURI must be a distinct non-empty URI")
	}
}
