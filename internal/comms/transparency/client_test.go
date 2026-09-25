package transparency

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/tl"
)

func TestClientSealAndFetchPubKey(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	ts := httptest.NewServer(tl.NewService(priv, zerolog.Nop()).Handler())
	defer ts.Close()

	c := New(ts.URL)
	ctx := context.Background()

	issuer, _ := crypto.GenerateEd25519()
	statement, _ := crypto.SignCOSE1(issuer, []byte(`{"type":"greet.completed"}`))

	rec, err := c.Seal(ctx, statement)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if rec.TreeSize != 1 || rec.EntryIndex != 0 {
		t.Fatalf("receipt index/size = %d/%d", rec.EntryIndex, rec.TreeSize)
	}
	if !crypto.VerifyInclusion(crypto.LeafHash(statement), rec.EntryIndex, rec.TreeSize, rec.Proof, rec.Root) {
		t.Fatal("inclusion proof does not verify")
	}

	tlPub, err := c.FetchPubKey(ctx)
	if err != nil {
		t.Fatalf("fetch pubkey: %v", err)
	}
	if !tlPub.Equal(priv.Public()) {
		t.Fatal("fetched pubkey does not match TL key")
	}
	// The receipt is signed by the TL key we fetched.
	_, signer, err := crypto.VerifyCOSE1(rec.COSE)
	if err != nil {
		t.Fatal(err)
	}
	if !signer.Equal(tlPub) {
		t.Fatal("receipt signer != fetched TL pubkey")
	}
}

func TestClientSealReturnsErrorOnServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	c := New(ts.URL)
	if _, err := c.Seal(context.Background(), []byte("stmt")); err == nil {
		t.Fatal("expected error for a 500 seal response")
	}
}

func TestClientSealReturnsErrorOnNonJSONBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}))
	defer ts.Close()

	c := New(ts.URL)
	if _, err := c.Seal(context.Background(), []byte("stmt")); err == nil {
		t.Fatal("expected error for a non-JSON receipt body")
	}
}

func TestClientFetchPubKeyReturnsErrorOnServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	c := New(ts.URL)
	if _, err := c.FetchPubKey(context.Background()); err == nil {
		t.Fatal("expected error for a 500 pubkey response")
	}
}

func TestClientFetchPubKeyRejectsWrongKeyType(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(crypto.JWK{Kty: "RSA", Crv: "Ed25519", X: "AA"})
	}))
	defer ts.Close()

	c := New(ts.URL)
	if _, err := c.FetchPubKey(context.Background()); err == nil {
		t.Fatal("expected error for a non-OKP/Ed25519 JWK")
	}
}

func TestClientFetchPubKeyRejectsBadBase64(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(crypto.JWK{Kty: "OKP", Crv: "Ed25519", X: "not-valid-base64!!"})
	}))
	defer ts.Close()

	c := New(ts.URL)
	if _, err := c.FetchPubKey(context.Background()); err == nil {
		t.Fatal("expected error for invalid base64 in x")
	}
}

func TestClientSealReturnsErrorOnInvalidBaseURL(t *testing.T) {
	// A control character in the URL makes request construction itself fail.
	c := New("http://\x7f")
	if _, err := c.Seal(context.Background(), []byte("stmt")); err == nil {
		t.Fatal("expected error for an invalid base URL")
	}
}

func TestClientSealReturnsErrorOnUnreachableServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	ts.Close() // now nothing is listening
	c := New(ts.URL)
	if _, err := c.Seal(context.Background(), []byte("stmt")); err == nil {
		t.Fatal("expected error for an unreachable server")
	}
}

func TestClientFetchPubKeyReturnsErrorOnInvalidBaseURL(t *testing.T) {
	c := New("http://\x7f")
	if _, err := c.FetchPubKey(context.Background()); err == nil {
		t.Fatal("expected error for an invalid base URL")
	}
}

func TestClientFetchPubKeyReturnsErrorOnUnreachableServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	ts.Close()
	c := New(ts.URL)
	if _, err := c.FetchPubKey(context.Background()); err == nil {
		t.Fatal("expected error for an unreachable server")
	}
}

func TestClientFetchPubKeyRejectsWrongKeyLength(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		short := base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3})
		_ = json.NewEncoder(w).Encode(crypto.JWK{Kty: "OKP", Crv: "Ed25519", X: short})
	}))
	defer ts.Close()

	c := New(ts.URL)
	if _, err := c.FetchPubKey(context.Background()); err == nil {
		t.Fatal("expected error for a wrong-length embedded key")
	}
}
