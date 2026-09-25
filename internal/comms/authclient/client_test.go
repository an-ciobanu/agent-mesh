package authclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
)

func TestFetchPubKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /pubkey", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(crypto.PublicJWK(pub))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	got, err := New().FetchPubKey(context.Background(), ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(pub) {
		t.Fatal("fetched key does not match")
	}
}

func TestFetchPubKeyNon200(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer ts.Close()
	if _, err := New().FetchPubKey(context.Background(), ts.URL); err == nil {
		t.Fatal("expected error on non-200 status")
	}
}
