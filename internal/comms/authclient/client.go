// Package authclient fetches a mandate authority's public key over HTTP.
package authclient

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
)

// Client fetches authority public keys.
type Client struct {
	http *http.Client
}

// New returns a client with a bounded timeout.
func New() *Client {
	return &Client{http: &http.Client{Timeout: 5 * time.Second}}
}

// FetchPubKey GETs baseURL/pubkey and returns the authority's Ed25519 key.
func (c *Client) FetchPubKey(ctx context.Context, baseURL string) (ed25519.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/pubkey", nil)
	if err != nil {
		return nil, fmt.Errorf("build pubkey request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pubkey request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pubkey: unexpected status %d", resp.StatusCode)
	}
	var jwk crypto.JWK
	if err := json.NewDecoder(resp.Body).Decode(&jwk); err != nil {
		return nil, fmt.Errorf("decode jwk: %w", err)
	}
	pub, err := crypto.PublicKeyFromJWK(jwk)
	if err != nil {
		return nil, fmt.Errorf("authority pubkey: %w", err)
	}
	return pub, nil
}
