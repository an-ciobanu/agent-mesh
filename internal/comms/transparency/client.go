// Package transparency is the HTTP client adapter for the domain.Transparency port.
package transparency

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

// Client talks to a transparency-log service over HTTP.
type Client struct {
	base string
	http *http.Client
}

// New returns a transparency client for the given TL base URL.
func New(base string) *Client {
	return &Client{base: base, http: &http.Client{Timeout: 5 * time.Second}}
}

// Seal submits a signed statement and returns its inclusion receipt.
func (c *Client) Seal(ctx context.Context, statement []byte) (domain.Receipt, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/entries", bytes.NewReader(statement))
	if err != nil {
		return domain.Receipt{}, fmt.Errorf("build seal request: %w", err)
	}
	req.Header.Set("Content-Type", "application/cose")
	resp, err := c.http.Do(req)
	if err != nil {
		return domain.Receipt{}, fmt.Errorf("seal request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return domain.Receipt{}, fmt.Errorf("seal: unexpected status %d", resp.StatusCode)
	}
	var rec domain.Receipt
	if err := json.NewDecoder(resp.Body).Decode(&rec); err != nil {
		return domain.Receipt{}, fmt.Errorf("decode receipt: %w", err)
	}
	return rec, nil
}

// FetchPubKey returns the transparency log's Ed25519 public key.
func (c *Client) FetchPubKey(ctx context.Context) (ed25519.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/pubkey", nil)
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
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" {
		return nil, fmt.Errorf("pubkey: not an Ed25519 OKP key")
	}
	raw, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("pubkey: decode x: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("pubkey: bad size %d", len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

var _ domain.Transparency = (*Client)(nil)
