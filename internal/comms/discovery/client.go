// Package discovery is the HTTP client adapter for the domain.Discovery port.
package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

// Client talks to a registry service over HTTP.
type Client struct {
	base string
	http *http.Client
}

// New returns a discovery client for the given registry base URL.
func New(registryBaseURL string) *Client {
	return &Client{base: registryBaseURL, http: &http.Client{Timeout: 5 * time.Second}}
}

// Register publishes this agent's discovery record.
func (c *Client) Register(ctx context.Context, info domain.AgentInfo) error {
	b, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("marshal agent info: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/register", bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("build register request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("register request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("register: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// Search returns agents matching role (empty role returns all).
func (c *Client) Search(ctx context.Context, role string) ([]domain.AgentInfo, error) {
	u := c.base + "/search?" + url.Values{"role": {role}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("build search request: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("search request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("search: unexpected status %d", resp.StatusCode)
	}

	var out []domain.AgentInfo
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode search response: %w", err)
	}
	return out, nil
}

// Compile-time assertion that Client satisfies the port.
var _ domain.Discovery = (*Client)(nil)
