// Package resolver reads a peer's Agent Card to learn how to call it.
package resolver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
)

// Resolver fetches and interprets peer Agent Cards.
type Resolver struct {
	http *http.Client
}

// New returns a resolver with a bounded HTTP timeout.
func New() *Resolver {
	return &Resolver{http: &http.Client{Timeout: 5 * time.Second}}
}

// FetchCard retrieves the Agent Card at cardURL.
func (r *Resolver) FetchCard(ctx context.Context, cardURL string) (a2a.Card, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cardURL, nil)
	if err != nil {
		return a2a.Card{}, fmt.Errorf("build card request: %w", err)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return a2a.Card{}, fmt.Errorf("fetch card: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return a2a.Card{}, fmt.Errorf("fetch card: unexpected status %d", resp.StatusCode)
	}
	var card a2a.Card
	if err := json.NewDecoder(resp.Body).Decode(&card); err != nil {
		return a2a.Card{}, fmt.Errorf("decode card: %w", err)
	}
	return card, nil
}
