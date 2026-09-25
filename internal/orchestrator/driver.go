package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Driver turns a browser collision into a real agent-to-agent greet by calling
// the initiator agent's P5a /trigger/greet endpoint.
type Driver struct {
	roster Roster
	http   *http.Client
}

// NewDriver builds a Driver over the roster.
func NewDriver(r Roster) *Driver {
	return &Driver{roster: r, http: &http.Client{Timeout: 10 * time.Second}}
}

// Collide makes agent `from` greet agent `to`. It returns the greet id so the
// browser can correlate the SSE events. The target must not be the authority.
func (d *Driver) Collide(ctx context.Context, from, to string) (string, error) {
	fromAgent, ok := d.roster.ByName(from)
	if !ok {
		return "", fmt.Errorf("unknown initiator %q", from)
	}
	toAgent, ok := d.roster.ByName(to)
	if !ok {
		return "", fmt.Errorf("unknown target %q", to)
	}
	if toAgent.Policy == "authority" {
		return "", fmt.Errorf("the authority is not greetable")
	}
	body, _ := json.Marshal(map[string]string{"toRole": toAgent.Role, "toName": toAgent.Name, "text": "hi " + toAgent.Name})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fromAgent.BaseURL()+"/trigger/greet", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("trigger %s: %w", from, err)
	}
	defer resp.Body.Close()
	var out struct {
		GreetID string `json:"greetId"`
		Error   string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode trigger response: %w", err)
	}
	if out.GreetID == "" {
		return "", fmt.Errorf("trigger returned no greet id (error: %s)", out.Error)
	}
	return out.GreetID, nil
}
