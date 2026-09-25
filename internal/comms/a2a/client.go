package a2a

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
)

// Client sends A2A greets to peer agents.
type Client struct {
	http *http.Client
}

// NewClient returns an A2A client with a bounded timeout.
func NewClient() *Client {
	return &Client{http: &http.Client{Timeout: 5 * time.Second}}
}

// SendGreet signs payload with priv, sends an A2A message/send to endpoint, and
// returns the peer's reply text.
func (c *Client) SendGreet(ctx context.Context, endpoint string, priv ed25519.PrivateKey, payload GreetPayload) (string, error) {
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal greet payload: %w", err)
	}
	jws, err := crypto.SignJWS(priv, pb)
	if err != nil {
		return "", fmt.Errorf("sign greet: %w", err)
	}

	body, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  MethodMessageSend,
		Params:  messageParams{Message: Message{Role: "user", Parts: []Part{{Kind: "text", Text: payload.Greeting}}}},
	})
	if err != nil {
		return "", fmt.Errorf("marshal rpc request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderRequestJWS, jws)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("send greet: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("greet: unexpected status %d", resp.StatusCode)
	}

	var out rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	if out.Error != nil {
		return "", fmt.Errorf("greet rejected: %s (code %d)", out.Error.Message, out.Error.Code)
	}
	if out.Result == nil || len(out.Result.Parts) == 0 {
		return "", fmt.Errorf("greet: empty reply")
	}
	return out.Result.Parts[0].Text, nil
}
