package a2a

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

// SendOption customizes an outbound greet request's headers before it is sent.
type SendOption func(http.Header)

// WithMandate attaches a mandate (COSE_Sign1 bytes) to the greet via the
// X-ANS-Mandate header, base64-std encoded.
func WithMandate(mandate []byte) SendOption {
	return func(h http.Header) {
		h.Set(HeaderMandate, base64.StdEncoding.EncodeToString(mandate))
	}
}

// WithDPoP attaches an RFC 9449 DPoP proof (a compact JWS) to the greet via the
// X-ANS-DPoP header.
func WithDPoP(proof string) SendOption {
	return func(h http.Header) {
		h.Set(HeaderDPoP, proof)
	}
}

// Client sends A2A greets to peer agents.
type Client struct {
	http *http.Client
}

// NewClient returns an A2A client with a bounded timeout.
func NewClient() *Client {
	return &Client{http: &http.Client{Timeout: 5 * time.Second}}
}

// SendGreet signs payload with priv, sends an A2A message/send to endpoint, and
// returns the peer's reply text plus any transparency evidence the peer sealed
// (nil if the peer did not seal).
func (c *Client) SendGreet(ctx context.Context, endpoint string, priv ed25519.PrivateKey, payload GreetPayload, opts ...SendOption) (string, *domain.EvidenceBundle, error) {
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", nil, fmt.Errorf("marshal greet payload: %w", err)
	}
	jws, err := crypto.SignJWS(priv, pb)
	if err != nil {
		return "", nil, fmt.Errorf("sign greet: %w", err)
	}

	body, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  MethodMessageSend,
		Params:  messageParams{Message: Message{Role: "user", Parts: []Part{{Kind: "text", Text: payload.Greeting}}}},
	})
	if err != nil {
		return "", nil, fmt.Errorf("marshal rpc request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderRequestJWS, jws)
	for _, opt := range opts {
		opt(req.Header)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("send greet: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("greet: unexpected status %d", resp.StatusCode)
	}

	var out rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", nil, fmt.Errorf("decode response: %w", err)
	}
	if out.Error != nil {
		return "", nil, fmt.Errorf("greet rejected: %s (code %d)", out.Error.Message, out.Error.Code)
	}
	if out.Result == nil || len(out.Result.Parts) == 0 {
		return "", nil, fmt.Errorf("greet: empty reply")
	}
	return out.Result.Parts[0].Text, out.Evidence, nil
}
