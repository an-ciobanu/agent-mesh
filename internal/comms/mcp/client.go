package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Client invokes MCP tools over HTTP.
type Client struct {
	http *http.Client
}

// NewClient returns an MCP client with a bounded timeout.
func NewClient() *Client {
	return &Client{http: &http.Client{Timeout: 5 * time.Second}}
}

// Call invokes tool at endpoint with args and returns the tool's JSON payload.
func (c *Client) Call(ctx context.Context, endpoint, tool string, args any) (json.RawMessage, error) {
	argsJSON, err := json.Marshal(args)
	if err != nil {
		return nil, fmt.Errorf("marshal args: %w", err)
	}
	body, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0", ID: json.RawMessage("1"), Method: MethodToolsCall,
		Params: callParams{Name: tool, Arguments: argsJSON},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mcp request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mcp: unexpected status %d", resp.StatusCode)
	}

	var out rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if out.Error != nil {
		return nil, fmt.Errorf("mcp error: %s (code %d)", out.Error.Message, out.Error.Code)
	}
	if out.Result == nil || len(out.Result.Content) == 0 {
		return nil, fmt.Errorf("mcp: empty result")
	}
	if out.Result.IsError {
		return nil, fmt.Errorf("tool %q failed: %s", tool, out.Result.Content[0].Text)
	}
	return json.RawMessage(out.Result.Content[0].Text), nil
}
