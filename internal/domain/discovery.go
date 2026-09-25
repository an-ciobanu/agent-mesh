// Package domain holds agent-mesh core types and ports (no I/O).
package domain

import "context"

// AgentInfo is the public discovery record an agent publishes to the registry.
type AgentInfo struct {
	Name    string `json:"name"`    // unique instance name, e.g. "greeter-open"
	Role    string `json:"role"`    // coarse role, e.g. "greeter", "authority"
	BaseURL string `json:"baseURL"` // e.g. "http://127.0.0.1:18101"
	CardURL string `json:"cardURL"` // baseURL + "/.well-known/agent-card.json"
}

// Discovery is the registry port: agents register, callers search by role.
type Discovery interface {
	Register(ctx context.Context, info AgentInfo) error
	Search(ctx context.Context, role string) ([]AgentInfo, error)
}
