// Package mcp is a minimal MCP (Model Context Protocol) tools layer: a
// JSON-RPC 2.0 tools/call server and client, used for agent capability tools.
package mcp

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog"
)

// MethodToolsCall is the MCP JSON-RPC method for invoking a tool.
const MethodToolsCall = "tools/call"

// ToolFunc handles one tool invocation: it receives the raw JSON arguments and
// returns a raw JSON payload (delivered to the client as the tool's text result).
type ToolFunc func(ctx context.Context, args json.RawMessage) (json.RawMessage, error)

// Server dispatches MCP tools/call requests to registered tools.
type Server struct {
	tools map[string]ToolFunc
	log   zerolog.Logger
}

// NewServer returns an MCP server with no tools registered.
func NewServer(log zerolog.Logger) *Server {
	return &Server{tools: make(map[string]ToolFunc), log: log.With().Str("component", "mcp").Logger()}
}

// Register adds a tool under name.
func (s *Server) Register(name string, fn ToolFunc) { s.tools[name] = fn }

// Handler serves POST /mcp.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /mcp", s.handleCall)
	return mux
}

type callParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type rpcRequest struct {
	JSONRPC string     `json:"jsonrpc"`
	ID      int        `json:"id"`
	Method  string     `json:"method"`
	Params  callParams `json:"params"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type toolResult struct {
	Content []contentBlock `json:"content"`
	IsError bool           `json:"isError"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Result  *toolResult `json:"result,omitempty"`
	Error   *rpcError   `json:"error,omitempty"`
}

func (s *Server) handleCall(w http.ResponseWriter, r *http.Request) {
	var req rpcRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, 0, -32700, "parse error")
		return
	}
	if req.Method != MethodToolsCall {
		s.writeError(w, req.ID, -32601, "method not found")
		return
	}
	fn, ok := s.tools[req.Params.Name]
	if !ok {
		s.writeError(w, req.ID, -32601, "unknown tool: "+req.Params.Name)
		return
	}
	out, err := fn(r.Context(), req.Params.Arguments)
	if err != nil {
		s.log.Warn().Err(err).Str("tool", req.Params.Name).Msg("tool returned error")
		s.writeResult(w, req.ID, &toolResult{Content: []contentBlock{{Type: "text", Text: err.Error()}}, IsError: true})
		return
	}
	s.log.Info().Str("tool", req.Params.Name).Msg("tool call ok")
	s.writeResult(w, req.ID, &toolResult{Content: []contentBlock{{Type: "text", Text: string(out)}}, IsError: false})
}

func (s *Server) writeResult(w http.ResponseWriter, id int, res *toolResult) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(rpcResponse{JSONRPC: "2.0", ID: id, Result: res}); err != nil {
		s.log.Error().Err(err).Msg("encode result")
	}
}

func (s *Server) writeError(w http.ResponseWriter, id, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}); err != nil {
		s.log.Error().Err(err).Msg("encode error")
	}
}
