package a2a

import (
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

const (
	// HeaderRequestJWS carries the caller's compact identity JWS ("who is asking").
	HeaderRequestJWS = "X-ANS-Request-JWS"
	// MethodMessageSend is the A2A JSON-RPC method for sending a message.
	MethodMessageSend = "message/send"
)

// GreetPayload is the signed body of a greet: who, to whom, and what.
type GreetPayload struct {
	CallerAns   string `json:"callerAns"`
	AudienceAns string `json:"audienceAns"`
	Greeting    string `json:"greeting"`
}

// Part is one A2A message part.
type Part struct {
	Kind string `json:"kind"`
	Text string `json:"text"`
}

// Message is an A2A message.
type Message struct {
	Role  string `json:"role"`
	Parts []Part `json:"parts"`
}

type messageParams struct {
	Message Message `json:"message"`
}

type rpcRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      int           `json:"id"`
	Method  string        `json:"method"`
	Params  messageParams `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      int       `json:"id"`
	Result  *Message  `json:"result,omitempty"`
	Error   *rpcError `json:"error,omitempty"`
}

// GreetService handles inbound A2A greets: verify caller identity, enforce the
// agent's GreetPolicy, and reply.
type GreetService struct {
	selfAns string
	policy  domain.GreetPolicy
	log     zerolog.Logger
}

// NewGreetService builds a greet handler for an agent whose ANS name is selfAns.
func NewGreetService(selfAns string, p domain.GreetPolicy, log zerolog.Logger) *GreetService {
	return &GreetService{selfAns: selfAns, policy: p, log: log.With().Str("component", "a2a").Logger()}
}

// HandleMessageSend implements POST /a2a (A2A message/send) for greets.
func (g *GreetService) HandleMessageSend(w http.ResponseWriter, r *http.Request) {
	var req rpcRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		g.writeError(w, 0, -32700, "parse error")
		return
	}
	if req.Method != MethodMessageSend {
		g.writeError(w, req.ID, -32601, "method not found")
		return
	}

	jws := r.Header.Get(HeaderRequestJWS)
	if jws == "" {
		g.log.Warn().Msg("greet: missing identity proof")
		g.writeError(w, req.ID, -32000, "missing identity proof")
		return
	}
	payload, _, err := crypto.VerifyJWS(jws)
	if err != nil {
		g.log.Warn().Err(err).Msg("greet: identity proof invalid")
		g.writeError(w, req.ID, -32001, "invalid identity proof")
		return
	}
	var gp GreetPayload
	if err := json.Unmarshal(payload, &gp); err != nil {
		g.writeError(w, req.ID, -32602, "invalid greet payload")
		return
	}
	if gp.AudienceAns != g.selfAns {
		g.log.Warn().Str("audienceAns", gp.AudienceAns).Str("selfAns", g.selfAns).Msg("greet: audience mismatch")
		g.writeError(w, req.ID, -32002, "audience mismatch")
		return
	}

	if err := g.policy.Authorize(r.Context(), domain.GreetRequest{
		CallerAns:   gp.CallerAns,
		AudienceAns: gp.AudienceAns,
		Greeting:    gp.Greeting,
	}); err != nil {
		g.log.Warn().Err(err).Str("callerAns", gp.CallerAns).Msg("greet: policy rejected")
		g.writeError(w, req.ID, -32003, "greet not authorized: "+err.Error())
		return
	}

	g.log.Info().Str("callerAns", gp.CallerAns).Str("greeting", gp.Greeting).Msg("greet accepted")
	g.writeResult(w, req.ID, &Message{
		Role:  "agent",
		Parts: []Part{{Kind: "text", Text: "hi " + gp.CallerAns + ", this is " + g.selfAns}},
	})
}

func (g *GreetService) writeResult(w http.ResponseWriter, id int, msg *Message) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(rpcResponse{JSONRPC: "2.0", ID: id, Result: msg}); err != nil {
		g.log.Error().Err(err).Msg("greet: encode result")
	}
}

// writeError emits a JSON-RPC error object (HTTP 200 per JSON-RPC convention).
func (g *GreetService) writeError(w http.ResponseWriter, id, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: message}}); err != nil {
		g.log.Error().Err(err).Msg("greet: encode error")
	}
}
