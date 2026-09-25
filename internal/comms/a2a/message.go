package a2a

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

const (
	// HeaderRequestJWS carries the caller's compact identity JWS ("who is asking").
	HeaderRequestJWS = "X-ANS-Request-JWS"
	// MethodMessageSend is the A2A JSON-RPC method for sending a message.
	MethodMessageSend = "message/send"
	// HeaderMandate carries the caller's presented mandate (a COSE_Sign1 over
	// domain.MandateClaims), base64-std encoded. Optional; a mandate-gated
	// policy requires it.
	HeaderMandate = "X-ANS-Mandate"
	// HeaderDPoP carries the caller's RFC 9449 DPoP proof (an ES256 compact JWS)
	// verbatim. Optional; a nonce-gated policy requires it.
	HeaderDPoP = "X-ANS-DPoP"
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
	JSONRPC  string                 `json:"jsonrpc"`
	ID       int                    `json:"id"`
	Result   *Message               `json:"result,omitempty"`
	Evidence *domain.EvidenceBundle `json:"evidence,omitempty"` // sealed greet.completed evidence (P2)
	Error    *rpcError              `json:"error,omitempty"`
}

// greetEvent is the canonical "greet.completed" statement payload that is
// COSE-signed and sealed into the transparency log.
type greetEvent struct {
	Type                string `json:"type"`
	CallerAns           string `json:"callerAns"`
	AudienceAns         string `json:"audienceAns"`
	Greeting            string `json:"greeting"`
	CallerKeyThumbprint string `json:"callerKeyThumbprint"`
	At                  string `json:"at"`
}

// GreetService handles inbound A2A greets: verify caller identity, enforce the
// agent's GreetPolicy, optionally seal the completed greet, and reply.
type GreetService struct {
	selfAns string
	policy  domain.GreetPolicy
	priv    ed25519.PrivateKey  // greeter identity key; signs sealed statements
	tp      domain.Transparency // nil => sealing disabled
	log     zerolog.Logger
}

// Option configures a GreetService.
type Option func(*GreetService)

// WithSealing enables transparency sealing: on each accepted greet the service
// signs a greet.completed statement with priv and seals it via tp.
func WithSealing(priv ed25519.PrivateKey, tp domain.Transparency) Option {
	return func(g *GreetService) {
		g.priv = priv
		g.tp = tp
	}
}

// NewGreetService builds a greet handler for an agent whose ANS name is selfAns.
func NewGreetService(selfAns string, p domain.GreetPolicy, log zerolog.Logger, opts ...Option) *GreetService {
	g := &GreetService{selfAns: selfAns, policy: p, log: log.With().Str("component", "a2a").Logger()}
	for _, o := range opts {
		o(g)
	}
	return g
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
	payload, jwk, err := crypto.VerifyJWS(jws)
	if err != nil {
		g.log.Warn().Err(err).Msg("greet: identity proof invalid")
		g.writeError(w, req.ID, -32001, "invalid identity proof")
		return
	}
	thumb := crypto.Thumbprint(jwk)

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

	var mandate []byte
	if mh := r.Header.Get(HeaderMandate); mh != "" {
		decoded, derr := base64.StdEncoding.DecodeString(mh)
		if derr != nil {
			g.log.Warn().Err(derr).Msg("greet: invalid mandate encoding")
			g.writeError(w, req.ID, -32602, "invalid mandate encoding")
			return
		}
		mandate = decoded
	}

	if err := g.policy.Authorize(r.Context(), domain.GreetRequest{
		CallerAns:           gp.CallerAns,
		AudienceAns:         gp.AudienceAns,
		Greeting:            gp.Greeting,
		CallerKeyThumbprint: thumb,
		Mandate:             mandate,
		DPoPProof:           r.Header.Get(HeaderDPoP),
		HTTPMethod:          r.Method,
		HTTPURL:             "http://" + r.Host + r.URL.Path,
	}); err != nil {
		g.log.Warn().Err(err).Str("callerAns", gp.CallerAns).Msg("greet: policy rejected")
		g.writeError(w, req.ID, -32003, "greet not authorized: "+err.Error())
		return
	}

	evidence := g.seal(r, gp, thumb)

	g.log.Info().Str("callerAns", gp.CallerAns).Str("callerKeyThumbprint", thumb).Bool("sealed", evidence != nil).Msg("greet accepted")
	g.writeResult(w, req.ID, &Message{
		Role:  "agent",
		Parts: []Part{{Kind: "text", Text: "hi " + gp.CallerAns + ", this is " + g.selfAns}},
	}, evidence)
}

// seal signs a greet.completed statement and seals it to the transparency log.
// Sealing is best-effort: a failure is logged at ERROR and the greet still
// succeeds without evidence (the greeting is the primary function).
func (g *GreetService) seal(r *http.Request, gp GreetPayload, thumb string) *domain.EvidenceBundle {
	if g.tp == nil || g.priv == nil {
		return nil
	}
	event, err := json.Marshal(greetEvent{
		Type:                "greet.completed",
		CallerAns:           gp.CallerAns,
		AudienceAns:         gp.AudienceAns,
		Greeting:            gp.Greeting,
		CallerKeyThumbprint: thumb,
		At:                  time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		g.log.Error().Err(err).Msg("seal: marshal event")
		return nil
	}
	statement, err := crypto.SignCOSE1(g.priv, event)
	if err != nil {
		g.log.Error().Err(err).Msg("seal: sign statement")
		return nil
	}
	receipt, err := g.tp.Seal(r.Context(), statement)
	if err != nil {
		g.log.Error().Err(err).Msg("seal: transparency seal")
		return nil
	}
	g.log.Info().Int("entryIndex", receipt.EntryIndex).Int("treeSize", receipt.TreeSize).Msg("greet sealed")
	return &domain.EvidenceBundle{Statement: statement, Receipt: receipt}
}

func (g *GreetService) writeResult(w http.ResponseWriter, id int, msg *Message, evidence *domain.EvidenceBundle) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(rpcResponse{JSONRPC: "2.0", ID: id, Result: msg, Evidence: evidence}); err != nil {
		g.log.Error().Err(err).Msg("greet: encode result")
	}
}

func (g *GreetService) writeError(w http.ResponseWriter, id, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: message}}); err != nil {
		g.log.Error().Err(err).Msg("greet: encode error")
	}
}
