package a2a

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/events"
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
	// HeaderGreetID correlates both agents' event streams for one greet. The
	// initiator sets it; the responder generates one if absent. It is metadata
	// only — it does not alter the JSON-RPC request/response body.
	HeaderGreetID = "X-ANS-Greet-Id"
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
	selfAns   string
	policy    domain.GreetPolicy
	priv      ed25519.PrivateKey  // greeter identity key; signs sealed statements
	tp        domain.Transparency // nil => sealing disabled
	log       zerolog.Logger
	events    events.Emitter
	agentName string
	role      string
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

// WithEvents makes the service emit per-step responder events (and install an
// emitter scope on the request context so the greet policy can emit its checks).
func WithEvents(em events.Emitter, agentName, role string) Option {
	return func(g *GreetService) {
		g.events = em
		g.agentName = agentName
		g.role = role
	}
}

// NewGreetService builds a greet handler for an agent whose ANS name is selfAns.
func NewGreetService(selfAns string, p domain.GreetPolicy, log zerolog.Logger, opts ...Option) *GreetService {
	g := &GreetService{selfAns: selfAns, policy: p, events: events.Nop{}, role: "responder", log: log.With().Str("component", "a2a").Logger()}
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

	greetID := r.Header.Get(HeaderGreetID)
	if greetID == "" {
		greetID = events.NewGreetID()
	}
	name := g.agentName
	if name == "" {
		name = g.selfAns
	}
	ctx := events.WithScope(r.Context(), g.events, greetID, name, events.RoleResponder)

	jws := r.Header.Get(HeaderRequestJWS)
	if jws == "" {
		events.Emit(ctx, "jws.verify", events.StatusFail, map[string]string{"error": "missing identity proof"})
		g.log.Warn().Msg("greet: missing identity proof")
		g.writeError(w, req.ID, -32000, "missing identity proof")
		return
	}
	payload, jwk, err := crypto.VerifyJWS(jws)
	if err != nil {
		events.Emit(ctx, "jws.verify", events.StatusFail, map[string]string{"error": err.Error()})
		g.log.Warn().Err(err).Msg("greet: identity proof invalid")
		g.writeError(w, req.ID, -32001, "invalid identity proof")
		return
	}
	thumb := crypto.Thumbprint(jwk)
	events.Emit(ctx, "jws.verify", events.StatusOK, map[string]string{"thumbprint": thumb})

	var gp GreetPayload
	if err := json.Unmarshal(payload, &gp); err != nil {
		g.writeError(w, req.ID, -32602, "invalid greet payload")
		return
	}
	if gp.AudienceAns != g.selfAns {
		events.Emit(ctx, "audience", events.StatusFail, map[string]string{"audience": gp.AudienceAns, "self": g.selfAns})
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

	if err := g.policy.Authorize(ctx, domain.GreetRequest{
		CallerAns:           gp.CallerAns,
		AudienceAns:         gp.AudienceAns,
		Greeting:            gp.Greeting,
		CallerKeyThumbprint: thumb,
		Mandate:             mandate,
		DPoPProof:           r.Header.Get(HeaderDPoP),
		HTTPMethod:          r.Method,
		HTTPURL:             "http://" + r.Host + r.URL.Path,
	}); err != nil {
		events.Emit(ctx, "gate", events.StatusFail, map[string]string{"reason": err.Error()})
		g.log.Warn().Err(err).Str("callerAns", gp.CallerAns).Msg("greet: policy rejected")
		g.writeError(w, req.ID, -32003, "greet not authorized: "+err.Error())
		return
	}
	events.Emit(ctx, "gate", events.StatusOK, nil)

	evidence := g.sealCtx(ctx, r, gp, thumb)

	g.log.Info().Str("callerAns", gp.CallerAns).Str("callerKeyThumbprint", thumb).Bool("sealed", evidence != nil).Msg("greet accepted")
	g.writeResult(w, req.ID, &Message{
		Role:  "agent",
		Parts: []Part{{Kind: "text", Text: "hi " + gp.CallerAns + ", this is " + g.selfAns}},
	}, evidence)
}

// sealCtx signs a greet.completed statement and seals it to the transparency
// log. Sealing is best-effort: a failure is logged at ERROR and the greet
// still succeeds without evidence (the greeting is the primary function).
func (g *GreetService) sealCtx(ctx context.Context, r *http.Request, gp GreetPayload, thumb string) *domain.EvidenceBundle {
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
		events.Emit(ctx, "seal", events.StatusFail, map[string]string{"error": err.Error()})
		g.log.Error().Err(err).Msg("seal: transparency seal")
		return nil
	}
	events.Emit(ctx, "seal", events.StatusOK, map[string]string{
		"entryIndex": strconv.Itoa(receipt.EntryIndex),
		"treeSize":   strconv.Itoa(receipt.TreeSize),
	})
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
