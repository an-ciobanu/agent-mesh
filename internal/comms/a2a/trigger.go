package a2a

import (
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/events"
)

// GreetFunc initiates a greet from this agent to a peer identified by role or
// name, using the agent's own identity. It returns the reply, whether the peer
// accepted, and any error. The greet id is supplied so events correlate.
type GreetFunc func(greetID, toRole, toName, text string) (reply string, accepted bool, err error)

type triggerReq struct {
	ToRole string `json:"toRole,omitempty"`
	ToName string `json:"toName,omitempty"`
	Text   string `json:"text,omitempty"`
}

type triggerResp struct {
	GreetID  string `json:"greetId"`
	Reply    string `json:"reply,omitempty"`
	Accepted bool   `json:"accepted"`
	Error    string `json:"error,omitempty"`
}

// TriggerService exposes POST /trigger/greet so a driver (the P5b orchestrator)
// can make this agent initiate a real greet. It is opt-in (mounted only when the
// agent is started with --allow-trigger) and never enabled on a plain server.
type TriggerService struct {
	self  string
	greet GreetFunc
	log   zerolog.Logger
	em    events.Emitter
}

// NewTriggerService builds a trigger handler for the agent named self.
func NewTriggerService(self string, greet GreetFunc, log zerolog.Logger, em events.Emitter) *TriggerService {
	if em == nil {
		em = events.Nop{}
	}
	return &TriggerService{self: self, greet: greet, log: log.With().Str("component", "trigger").Logger(), em: em}
}

// HandleGreet handles POST /trigger/greet.
func (t *TriggerService) HandleGreet(w http.ResponseWriter, r *http.Request) {
	var req triggerReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.ToRole == "" && req.ToName == "" {
		http.Error(w, "toRole or toName required", http.StatusBadRequest)
		return
	}
	if req.Text == "" {
		req.Text = "hello"
	}
	greetID := events.NewGreetID()

	reply, accepted, err := t.greet(greetID, req.ToRole, req.ToName, req.Text)
	resp := triggerResp{GreetID: greetID, Reply: reply, Accepted: accepted}
	if err != nil {
		resp.Error = err.Error()
		t.log.Warn().Err(err).Str("toName", req.ToName).Str("toRole", req.ToRole).Msg("trigger greet failed")
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
