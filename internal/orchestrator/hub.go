package orchestrator

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/events"
)

// Interaction is the assembled, both-point-of-view record of one greet.
type Interaction struct {
	GreetID string         `json:"greetId"`
	From    string         `json:"from"`
	To      string         `json:"to"`
	Type    string         `json:"type"`
	Verdict string         `json:"verdict"`
	Reason  string         `json:"reason,omitempty"`
	Events  []events.Event `json:"events"`
}

// Hub ingests agent events, assembles interactions, and fans out every event to
// SSE subscribers.
type Hub struct {
	mu    sync.Mutex
	inter map[string]*Interaction
	subs  map[chan []byte]struct{}
	log   zerolog.Logger
}

// NewHub builds an empty hub.
func NewHub(log zerolog.Logger) *Hub {
	return &Hub{
		inter: map[string]*Interaction{},
		subs:  map[chan []byte]struct{}{},
		log:   log.With().Str("component", "hub").Logger(),
	}
}

// Ingest records one event and broadcasts it.
func (h *Hub) Ingest(e events.Event) {
	h.mu.Lock()
	it := h.inter[e.GreetID]
	if it == nil {
		it = &Interaction{GreetID: e.GreetID}
		h.inter[e.GreetID] = it
	}
	it.Events = append(it.Events, e)
	if e.Role == events.RoleInitiator && it.From == "" {
		it.From = e.Agent
	}
	if e.Role == events.RoleResponder && it.To == "" {
		it.To = e.Agent
	}
	switch e.Step {
	case "requirement":
		if t := e.Detail["type"]; t != "" {
			it.Type = t
		}
	case "greet.reply":
		it.Verdict = "accepted"
	case "greet.rejected":
		it.Verdict = "rejected"
		if r := e.Detail["error"]; r != "" {
			it.Reason = r
		}
	case "receipt":
		it.Verdict = "accepted"
	case "purchase.rejected":
		it.Verdict = "rejected"
		if r := e.Detail["error"]; r != "" {
			it.Reason = r
		}
	case "gate":
		if e.Status == events.StatusFail && it.Reason == "" {
			it.Reason = e.Detail["reason"]
		}
	}
	h.mu.Unlock()

	frame, err := json.Marshal(e)
	if err != nil {
		h.log.Error().Err(err).Msg("marshal event frame")
		return
	}
	h.broadcast(frame)
}

func (h *Hub) broadcast(frame []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- frame:
		default: // drop for a slow subscriber; never block ingestion
		}
	}
}

// Subscribe returns a channel of event frames and a cancel func.
func (h *Hub) Subscribe() (<-chan []byte, func()) {
	ch := make(chan []byte, 64)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		if _, ok := h.subs[ch]; ok {
			delete(h.subs, ch)
			close(ch)
		}
		h.mu.Unlock()
	}
}

// Interaction returns a snapshot of the interaction for greetID.
func (h *Hub) Interaction(greetID string) (Interaction, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	it, ok := h.inter[greetID]
	if !ok {
		return Interaction{}, false
	}
	return *it, true
}

// ServeSSE streams events to the browser as Server-Sent Events.
func (h *Hub) ServeSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch, cancel := h.Subscribe()
	defer cancel()
	for {
		select {
		case <-r.Context().Done():
			return
		case frame, ok := <-ch:
			if !ok {
				return
			}
			if _, err := w.Write([]byte("data: ")); err != nil {
				return
			}
			if _, err := w.Write(frame); err != nil {
				return
			}
			if _, err := w.Write([]byte("\n\n")); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}
