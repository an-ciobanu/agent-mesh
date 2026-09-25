// Package events carries a per-step, per-agent event stream so an interaction
// between two agents can be reconstructed from each agent's own point of view.
// Events are written as JSON lines to a side channel (stdout); ordinary logs go
// to stderr. Emission is context-scoped: guards and initiators emit through the
// request/call context, so their signatures and the domain DTOs never change,
// and callers without a scope (e.g. unit tests, meshctl) get a silent no-op.
package events

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Roles.
const (
	RoleInitiator = "initiator"
	RoleResponder = "responder"
)

// Statuses.
const (
	StatusOK   = "ok"
	StatusFail = "fail"
	StatusInfo = "info"
)

// Event is a single step in a greet, reported by the agent that performed it.
type Event struct {
	GreetID string            `json:"greetId"`
	Agent   string            `json:"agent"`
	Role    string            `json:"role"`
	Step    string            `json:"step"`
	Status  string            `json:"status"`
	Detail  map[string]string `json:"detail,omitempty"`
	TS      time.Time         `json:"ts"`
}

// Emitter records events.
type Emitter interface {
	Emit(Event)
}

// Nop is an Emitter that discards events. It is the zero-value behavior when no
// emitter is installed.
type Nop struct{}

// Emit does nothing.
func (Nop) Emit(Event) {}

// JSONEmitter writes one JSON object per line to w, safe for concurrent use.
type JSONEmitter struct {
	mu  sync.Mutex
	enc *json.Encoder
}

// NewJSONEmitter builds a JSONEmitter over w.
func NewJSONEmitter(w io.Writer) *JSONEmitter {
	return &JSONEmitter{enc: json.NewEncoder(w)}
}

// Emit stamps TS if unset and writes the event as one line.
func (j *JSONEmitter) Emit(e Event) {
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	_ = j.enc.Encode(e) // json.Encoder.Encode appends a newline
}

// NewGreetID returns a random 128-bit hex id correlating both agents' events.
func NewGreetID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type scopeKey struct{}

type scope struct {
	em      Emitter
	greetID string
	agent   string
	role    string
}

// WithScope installs an emitter and the fixed per-interaction fields into ctx.
func WithScope(ctx context.Context, em Emitter, greetID, agent, role string) context.Context {
	if em == nil {
		em = Nop{}
	}
	return context.WithValue(ctx, scopeKey{}, &scope{em: em, greetID: greetID, agent: agent, role: role})
}

// GreetIDFromContext returns the scope's greet id, or "" if no scope.
func GreetIDFromContext(ctx context.Context) string {
	if s, ok := ctx.Value(scopeKey{}).(*scope); ok {
		return s.greetID
	}
	return ""
}

// Emit reports a step using the emitter and fixed fields in ctx. It is a no-op
// when no scope is installed.
func Emit(ctx context.Context, step, status string, detail map[string]string) {
	s, ok := ctx.Value(scopeKey{}).(*scope)
	if !ok {
		return
	}
	s.em.Emit(Event{
		GreetID: s.greetID,
		Agent:   s.agent,
		Role:    s.role,
		Step:    step,
		Status:  status,
		Detail:  detail,
	})
}
