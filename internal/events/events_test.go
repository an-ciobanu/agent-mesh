package events

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestJSONEmitterWritesOneLinePerEvent(t *testing.T) {
	var buf bytes.Buffer
	em := NewJSONEmitter(&buf)
	em.Emit(Event{GreetID: "g1", Agent: "chris", Role: RoleInitiator, Step: "greet.send", Status: StatusOK})
	em.Emit(Event{GreetID: "g1", Agent: "ema", Role: RoleResponder, Step: "gate", Status: StatusFail})

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d: %q", len(lines), buf.String())
	}
	var e Event
	if err := json.Unmarshal([]byte(lines[1]), &e); err != nil {
		t.Fatalf("line not valid JSON: %v", err)
	}
	if e.Agent != "ema" || e.Step != "gate" || e.Status != StatusFail {
		t.Fatalf("unexpected event: %+v", e)
	}
	if e.TS.IsZero() {
		t.Fatalf("emitter must stamp TS")
	}
}

func TestEmitFromContextIsNoopWithoutScope(t *testing.T) {
	Emit(context.Background(), "gate", StatusOK, nil)
}

func TestEmitFromContextUsesScope(t *testing.T) {
	var buf bytes.Buffer
	ctx := WithScope(context.Background(), NewJSONEmitter(&buf), "g7", "ema", RoleResponder)
	if got := GreetIDFromContext(ctx); got != "g7" {
		t.Fatalf("GreetIDFromContext = %q, want g7", got)
	}
	Emit(ctx, "authority.pin", StatusOK, map[string]string{"authority": "auth-1"})

	var e Event
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &e); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if e.GreetID != "g7" || e.Agent != "ema" || e.Role != RoleResponder || e.Step != "authority.pin" {
		t.Fatalf("scope not applied: %+v", e)
	}
	if e.Detail["authority"] != "auth-1" {
		t.Fatalf("detail lost: %+v", e.Detail)
	}
}

func TestNewGreetIDIsHexAndUnique(t *testing.T) {
	a, b := NewGreetID(), NewGreetID()
	if len(a) != 32 || a == b {
		t.Fatalf("weak greet id: %q %q", a, b)
	}
}
