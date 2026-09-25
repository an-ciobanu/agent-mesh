package orchestrator

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/events"
)

func ev(greetID, agent, role, step, status string, detail map[string]string) events.Event {
	return events.Event{GreetID: greetID, Agent: agent, Role: role, Step: step, Status: status, Detail: detail, TS: time.Now()}
}

func TestHubAssemblesInteractionAndVerdict(t *testing.T) {
	h := NewHub(zerolog.Nop())
	h.Ingest(ev("g1", "Noah", events.RoleInitiator, "card.read", events.StatusOK, map[string]string{"peer": "Ada"}))
	h.Ingest(ev("g1", "Noah", events.RoleInitiator, "requirement", events.StatusInfo, map[string]string{"type": "open"}))
	h.Ingest(ev("g1", "Ada", events.RoleResponder, "jws.verify", events.StatusOK, nil))
	h.Ingest(ev("g1", "Ada", events.RoleResponder, "gate", events.StatusOK, nil))
	h.Ingest(ev("g1", "Noah", events.RoleInitiator, "greet.reply", events.StatusOK, map[string]string{"reply": "hi"}))

	it, ok := h.Interaction("g1")
	if !ok {
		t.Fatal("no interaction")
	}
	if it.From != "Noah" || it.To != "Ada" || it.Type != "open" {
		t.Fatalf("from/to/type = %s/%s/%s", it.From, it.To, it.Type)
	}
	if it.Verdict != "accepted" {
		t.Fatalf("verdict = %q", it.Verdict)
	}
	if len(it.Events) != 5 {
		t.Fatalf("events = %d", len(it.Events))
	}
}

func TestHubRejectionVerdict(t *testing.T) {
	h := NewHub(zerolog.Nop())
	h.Ingest(ev("g2", "Noah", events.RoleInitiator, "requirement", events.StatusInfo, map[string]string{"type": "nonce"}))
	h.Ingest(ev("g2", "Zoe", events.RoleResponder, "gate", events.StatusFail, map[string]string{"reason": "nonce already used"}))
	h.Ingest(ev("g2", "Noah", events.RoleInitiator, "greet.rejected", events.StatusFail, map[string]string{"error": "greet rejected"}))
	it, _ := h.Interaction("g2")
	if it.Verdict != "rejected" || it.Reason == "" {
		t.Fatalf("verdict=%q reason=%q", it.Verdict, it.Reason)
	}
}

func TestHubBroadcastsToSubscribers(t *testing.T) {
	h := NewHub(zerolog.Nop())
	ch, cancel := h.Subscribe()
	defer cancel()
	h.Ingest(ev("g3", "Ada", events.RoleResponder, "gate", events.StatusOK, nil))

	select {
	case raw := <-ch:
		var e events.Event
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatalf("bad frame: %v", err)
		}
		if e.GreetID != "g3" || e.Step != "gate" {
			t.Fatalf("frame = %+v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("no broadcast received")
	}
}
