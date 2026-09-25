package integration

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/orchestrator"
)

func TestP5OrchestratorCollideEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real processes; skipped in -short")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	binDir := t.TempDir()
	for _, b := range []string{"registry", "transparency", "authority", "agent"} {
		cmd := exec.Command("go", "build", "-o", filepath.Join(binDir, b), "./cmd/"+b)
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", b, err, out)
		}
	}

	roster := orchestrator.Roster{Agents: []orchestrator.Agent{
		{Name: "Ada", Role: "greeter-open", Policy: "open", Type: "simple", Addr: "127.0.0.1:19201"},
		{Name: "Noah", Role: "greeter-open", Policy: "open", Type: "simple", Addr: "127.0.0.1:19202"},
	}}
	hub := orchestrator.NewHub(zerolog.Nop())
	sup := orchestrator.NewSupervisor(binDir, "127.0.0.1:19090", "127.0.0.1:19091", roster, hub, zerolog.Nop())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("start mesh: %v", err)
	}
	defer sup.Stop()

	greetID, err := orchestrator.NewDriver(roster).Collide(ctx, "Noah", "Ada")
	if err != nil {
		t.Fatalf("collide: %v", err)
	}

	var it orchestrator.Interaction
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if got, ok := hub.Interaction(greetID); ok && got.Verdict != "" {
			it = got
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if it.Verdict != "accepted" {
		t.Fatalf("verdict = %q (from=%s to=%s events=%d)", it.Verdict, it.From, it.To, len(it.Events))
	}
	if it.From != "Noah" || it.To != "Ada" {
		t.Fatalf("from/to = %s/%s", it.From, it.To)
	}
	var sawInitiator, sawResponder bool
	for _, e := range it.Events {
		if e.Role == "initiator" {
			sawInitiator = true
		}
		if e.Role == "responder" {
			sawResponder = true
		}
	}
	if !sawInitiator || !sawResponder {
		t.Fatalf("missing a point of view: initiator=%v responder=%v", sawInitiator, sawResponder)
	}
}
