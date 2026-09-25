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

func TestP6MandateFollowsNamedAuthority(t *testing.T) {
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
		{Name: "authority-1", Role: "authority", Policy: "authority", Addr: "127.0.0.1:19110"},
		{Name: "authority-2", Role: "authority", Policy: "authority", Addr: "127.0.0.1:19111"},
		{Name: "Ada", Role: "greeter-open", Policy: "open", Type: "simple", Addr: "127.0.0.1:19201"},
		{Name: "Kai", Role: "greeter-mandate", Policy: "mandate", Type: "token", Addr: "127.0.0.1:19206", Authority: "authority-2"},
	}}
	hub := orchestrator.NewHub(zerolog.Nop())
	sup := orchestrator.NewSupervisor(binDir, "127.0.0.1:19090", "127.0.0.1:19091", roster, hub, zerolog.Nop())

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("start mesh: %v", err)
	}
	defer sup.Stop()

	greetID, err := orchestrator.NewDriver(roster).Collide(ctx, "Ada", "Kai")
	if err != nil {
		t.Fatalf("collide: %v", err)
	}

	var it orchestrator.Interaction
	deadline := time.Now().Add(12 * time.Second)
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
	var acquiredFrom string
	for _, e := range it.Events {
		if e.Step == "mandate.acquire" && e.Status == "ok" {
			acquiredFrom = e.Detail["authority"]
		}
	}
	if acquiredFrom != "authority-2" {
		t.Fatalf("mandate acquired from %q; want authority-2", acquiredFrom)
	}
}
