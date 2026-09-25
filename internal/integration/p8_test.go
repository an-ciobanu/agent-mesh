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

// mkACPSeller builds an ACP seller agent that trusts the named authority,
// mirroring orchestrator's unexported mkSeller helper.
func mkACPSeller(name, addr, authority string) orchestrator.Agent {
	return orchestrator.Agent{
		Name:      name,
		Role:      "seller",
		Policy:    "acp",
		Type:      "acp",
		Color:     orchestrator.ColorACP,
		Addr:      addr,
		Authority: authority,
		Protocol:  "acp",
	}
}

func TestP8_ACPPurchaseEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: spawns real processes")
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
		{Name: "authority-1", Role: "authority", Policy: "authority", Addr: "127.0.0.1:19410"},
		{Name: "Ada", Role: "greeter-open", Policy: "open", Type: "simple", Addr: "127.0.0.1:19401"},
		mkACPSeller("Shopa", "127.0.0.1:19402", "authority-1"),
	}}
	hub := orchestrator.NewHub(zerolog.Nop())
	sup := orchestrator.NewSupervisor(binDir, "127.0.0.1:19490", "127.0.0.1:19491", roster, hub, zerolog.Nop())
	sup.WithSellerPayment("fake")

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("start mesh: %v", err)
	}
	defer sup.Stop()

	book := orchestrator.NewAgentBook(roster, 19500)
	greetID, err := orchestrator.NewDriver(book).Collide(ctx, "Ada", "Shopa")
	if err != nil {
		t.Fatalf("collide: %v", err)
	}

	var it orchestrator.Interaction
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if got, ok := hub.Interaction(greetID); ok && got.Verdict != "" {
			it = got
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if it.Verdict != "accepted" {
		t.Fatalf("verdict = %q reason=%q events=%d", it.Verdict, it.Reason, len(it.Events))
	}
}
