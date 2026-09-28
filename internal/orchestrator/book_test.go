package orchestrator

import (
	"strconv"
	"testing"
)

func TestBookStartsFromBaseRoster(t *testing.T) {
	b := NewAgentBook(DefaultRoster(), 18300)
	if len(b.List()) != len(DefaultRoster().Agents) {
		t.Fatalf("book should start with the base roster")
	}
	if _, ok := b.ByName("Ada"); !ok {
		t.Fatal("base agent Ada missing")
	}
}

func TestBookMintAddRemove(t *testing.T) {
	b := NewAgentBook(DefaultRoster(), 18300)
	base := len(b.List())

	a, ok := b.NextAgent()
	if !ok {
		t.Fatal("NextAgent should mint an agent")
	}
	if a.Name == "" || a.Addr == "" || a.Type == "" || a.Policy == "" {
		t.Fatalf("minted agent incomplete: %+v", a)
	}
	if a.Policy == "mandate" && a.Authority == "" {
		t.Fatalf("minted mandate agent must trust an authority: %+v", a)
	}
	if _, exists := b.ByName(a.Name); exists {
		t.Fatal("NextAgent must not be in the book until Add")
	}

	b.Add(a)
	if len(b.List()) != base+1 {
		t.Fatalf("Add did not grow the book")
	}
	if got, ok := b.ByName(a.Name); !ok || got.Addr != a.Addr {
		t.Fatal("added agent not found")
	}

	removed, ok := b.RemoveLast()
	if !ok || removed.Name != a.Name {
		t.Fatalf("RemoveLast should return the dynamic agent, got %+v ok=%v", removed, ok)
	}
	if len(b.List()) != base {
		t.Fatalf("RemoveLast did not shrink the book")
	}
}

func TestBookNeverRemovesBaseRoster(t *testing.T) {
	b := NewAgentBook(DefaultRoster(), 18300)
	if _, ok := b.RemoveLast(); ok {
		t.Fatal("RemoveLast must refuse to remove a base-roster agent")
	}
}

func TestBookPoolIsDeterministicAndCapped(t *testing.T) {
	b := NewAgentBook(DefaultRoster(), 18300)
	if got := b.PoolMax(); got != len(dynamicPool) || got != 15 {
		t.Fatalf("PoolMax = %d, want 15", got)
	}
	if got := b.BaseCount(); got != len(DefaultRoster().Agents) {
		t.Fatalf("BaseCount = %d, want %d", got, len(DefaultRoster().Agents))
	}

	// Reveal the whole pool; names/ports must be the fixed cast in order.
	for i, spec := range dynamicPool {
		a, ok := b.NextAgent()
		if !ok {
			t.Fatalf("pool exhausted early at %d", i)
		}
		if a.Name != spec.name {
			t.Fatalf("reveal %d: name = %q, want %q (order must be deterministic)", i, a.Name, spec.name)
		}
		if want := "127.0.0.1:" + strconv.Itoa(18300+i); a.Addr != want {
			t.Fatalf("reveal %d: addr = %q, want %q", i, a.Addr, want)
		}
		if spec.policy == "mandate" && a.Authority != spec.authority {
			t.Fatalf("reveal %d: authority = %q, want %q", i, a.Authority, spec.authority)
		}
		b.Add(a)
	}
	// Hard cap: nothing beyond the fixed pool.
	if _, ok := b.NextAgent(); ok {
		t.Fatal("NextAgent must return false once the fixed pool is exhausted (hard cap)")
	}

	// Deterministic across runs: a fresh book reveals the same first agent.
	b2 := NewAgentBook(DefaultRoster(), 18300)
	if a, _ := b2.NextAgent(); a.Name != dynamicPool[0].name {
		t.Fatalf("first reveal = %q, want %q (cast must be identical every run)", a.Name, dynamicPool[0].name)
	}
}

func TestBookMintsUniqueNamesAndPorts(t *testing.T) {
	b := NewAgentBook(DefaultRoster(), 18300)
	seenName, seenAddr := map[string]bool{}, map[string]bool{}
	for i := 0; i < 6; i++ {
		a, ok := b.NextAgent()
		if !ok {
			break
		}
		if seenName[a.Name] || seenAddr[a.Addr] {
			t.Fatalf("duplicate name/addr minted: %+v", a)
		}
		seenName[a.Name], seenAddr[a.Addr] = true, true
		b.Add(a)
	}
	if len(seenName) < 4 {
		t.Fatalf("expected several unique agents, got %d", len(seenName))
	}
}
