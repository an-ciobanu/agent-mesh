package orchestrator

import "testing"

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
