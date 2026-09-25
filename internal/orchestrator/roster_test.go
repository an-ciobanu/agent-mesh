package orchestrator

import "testing"

func TestDefaultRosterMapsPolicyToType(t *testing.T) {
	r := DefaultRoster()
	byName := map[string]Agent{}
	for _, a := range r.Agents {
		byName[a.Name] = a
	}
	if got := byName["Ada"]; got.Type != "simple" || got.Color != "#f4523b" || got.Policy != "open" {
		t.Fatalf("Ada = %+v", got)
	}
	if got := byName["Zoe"]; got.Type != "nonce" || got.Color != "#f2c94c" {
		t.Fatalf("Zoe = %+v", got)
	}
	if got := byName["Chris"]; got.Type != "token" || got.Color != "#4aa3ff" {
		t.Fatalf("Chris = %+v", got)
	}
	if got := byName["authority-1"]; got.Type != "authority" {
		t.Fatalf("authority = %+v", got)
	}
}

func TestRosterByName(t *testing.T) {
	r := DefaultRoster()
	a, ok := r.ByName("Zoe")
	if !ok || a.Role != "greeter-nonce" {
		t.Fatalf("ByName(Zoe) = %+v ok=%v", a, ok)
	}
	if _, ok := r.ByName("nobody"); ok {
		t.Fatalf("ByName(nobody) should be false")
	}
}

func TestGreetersHaveDistinctAddrs(t *testing.T) {
	seen := map[string]bool{}
	for _, a := range DefaultRoster().Agents {
		if seen[a.Addr] {
			t.Fatalf("duplicate addr %s", a.Addr)
		}
		seen[a.Addr] = true
	}
}
