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

func TestRosterHasTwoAuthoritiesAndTrustWiring(t *testing.T) {
	r := DefaultRoster()
	var auth int
	for _, a := range r.Agents {
		if a.Policy == "authority" {
			auth++
		}
	}
	if auth != 2 {
		t.Fatalf("want 2 authorities, got %d", auth)
	}
	chris, _ := r.ByName("Chris")
	kai, ok := r.ByName("Kai")
	if !ok {
		t.Fatal("expected a second token greeter 'Kai'")
	}
	if chris.Policy != "mandate" || chris.Authority != "authority-1" {
		t.Fatalf("Chris should trust authority-1: %+v", chris)
	}
	if kai.Policy != "mandate" || kai.Authority != "authority-2" {
		t.Fatalf("Kai should trust authority-2: %+v", kai)
	}
}

func TestDefaultRosterIncludesACPSeller(t *testing.T) {
	r := DefaultRoster()
	var sellers int
	for _, a := range r.Agents {
		if a.Type == "acp" {
			sellers++
			if a.Color != ColorACP {
				t.Fatalf("seller %q color = %q, want %q", a.Name, a.Color, ColorACP)
			}
			if a.Policy != "acp" || a.Role != "seller" {
				t.Fatalf("seller %q policy/role = %q/%q", a.Name, a.Policy, a.Role)
			}
			if a.Authority == "" {
				t.Fatalf("seller %q has no authority", a.Name)
			}
		}
	}
	if sellers == 0 {
		t.Fatal("expected at least one ACP seller in the default roster")
	}
}
