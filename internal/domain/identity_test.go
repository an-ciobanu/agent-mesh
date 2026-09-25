package domain

import "testing"

func TestLocalANSName(t *testing.T) {
	got := LocalANSName("greeter-open")
	want := "ans://v1.0.0.greeter-open.mesh.local"
	if got != want {
		t.Fatalf("LocalANSName = %q, want %q", got, want)
	}
}
