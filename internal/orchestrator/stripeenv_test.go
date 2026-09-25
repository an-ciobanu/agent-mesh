package orchestrator

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadStripeEnvParsesKeyValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stripe.env")
	if err := os.WriteFile(path, []byte("# comment\nSTRIPE_SECRET_KEY=sk_test_xyz\n\nOTHER=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := LoadStripeEnv(path)
	if env["STRIPE_SECRET_KEY"] != "sk_test_xyz" || env["OTHER"] != "1" {
		t.Fatalf("unexpected env: %+v", env)
	}
	if got := LoadStripeEnv(filepath.Join(dir, "missing.env")); len(got) != 0 {
		t.Fatalf("missing file should yield empty map, got %+v", got)
	}
}
