package orchestrator

import (
	"bufio"
	"os"
	"strings"
)

// LoadStripeEnv reads KEY=VALUE lines from path (blank lines and #comments
// ignored) into a map. A missing or unreadable file yields an empty map — the
// seller then fails closed at startup when the Stripe key is absent.
func LoadStripeEnv(path string) map[string]string {
	out := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}
