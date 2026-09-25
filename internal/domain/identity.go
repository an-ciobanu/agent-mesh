package domain

// LocalANSName returns the local-development ANS name for an agent instance.
// Online ANS registration (real names, DNS, certs) is deferred; this gives
// agents a stable, verifiable name to sign as during local development.
func LocalANSName(name string) string {
	return "ans://v1.0.0." + name + ".mesh.local"
}
