// Package orchestrator runs the P5 demo mesh: it spawns the registry, the
// transparency log, an authority, and a roster of event-emitting agents; it
// captures the agents' event streams and assembles them, by greet id, into the
// two-point-of-view interactions the browser renders.
package orchestrator

// UI colors (must match web/index.html).
const (
	ColorSimple    = "#f4523b" // open   greeter -> red
	ColorNonce     = "#f2c94c" // nonce  greeter -> yellow
	ColorToken     = "#4aa3ff" // mandate greeter -> blue
	ColorAuthority = "#8b93a7" // authority -> gray
)

// Agent is one member of the demo mesh.
type Agent struct {
	Name      string `json:"name"`
	Role      string `json:"role"`
	Policy    string `json:"policy"` // open | nonce | mandate | authority
	Type      string `json:"type"`   // simple | nonce | token | authority (UI)
	Color     string `json:"color"`
	Addr      string `json:"-"` // host:port (not exposed to the browser)
	Authority string `json:"-"` // for mandate greeters: the authority (name) this greeter trusts
}

// BaseURL returns the agent's HTTP base URL.
func (a Agent) BaseURL() string { return "http://" + a.Addr }

// Roster is the set of agents in the demo.
type Roster struct {
	Agents []Agent
}

// ByName returns the agent with the given name.
func (r Roster) ByName(name string) (Agent, bool) {
	for _, a := range r.Agents {
		if a.Name == name {
			return a, true
		}
	}
	return Agent{}, false
}

// Greeters returns the non-authority agents (the collidable ones).
func (r Roster) Greeters() []Agent {
	var out []Agent
	for _, a := range r.Agents {
		if a.Policy != "authority" {
			out = append(out, a)
		}
	}
	return out
}

func mkAgent(name, role, policy, addr string) Agent {
	a := Agent{Name: name, Role: role, Policy: policy, Addr: addr}
	switch policy {
	case "open":
		a.Type, a.Color = "simple", ColorSimple
	case "nonce":
		a.Type, a.Color = "nonce", ColorNonce
	case "mandate":
		a.Type, a.Color = "token", ColorToken
	case "authority":
		a.Type, a.Color = "authority", ColorAuthority
	}
	return a
}

// mkMandate builds a token greeter that trusts the named authority.
func mkMandate(name, role, addr, authority string) Agent {
	a := mkAgent(name, role, "mandate", addr)
	a.Authority = authority
	return a
}

// DefaultRoster is the demo's fixed set of agents. Circles in the UI are these
// real processes; the count is a launch-time property (real OS processes), not a
// browser slider.
func DefaultRoster() Roster {
	return Roster{Agents: []Agent{
		mkAgent("authority-1", "authority", "authority", "127.0.0.1:18110"),
		mkAgent("authority-2", "authority", "authority", "127.0.0.1:18111"),
		mkAgent("Ada", "greeter-open", "open", "127.0.0.1:18201"),
		mkAgent("Noah", "greeter-open", "open", "127.0.0.1:18202"),
		mkAgent("Ema", "greeter-open", "open", "127.0.0.1:18205"),
		mkAgent("Zoe", "greeter-nonce", "nonce", "127.0.0.1:18203"),
		mkMandate("Chris", "greeter-mandate", "127.0.0.1:18204", "authority-1"),
		mkMandate("Kai", "greeter-mandate", "127.0.0.1:18206", "authority-2"),
	}}
}
