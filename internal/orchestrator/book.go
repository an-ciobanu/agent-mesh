package orchestrator

import (
	"math/rand"
	"strconv"
	"sync"
)

// namePool is the set of human names dynamic agents draw from (base-roster names
// excluded at runtime).
var namePool = []string{
	"Luna", "Milo", "Priya", "Theo", "Nina", "Omar", "Sofia", "Ravi",
	"Bao", "Tess", "Jonas", "Iris", "Leo", "Mia", "Ada2", "Noah2",
}

// dynType is a weighted random greeter type for a new agent.
func dynType() (role, policy string) {
	switch n := rand.Intn(100); {
	case n < 60:
		return "greeter-open", "open"
	case n < 85:
		return "greeter-nonce", "nonce"
	default:
		return "greeter-mandate", "mandate"
	}
}

// AgentBook is the mesh's live set of agents: the base roster plus any spawned at
// runtime. It is safe for concurrent use and mints new random agents.
type AgentBook struct {
	mu        sync.Mutex
	agents    []Agent
	baseCount int
	nextPort  int
	usedNames map[string]bool
	usedAddrs map[string]bool
}

// NewAgentBook seeds a book from base; dynamic agents get ports from startPort up.
func NewAgentBook(base Roster, startPort int) *AgentBook {
	b := &AgentBook{
		agents:    append([]Agent(nil), base.Agents...),
		baseCount: len(base.Agents),
		nextPort:  startPort,
		usedNames: map[string]bool{},
		usedAddrs: map[string]bool{},
	}
	for _, a := range base.Agents {
		b.usedNames[a.Name] = true
		b.usedAddrs[a.Addr] = true
	}
	return b
}

// List returns a snapshot of the current agents.
func (b *AgentBook) List() []Agent {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]Agent(nil), b.agents...)
}

// ByName returns the agent with the given name.
func (b *AgentBook) ByName(name string) (Agent, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, a := range b.agents {
		if a.Name == name {
			return a, true
		}
	}
	return Agent{}, false
}

// NextAgent mints (but does not add) a new random dynamic agent: a unique name, a
// free port, a weighted-random type, and — for a mandate greeter — a random
// existing authority to trust. Returns false if no name is available.
func (b *AgentBook) NextAgent() (Agent, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	name := ""
	for _, n := range namePool {
		if !b.usedNames[n] {
			name = n
			break
		}
	}
	if name == "" {
		return Agent{}, false
	}
	for b.usedAddrs["127.0.0.1:"+strconv.Itoa(b.nextPort)] {
		b.nextPort++
	}
	addr := "127.0.0.1:" + strconv.Itoa(b.nextPort)
	b.nextPort++

	role, policy := dynType()
	a := mkAgent(name, role, policy, addr)
	if policy == "mandate" {
		auths := b.authoritiesLocked()
		if len(auths) == 0 {
			a = mkAgent(name, "greeter-open", "open", addr)
		} else {
			a.Authority = auths[rand.Intn(len(auths))]
		}
	}
	return a, true
}

// Add appends a minted agent and marks its name/addr used.
func (b *AgentBook) Add(a Agent) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.agents = append(b.agents, a)
	b.usedNames[a.Name] = true
	b.usedAddrs[a.Addr] = true
}

// RemoveLast removes and returns the most-recently-added dynamic agent. It never
// removes a base-roster agent; returns false when only the base remains.
func (b *AgentBook) RemoveLast() (Agent, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.agents) <= b.baseCount {
		return Agent{}, false
	}
	last := b.agents[len(b.agents)-1]
	b.agents = b.agents[:len(b.agents)-1]
	delete(b.usedNames, last.Name)
	delete(b.usedAddrs, last.Addr)
	return last, true
}

func (b *AgentBook) authoritiesLocked() []string {
	var out []string
	for _, a := range b.agents {
		if a.Policy == "authority" {
			out = append(out, a.Name)
		}
	}
	return out
}
