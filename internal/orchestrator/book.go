package orchestrator

import (
	"strconv"
	"sync"
)

// poolSpec is one entry in the fixed dynamic-agent pool: a deterministic name,
// greeter policy, and — for token (mandate) greeters — the authority it trusts.
type poolSpec struct {
	name      string
	role      string
	policy    string
	authority string
}

// dynamicPool is the fixed, ordered cast of 15 greeters the agents slider reveals.
// It is deterministic: the same names, types, and reveal order every run (8 open /
// 4 nonce / 3 token). Token greeters trust an authority present in the base roster.
var dynamicPool = []poolSpec{
	{"Luna", "greeter-open", "open", ""},
	{"Milo", "greeter-nonce", "nonce", ""},
	{"Priya", "greeter-mandate", "mandate", "authority-1"},
	{"Theo", "greeter-open", "open", ""},
	{"Nina", "greeter-open", "open", ""},
	{"Omar", "greeter-nonce", "nonce", ""},
	{"Sofia", "greeter-mandate", "mandate", "authority-2"},
	{"Ravi", "greeter-open", "open", ""},
	{"Bao", "greeter-open", "open", ""},
	{"Tess", "greeter-nonce", "nonce", ""},
	{"Jonas", "greeter-mandate", "mandate", "authority-1"},
	{"Iris", "greeter-open", "open", ""},
	{"Leo", "greeter-open", "open", ""},
	{"Mia", "greeter-nonce", "nonce", ""},
	{"Zara", "greeter-open", "open", ""},
}

// AgentBook is the mesh's live set of agents: the base roster plus any revealed at
// runtime from the fixed dynamic pool. It is safe for concurrent use.
type AgentBook struct {
	mu        sync.Mutex
	agents    []Agent
	baseCount int
	pool      []Agent // the fixed cast of dynamic agents, ports pre-assigned
	usedNames map[string]bool
	usedAddrs map[string]bool
}

// NewAgentBook seeds a book from base; the fixed dynamic pool gets consecutive
// ports from startPort up.
func NewAgentBook(base Roster, startPort int) *AgentBook {
	b := &AgentBook{
		agents:    append([]Agent(nil), base.Agents...),
		baseCount: len(base.Agents),
		usedNames: map[string]bool{},
		usedAddrs: map[string]bool{},
	}
	for _, a := range base.Agents {
		b.usedNames[a.Name] = true
		b.usedAddrs[a.Addr] = true
	}
	for i, s := range dynamicPool {
		addr := "127.0.0.1:" + strconv.Itoa(startPort+i)
		a := mkAgent(s.name, s.role, s.policy, addr)
		if s.policy == "mandate" {
			a.Authority = s.authority
		}
		b.pool = append(b.pool, a)
	}
	return b
}

// PoolMax returns the hard cap on dynamic agents (the fixed pool size).
func (b *AgentBook) PoolMax() int { return len(b.pool) }

// BaseCount returns the number of always-present base-roster agents.
func (b *AgentBook) BaseCount() int { return b.baseCount }

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

// NextAgent returns (but does not add) the next unrevealed agent from the fixed
// dynamic pool, in reveal order. Returns false once all pool agents are revealed —
// this is the hard cap on the number of dynamic agents.
func (b *AgentBook) NextAgent() (Agent, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, a := range b.pool {
		if !b.usedNames[a.Name] {
			return a, true
		}
	}
	return Agent{}, false
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
