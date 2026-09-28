package orchestrator

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/events"
)

// Supervisor spawns and supervises the demo mesh's child processes.
type Supervisor struct {
	bin          string // directory holding the built binaries (e.g. "bin")
	registry     string // host:port
	transparency string
	roster       Roster
	hub          *Hub
	log          zerolog.Logger

	stripeEnv     []string // extra "K=V" entries injected into spawned children
	sellerPayment string   // ACP seller funding backend override ("stripe" | "fake")

	ctx context.Context

	mu        sync.Mutex
	cmds      []*exec.Cmd
	cmdByName map[string]*exec.Cmd
}

// NewSupervisor builds a supervisor. binDir holds the compiled binaries.
func NewSupervisor(binDir, registryAddr, transparencyAddr string, roster Roster, hub *Hub, log zerolog.Logger) *Supervisor {
	return &Supervisor{
		bin: binDir, registry: registryAddr, transparency: transparencyAddr,
		roster: roster, hub: hub, log: log.With().Str("component", "supervisor").Logger(),
		cmdByName: map[string]*exec.Cmd{},
	}
}

// WithChildEnv sets extra environment entries ("K=V") passed to spawned agents.
func (s *Supervisor) WithChildEnv(env []string) { s.stripeEnv = env }

// WithSellerPayment overrides the ACP seller funding backend ("stripe" | "fake").
func (s *Supervisor) WithSellerPayment(mode string) { s.sellerPayment = mode }

// Start launches registry, transparency, authority, and agents in order, waiting
// for each tier's readiness. Agent stdout is streamed into the hub.
func (s *Supervisor) Start(ctx context.Context) error {
	s.ctx = ctx
	regURL := "http://" + s.registry
	tlURL := "http://" + s.transparency

	if err := s.spawn(ctx, "registry", nil, s.bin+"/registry", "--addr", s.registry); err != nil {
		return err
	}
	// internal/registry/service.go registers "GET /search" (returns 200 with an
	// empty JSON array before any agent has registered).
	if err := waitReady(ctx, regURL+"/search", 5*time.Second); err != nil {
		return fmt.Errorf("registry not ready: %w", err)
	}
	if err := s.spawn(ctx, "transparency", nil, s.bin+"/transparency", "--addr", s.transparency); err != nil {
		return err
	}
	// internal/tl/service.go registers "GET /pubkey" (returns 200 as soon as the
	// service's Ed25519 key is loaded; unlike /checkpoint it has no dependency on
	// log state).
	if err := waitReady(ctx, tlURL+"/pubkey", 5*time.Second); err != nil {
		s.log.Warn().Err(err).Msg("transparency readiness probe failed; continuing")
	}
	for _, a := range s.roster.Agents {
		if a.Policy != "authority" {
			continue
		}
		if err := s.spawn(ctx, a.Name, nil, s.bin+"/authority", "--name", a.Name, "--addr", a.Addr, "--registry", regURL, "--transparency", tlURL); err != nil {
			return err
		}
		if err := waitReady(ctx, a.BaseURL()+"/.well-known/agent-card.json", 5*time.Second); err != nil {
			s.log.Warn().Err(err).Str("authority", a.Name).Msg("authority readiness probe failed; continuing")
		}
	}
	for _, a := range s.roster.Greeters() {
		if err := s.spawn(ctx, a.Name, s.hub, s.bin+"/agent", s.greeterArgs(a)...); err != nil {
			return err
		}
	}
	for _, a := range s.roster.Greeters() {
		_ = waitReady(ctx, a.BaseURL()+"/.well-known/agent-card.json", 8*time.Second)
	}
	return nil
}

// greeterArgs builds the CLI args for a greeter agent process.
func (s *Supervisor) greeterArgs(a Agent) []string {
	regURL := "http://" + s.registry
	tlURL := "http://" + s.transparency
	if a.Policy == "acp" || a.Policy == "ucp" {
		payment := s.sellerPayment
		if payment == "" {
			payment = "stripe"
		}
		protoFlag := "--acp"
		if a.Policy == "ucp" {
			protoFlag = "--ucp"
		}
		return []string{
			"--name", a.Name, "--role", a.Role, "--addr", a.Addr,
			"--registry", regURL, "--transparency", tlURL, protoFlag, "--payment", payment,
			"--authority-role", "authority", "--authority-name", a.Authority,
			"--events",
		}
	}
	args := []string{
		"--name", a.Name, "--role", a.Role, "--addr", a.Addr,
		"--registry", regURL, "--transparency", tlURL,
		"--policy", a.Policy, "--events", "--allow-trigger",
	}
	if a.Policy == "mandate" {
		args = append(args, "--authority-role", "authority", "--scope", "greet")
		if a.Authority != "" {
			args = append(args, "--authority-name", a.Authority)
		}
	}
	return args
}

// SpawnOne starts a single greeter at runtime, streaming its events into the hub,
// and waits briefly for it to become ready. Used by POST /spawn.
func (s *Supervisor) SpawnOne(a Agent) error {
	if err := s.spawn(s.ctx, a.Name, s.hub, s.bin+"/agent", s.greeterArgs(a)...); err != nil {
		return err
	}
	return waitReady(s.ctx, a.BaseURL()+"/.well-known/agent-card.json", 8*time.Second)
}

// Kill terminates a single agent by name (used by POST /despawn).
func (s *Supervisor) Kill(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cmd, ok := s.cmdByName[name]; ok {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		delete(s.cmdByName, name)
	}
}

// spawn starts one child. If hub != nil, the child's stdout is parsed as event
// JSON lines and ingested (used for agents).
func (s *Supervisor) spawn(ctx context.Context, name string, hub *Hub, path string, args ...string) error {
	cmd := exec.CommandContext(ctx, path, args...)
	if len(s.stripeEnv) > 0 {
		cmd.Env = append(os.Environ(), s.stripeEnv...)
	}
	if hub != nil {
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return fmt.Errorf("stdout pipe for %s: %w", name, err)
		}
		go s.pump(name, hub, stdout)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", name, err)
	}
	s.mu.Lock()
	s.cmds = append(s.cmds, cmd)
	s.cmdByName[name] = cmd
	s.mu.Unlock()
	s.log.Info().Str("proc", name).Int("pid", cmd.Process.Pid).Msg("spawned")
	return nil
}

func (s *Supervisor) pump(name string, hub *Hub, r interface{ Read([]byte) (int, error) }) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var e events.Event
		if err := json.Unmarshal(line, &e); err != nil {
			continue
		}
		hub.Ingest(e)
	}
	if err := sc.Err(); err != nil {
		s.log.Warn().Err(err).Str("proc", name).Msg("stdout scan ended with error")
	}
}

// Stop terminates all child processes.
func (s *Supervisor) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.cmds {
		if c.Process != nil {
			_ = c.Process.Kill()
		}
	}
}

func waitReady(ctx context.Context, url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	cli := &http.Client{Timeout: 500 * time.Millisecond}
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := cli.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
	}
	return fmt.Errorf("timeout waiting for %s", url)
}
