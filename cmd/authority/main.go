// Command authority runs an agent-mesh mandate authority: it serves an Agent
// Card, an MCP issue_mandate tool, and its public key, and registers with the
// discovery registry as role "authority".
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/authority"
	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/discovery"
	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

func main() {
	name := flag.String("name", "authority-1", "authority name")
	addr := flag.String("addr", "127.0.0.1:18110", "listen address")
	registryURL := flag.String("registry", "http://127.0.0.1:18090", "registry base URL")
	keyDir := flag.String("keys", "", "identity key directory (default: ./data/<name>)")
	ttl := flag.Duration("ttl", time.Hour, "mandate validity window")
	flag.Parse()

	log := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Str("agent", *name).Logger()

	if *ttl <= 0 {
		log.Fatal().Dur("ttl", *ttl).Msg("ttl must be > 0")
	}

	dir := *keyDir
	if dir == "" {
		dir = filepath.Join("data", *name)
	}
	priv, err := crypto.LoadOrCreateEd25519(filepath.Join(dir, "id_ed25519.seed"))
	if err != nil {
		log.Fatal().Err(err).Msg("load identity key")
	}
	selfAns := domain.LocalANSName(*name)
	auth := authority.New(selfAns, priv, *ttl, log)

	mcpSrv := mcp.NewServer(log)
	mcpSrv.Register("issue_mandate", auth.MCPTool())
	mcpSrv.Register("issue_spend_mandate", auth.SpendMCPTool())
	mcpSrv.Register("issue_checkout_mandate", auth.CheckoutMandateMCPTool())
	mcpSrv.Register("issue_payment_mandate", auth.PaymentMandateMCPTool())

	baseURL := "http://" + *addr
	card := a2a.Card{Name: *name, Version: "0.1.0", Security: []map[string][]string{}}

	mux := http.NewServeMux()
	mux.Handle("/.well-known/agent-card.json", a2a.CardHandler(card, log))
	mux.Handle("/mcp", mcpSrv.Handler())
	mux.HandleFunc("GET /pubkey", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(crypto.PublicJWK(priv.Public().(ed25519.PublicKey))); err != nil {
			log.Error().Err(err).Msg("pubkey: encode")
		}
	})

	srv := &http.Server{Addr: *addr, Handler: mux}
	go func() {
		log.Info().Str("addr", *addr).Str("ans", selfAns).Msg("authority listening")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("authority server exited")
		}
	}()

	disco := discovery.New(*registryURL)
	info := domain.AgentInfo{
		Name:    *name,
		Role:    "authority",
		BaseURL: baseURL,
		CardURL: baseURL + "/.well-known/agent-card.json",
	}
	ctx := context.Background()
	var regErr error
	for i := 0; i < 10; i++ {
		if regErr = disco.Register(ctx, info); regErr == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if regErr != nil {
		log.Error().Err(regErr).Msg("could not register with registry")
	} else {
		log.Info().Str("registry", *registryURL).Str("role", "authority").Msg("registered with registry")
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	log.Info().Msg("authority stopped")
}
