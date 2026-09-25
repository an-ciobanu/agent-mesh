// Command agent runs a single agent-mesh agent: it loads an Ed25519 identity,
// serves its A2A Agent Card, and registers with the discovery registry.
package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/authclient"
	"github.com/an-ciobanu/agent-mesh/internal/comms/discovery"
	"github.com/an-ciobanu/agent-mesh/internal/comms/transparency"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
)

func main() {
	name := flag.String("name", "", "unique agent name (required)")
	role := flag.String("role", "greeter", "agent role")
	addr := flag.String("addr", "127.0.0.1:18101", "listen address")
	registryURL := flag.String("registry", "http://127.0.0.1:18090", "registry base URL")
	keyDir := flag.String("keys", "", "identity key directory (default: ./data/<name>)")
	transparencyURL := flag.String("transparency", "", "transparency log base URL; enables sealing of accepted greets")
	policyName := flag.String("policy", "open", "greet policy: open | mandate")
	authorityRole := flag.String("authority-role", "authority", "role of the mandate authority (when --policy=mandate)")
	scope := flag.String("scope", "greet", "required mandate scope (when --policy=mandate)")
	flag.Parse()

	log := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Str("agent", *name).Logger()
	if *name == "" {
		log.Fatal().Msg("--name is required")
	}

	dir := *keyDir
	if dir == "" {
		dir = filepath.Join("data", *name)
	}
	priv, err := crypto.LoadOrCreateEd25519(filepath.Join(dir, "id_ed25519.seed"))
	if err != nil {
		log.Fatal().Err(err).Msg("load identity key")
	}

	baseURL := "http://" + *addr
	selfAns := domain.LocalANSName(*name)

	disco := discovery.New(*registryURL)
	ctx := context.Background()

	var greetPolicy domain.GreetPolicy = policy.Open{}
	card := a2a.Card{
		Name:    *name,
		Version: "0.1.0",
		// URL is left unset here: serveCard fills it in per-request from the
		// request host, so it is correct regardless of the bound port.
		Security: []map[string][]string{}, // open by default
	}

	if *policyName == "mandate" {
		authPeer, authPub := resolveAuthority(ctx, disco, authclient.New(), *authorityRole, log)
		authorityAns := domain.LocalANSName(authPeer.Name)
		greetPolicy = policy.NewMandate(selfAns, authorityAns, authPub, *scope, log)
		card.Security = []map[string][]string{{"mandate": {}}}
		card.Capabilities = &a2a.Capabilities{Extensions: []a2a.Extension{{
			URI:         a2a.ExtMandateURI,
			Description: "present a mandate from the authority",
			Required:    true,
			Params:      map[string]any{"authorityRole": *authorityRole, "scope": *scope},
		}}}
		log.Info().Str("authorityAns", authorityAns).Str("scope", *scope).Msg("mandate policy enabled")
	}

	var opts []a2a.Option
	if *transparencyURL != "" {
		opts = append(opts, a2a.WithSealing(priv, transparency.New(*transparencyURL)))
		log.Info().Str("transparency", *transparencyURL).Msg("greet sealing enabled")
	}
	greetSvc := a2a.NewGreetService(selfAns, greetPolicy, log, opts...)
	srv := &http.Server{Addr: *addr, Handler: a2a.NewMux(card, greetSvc, log)}
	go func() {
		log.Info().Str("addr", *addr).Str("ans", selfAns).Msg("agent listening")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("agent server exited")
		}
	}()

	info := domain.AgentInfo{
		Name:    *name,
		Role:    *role,
		BaseURL: baseURL,
		CardURL: baseURL + "/.well-known/agent-card.json",
	}
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
		log.Info().Str("registry", *registryURL).Str("role", *role).Msg("registered with registry")
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	log.Info().Msg("agent stopped")
}

// resolveAuthority discovers the authority of the given role and pins its public
// key, retrying to tolerate startup races. A mandate greeter cannot serve
// without a pinned authority key, so failure is fatal (fail closed).
func resolveAuthority(ctx context.Context, disco *discovery.Client, ac *authclient.Client, role string, log zerolog.Logger) (domain.AgentInfo, ed25519.PublicKey) {
	for i := 0; i < 20; i++ {
		peers, err := disco.Search(ctx, role)
		if err == nil && len(peers) > 0 {
			pub, perr := ac.FetchPubKey(ctx, peers[0].BaseURL)
			if perr == nil {
				log.Info().Str("authority", peers[0].Name).Str("baseURL", peers[0].BaseURL).Msg("pinned authority key")
				return peers[0], pub
			}
			log.Warn().Err(perr).Msg("fetch authority pubkey; retrying")
		}
		time.Sleep(250 * time.Millisecond)
	}
	log.Fatal().Str("role", role).Msg("could not resolve/pin the authority; a mandate greeter cannot start without it")
	return domain.AgentInfo{}, nil // unreachable
}
