// Command agent runs a single agent-mesh agent: it loads an Ed25519 identity,
// serves its A2A Agent Card, and registers with the discovery registry.
package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/audit"
	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/authclient"
	"github.com/an-ciobanu/agent-mesh/internal/comms/discovery"
	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
	"github.com/an-ciobanu/agent-mesh/internal/comms/resolver"
	"github.com/an-ciobanu/agent-mesh/internal/comms/transparency"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/events"
	"github.com/an-ciobanu/agent-mesh/internal/greet"
	"github.com/an-ciobanu/agent-mesh/internal/nonce"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
)

func main() {
	name := flag.String("name", "", "unique agent name (required)")
	role := flag.String("role", "greeter", "agent role")
	addr := flag.String("addr", "127.0.0.1:18101", "listen address")
	registryURL := flag.String("registry", "http://127.0.0.1:18090", "registry base URL")
	keyDir := flag.String("keys", "", "identity key directory (default: ./data/<name>)")
	transparencyURL := flag.String("transparency", "", "transparency log base URL; enables sealing of accepted greets")
	policyName := flag.String("policy", "open", "greet policy: open | mandate | nonce")
	authorityRole := flag.String("authority-role", "authority", "role of the mandate authority (when --policy=mandate)")
	scope := flag.String("scope", "greet", "required mandate scope (when --policy=mandate)")
	nonceTTL := flag.Duration("nonce-ttl", 2*time.Minute, "nonce validity window (when --policy=nonce)")
	emitEvents := flag.Bool("events", false, "emit per-step greet events as JSON lines to stdout")
	allowTrigger := flag.Bool("allow-trigger", false, "expose POST /trigger/greet so a driver can make this agent initiate greets (demo only)")
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

	var em events.Emitter = events.Nop{}
	if *emitEvents {
		em = events.NewJSONEmitter(os.Stdout)
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

	var mcpHandler http.Handler

	switch *policyName {
	case "open":
		// default greetPolicy (policy.Open{}) and open card already set above.
	case "mandate":
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
	case "nonce":
		store := nonce.NewStore(*nonceTTL)
		greetPolicy = policy.NewNonce(selfAns, store, log)
		mcpSrv := mcp.NewServer(log)
		mcpSrv.Register("get_nonce", store.MCPTool())
		mcpHandler = mcpSrv.Handler()
		card.Security = []map[string][]string{{"dpop": {}}}
		card.Capabilities = &a2a.Capabilities{Extensions: []a2a.Extension{{
			URI:         a2a.ExtNonceURI,
			Description: "obtain a nonce via get_nonce and present a DPoP proof",
			Required:    true,
		}}}
		log.Info().Dur("nonceTTL", *nonceTTL).Msg("nonce policy enabled")
	default:
		log.Fatal().Str("policy", *policyName).Msg("unknown --policy (want: open | mandate | nonce)")
	}

	var opts []a2a.Option
	if *transparencyURL != "" {
		opts = append(opts, a2a.WithSealing(priv, transparency.New(*transparencyURL)))
		log.Info().Str("transparency", *transparencyURL).Msg("greet sealing enabled")
	}
	opts = append(opts, a2a.WithEvents(em, *name, *role))
	greetSvc := a2a.NewGreetService(selfAns, greetPolicy, log, opts...)
	mux := a2a.NewMux(card, greetSvc, log)
	if mcpHandler != nil {
		mux.Handle("/mcp", mcpHandler)
	}
	if *allowTrigger {
		res := resolver.New()
		a2aCli := a2a.NewClient()
		mcpCli := mcp.NewClient()
		greetFn := func(greetID, toRole, toName, text string) (string, bool, error) {
			if toRole == "" {
				return "", false, fmt.Errorf("toRole is required")
			}
			gctx := events.WithScope(context.Background(), em, greetID, *name, events.RoleInitiator)
			peers, serr := disco.Search(gctx, toRole)
			if serr != nil {
				return "", false, fmt.Errorf("discover role %q: %w", toRole, serr)
			}
			if len(peers) == 0 {
				return "", false, fmt.Errorf("no agents found for role %q", toRole)
			}
			peer := peers[0]
			if toName != "" {
				found := false
				for _, p := range peers {
					if p.Name == toName {
						peer, found = p, true
						break
					}
				}
				if !found {
					return "", false, fmt.Errorf("no agent named %q in role %q", toName, toRole)
				}
			}
			reply, evidence, err := greet.GreetPeer(gctx, res, a2aCli, mcpCli, disco, priv, selfAns, peer, text)
			if err != nil {
				return "", false, err
			}
			auditEvidence(gctx, *transparencyURL, evidence, log)
			return reply, true, nil
		}
		trig := a2a.NewTriggerService(*name, greetFn, log, em)
		mux.HandleFunc("POST /trigger/greet", trig.HandleGreet)
		log.Info().Msg("trigger endpoint enabled (POST /trigger/greet)")
	}
	srv := &http.Server{Addr: *addr, Handler: mux}
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

// auditEvidence independently verifies the greeter's sealed evidence against the
// transparency log and emits an `audit` event so the UI can show the TL capstone
// (real inclusion proof), not just a claim. Best-effort: any failure emits a
// fail-status audit event and returns.
func auditEvidence(ctx context.Context, tlURL string, evidence *domain.EvidenceBundle, log zerolog.Logger) {
	if evidence == nil {
		events.Emit(ctx, "audit", events.StatusInfo, map[string]string{"note": "no evidence (greeter not sealing)"})
		return
	}
	if tlURL == "" {
		events.Emit(ctx, "audit", events.StatusInfo, map[string]string{
			"entryIndex": strconv.Itoa(evidence.Receipt.EntryIndex),
			"treeSize":   strconv.Itoa(evidence.Receipt.TreeSize),
			"note":       "sealed; no --transparency to audit",
		})
		return
	}
	tlPub, err := transparency.New(tlURL).FetchPubKey(ctx)
	if err != nil {
		events.Emit(ctx, "audit", events.StatusFail, map[string]string{"error": "fetch TL pubkey: " + err.Error()})
		return
	}
	auditorPriv, err := crypto.GenerateEd25519()
	if err != nil {
		events.Emit(ctx, "audit", events.StatusFail, map[string]string{"error": "gen auditor key: " + err.Error()})
		return
	}
	verdict, _, err := audit.New(domain.LocalANSName("auditor"), auditorPriv, log).Verify(ctx, *evidence, tlPub)
	if err != nil {
		events.Emit(ctx, "audit", events.StatusFail, map[string]string{"error": err.Error()})
		return
	}
	events.Emit(ctx, "audit", events.StatusOK, map[string]string{
		"verdict":    verdict.Verdict,
		"entryIndex": strconv.Itoa(evidence.Receipt.EntryIndex),
		"treeSize":   strconv.Itoa(evidence.Receipt.TreeSize),
	})
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
