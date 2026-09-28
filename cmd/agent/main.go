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
	"github.com/an-ciobanu/agent-mesh/internal/commerce"
	"github.com/an-ciobanu/agent-mesh/internal/commerce/acp"
	"github.com/an-ciobanu/agent-mesh/internal/commerce/ucp"
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
	"github.com/an-ciobanu/agent-mesh/internal/stripe"
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
	authorityName := flag.String("authority-name", "", "specific authority to trust by name (when --policy=mandate); empty = first discovered")
	scope := flag.String("scope", "greet", "required mandate scope (when --policy=mandate)")
	nonceTTL := flag.Duration("nonce-ttl", 2*time.Minute, "nonce validity window (when --policy=nonce)")
	emitEvents := flag.Bool("events", false, "emit per-step greet events as JSON lines to stdout")
	allowTrigger := flag.Bool("allow-trigger", false, "expose POST /trigger/greet so a driver can make this agent initiate greets (demo only)")
	acpSeller := flag.Bool("acp", false, "run as an ACP seller (serves /acp/* instead of a greet policy)")
	ucpSeller := flag.Bool("ucp", false, "run as a UCP seller (serves /.well-known/ucp + /ucp/* instead of a greet policy)")
	acpCurrency := flag.String("acp-currency", "usd", "ACP catalog currency (when --acp)")
	payment := flag.String("payment", "stripe", "ACP funding backend: stripe | fake (when --acp)")
	stripeKeyEnv := flag.String("stripe-key-env", "STRIPE_SECRET_KEY", "env var holding the Stripe test secret key (when --acp --payment=stripe)")
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

	if *acpSeller {
		runACPSeller(ctx, acpSellerParams{
			name: *name, role: *role, addr: *addr, baseURL: baseURL, selfAns: selfAns,
			registryURL: *registryURL, currency: *acpCurrency, payment: *payment,
			stripeKeyEnv: *stripeKeyEnv, authorityRole: *authorityRole, authorityName: *authorityName,
			priv: priv, em: em, log: log, disco: disco,
		})
		return
	}

	if *ucpSeller {
		runUCPSeller(ctx, acpSellerParams{
			name: *name, role: *role, addr: *addr, baseURL: baseURL, selfAns: selfAns,
			registryURL: *registryURL, currency: *acpCurrency, payment: *payment,
			stripeKeyEnv: *stripeKeyEnv, authorityRole: *authorityRole, authorityName: *authorityName,
			priv: priv, em: em, log: log, disco: disco,
		})
		return
	}

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
		authPeer, authPub := resolveAuthority(ctx, disco, authclient.New(), *authorityRole, *authorityName, log)
		authorityAns := domain.LocalANSName(authPeer.Name)
		greetPolicy = policy.NewMandate(selfAns, authorityAns, authPub, *scope, log)
		card.Security = []map[string][]string{{"mandate": {}}}
		card.Capabilities = &a2a.Capabilities{Extensions: []a2a.Extension{{
			URI:         a2a.ExtMandateURI,
			Description: "present a mandate from the authority",
			Required:    true,
			Params:      map[string]any{"authorityRole": *authorityRole, "authorityAns": authorityAns, "scope": *scope},
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

		buyFn := func(greetID, toName string) (string, string, error) {
			gctx := events.WithScope(context.Background(), em, greetID, *name, events.RoleInitiator)
			peers, serr := disco.Search(gctx, "seller")
			if serr != nil {
				return "", "", fmt.Errorf("discover sellers: %w", serr)
			}
			var peer domain.AgentInfo
			found := false
			for _, pr := range peers {
				if pr.Name == toName {
					peer, found = pr, true
					break
				}
			}
			if !found {
				return "", "", fmt.Errorf("no seller named %q", toName)
			}
			card, cerr := res.FetchCard(gctx, peer.CardURL)
			if cerr != nil {
				return "", "", fmt.Errorf("read seller card: %w", cerr)
			}
			var result commerce.BuyResult
			var berr error
			switch {
			case hasExt(card, a2a.ExtACPURI):
				result, berr = acp.BuyPeer(gctx, http.DefaultClient, mcpCli, disco, selfAns, peer, card)
			case hasExt(card, a2a.ExtUCPURI):
				result, berr = ucp.BuyPeer(gctx, http.DefaultClient, mcpCli, disco, selfAns, peer, card)
			default:
				return "", "", fmt.Errorf("seller %q advertises no known commerce protocol", toName)
			}
			if berr != nil {
				return "", "", berr
			}
			return result.PaymentRef, result.Status, nil
		}
		trig.SetBuy(buyFn)
		mux.HandleFunc("POST /trigger/buy", trig.HandleBuy)
		log.Info().Msg("buy endpoint enabled (POST /trigger/buy)")
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

type acpSellerParams struct {
	name, role, addr, baseURL, selfAns, registryURL string
	currency, payment, stripeKeyEnv                 string
	authorityRole, authorityName                    string
	priv                                            ed25519.PrivateKey
	em                                              events.Emitter
	log                                             zerolog.Logger
	disco                                           *discovery.Client
}

// runACPSeller runs the agent as an ACP seller: it resolves and pins the authority
// that issues valid spend-mandates, builds a spend guard and a payment backend,
// serves the ACP endpoints, and registers as its role. It blocks until signalled.
func runACPSeller(ctx context.Context, p acpSellerParams) {
	authPeer, authPub := resolveAuthority(ctx, p.disco, authclient.New(), p.authorityRole, p.authorityName, p.log)
	authorityAns := domain.LocalANSName(authPeer.Name)
	guard := policy.NewSpend(p.selfAns, authorityAns, authPub, p.log)

	var pay commerce.PaymentPrimitive
	switch p.payment {
	case "fake":
		pay = commerce.FakePayment{}
		p.log.Info().Msg("ACP payment backend: fake (no network)")
	case "stripe":
		key := os.Getenv(p.stripeKeyEnv)
		if key == "" {
			p.log.Fatal().Str("env", p.stripeKeyEnv).Msg("ACP seller: Stripe secret key missing (fail closed)")
		}
		pay = commerce.StripePaymentIntent{Client: stripe.NewClient(key)}
		p.log.Info().Msg("ACP payment backend: stripe (test mode)")
	default:
		p.log.Fatal().Str("payment", p.payment).Msg("unknown --payment (want: stripe | fake)")
	}

	seller := acp.NewSeller(acp.SellerConfig{
		SelfAns: p.selfAns, AgentName: p.name, Currency: p.currency,
		Catalog: commerce.DefaultCatalog(p.currency), Guard: guard, Payment: pay,
		Events: p.em, Log: p.log,
	})

	card := a2a.Card{
		Name: p.name, Version: "0.1.0", Security: []map[string][]string{},
		Capabilities: &a2a.Capabilities{Extensions: []a2a.Extension{{
			URI:         a2a.ExtACPURI,
			Description: "buy over the Agentic Commerce Protocol; present a spend-mandate from the named authority",
			Required:    true,
			Params: map[string]any{
				"catalogPath": "/acp/catalog", "checkoutPath": "/acp/checkout_sessions",
				"authorityRole": p.authorityRole, "authorityAns": authorityAns, "currency": p.currency,
			},
		}}},
	}

	mux := http.NewServeMux()
	mux.Handle("/.well-known/agent-card.json", a2a.CardHandler(card, p.log))
	seller.Mount(mux)

	srv := &http.Server{Addr: p.addr, Handler: mux}
	go func() {
		p.log.Info().Str("addr", p.addr).Str("ans", p.selfAns).Msg("ACP seller listening")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			p.log.Fatal().Err(err).Msg("acp seller server exited")
		}
	}()

	info := domain.AgentInfo{Name: p.name, Role: p.role, BaseURL: p.baseURL, CardURL: p.baseURL + "/.well-known/agent-card.json"}
	for i := 0; i < 10; i++ {
		if err := p.disco.Register(ctx, info); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	p.log.Info().Msg("acp seller stopped")
}

// runUCPSeller runs the agent as a UCP seller: resolves+pins the authority, builds
// a UCP guard and a payment backend, uses its own identity key to sign checkout
// terms, serves the UCP endpoints, and registers as its role.
func runUCPSeller(ctx context.Context, p acpSellerParams) {
	authPeer, authPub := resolveAuthority(ctx, p.disco, authclient.New(), p.authorityRole, p.authorityName, p.log)
	authorityAns := domain.LocalANSName(authPeer.Name)
	guard := policy.NewUCP(p.selfAns, authorityAns, authPub, p.log)

	var pay commerce.PaymentPrimitive
	switch p.payment {
	case "fake":
		pay = commerce.FakePayment{}
		p.log.Info().Msg("UCP payment backend: fake (no network)")
	case "stripe":
		key := os.Getenv(p.stripeKeyEnv)
		if key == "" {
			p.log.Fatal().Str("env", p.stripeKeyEnv).Msg("UCP seller: Stripe secret key missing (fail closed)")
		}
		pay = commerce.StripePaymentIntent{Client: stripe.NewClient(key)}
		p.log.Info().Msg("UCP payment backend: stripe (test mode)")
	default:
		p.log.Fatal().Str("payment", p.payment).Msg("unknown --payment (want: stripe | fake)")
	}

	seller := ucp.NewSeller(ucp.SellerConfig{
		SelfAns: p.selfAns, AgentName: p.name, Currency: p.currency,
		Catalog: commerce.DefaultCatalog(p.currency), Guard: guard, Payment: pay,
		SignKey: p.priv, AuthorityRole: p.authorityRole, AuthorityAns: authorityAns,
		Events: p.em, Log: p.log,
	})

	card := a2a.Card{
		Name: p.name, Version: "0.1.0", Security: []map[string][]string{},
		Capabilities: &a2a.Capabilities{Extensions: []a2a.Extension{{
			URI:         a2a.ExtUCPURI,
			Description: "buy over the Universal Commerce Protocol; see /.well-known/ucp",
			Required:    true,
			Params:      map[string]any{"profilePath": "/.well-known/ucp", "authorityRole": p.authorityRole, "authorityAns": authorityAns, "currency": p.currency},
		}}},
	}

	mux := http.NewServeMux()
	mux.Handle("/.well-known/agent-card.json", a2a.CardHandler(card, p.log))
	seller.Mount(mux)

	srv := &http.Server{Addr: p.addr, Handler: mux}
	go func() {
		p.log.Info().Str("addr", p.addr).Str("ans", p.selfAns).Msg("UCP seller listening")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			p.log.Fatal().Err(err).Msg("ucp seller server exited")
		}
	}()

	info := domain.AgentInfo{Name: p.name, Role: p.role, BaseURL: p.baseURL, CardURL: p.baseURL + "/.well-known/agent-card.json"}
	for i := 0; i < 10; i++ {
		if err := p.disco.Register(ctx, info); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	p.log.Info().Msg("ucp seller stopped")
}

// hasExt reports whether card advertises the A2A capabilities extension uri.
func hasExt(card a2a.Card, uri string) bool {
	if card.Capabilities == nil {
		return false
	}
	for _, e := range card.Capabilities.Extensions {
		if e.URI == uri {
			return true
		}
	}
	return false
}

// resolveAuthority discovers the authority of the given role — optionally the one
// named `name` — and pins its public key, retrying to tolerate startup races. A
// mandate greeter cannot serve without a pinned authority key, so failure is
// fatal (fail closed).
func resolveAuthority(ctx context.Context, disco *discovery.Client, ac *authclient.Client, role, name string, log zerolog.Logger) (domain.AgentInfo, ed25519.PublicKey) {
	for i := 0; i < 20; i++ {
		peers, err := disco.Search(ctx, role)
		if err == nil && len(peers) > 0 {
			for _, p := range peers {
				if name != "" && p.Name != name {
					continue
				}
				pub, perr := ac.FetchPubKey(ctx, p.BaseURL)
				if perr == nil {
					log.Info().Str("authority", p.Name).Str("baseURL", p.BaseURL).Msg("pinned authority key")
					return p, pub
				}
				log.Warn().Err(perr).Str("authority", p.Name).Msg("fetch authority pubkey; retrying")
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	log.Fatal().Str("role", role).Str("name", name).Msg("could not resolve/pin the authority; a mandate greeter cannot start without it")
	return domain.AgentInfo{}, nil // unreachable
}
