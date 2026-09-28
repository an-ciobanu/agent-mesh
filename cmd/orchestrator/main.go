// Command orchestrator runs the P5 demo: it spawns the mesh (registry,
// transparency log, authority, and a roster of event-emitting agents), captures
// their event streams, and serves a browser UI that turns canvas collisions into
// real agent-to-agent greets rendered from the agents' own events.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/orchestrator"
)

func main() {
	uiAddr := flag.String("addr", "127.0.0.1:18080", "UI listen address")
	binDir := flag.String("bin", "bin", "directory containing the built binaries")
	webDir := flag.String("web", "web", "directory containing index.html")
	registryAddr := flag.String("registry", "127.0.0.1:18090", "registry listen address")
	tlAddr := flag.String("transparency", "127.0.0.1:18091", "transparency log listen address")
	stripeEnvPath := flag.String("stripe-env", "data/stripe.env", "path to KEY=VALUE file with STRIPE_SECRET_KEY for ACP sellers")
	flag.Parse()

	log := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Str("component", "orchestrator").Logger()

	roster := orchestrator.DefaultRoster()
	book := orchestrator.NewAgentBook(roster, 18300)
	hub := orchestrator.NewHub(log)
	driver := orchestrator.NewDriver(book)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sup := orchestrator.NewSupervisor(*binDir, *registryAddr, *tlAddr, roster, hub, log)
	if env := orchestrator.LoadStripeEnv(*stripeEnvPath); len(env) > 0 {
		var kv []string
		for k, v := range env {
			kv = append(kv, k+"="+v)
		}
		sup.WithChildEnv(kv)
		log.Info().Str("path", *stripeEnvPath).Msg("loaded Stripe env for ACP sellers")
	} else {
		log.Warn().Str("path", *stripeEnvPath).Msg("no Stripe env found; ACP sellers will fail to start (add data/stripe.env)")
	}
	if err := sup.Start(ctx); err != nil {
		log.Fatal().Err(err).Msg("start mesh")
	}
	defer sup.Stop()

	// Reveal an initial handful of the fixed dynamic pool so the mesh opens with a
	// few extra greeters already running and registered.
	const initialExtra = 5
	for i := 0; i < initialExtra; i++ {
		a, ok := book.NextAgent()
		if !ok {
			break
		}
		if err := sup.SpawnOne(a); err != nil {
			log.Warn().Err(err).Str("agent", a.Name).Msg("initial spawn failed")
			break
		}
		book.Add(a)
		log.Info().Str("agent", a.Name).Str("policy", a.Policy).Msg("spawned initial dynamic agent")
	}

	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServer(http.Dir(*webDir)))
	mux.HandleFunc("GET /config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int{"baseCount": book.BaseCount(), "poolMax": book.PoolMax()})
	})
	mux.HandleFunc("GET /agents", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(book.List())
	})
	mux.HandleFunc("GET /events", hub.ServeSSE)
	mux.HandleFunc("POST /collide", func(w http.ResponseWriter, r *http.Request) {
		var body struct{ From, To string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		greetID, err := driver.Collide(r.Context(), body.From, body.To)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		from, _ := roster.ByName(body.From)
		to, _ := roster.ByName(body.To)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"greetId": greetID, "from": from.Name, "to": to.Name, "type": to.Type,
		})
	})
	mux.HandleFunc("POST /spawn", func(w http.ResponseWriter, r *http.Request) {
		a, ok := book.NextAgent()
		w.Header().Set("Content-Type", "application/json")
		if !ok {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "no more agents available"})
			return
		}
		if err := sup.SpawnOne(a); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		book.Add(a)
		log.Info().Str("agent", a.Name).Str("policy", a.Policy).Msg("spawned dynamic agent")
		_ = json.NewEncoder(w).Encode(a)
	})
	mux.HandleFunc("POST /despawn", func(w http.ResponseWriter, r *http.Request) {
		a, ok := book.RemoveLast()
		w.Header().Set("Content-Type", "application/json")
		if !ok {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "no dynamic agents to remove"})
			return
		}
		sup.Kill(a.Name)
		log.Info().Str("agent", a.Name).Msg("despawned dynamic agent")
		_ = json.NewEncoder(w).Encode(map[string]string{"removed": a.Name})
	})

	srv := &http.Server{Addr: *uiAddr, Handler: mux}
	go func() {
		log.Info().Str("addr", *uiAddr).Msg("orchestrator UI listening — open http://" + *uiAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("ui server exited")
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Info().Msg("shutting down mesh")
	shutdownCtx, c := context.WithTimeout(context.Background(), 3*time.Second)
	defer c()
	_ = srv.Shutdown(shutdownCtx)
	cancel()
	sup.Stop()
}
