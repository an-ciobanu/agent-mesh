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
	flag.Parse()

	log := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Str("component", "orchestrator").Logger()

	roster := orchestrator.DefaultRoster()
	hub := orchestrator.NewHub(log)
	driver := orchestrator.NewDriver(roster)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sup := orchestrator.NewSupervisor(*binDir, *registryAddr, *tlAddr, roster, hub, log)
	if err := sup.Start(ctx); err != nil {
		log.Fatal().Err(err).Msg("start mesh")
	}
	defer sup.Stop()

	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServer(http.Dir(*webDir)))
	mux.HandleFunc("GET /agents", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(roster.Agents)
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
