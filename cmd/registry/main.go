// Command registry runs the agent-mesh discovery service.
package main

import (
	"flag"
	"net/http"
	"os"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/registry"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:18090", "listen address")
	flag.Parse()

	log := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()
	svc := registry.New(log)

	log.Info().Str("addr", *addr).Msg("registry listening")
	if err := http.ListenAndServe(*addr, svc.Handler()); err != nil {
		log.Fatal().Err(err).Msg("registry server exited")
	}
}
