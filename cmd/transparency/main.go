// Command transparency runs the agent-mesh transparency log.
package main

import (
	"flag"
	"net/http"
	"os"
	"path/filepath"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/tl"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:18091", "listen address")
	keyDir := flag.String("keys", "data/transparency", "directory for the TL signing key")
	flag.Parse()

	log := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()

	priv, err := crypto.LoadOrCreateEd25519(filepath.Join(*keyDir, "id_ed25519.seed"))
	if err != nil {
		log.Fatal().Err(err).Msg("load transparency key")
	}
	svc := tl.NewService(priv, log)

	log.Info().Str("addr", *addr).Msg("transparency log listening")
	if err := http.ListenAndServe(*addr, svc.Handler()); err != nil {
		log.Fatal().Err(err).Msg("transparency server exited")
	}
}
