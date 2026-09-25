// Command meshctl drives the mesh from the terminal. P1 subcommand: greet.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/discovery"
	"github.com/an-ciobanu/agent-mesh/internal/comms/resolver"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/greet"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: meshctl <command> [flags]")
		fmt.Fprintln(os.Stderr, "commands: greet")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "greet":
		runGreet(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		os.Exit(2)
	}
}

func runGreet(args []string) {
	fs := flag.NewFlagSet("greet", flag.ExitOnError)
	registryURL := fs.String("registry", "http://127.0.0.1:18090", "registry base URL")
	from := fs.String("from", "visitor", "initiator name (identity)")
	toRole := fs.String("to-role", "greeter", "role of the agent to greet")
	text := fs.String("text", "hello", "greeting text")
	keyDir := fs.String("keys", "", "identity key directory (default: ./data/<from>)")
	_ = fs.Parse(args)

	log := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()

	dir := *keyDir
	if dir == "" {
		dir = filepath.Join("data", *from)
	}
	priv, err := crypto.LoadOrCreateEd25519(filepath.Join(dir, "id_ed25519.seed"))
	if err != nil {
		log.Fatal().Err(err).Msg("load identity key")
	}
	callerAns := domain.LocalANSName(*from)

	reply, peer, err := greet.Initiate(
		context.Background(),
		discovery.New(*registryURL),
		resolver.New(),
		a2a.NewClient(),
		priv, callerAns, *toRole, *text,
	)
	if err != nil {
		log.Fatal().Err(err).Msg("greet failed")
	}
	log.Info().Str("peer", peer.Name).Str("callerAns", callerAns).Msg("greet sent")
	fmt.Printf("greeted %s (%s)\nreply: %s\n", peer.Name, peer.BaseURL, reply)
}
