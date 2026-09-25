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
	"github.com/an-ciobanu/agent-mesh/internal/comms/transparency"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/greet"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: meshctl <command> [flags]")
		fmt.Fprintln(os.Stderr, "commands: greet, tl-check")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "greet":
		runGreet(os.Args[2:])
	case "tl-check":
		runTLCheck(os.Args[2:])
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

func runTLCheck(args []string) {
	fs := flag.NewFlagSet("tl-check", flag.ExitOnError)
	tlURL := fs.String("transparency", "http://127.0.0.1:18091", "transparency log base URL")
	_ = fs.Parse(args)

	log := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()
	ctx := context.Background()

	// Sign a sample statement with an ephemeral issuer key and seal it.
	issuer, err := crypto.GenerateEd25519()
	if err != nil {
		log.Fatal().Err(err).Msg("generate issuer key")
	}
	statement, err := crypto.SignCOSE1(issuer, []byte(`{"type":"tl-check","note":"meshctl self-test"}`))
	if err != nil {
		log.Fatal().Err(err).Msg("sign statement")
	}

	tc := transparency.New(*tlURL)
	rec, err := tc.Seal(ctx, statement)
	if err != nil {
		log.Fatal().Err(err).Msg("seal statement")
	}
	tlPub, err := tc.FetchPubKey(ctx)
	if err != nil {
		log.Fatal().Err(err).Msg("fetch TL pubkey")
	}

	// Verify the receipt is TL-signed and the inclusion proof holds.
	_, signer, err := crypto.VerifyCOSE1(rec.COSE)
	if err != nil {
		log.Fatal().Err(err).Msg("verify receipt cose")
	}
	if !signer.Equal(tlPub) {
		log.Fatal().Msg("receipt not signed by the TL key")
	}
	if !crypto.VerifyInclusion(crypto.LeafHash(statement), rec.EntryIndex, rec.TreeSize, rec.Proof, rec.Root) {
		log.Fatal().Msg("inclusion proof failed to verify")
	}

	fmt.Printf("sealed entry %d of %d; receipt TL-signed and inclusion proof verified OK\n", rec.EntryIndex, rec.TreeSize)
}
