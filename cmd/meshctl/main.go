// Command meshctl drives the mesh from the terminal. P1 subcommand: greet.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/audit"
	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/discovery"
	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
	"github.com/an-ciobanu/agent-mesh/internal/comms/resolver"
	"github.com/an-ciobanu/agent-mesh/internal/comms/transparency"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/greet"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: meshctl <command> [flags]")
		fmt.Fprintln(os.Stderr, "commands: greet, tl-check, mandate-check")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "greet":
		runGreet(os.Args[2:])
	case "tl-check":
		runTLCheck(os.Args[2:])
	case "mandate-check":
		runMandateCheck(os.Args[2:])
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
	tlURL := fs.String("transparency", "http://127.0.0.1:18091", "transparency log base URL (for --audit)")
	doAudit := fs.Bool("audit", false, "independently audit the greeter's sealed evidence")
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
	ctx := context.Background()

	reply, evidence, peer, err := greet.Initiate(
		ctx,
		discovery.New(*registryURL),
		resolver.New(),
		a2a.NewClient(),
		priv, callerAns, *toRole, *text,
	)
	if err != nil {
		log.Fatal().Err(err).Msg("greet failed")
	}
	fmt.Printf("greeted %s (%s)\nreply: %s\n", peer.Name, peer.BaseURL, reply)
	if evidence != nil {
		fmt.Printf("sealed: entry %d of %d\n", evidence.Receipt.EntryIndex, evidence.Receipt.TreeSize)
	}

	if *doAudit {
		if evidence == nil {
			log.Fatal().Msg("--audit requested but the greeter returned no evidence (run the agent with --transparency)")
		}
		tlPub, err := transparency.New(*tlURL).FetchPubKey(ctx)
		if err != nil {
			log.Fatal().Err(err).Msg("fetch transparency-log pubkey")
		}
		auditorPriv, err := crypto.GenerateEd25519()
		if err != nil {
			log.Fatal().Err(err).Msg("generate auditor key")
		}
		verdict, _, err := audit.New(domain.LocalANSName("auditor"), auditorPriv, log).Verify(ctx, *evidence, tlPub)
		if err != nil {
			log.Fatal().Err(err).Msg("audit")
		}
		fmt.Printf("audit verdict: %s\n", verdict.Verdict)
		for _, c := range verdict.Checks {
			fmt.Printf("  - %s\n", c)
		}
	}
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

func runMandateCheck(args []string) {
	fs := flag.NewFlagSet("mandate-check", flag.ExitOnError)
	registryURL := fs.String("registry", "http://127.0.0.1:18090", "registry base URL")
	subject := fs.String("subject", "visitor", "subject name")
	audience := fs.String("audience", "greeter-mandate", "audience name")
	scope := fs.String("scope", "greet", "requested scope")
	_ = fs.Parse(args)

	log := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()
	ctx := context.Background()

	peers, err := discovery.New(*registryURL).Search(ctx, "authority")
	if err != nil {
		log.Fatal().Err(err).Msg("discover authority")
	}
	if len(peers) == 0 {
		log.Fatal().Msg("no authority registered")
	}
	authURL := peers[0].BaseURL + "/mcp"

	raw, err := mcp.NewClient().Call(ctx, authURL, "issue_mandate", map[string]string{
		"subjectAns":  domain.LocalANSName(*subject),
		"audienceAns": domain.LocalANSName(*audience),
		"scope":       *scope,
	})
	if err != nil {
		log.Fatal().Err(err).Msg("issue_mandate")
	}
	var res struct {
		MandateCOSE []byte `json:"mandateCose"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		log.Fatal().Err(err).Msg("parse issue_mandate result")
	}

	payload, authPub, err := crypto.VerifyCOSE1(res.MandateCOSE)
	if err != nil {
		log.Fatal().Err(err).Msg("verify mandate")
	}
	var claims domain.MandateClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		log.Fatal().Err(err).Msg("parse mandate claims")
	}

	fmt.Printf("mandate %s: subject=%s audience=%s scope=%s (valid %s..%s)\n",
		claims.MandateID, claims.SubjectAns, claims.AudienceAns, claims.Scope, claims.NotBefore, claims.NotAfter)
	fmt.Printf("signed by authority %s (key %s)\n", claims.AuthorityAns, crypto.Thumbprint(crypto.PublicJWK(authPub)))
	fmt.Println("mandate issued and verified OK")
}
