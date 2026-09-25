// Package greet drives an initiator: discover a peer, resolve how to call it,
// satisfy any mandate requirement its card advertises, and send an
// identity-signed greet.
package greet

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
	"github.com/an-ciobanu/agent-mesh/internal/comms/resolver"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/events"
)

// Initiate finds a peer of role toRole, reads its Agent Card to learn how to
// call it, satisfies any mandate requirement the card advertises (by discovering
// the authority the card points to and obtaining a mandate over MCP), and sends
// an identity-signed greet. It returns the reply, any transparency evidence the
// peer sealed (nil if none), and the peer it greeted. Nothing about the peer or
// the authority is hardcoded: the requirement is discovered from the card.
func Initiate(
	ctx context.Context,
	disco domain.Discovery,
	res *resolver.Resolver,
	cli *a2a.Client,
	mcpCli *mcp.Client,
	priv ed25519.PrivateKey,
	callerAns, toRole, greeting string,
) (string, *domain.EvidenceBundle, domain.AgentInfo, error) {
	events.Emit(ctx, "discover", events.StatusInfo, map[string]string{"role": toRole})
	peers, err := disco.Search(ctx, toRole)
	if err != nil {
		return "", nil, domain.AgentInfo{}, fmt.Errorf("discover role %q: %w", toRole, err)
	}
	if len(peers) == 0 {
		return "", nil, domain.AgentInfo{}, fmt.Errorf("no agents found for role %q", toRole)
	}
	peer := peers[0]
	reply, evidence, err := GreetPeer(ctx, res, cli, mcpCli, disco, priv, callerAns, peer, greeting)
	return reply, evidence, peer, err
}

// GreetPeer greets a specific, already-discovered peer: read its card, satisfy
// whatever requirement the card advertises (mandate or DPoP nonce), and send an
// identity-signed greet. disco is used only to discover a mandate authority and
// may be nil for open/nonce peers. Steps are emitted through ctx (no-op if no
// scope). Nothing about the peer or authority is hardcoded.
func GreetPeer(
	ctx context.Context,
	res *resolver.Resolver,
	cli *a2a.Client,
	mcpCli *mcp.Client,
	disco domain.Discovery,
	priv ed25519.PrivateKey,
	callerAns string,
	peer domain.AgentInfo,
	greeting string,
) (string, *domain.EvidenceBundle, error) {
	card, err := res.FetchCard(ctx, peer.CardURL)
	if err != nil {
		return "", nil, fmt.Errorf("resolve peer card: %w", err)
	}
	events.Emit(ctx, "card.read", events.StatusOK, map[string]string{"peer": peer.Name, "url": card.URL})

	audienceAns := domain.LocalANSName(peer.Name)
	greetID := events.GreetIDFromContext(ctx)
	opts := []a2a.SendOption{a2a.WithGreetID(greetID)}

	if ext, ok := mandateExtension(card); ok {
		events.Emit(ctx, "requirement", events.StatusInfo, map[string]string{"type": "mandate"})
		if disco == nil {
			return "", nil, fmt.Errorf("peer %q requires a mandate but no discovery is available", peer.Name)
		}
		mandate, merr := acquireMandate(ctx, disco, mcpCli, ext, callerAns, audienceAns)
		if merr != nil {
			events.Emit(ctx, "mandate.acquire", events.StatusFail, map[string]string{"error": merr.Error()})
			return "", nil, merr
		}
		events.Emit(ctx, "mandate.acquire", events.StatusOK, map[string]string{
			"authority": stringParam(ext.Params, "authorityRole", "authority"),
			"scope":     stringParam(ext.Params, "scope", "greet"),
			"audience":  audienceAns,
			"tool":      "issue_mandate (MCP)",
		})
		opts = append(opts, a2a.WithMandate(mandate))
	} else if _, ok := nonceExtension(card); ok {
		events.Emit(ctx, "requirement", events.StatusInfo, map[string]string{"type": "nonce"})
		proof, nerr := acquireDPoPProof(ctx, mcpCli, peer.BaseURL, card.URL)
		if nerr != nil {
			events.Emit(ctx, "dpop.build", events.StatusFail, map[string]string{"error": nerr.Error()})
			return "", nil, nerr
		}
		events.Emit(ctx, "dpop.build", events.StatusOK, map[string]string{"alg": "ES256", "htm": "POST", "htu": card.URL})
		opts = append(opts, a2a.WithDPoP(proof))
	} else if len(card.Security) != 0 {
		return "", nil, fmt.Errorf("peer %q requires unsupported authentication", peer.Name)
	} else {
		events.Emit(ctx, "requirement", events.StatusInfo, map[string]string{"type": "open"})
	}

	events.Emit(ctx, "greet.send", events.StatusInfo, map[string]string{"to": peer.Name})
	reply, evidence, err := cli.SendGreet(ctx, card.URL, priv, a2a.GreetPayload{
		CallerAns:   callerAns,
		AudienceAns: audienceAns,
		Greeting:    greeting,
	}, opts...)
	if err != nil {
		events.Emit(ctx, "greet.rejected", events.StatusFail, map[string]string{"error": err.Error()})
		return "", nil, err
	}
	events.Emit(ctx, "greet.reply", events.StatusOK, map[string]string{"reply": reply})
	return reply, evidence, nil
}

// mandateExtension returns the mandate-required extension if the card advertises it.
func mandateExtension(card a2a.Card) (a2a.Extension, bool) {
	if card.Capabilities == nil {
		return a2a.Extension{}, false
	}
	for _, e := range card.Capabilities.Extensions {
		if e.URI == a2a.ExtMandateURI {
			return e, true
		}
	}
	return a2a.Extension{}, false
}

// acquireMandate discovers the authority named by the extension and obtains a
// mandate for callerAns->audienceAns via the authority's issue_mandate MCP tool.
func acquireMandate(ctx context.Context, disco domain.Discovery, mcpCli *mcp.Client, ext a2a.Extension, callerAns, audienceAns string) ([]byte, error) {
	authorityRole := stringParam(ext.Params, "authorityRole", "authority")
	scope := stringParam(ext.Params, "scope", "greet")

	authorities, err := disco.Search(ctx, authorityRole)
	if err != nil {
		return nil, fmt.Errorf("discover authority role %q: %w", authorityRole, err)
	}
	if len(authorities) == 0 {
		return nil, fmt.Errorf("no authority found for role %q", authorityRole)
	}
	authURL := authorities[0].BaseURL + "/mcp"

	raw, err := mcpCli.Call(ctx, authURL, "issue_mandate", map[string]string{
		"subjectAns":  callerAns,
		"audienceAns": audienceAns,
		"scope":       scope,
	})
	if err != nil {
		return nil, fmt.Errorf("issue_mandate: %w", err)
	}
	var out struct {
		MandateCOSE []byte `json:"mandateCose"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("parse issue_mandate result: %w", err)
	}
	if len(out.MandateCOSE) == 0 {
		return nil, fmt.Errorf("authority returned an empty mandate")
	}
	return out.MandateCOSE, nil
}

// nonceExtension returns the DPoP-nonce extension if the card advertises it.
func nonceExtension(card a2a.Card) (a2a.Extension, bool) {
	if card.Capabilities == nil {
		return a2a.Extension{}, false
	}
	for _, e := range card.Capabilities.Extensions {
		if e.URI == a2a.ExtNonceURI {
			return e, true
		}
	}
	return a2a.Extension{}, false
}

// acquireDPoPProof fetches a fresh nonce from the greeter's get_nonce MCP tool
// and returns a per-session DPoP proof (P-256/ES256) over it, bound to htu.
func acquireDPoPProof(ctx context.Context, mcpCli *mcp.Client, peerBaseURL, htu string) (string, error) {
	raw, err := mcpCli.Call(ctx, peerBaseURL+"/mcp", "get_nonce", map[string]string{})
	if err != nil {
		return "", fmt.Errorf("get_nonce: %w", err)
	}
	var out struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("parse get_nonce result: %w", err)
	}
	if out.Nonce == "" {
		return "", fmt.Errorf("greeter returned an empty nonce")
	}
	events.Emit(ctx, "nonce.get", events.StatusOK, map[string]string{"nonce": out.Nonce, "tool": "get_nonce (MCP)", "use": "single-use"})
	key, err := crypto.GenerateDPoPKey()
	if err != nil {
		return "", fmt.Errorf("generate dpop key: %w", err)
	}
	proof, err := crypto.CreateDPoPProof(key, crypto.DPoPClaims{
		HTM:   "POST",
		HTU:   htu,
		IAT:   time.Now().Unix(),
		JTI:   randID(),
		Nonce: out.Nonce,
	})
	if err != nil {
		return "", fmt.Errorf("create dpop proof: %w", err)
	}
	return proof, nil
}

func randID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// stringParam reads a string extension param, falling back to def.
func stringParam(params map[string]any, key, def string) string {
	if params != nil {
		if v, ok := params[key].(string); ok && v != "" {
			return v
		}
	}
	return def
}
