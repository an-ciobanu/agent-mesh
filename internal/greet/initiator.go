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
) (string, *domain.EvidenceBundle, []domain.EvidenceBundle, domain.AgentInfo, error) {
	events.Emit(ctx, "discover", events.StatusInfo, map[string]string{"role": toRole})
	peers, err := disco.Search(ctx, toRole)
	if err != nil {
		return "", nil, nil, domain.AgentInfo{}, fmt.Errorf("discover role %q: %w", toRole, err)
	}
	if len(peers) == 0 {
		return "", nil, nil, domain.AgentInfo{}, fmt.Errorf("no agents found for role %q", toRole)
	}
	peer := peers[0]
	reply, evidence, mandateEv, err := GreetPeer(ctx, res, cli, mcpCli, disco, priv, callerAns, peer, greeting)
	return reply, evidence, mandateEv, peer, err
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
) (string, *domain.EvidenceBundle, []domain.EvidenceBundle, error) {
	card, err := res.FetchCard(ctx, peer.CardURL)
	if err != nil {
		return "", nil, nil, fmt.Errorf("resolve peer card: %w", err)
	}
	events.Emit(ctx, "card.read", events.StatusOK, map[string]string{"peer": peer.Name, "url": card.URL})

	audienceAns := domain.LocalANSName(peer.Name)
	greetID := events.GreetIDFromContext(ctx)
	opts := []a2a.SendOption{a2a.WithGreetID(greetID)}
	var mandateEv []domain.EvidenceBundle

	if ext, ok := mandateExtension(card); ok {
		events.Emit(ctx, "requirement", events.StatusInfo, map[string]string{"type": "mandate"})
		if disco == nil {
			return "", nil, nil, fmt.Errorf("peer %q requires a mandate but no discovery is available", peer.Name)
		}
		mandate, authName, ev, merr := acquireMandate(ctx, disco, mcpCli, ext, callerAns, audienceAns)
		if merr != nil {
			events.Emit(ctx, "mandate.acquire", events.StatusFail, map[string]string{"error": merr.Error(), "authority": authName})
			return "", nil, nil, merr
		}
		events.Emit(ctx, "mandate.acquire", events.StatusOK, map[string]string{
			"authority": authName,
			"scope":     stringParam(ext.Params, "scope", "greet"),
			"audience":  audienceAns,
			"tool":      "issue_mandate (MCP)",
		})
		if ev != nil {
			mandateEv = append(mandateEv, *ev)
		}
		opts = append(opts, a2a.WithMandate(mandate))
	} else if _, ok := nonceExtension(card); ok {
		events.Emit(ctx, "requirement", events.StatusInfo, map[string]string{"type": "nonce"})
		proof, nerr := acquireDPoPProof(ctx, mcpCli, peer.BaseURL, card.URL)
		if nerr != nil {
			events.Emit(ctx, "dpop.build", events.StatusFail, map[string]string{"error": nerr.Error()})
			return "", nil, nil, nerr
		}
		events.Emit(ctx, "dpop.build", events.StatusOK, map[string]string{"alg": "ES256", "htm": "POST", "htu": card.URL})
		opts = append(opts, a2a.WithDPoP(proof))
	} else if len(card.Security) != 0 {
		return "", nil, nil, fmt.Errorf("peer %q requires unsupported authentication", peer.Name)
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
		return "", nil, nil, err
	}
	events.Emit(ctx, "greet.reply", events.StatusOK, map[string]string{"reply": reply})
	return reply, evidence, mandateEv, nil
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

// selectAuthority picks the authority a caller must use from those discovered by
// role. When authorityAns is set (the card named a specific authority), it
// returns the peer whose ANS matches — fail closed if none does. When it is
// empty (single-authority / back-compat), it returns the first peer.
func selectAuthority(peers []domain.AgentInfo, authorityAns string) (domain.AgentInfo, bool) {
	if len(peers) == 0 {
		return domain.AgentInfo{}, false
	}
	if authorityAns == "" {
		return peers[0], true
	}
	for _, p := range peers {
		if domain.LocalANSName(p.Name) == authorityAns {
			return p, true
		}
	}
	return domain.AgentInfo{}, false
}

// acquireMandate discovers the authority named by the extension and obtains a
// mandate for callerAns->audienceAns via the authority's issue_mandate MCP tool.
// It returns the chosen authority's name and the authority-sealed issuance
// evidence (nil if the authority did not seal) alongside the mandate so callers
// can report which authority was used and audit that the issuance was logged.
func acquireMandate(ctx context.Context, disco domain.Discovery, mcpCli *mcp.Client, ext a2a.Extension, callerAns, audienceAns string) ([]byte, string, *domain.EvidenceBundle, error) {
	authorityRole := stringParam(ext.Params, "authorityRole", "authority")
	authorityAns := stringParam(ext.Params, "authorityAns", "")
	scope := stringParam(ext.Params, "scope", "greet")

	authorities, err := disco.Search(ctx, authorityRole)
	if err != nil {
		return nil, "", nil, fmt.Errorf("discover authority role %q: %w", authorityRole, err)
	}
	authority, ok := selectAuthority(authorities, authorityAns)
	if !ok {
		return nil, "", nil, fmt.Errorf("no authority %q found under role %q", authorityAns, authorityRole)
	}
	authURL := authority.BaseURL + "/mcp"

	events.Emit(ctx, "authority.resolve", events.StatusOK, map[string]string{"authority": authority.Name, "role": authorityRole})
	events.Emit(ctx, "mandate.request", events.StatusInfo, map[string]string{"authority": authority.Name, "tool": "issue_mandate", "endpoint": authURL, "scope": scope})

	raw, err := mcpCli.Call(ctx, authURL, "issue_mandate", map[string]string{
		"subjectAns":  callerAns,
		"audienceAns": audienceAns,
		"scope":       scope,
	})
	if err != nil {
		return nil, authority.Name, nil, fmt.Errorf("issue_mandate: %w", err)
	}
	var out struct {
		MandateCOSE []byte                 `json:"mandateCose"`
		Evidence    *domain.EvidenceBundle `json:"evidence"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, authority.Name, nil, fmt.Errorf("parse issue_mandate result: %w", err)
	}
	if len(out.MandateCOSE) == 0 {
		return nil, authority.Name, nil, fmt.Errorf("authority returned an empty mandate")
	}
	return out.MandateCOSE, authority.Name, out.Evidence, nil
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
