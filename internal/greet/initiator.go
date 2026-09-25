// Package greet drives an initiator: discover a peer, resolve how to call it,
// and send an identity-signed greet.
package greet

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/resolver"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

// Initiate finds a peer of role toRole, verifies it is open (declares no
// security), and sends it an identity-signed greet. It returns the reply, any
// transparency evidence the peer sealed (nil if none), and the peer it greeted.
func Initiate(
	ctx context.Context,
	disco domain.Discovery,
	res *resolver.Resolver,
	cli *a2a.Client,
	priv ed25519.PrivateKey,
	callerAns, toRole, greeting string,
) (string, *domain.EvidenceBundle, domain.AgentInfo, error) {
	peers, err := disco.Search(ctx, toRole)
	if err != nil {
		return "", nil, domain.AgentInfo{}, fmt.Errorf("discover role %q: %w", toRole, err)
	}
	if len(peers) == 0 {
		return "", nil, domain.AgentInfo{}, fmt.Errorf("no agents found for role %q", toRole)
	}
	peer := peers[0]

	card, err := res.FetchCard(ctx, peer.CardURL)
	if err != nil {
		return "", nil, peer, fmt.Errorf("resolve peer card: %w", err)
	}
	if len(card.Security) != 0 {
		return "", nil, peer, fmt.Errorf("peer %q requires authentication not supported in P1", peer.Name)
	}

	reply, evidence, err := cli.SendGreet(ctx, card.URL, priv, a2a.GreetPayload{
		CallerAns:   callerAns,
		AudienceAns: domain.LocalANSName(peer.Name),
		Greeting:    greeting,
	})
	if err != nil {
		return "", nil, peer, err
	}
	return reply, evidence, peer, nil
}
