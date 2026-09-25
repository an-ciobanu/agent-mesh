package acp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/events"
)

// BuyResult is what a completed purchase returns to the caller.
type BuyResult struct {
	PaymentRef string
	Status     string
	ItemID     string
}

// BuyPeer drives a full ACP purchase against an already-discovered seller peer
// whose card advertises the ACP extension: fetch catalog, pick the cheapest item,
// acquire a spend-mandate from the named authority (over MCP), then create and
// complete a checkout session. Nothing about the seller or authority is hardcoded;
// everything is read from the card. Steps are emitted through ctx (no-op if no
// scope). disco is used only to discover the authority.
func BuyPeer(ctx context.Context, httpc *http.Client, mcpCli *mcp.Client, disco domain.Discovery, callerAns string, peer domain.AgentInfo, card a2a.Card) (BuyResult, error) {
	ext, ok := acpExtension(card)
	if !ok {
		return BuyResult{}, fmt.Errorf("peer %q does not advertise ACP", peer.Name)
	}
	events.Emit(ctx, "requirement", events.StatusInfo, map[string]string{"type": "acp"})
	events.Emit(ctx, "card.read", events.StatusOK, map[string]string{"peer": peer.Name, "url": card.URL})

	catalogPath := strParam(ext.Params, "catalogPath", "/acp/catalog")
	checkoutPath := strParam(ext.Params, "checkoutPath", "/acp/checkout_sessions")
	authorityRole := strParam(ext.Params, "authorityRole", "authority")
	authorityAns := strParam(ext.Params, "authorityAns", "")
	greetID := events.GreetIDFromContext(ctx)

	items, err := fetchCatalog(ctx, httpc, greetID, peer.BaseURL+catalogPath)
	if err != nil {
		return BuyResult{}, err
	}
	events.Emit(ctx, "catalog.fetch", events.StatusOK, map[string]string{"items": strconv.Itoa(len(items))})
	item, ok := LowestPriced(items)
	if !ok {
		return BuyResult{}, fmt.Errorf("seller %q has an empty catalog", peer.Name)
	}
	events.Emit(ctx, "item.select", events.StatusOK, map[string]string{
		"item": item.ID, "amount": strconv.FormatInt(item.Amount, 10), "currency": item.Currency,
	})

	audienceAns := domain.LocalANSName(peer.Name)
	auth, ok, err := pickAuthority(ctx, disco, authorityRole, authorityAns)
	if err != nil {
		return BuyResult{}, err
	}
	if !ok {
		return BuyResult{}, fmt.Errorf("no authority %q under role %q", authorityAns, authorityRole)
	}
	mandate, err := acquireSpendMandate(ctx, mcpCli, auth.BaseURL+"/mcp", callerAns, audienceAns, item)
	if err != nil {
		events.Emit(ctx, "spend.acquire", events.StatusFail, map[string]string{"error": err.Error(), "authority": auth.Name})
		return BuyResult{}, err
	}
	events.Emit(ctx, "spend.acquire", events.StatusOK, map[string]string{
		"authority": auth.Name, "item": item.ID, "maxAmount": strconv.FormatInt(item.Amount, 10), "currency": item.Currency, "tool": "issue_spend_mandate (MCP)",
	})

	sessionID, amount, err := createSession(ctx, httpc, greetID, peer.BaseURL+checkoutPath, item.ID)
	if err != nil {
		return BuyResult{}, err
	}
	events.Emit(ctx, "checkout.create", events.StatusOK, map[string]string{"sessionId": sessionID, "amount": strconv.FormatInt(amount, 10)})

	events.Emit(ctx, "checkout.complete", events.StatusInfo, map[string]string{"sessionId": sessionID})
	res, err := completeSession(ctx, httpc, greetID, peer.BaseURL+checkoutPath+"/"+sessionID+"/complete", callerAns, mandate)
	if err != nil {
		events.Emit(ctx, "purchase.rejected", events.StatusFail, map[string]string{"error": err.Error()})
		return BuyResult{}, err
	}
	events.Emit(ctx, "receipt", events.StatusOK, map[string]string{"paymentRef": res.PaymentRef, "status": res.Status, "provider": res.Provider})
	return BuyResult{PaymentRef: res.PaymentRef, Status: res.Status, ItemID: item.ID}, nil
}

func acpExtension(card a2a.Card) (a2a.Extension, bool) {
	if card.Capabilities == nil {
		return a2a.Extension{}, false
	}
	for _, e := range card.Capabilities.Extensions {
		if e.URI == a2a.ExtACPURI {
			return e, true
		}
	}
	return a2a.Extension{}, false
}

func pickAuthority(ctx context.Context, disco domain.Discovery, role, wantAns string) (domain.AgentInfo, bool, error) {
	peers, err := disco.Search(ctx, role)
	if err != nil {
		return domain.AgentInfo{}, false, fmt.Errorf("discover authority role %q: %w", role, err)
	}
	if len(peers) == 0 {
		return domain.AgentInfo{}, false, nil
	}
	if wantAns == "" {
		return peers[0], true, nil
	}
	for _, p := range peers {
		if domain.LocalANSName(p.Name) == wantAns {
			return p, true, nil
		}
	}
	return domain.AgentInfo{}, false, nil
}

func acquireSpendMandate(ctx context.Context, mcpCli *mcp.Client, authURL, subjectAns, audienceAns string, item Item) ([]byte, error) {
	raw, err := mcpCli.Call(ctx, authURL, "issue_spend_mandate", map[string]any{
		"subjectAns": subjectAns, "audienceAns": audienceAns,
		"itemId": item.ID, "maxAmount": item.Amount, "currency": item.Currency,
	})
	if err != nil {
		return nil, fmt.Errorf("issue_spend_mandate: %w", err)
	}
	var out struct {
		MandateCOSE []byte `json:"mandateCose"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("parse issue_spend_mandate: %w", err)
	}
	if len(out.MandateCOSE) == 0 {
		return nil, fmt.Errorf("authority returned an empty spend mandate")
	}
	return out.MandateCOSE, nil
}

func fetchCatalog(ctx context.Context, httpc *http.Client, greetID, url string) ([]Item, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	setGreet(req, greetID)
	resp, err := httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch catalog: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("catalog: status %d", resp.StatusCode)
	}
	var out struct {
		Items []Item `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode catalog: %w", err)
	}
	return out.Items, nil
}

func createSession(ctx context.Context, httpc *http.Client, greetID, url, itemID string) (string, int64, error) {
	body, _ := json.Marshal(map[string]string{"itemId": itemID})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	setGreet(req, greetID)
	resp, err := httpc.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("create session: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("create session: status %d", resp.StatusCode)
	}
	var out struct {
		SessionID string `json:"sessionId"`
		Amount    int64  `json:"amount"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", 0, fmt.Errorf("decode session: %w", err)
	}
	if out.SessionID == "" {
		return "", 0, fmt.Errorf("seller returned no session id")
	}
	return out.SessionID, out.Amount, nil
}

type completeResult struct {
	Provider   string `json:"provider"`
	PaymentRef string `json:"paymentRef"`
	Status     string `json:"status"`
}

func completeSession(ctx context.Context, httpc *http.Client, greetID, url, callerAns string, mandate []byte) (completeResult, error) {
	body, _ := json.Marshal(map[string]any{"callerAns": callerAns, "spendMandate": mandate})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	setGreet(req, greetID)
	resp, err := httpc.Do(req)
	if err != nil {
		return completeResult{}, fmt.Errorf("complete: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if e.Error != "" {
			return completeResult{}, fmt.Errorf("%s", e.Error)
		}
		return completeResult{}, fmt.Errorf("complete: status %d", resp.StatusCode)
	}
	var out completeResult
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return completeResult{}, fmt.Errorf("decode receipt: %w", err)
	}
	return out, nil
}

func setGreet(req *http.Request, greetID string) {
	if greetID != "" {
		req.Header.Set(HeaderGreetID, greetID)
	}
}

func strParam(params map[string]any, key, def string) string {
	if params != nil {
		if v, ok := params[key].(string); ok && v != "" {
			return v
		}
	}
	return def
}
