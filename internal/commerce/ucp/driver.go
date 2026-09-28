package ucp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/an-ciobanu/agent-mesh/internal/commerce"
	"github.com/an-ciobanu/agent-mesh/internal/comms/a2a"
	"github.com/an-ciobanu/agent-mesh/internal/comms/mcp"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/events"
)

type ucpProfile struct {
	Handlers []struct {
		ID           string `json:"id"`
		TokenizePath string `json:"tokenizePath"`
	} `json:"handlers"`
	Checkout struct {
		CatalogPath  string `json:"catalogPath"`
		SessionsPath string `json:"sessionsPath"`
	} `json:"checkout"`
	AP2 struct {
		AuthorityRole string `json:"authorityRole"`
		AuthorityAns  string `json:"authorityAns"`
	} `json:"ap2"`
	SigningKey crypto.JWK `json:"signingKey"`
}

// BuyPeer drives a full UCP purchase against an already-discovered seller whose
// card advertises the UCP extension: read /.well-known/ucp, pick the cheapest item,
// create a session and verify the seller-signed terms, update it, obtain the two
// AP2 mandates from the named authority, tokenize, and complete. Card-driven; no
// hardcoding. Steps emit through ctx.
func BuyPeer(ctx context.Context, httpc *http.Client, mcpCli *mcp.Client, disco domain.Discovery, callerAns string, peer domain.AgentInfo, card a2a.Card) (commerce.BuyResult, error) {
	ext, ok := ucpExtension(card)
	if !ok {
		return commerce.BuyResult{}, fmt.Errorf("peer %q does not advertise UCP", peer.Name)
	}
	events.Emit(ctx, "requirement", events.StatusInfo, map[string]string{"type": "ucp"})
	events.Emit(ctx, "card.read", events.StatusOK, map[string]string{"peer": peer.Name, "url": card.URL})
	greetID := events.GreetIDFromContext(ctx)
	profilePath := strParam(ext.Params, "profilePath", "/.well-known/ucp")

	var prof ucpProfile
	if err := getJSON(ctx, httpc, greetID, peer.BaseURL+profilePath, &prof); err != nil {
		return commerce.BuyResult{}, fmt.Errorf("read ucp profile: %w", err)
	}
	if len(prof.Handlers) == 0 {
		return commerce.BuyResult{}, fmt.Errorf("seller %q advertises no UCP handler", peer.Name)
	}
	sellerPub, err := crypto.PublicKeyFromJWK(prof.SigningKey)
	if err != nil {
		return commerce.BuyResult{}, fmt.Errorf("seller signing key: %w", err)
	}
	events.Emit(ctx, "profile.read", events.StatusOK, map[string]string{"handler": prof.Handlers[0].ID, "authority": prof.AP2.AuthorityAns})

	var cat struct {
		Items []commerce.Item `json:"items"`
	}
	if err := getJSON(ctx, httpc, greetID, peer.BaseURL+prof.Checkout.CatalogPath, &cat); err != nil {
		return commerce.BuyResult{}, err
	}
	item, ok := commerce.LowestPriced(cat.Items)
	if !ok {
		return commerce.BuyResult{}, fmt.Errorf("seller %q has an empty catalog", peer.Name)
	}
	events.Emit(ctx, "catalog.fetch", events.StatusOK, map[string]string{"items": strconv.Itoa(len(cat.Items))})
	events.Emit(ctx, "item.select", events.StatusOK, map[string]string{"item": item.ID, "amount": strconv.FormatInt(item.Amount, 10)})

	// create session
	var sess struct {
		CheckoutID        string `json:"checkoutId"`
		ItemID            string `json:"itemId"`
		Amount            int64  `json:"amount"`
		Currency          string `json:"currency"`
		CheckoutSignature []byte `json:"checkoutSignature"`
	}
	if err := postJSON(ctx, httpc, greetID, peer.BaseURL+prof.Checkout.SessionsPath, map[string]string{"itemId": item.ID}, &sess); err != nil {
		return commerce.BuyResult{}, err
	}
	events.Emit(ctx, "session.create", events.StatusOK, map[string]string{"checkoutId": sess.CheckoutID, "amount": strconv.FormatInt(sess.Amount, 10)})
	if err := verifyTerms(sess.CheckoutSignature, sellerPub, sess.CheckoutID, sess.Amount); err != nil {
		events.Emit(ctx, "terms.verify", events.StatusFail, map[string]string{"error": err.Error()})
		return commerce.BuyResult{}, err
	}
	events.Emit(ctx, "terms.verify", events.StatusOK, map[string]string{"result": "seller signature over terms valid — terms authentic"})

	// update session (fulfillment) -> new amount + new signature
	var upd struct {
		Amount            int64  `json:"amount"`
		Currency          string `json:"currency"`
		CheckoutSignature []byte `json:"checkoutSignature"`
	}
	if err := postJSON(ctx, httpc, greetID, peer.BaseURL+prof.Checkout.SessionsPath+"/"+sess.CheckoutID, map[string]any{}, &upd); err != nil {
		return commerce.BuyResult{}, err
	}
	if err := verifyTerms(upd.CheckoutSignature, sellerPub, sess.CheckoutID, upd.Amount); err != nil {
		events.Emit(ctx, "terms.verify", events.StatusFail, map[string]string{"error": err.Error()})
		return commerce.BuyResult{}, err
	}
	events.Emit(ctx, "session.update", events.StatusOK, map[string]string{"checkoutId": sess.CheckoutID, "amount": strconv.FormatInt(upd.Amount, 10)})
	amount, currency := upd.Amount, upd.Currency

	// mandates from the named authority
	audienceAns := domain.LocalANSName(peer.Name)
	auth, ok, err := pickAuthority(ctx, disco, prof.AP2.AuthorityRole, prof.AP2.AuthorityAns)
	if err != nil {
		return commerce.BuyResult{}, err
	}
	if !ok {
		return commerce.BuyResult{}, fmt.Errorf("no authority %q under role %q", prof.AP2.AuthorityAns, prof.AP2.AuthorityRole)
	}
	events.Emit(ctx, "authority.resolve", events.StatusOK, map[string]string{"authority": auth.Name, "role": prof.AP2.AuthorityRole})

	events.Emit(ctx, "checkout.request", events.StatusInfo, map[string]string{"authority": auth.Name, "tool": "issue_checkout_mandate", "endpoint": auth.BaseURL + "/mcp"})
	cm, err := acquireMandate(ctx, mcpCli, auth.BaseURL+"/mcp", "issue_checkout_mandate", map[string]any{
		"subjectAns": callerAns, "audienceAns": audienceAns, "checkoutId": sess.CheckoutID, "itemId": item.ID, "amount": amount, "currency": currency,
	})
	if err != nil {
		events.Emit(ctx, "checkout.acquire", events.StatusFail, map[string]string{"error": err.Error()})
		return commerce.BuyResult{}, err
	}
	events.Emit(ctx, "checkout.acquire", events.StatusOK, map[string]string{"authority": auth.Name, "tool": "issue_checkout_mandate (MCP)"})

	events.Emit(ctx, "payment.request", events.StatusInfo, map[string]string{"authority": auth.Name, "tool": "issue_payment_mandate", "endpoint": auth.BaseURL + "/mcp"})
	pm, err := acquireMandate(ctx, mcpCli, auth.BaseURL+"/mcp", "issue_payment_mandate", map[string]any{
		"subjectAns": callerAns, "audienceAns": audienceAns, "amount": amount, "currency": currency,
	})
	if err != nil {
		events.Emit(ctx, "payment.acquire", events.StatusFail, map[string]string{"error": err.Error()})
		return commerce.BuyResult{}, err
	}
	events.Emit(ctx, "payment.acquire", events.StatusOK, map[string]string{"authority": auth.Name, "tool": "issue_payment_mandate (MCP)"})

	// tokenize via the handler
	var tok struct {
		Token string `json:"token"`
	}
	if err := postJSON(ctx, httpc, greetID, peer.BaseURL+prof.Handlers[0].TokenizePath, map[string]any{
		"binding":    map[string]string{"checkoutId": sess.CheckoutID},
		"allowance":  map[string]any{"maxAmount": amount, "currency": currency},
		"credential": map[string]string{"type": "card"},
	}, &tok); err != nil {
		return commerce.BuyResult{}, err
	}
	if tok.Token == "" {
		return commerce.BuyResult{}, fmt.Errorf("handler returned no token")
	}
	events.Emit(ctx, "tokenize", events.StatusOK, map[string]string{"handler": prof.Handlers[0].ID, "token": tok.Token})

	// complete
	events.Emit(ctx, "checkout.complete", events.StatusInfo, map[string]string{"checkoutId": sess.CheckoutID})
	var rec struct {
		Provider   string `json:"provider"`
		PaymentRef string `json:"paymentRef"`
		Status     string `json:"status"`
	}
	if err := postJSONExpect(ctx, httpc, greetID, peer.BaseURL+prof.Checkout.SessionsPath+"/"+sess.CheckoutID+"/complete", map[string]any{
		"callerAns": callerAns, "checkoutMandate": cm, "paymentMandate": pm, "paymentToken": tok.Token,
	}, &rec); err != nil {
		events.Emit(ctx, "purchase.rejected", events.StatusFail, map[string]string{"error": err.Error()})
		return commerce.BuyResult{}, err
	}
	events.Emit(ctx, "receipt", events.StatusOK, map[string]string{"paymentRef": rec.PaymentRef, "status": rec.Status, "provider": rec.Provider})
	return commerce.BuyResult{PaymentRef: rec.PaymentRef, Status: rec.Status, ItemID: item.ID}, nil
}

func ucpExtension(card a2a.Card) (a2a.Extension, bool) {
	if card.Capabilities == nil {
		return a2a.Extension{}, false
	}
	for _, e := range card.Capabilities.Extensions {
		if e.URI == a2a.ExtUCPURI {
			return e, true
		}
	}
	return a2a.Extension{}, false
}

func verifyTerms(sig []byte, sellerPub ed25519.PublicKey, checkoutID string, amount int64) error {
	if len(sig) == 0 {
		return fmt.Errorf("missing checkout signature")
	}
	payload, signer, err := crypto.VerifyCOSE1(sig)
	if err != nil {
		return fmt.Errorf("checkout signature invalid: %w", err)
	}
	if !signer.Equal(sellerPub) {
		return fmt.Errorf("checkout signature not from the advertised seller key")
	}
	var terms checkoutTerms
	if err := json.Unmarshal(payload, &terms); err != nil {
		return fmt.Errorf("signed terms malformed: %w", err)
	}
	if terms.CheckoutID != checkoutID || terms.Amount != amount {
		return fmt.Errorf("signed terms do not match session (id/amount)")
	}
	return nil
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

func acquireMandate(ctx context.Context, mcpCli *mcp.Client, authURL, tool string, args map[string]any) ([]byte, error) {
	raw, err := mcpCli.Call(ctx, authURL, tool, args)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", tool, err)
	}
	var out struct {
		MandateCOSE []byte `json:"mandateCose"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("parse %s: %w", tool, err)
	}
	if len(out.MandateCOSE) == 0 {
		return nil, fmt.Errorf("authority returned an empty mandate from %s", tool)
	}
	return out.MandateCOSE, nil
}

func getJSON(ctx context.Context, httpc *http.Client, greetID, url string, out any) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	setGreet(req, greetID)
	resp, err := httpc.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func postJSON(ctx context.Context, httpc *http.Client, greetID, url string, body, out any) error {
	return postJSONExpect(ctx, httpc, greetID, url, body, out)
}

func postJSONExpect(ctx context.Context, httpc *http.Client, greetID, url string, body, out any) error {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	setGreet(req, greetID)
	resp, err := httpc.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if e.Error != "" {
			return fmt.Errorf("%s", e.Error)
		}
		return fmt.Errorf("POST %s: status %d", url, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func setGreet(req *http.Request, greetID string) {
	if greetID != "" {
		req.Header.Set(commerce.HeaderGreetID, greetID)
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
