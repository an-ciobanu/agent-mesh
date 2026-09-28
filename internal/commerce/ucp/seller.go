// Package ucp implements the demo's Universal Commerce Protocol seller (server)
// and buyer driver (client): /.well-known/ucp discovery + a tokenize handler,
// seller-signed checkout terms, and a create->update->complete session gated by
// two authority-issued AP2 mandates and settled through a commerce.PaymentPrimitive.
package ucp

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/commerce"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/events"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
)

// shippingFee is added to a session's total on update (the fulfillment step).
const shippingFee int64 = 300

// checkoutTerms is the exact structure the seller COSE-signs (checkoutSignature)
// and the buyer verifies. Shared by seller.go and driver.go (same package).
type checkoutTerms struct {
	CheckoutID string `json:"checkoutId"`
	ItemID     string `json:"itemId"`
	Amount     int64  `json:"amount"`
	Currency   string `json:"currency"`
}

// SellerConfig configures a UCP seller service.
type SellerConfig struct {
	SelfAns       string
	AgentName     string
	Currency      string
	Catalog       []commerce.Item
	Guard         *policy.UCP
	Payment       commerce.PaymentPrimitive
	SignKey       ed25519.PrivateKey
	AuthorityRole string
	AuthorityAns  string
	Events        events.Emitter
	Log           zerolog.Logger
}

type ucpSession struct {
	checkoutID string
	itemID     string
	amount     int64
	currency   string
}

type tokenRec struct {
	checkoutID string
	maxAmount  int64
	currency   string
	expiresAt  time.Time
}

// Seller serves the UCP surface.
type Seller struct {
	cfg     SellerConfig
	signPub ed25519.PublicKey
	mu      sync.Mutex
	ses     map[string]ucpSession
	toks    map[string]tokenRec
	log     zerolog.Logger
}

// NewSeller builds a UCP seller.
func NewSeller(cfg SellerConfig) *Seller {
	if cfg.Events == nil {
		cfg.Events = events.Nop{}
	}
	return &Seller{
		cfg:     cfg,
		signPub: cfg.SignKey.Public().(ed25519.PublicKey),
		ses:     map[string]ucpSession{},
		toks:    map[string]tokenRec{},
		log:     cfg.Log.With().Str("component", "ucp-seller").Logger(),
	}
}

// Mount registers the UCP routes.
func (s *Seller) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/ucp", s.handleProfile)
	mux.HandleFunc("GET /ucp/catalog", s.handleCatalog)
	mux.HandleFunc("POST /ucp/checkout_sessions", s.handleCreate)
	mux.HandleFunc("POST /ucp/checkout_sessions/{id}", s.handleUpdate)
	mux.HandleFunc("POST /ucp/tokenize", s.handleTokenize)
	mux.HandleFunc("POST /ucp/checkout_sessions/{id}/complete", s.handleComplete)
}

func (s *Seller) handleProfile(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ucp_version": "2026-04-08",
		"handlers": []map[string]any{{
			"id": "stripe_payments", "type": "com.stripe.payments", "tokenizePath": "/ucp/tokenize",
			"instruments": []map[string]any{{"type": "card", "tokenization": "required"}},
		}},
		"checkout":   map[string]string{"catalogPath": "/ucp/catalog", "sessionsPath": "/ucp/checkout_sessions"},
		"ap2":        map[string]any{"required": true, "authorityRole": s.cfg.AuthorityRole, "authorityAns": s.cfg.AuthorityAns},
		"signingKey": crypto.PublicJWK(s.signPub),
	})
}

func (s *Seller) handleCatalog(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": s.cfg.Catalog})
}

func (s *Seller) sign(sess ucpSession) ([]byte, error) {
	b, err := json.Marshal(checkoutTerms{CheckoutID: sess.checkoutID, ItemID: sess.itemID, Amount: sess.amount, Currency: sess.currency})
	if err != nil {
		return nil, err
	}
	return crypto.SignCOSE1(s.cfg.SignKey, b)
}

func (s *Seller) handleCreate(w http.ResponseWriter, r *http.Request) {
	gctx := events.WithScope(r.Context(), s.cfg.Events, r.Header.Get(commerce.HeaderGreetID), s.cfg.AgentName, events.RoleResponder)
	var in struct {
		ItemID string `json:"itemId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	var item commerce.Item
	found := false
	for _, it := range s.cfg.Catalog {
		if it.ID == in.ItemID {
			item, found = it, true
			break
		}
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown item"})
		return
	}
	id := "cs_" + events.NewGreetID()[:16]
	sess := ucpSession{checkoutID: id, itemID: item.ID, amount: item.Amount, currency: item.Currency}
	s.mu.Lock()
	s.ses[id] = sess
	s.mu.Unlock()
	sig, err := s.sign(sess)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "sign terms"})
		return
	}
	events.Emit(gctx, "session.create", events.StatusOK, map[string]string{"checkoutId": id, "item": item.ID, "amount": strconv.FormatInt(item.Amount, 10), "signed": "terms COSE-signed"})
	writeJSON(w, http.StatusOK, map[string]any{"checkoutId": id, "itemId": item.ID, "amount": item.Amount, "currency": item.Currency, "status": "created", "checkoutSignature": sig})
}

func (s *Seller) handleUpdate(w http.ResponseWriter, r *http.Request) {
	gctx := events.WithScope(r.Context(), s.cfg.Events, r.Header.Get(commerce.HeaderGreetID), s.cfg.AgentName, events.RoleResponder)
	id := r.PathValue("id")
	s.mu.Lock()
	sess, ok := s.ses[id]
	if ok {
		sess.amount += shippingFee
		s.ses[id] = sess
	}
	s.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown session"})
		return
	}
	sig, err := s.sign(sess)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "sign terms"})
		return
	}
	events.Emit(gctx, "session.update", events.StatusOK, map[string]string{"checkoutId": id, "amount": strconv.FormatInt(sess.amount, 10), "fulfillment": "standard shipping added"})
	writeJSON(w, http.StatusOK, map[string]any{"checkoutId": id, "itemId": sess.itemID, "amount": sess.amount, "currency": sess.currency, "status": "updated", "checkoutSignature": sig})
}

func (s *Seller) handleTokenize(w http.ResponseWriter, r *http.Request) {
	gctx := events.WithScope(r.Context(), s.cfg.Events, r.Header.Get(commerce.HeaderGreetID), s.cfg.AgentName, events.RoleResponder)
	var in struct {
		Binding struct {
			CheckoutID string `json:"checkoutId"`
		} `json:"binding"`
		Allowance struct {
			MaxAmount int64  `json:"maxAmount"`
			Currency  string `json:"currency"`
		} `json:"allowance"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Binding.CheckoutID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	token := "utok_" + hex.EncodeToString(b)
	exp := time.Now().Add(time.Hour)
	s.mu.Lock()
	s.toks[token] = tokenRec{checkoutID: in.Binding.CheckoutID, maxAmount: in.Allowance.MaxAmount, currency: in.Allowance.Currency, expiresAt: exp}
	s.mu.Unlock()
	events.Emit(gctx, "token.issue", events.StatusOK, map[string]string{"checkoutId": in.Binding.CheckoutID, "maxAmount": strconv.FormatInt(in.Allowance.MaxAmount, 10), "handler": "stripe_payments"})
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "expiresAt": exp.UTC().Format(time.RFC3339)})
}

func (s *Seller) handleComplete(w http.ResponseWriter, r *http.Request) {
	gctx := events.WithScope(r.Context(), s.cfg.Events, r.Header.Get(commerce.HeaderGreetID), s.cfg.AgentName, events.RoleResponder)
	id := r.PathValue("id")
	s.mu.Lock()
	sess, ok := s.ses[id]
	s.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown session"})
		return
	}
	var in struct {
		CallerAns       string `json:"callerAns"`
		CheckoutMandate []byte `json:"checkoutMandate"`
		PaymentMandate  []byte `json:"paymentMandate"`
		PaymentToken    string `json:"paymentToken"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	if err := s.cfg.Guard.Verify(gctx, domain.UCPCompletion{
		CallerAns: in.CallerAns, CheckoutID: id, ItemID: sess.itemID, Amount: sess.amount, Currency: sess.currency,
		CheckoutMandate: in.CheckoutMandate, PaymentMandate: in.PaymentMandate,
	}); err != nil {
		s.log.Warn().Err(err).Str("checkout", id).Msg("ucp mandates rejected")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "purchase not authorized: " + err.Error()})
		return
	}
	s.mu.Lock()
	tok, tokOK := s.toks[in.PaymentToken]
	s.mu.Unlock()
	if !tokOK || tok.checkoutID != id || tok.currency != sess.currency || tok.maxAmount < sess.amount || time.Now().After(tok.expiresAt) {
		events.Emit(gctx, "token.verify", events.StatusFail, map[string]string{"error": "invalid or insufficient payment token"})
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid payment token"})
		return
	}
	events.Emit(gctx, "token.verify", events.StatusOK, map[string]string{"token": in.PaymentToken, "result": "bound to checkout, allowance covers amount"})

	res, err := s.cfg.Payment.Charge(gctx, commerce.ChargeRequest{Amount: sess.amount, Currency: sess.currency, ItemID: sess.itemID, BuyerAns: in.CallerAns, IdempotencyKey: id})
	if err != nil {
		events.Emit(gctx, "charge", events.StatusFail, map[string]string{"error": err.Error()})
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "charge failed: " + err.Error()})
		return
	}
	events.Emit(gctx, "charge", events.StatusOK, map[string]string{"provider": res.Provider, "ref": res.Ref, "status": res.Status})
	events.Emit(gctx, "receipt", events.StatusOK, map[string]string{"paymentRef": res.Ref, "status": res.Status})
	s.mu.Lock()
	delete(s.ses, id)
	delete(s.toks, in.PaymentToken)
	s.mu.Unlock()
	s.log.Info().Str("checkout", id).Str("paymentRef", res.Ref).Msg("ucp purchase completed")
	writeJSON(w, http.StatusOK, map[string]any{"status": "completed", "provider": res.Provider, "paymentRef": res.Ref, "itemId": sess.itemID, "amount": sess.amount, "currency": sess.currency})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
