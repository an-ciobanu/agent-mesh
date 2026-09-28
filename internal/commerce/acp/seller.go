package acp

import (
	"encoding/json"
	"net/http"
	"strconv"
	"sync"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/commerce"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/events"
	"github.com/an-ciobanu/agent-mesh/internal/policy"
)

// SellerConfig configures an ACP seller service.
type SellerConfig struct {
	SelfAns   string
	AgentName string
	Currency  string
	Catalog   []commerce.Item
	Guard     *policy.Spend
	Payment   commerce.PaymentPrimitive
	Events    events.Emitter
	Log       zerolog.Logger
}

type session struct {
	id       string
	itemID   string
	amount   int64
	currency string
}

// Seller serves the ACP catalog + checkout_sessions endpoints.
type Seller struct {
	cfg SellerConfig
	mu  sync.Mutex
	ses map[string]session
	log zerolog.Logger
}

// NewSeller builds a seller service.
func NewSeller(cfg SellerConfig) *Seller {
	if cfg.Events == nil {
		cfg.Events = events.Nop{}
	}
	return &Seller{cfg: cfg, ses: map[string]session{}, log: cfg.Log.With().Str("component", "acp-seller").Logger()}
}

// Mount registers the seller's routes on mux.
func (s *Seller) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /acp/catalog", s.handleCatalog)
	mux.HandleFunc("POST /acp/checkout_sessions", s.handleCreate)
	mux.HandleFunc("POST /acp/checkout_sessions/{id}/complete", s.handleComplete)
}

func (s *Seller) handleCatalog(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": s.cfg.Catalog})
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
	s.mu.Lock()
	s.ses[id] = session{id: id, itemID: item.ID, amount: item.Amount, currency: item.Currency}
	s.mu.Unlock()
	events.Emit(gctx, "session.create", events.StatusOK, map[string]string{
		"sessionId": id, "item": item.ID, "amount": strconv.FormatInt(item.Amount, 10), "currency": item.Currency,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"sessionId": id, "itemId": item.ID, "amount": item.Amount, "currency": item.Currency, "status": "ready_for_payment",
	})
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
		CallerAns    string `json:"callerAns"`
		SpendMandate []byte `json:"spendMandate"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	if err := s.cfg.Guard.Verify(gctx, domain.PurchaseRequest{
		CallerAns: in.CallerAns, ItemID: sess.itemID, Amount: sess.amount, Currency: sess.currency, SpendMandate: in.SpendMandate,
	}); err != nil {
		s.log.Warn().Err(err).Str("session", id).Msg("spend rejected")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "purchase not authorized: " + err.Error()})
		return
	}
	res, err := s.cfg.Payment.Charge(gctx, commerce.ChargeRequest{
		Amount: sess.amount, Currency: sess.currency, ItemID: sess.itemID,
		BuyerAns: in.CallerAns, IdempotencyKey: id,
	})
	if err != nil {
		events.Emit(gctx, "charge", events.StatusFail, map[string]string{"error": err.Error()})
		s.log.Error().Err(err).Str("session", id).Msg("charge failed")
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "charge failed: " + err.Error()})
		return
	}
	events.Emit(gctx, "charge", events.StatusOK, map[string]string{"provider": res.Provider, "ref": res.Ref, "status": res.Status})
	events.Emit(gctx, "receipt", events.StatusOK, map[string]string{"paymentRef": res.Ref, "status": res.Status})
	s.mu.Lock()
	delete(s.ses, id)
	s.mu.Unlock()
	s.log.Info().Str("session", id).Str("paymentRef", res.Ref).Str("status", res.Status).Msg("purchase completed")
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "completed", "provider": res.Provider, "paymentRef": res.Ref,
		"itemId": sess.itemID, "amount": sess.amount, "currency": sess.currency,
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
