package tl

import (
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

// maxStatementBytes bounds a submitted statement.
const maxStatementBytes = 1 << 20

// Service is the transparency-log HTTP service. It signs receipts with its own
// Ed25519 key.
type Service struct {
	log   *Log
	priv  ed25519.PrivateKey
	logID string // this log's identity: the thumbprint of its public key
	l     zerolog.Logger
}

// NewService returns a transparency service backed by a fresh empty log.
func NewService(priv ed25519.PrivateKey, log zerolog.Logger) *Service {
	pub := priv.Public().(ed25519.PublicKey)
	return &Service{
		log:   NewLog(),
		priv:  priv,
		logID: crypto.Thumbprint(crypto.PublicJWK(pub)),
		l:     log.With().Str("component", "tl").Logger(),
	}
}

// Handler returns the transparency-log routes.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /entries", s.handleAppend)
	mux.HandleFunc("GET /pubkey", s.handlePubKey)
	mux.HandleFunc("GET /checkpoint", s.handleCheckpoint)
	return mux
}

type receiptClaims struct {
	LogID      string `json:"logId"`
	EntryIndex int    `json:"entryIndex"`
	TreeSize   int    `json:"treeSize"`
	Root       []byte `json:"root"`
}

func (s *Service) handleAppend(w http.ResponseWriter, r *http.Request) {
	// Read one byte past the limit so an oversized body can be detected and
	// rejected, rather than silently truncated and sealed.
	statement, err := io.ReadAll(io.LimitReader(r.Body, maxStatementBytes+1))
	if err != nil {
		s.l.Warn().Err(err).Msg("append: read body")
		http.Error(w, "unreadable statement", http.StatusBadRequest)
		return
	}
	if len(statement) == 0 {
		http.Error(w, "empty statement", http.StatusBadRequest)
		return
	}
	if len(statement) > maxStatementBytes {
		s.l.Warn().Int("bytes", len(statement)).Msg("append: statement exceeds max size")
		http.Error(w, "statement exceeds maximum size", http.StatusRequestEntityTooLarge)
		return
	}

	index, size, root, proof := s.log.AppendAndProve(statement)

	claims, err := json.Marshal(receiptClaims{LogID: s.logID, EntryIndex: index, TreeSize: size, Root: root})
	if err != nil {
		s.l.Error().Err(err).Msg("append: marshal receipt claims")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	receiptCOSE, err := crypto.SignCOSE1(s.priv, claims)
	if err != nil {
		s.l.Error().Err(err).Msg("append: sign receipt")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.l.Info().Str("logId", s.logID).Int("entryIndex", index).Int("treeSize", size).Msg("statement sealed")
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(domain.Receipt{
		LogID: s.logID, EntryIndex: index, TreeSize: size, Root: root, Proof: proof, COSE: receiptCOSE,
	}); err != nil {
		s.l.Error().Err(err).Msg("append: encode receipt")
	}
}

func (s *Service) handlePubKey(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(crypto.PublicJWK(s.priv.Public().(ed25519.PublicKey))); err != nil {
		s.l.Error().Err(err).Msg("pubkey: encode")
	}
}

func (s *Service) handleCheckpoint(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{"treeSize": s.log.Size(), "root": s.log.Root()}); err != nil {
		s.l.Error().Err(err).Msg("checkpoint: encode")
	}
}
