// Package a2a serves and reads A2A Agent Cards.
package a2a

import (
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog"
)

// Card is a minimal A2A Agent Card. Security is an OpenAPI-style list of
// scheme requirement maps; an empty slice means "open" (no auth).
type Card struct {
	Name        string                `json:"name"`
	Description string                `json:"description,omitempty"`
	URL         string                `json:"url"`
	Version     string                `json:"version"`
	Security    []map[string][]string `json:"security"`
}

// CardHandler serves a fixed Agent Card at /.well-known/agent-card.json.
func CardHandler(card Card, log zerolog.Logger) http.Handler {
	l := log.With().Str("component", "a2a").Logger()
	if card.Security == nil {
		card.Security = []map[string][]string{}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/agent-card.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(card); err != nil {
			l.Error().Err(err).Msg("encode agent card")
			return
		}
		l.Debug().Str("name", card.Name).Msg("served agent card")
	})
	return mux
}
