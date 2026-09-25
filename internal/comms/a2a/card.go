// Package a2a serves and reads A2A Agent Cards and handles A2A messages.
package a2a

import (
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog"
)

// Card is a minimal A2A Agent Card. Security is an OpenAPI-style list of scheme
// requirement maps; an empty slice means "open" (no auth). URL is filled in
// dynamically at serve time from the request host.
type Card struct {
	Name        string                `json:"name"`
	Description string                `json:"description,omitempty"`
	URL         string                `json:"url"`
	Version     string                `json:"version"`
	Security    []map[string][]string `json:"security"`
}

// serveCard returns a handler that serves card, setting url to this host's /a2a
// endpoint so the value is correct regardless of the bound port.
func serveCard(card Card, log zerolog.Logger) http.HandlerFunc {
	l := log.With().Str("component", "a2a").Logger()
	if card.Security == nil {
		card.Security = []map[string][]string{}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		c := card
		c.URL = "http://" + r.Host + "/a2a"
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(c); err != nil {
			l.Error().Err(err).Msg("encode agent card")
			return
		}
		l.Debug().Str("name", c.Name).Msg("served agent card")
	}
}

// CardHandler serves only the Agent Card at /.well-known/agent-card.json.
func CardHandler(card Card, log zerolog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/agent-card.json", serveCard(card, log))
	return mux
}
