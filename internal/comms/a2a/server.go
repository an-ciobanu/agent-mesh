package a2a

import (
	"net/http"

	"github.com/rs/zerolog"
)

// NewMux serves both the Agent Card and the A2A message/send greet endpoint for
// one agent.
func NewMux(card Card, greet *GreetService, log zerolog.Logger) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/agent-card.json", serveCard(card, log))
	mux.HandleFunc("POST /a2a", greet.HandleMessageSend)
	return mux
}
