// Package registry is the in-memory discovery service for agent-mesh.
package registry

import (
	"encoding/json"
	"net/http"
	"sort"
	"sync"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

// Service is an in-memory registry keyed by agent name.
type Service struct {
	log    zerolog.Logger
	mu     sync.RWMutex
	byName map[string]domain.AgentInfo
}

// New returns a ready registry that logs under component "registry".
func New(log zerolog.Logger) *Service {
	return &Service{
		log:    log.With().Str("component", "registry").Logger(),
		byName: make(map[string]domain.AgentInfo),
	}
}

// Handler returns the registry HTTP routes.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /register", s.handleRegister)
	mux.HandleFunc("GET /search", s.handleSearch)
	return mux
}

func (s *Service) handleRegister(w http.ResponseWriter, r *http.Request) {
	var info domain.AgentInfo
	if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
		s.log.Warn().Err(err).Msg("register: invalid body")
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if info.Name == "" || info.BaseURL == "" {
		http.Error(w, "name and baseURL required", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.byName[info.Name] = info
	s.mu.Unlock()
	s.log.Info().Str("name", info.Name).Str("role", info.Role).Str("baseURL", info.BaseURL).Msg("agent registered")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) handleSearch(w http.ResponseWriter, r *http.Request) {
	role := r.URL.Query().Get("role")

	s.mu.RLock()
	out := make([]domain.AgentInfo, 0, len(s.byName))
	for _, info := range s.byName {
		if role == "" || info.Role == role {
			out = append(out, info)
		}
	}
	s.mu.RUnlock()

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(out); err != nil {
		s.log.Error().Err(err).Msg("search: encode response")
		return
	}
	s.log.Debug().Str("role", role).Int("results", len(out)).Msg("search served")
}
