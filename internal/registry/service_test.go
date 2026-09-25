package registry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

func TestRegisterThenSearchByRole(t *testing.T) {
	ts := httptest.NewServer(New(zerolog.Nop()).Handler())
	defer ts.Close()

	body := `{"name":"greeter-open","role":"greeter","baseURL":"http://x","cardURL":"http://x/.well-known/agent-card.json"}`
	resp, err := http.Post(ts.URL+"/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("register status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp, err = http.Get(ts.URL + "/search?role=greeter")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var got []domain.AgentInfo
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "greeter-open" {
		t.Fatalf("unexpected search result: %+v", got)
	}
}

func TestRegisterRejectsMissingFields(t *testing.T) {
	ts := httptest.NewServer(New(zerolog.Nop()).Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/register", "application/json", strings.NewReader(`{"role":"greeter"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for missing name/baseURL, got %d", resp.StatusCode)
	}
}
