package a2a

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func TestCardHandlerServesJSON(t *testing.T) {
	card := Card{
		Name:     "greeter-open",
		URL:      "http://127.0.0.1:18101",
		Version:  "0.1.0",
		Security: []map[string][]string{}, // open
	}
	ts := httptest.NewServer(CardHandler(card, zerolog.Nop()))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/.well-known/agent-card.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	var got Card
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Name != "greeter-open" || got.Version != "0.1.0" {
		t.Fatalf("unexpected card: %+v", got)
	}
	if got.Security == nil {
		t.Fatal("security must serialize as [], not null")
	}
}

func TestCardHandlerNormalizesNilSecurity(t *testing.T) {
	card := Card{Name: "x", Version: "0.1.0"} // Security left nil
	ts := httptest.NewServer(CardHandler(card, zerolog.Nop()))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/.well-known/agent-card.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"security":[]`) {
		t.Fatalf("expected security to serialize as [], got: %s", body)
	}
}
