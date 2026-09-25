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

func TestCardCapabilitiesRoundTrip(t *testing.T) {
	in := Card{
		Name:     "greeter-mandate",
		Version:  "0.1.0",
		Security: []map[string][]string{{"mandate": {}}},
		Capabilities: &Capabilities{Extensions: []Extension{{
			URI:         ExtMandateURI,
			Description: "present a mandate from the authority",
			Required:    true,
			Params:      map[string]any{"authorityRole": "authority", "scope": "greet"},
		}}},
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Card
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.Capabilities == nil || len(out.Capabilities.Extensions) != 1 {
		t.Fatalf("capabilities lost in round trip: %+v", out.Capabilities)
	}
	ext := out.Capabilities.Extensions[0]
	if ext.URI != ExtMandateURI || !ext.Required || ext.Params["scope"] != "greet" {
		t.Fatalf("extension round trip wrong: %+v", ext)
	}
}

func TestServeCardIncludesCapabilities(t *testing.T) {
	card := Card{
		Name:         "greeter-mandate",
		Version:      "0.1.0",
		Security:     []map[string][]string{{"mandate": {}}},
		Capabilities: &Capabilities{Extensions: []Extension{{URI: ExtMandateURI, Required: true}}},
	}
	ts := httptest.NewServer(CardHandler(card, zerolog.Nop()))
	defer ts.Close()

	resp, err := ts.Client().Get(ts.URL + "/.well-known/agent-card.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got Card
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Capabilities == nil || len(got.Capabilities.Extensions) != 1 || got.Capabilities.Extensions[0].URI != ExtMandateURI {
		t.Fatalf("served card dropped capabilities: %+v", got.Capabilities)
	}
	if got.URL == "" {
		t.Fatal("served card should still set URL dynamically")
	}
}
