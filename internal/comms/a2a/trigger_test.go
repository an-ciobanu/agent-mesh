package a2a

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/events"
)

func TestTriggerGreetRejectsBadBody(t *testing.T) {
	ts := NewTriggerService("chris", nil, zerolog.Nop(), events.Nop{})
	rr := httptest.NewRecorder()
	ts.HandleGreet(rr, httptest.NewRequest(http.MethodPost, "/trigger/greet", strings.NewReader("{")))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestTriggerGreetInvokesGreetFuncWithScope(t *testing.T) {
	var buf bytes.Buffer
	var gotGreetID, gotToName string
	greetFn := func(greetID, toRole, toName, text string) (string, bool, error) {
		gotGreetID, gotToName = greetID, toName
		return "hi chris, this is ema", true, nil
	}
	ts := NewTriggerService("chris", greetFn, zerolog.Nop(), events.NewJSONEmitter(&buf))

	body, _ := json.Marshal(triggerReq{ToName: "ema", Text: "hello"})
	rr := httptest.NewRecorder()
	ts.HandleGreet(rr, httptest.NewRequest(http.MethodPost, "/trigger/greet", bytes.NewReader(body)))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	var out triggerResp
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("bad resp: %v", err)
	}
	if !out.Accepted || out.GreetID == "" || out.GreetID != gotGreetID || gotToName != "ema" {
		t.Fatalf("unexpected: %+v (gotGreetID=%s toName=%s)", out, gotGreetID, gotToName)
	}
}

func TestHandleBuyRoutesToBuyFunc(t *testing.T) {
	trig := NewTriggerService("Ada", func(string, string, string, string) (string, bool, error) {
		return "", false, nil
	}, zerolog.Nop(), events.Nop{})
	trig.SetBuy(func(greetID, toName string) (string, string, error) {
		if toName != "shop-acp" {
			t.Fatalf("toName = %q", toName)
		}
		return "pi_fake_1", "succeeded", nil
	})
	srv := httptest.NewServer(http.HandlerFunc(trig.HandleBuy))
	defer srv.Close()
	resp, err := http.Post(srv.URL, "application/json", strings.NewReader(`{"toName":"shop-acp"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	var out struct {
		GreetID, PaymentRef, Status, Error string
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.GreetID == "" || out.PaymentRef != "pi_fake_1" || out.Status != "succeeded" || out.Error != "" {
		t.Fatalf("unexpected: %+v", out)
	}
}
