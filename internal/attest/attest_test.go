package attest_test

import (
	"context"
	"crypto/ed25519"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/attest"
	"github.com/an-ciobanu/agent-mesh/internal/comms/transparency"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/events"
	"github.com/an-ciobanu/agent-mesh/internal/tl"
)

type capture struct {
	mu  sync.Mutex
	evs []events.Event
}

func (c *capture) Emit(e events.Event) {
	c.mu.Lock()
	c.evs = append(c.evs, e)
	c.mu.Unlock()
}

func (c *capture) last() events.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.evs) == 0 {
		return events.Event{}
	}
	return c.evs[len(c.evs)-1]
}

func newTL(t *testing.T) (*httptest.Server, ed25519.PrivateKey) {
	t.Helper()
	priv, err := crypto.GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(tl.NewService(priv, zerolog.Nop()).Handler()), priv
}

func sealStatement(t *testing.T, tlURL string) domain.EvidenceBundle {
	t.Helper()
	issuerPriv, err := crypto.GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := crypto.SignCOSE1(issuerPriv, []byte(`{"hello":"world"}`))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := transparency.New(tlURL).Seal(context.Background(), stmt)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.LogID == "" {
		t.Fatal("receipt carries no log id")
	}
	return domain.EvidenceBundle{Statement: stmt, Receipt: receipt}
}

func scoped(cap *capture) context.Context {
	return events.WithScope(context.Background(), cap, "g1", "buyer", events.RoleInitiator)
}

func TestAuditValidEvidence(t *testing.T) {
	srv, _ := newTL(t)
	defer srv.Close()
	ev := sealStatement(t, srv.URL)

	cap := &capture{}
	if err := attest.Audit(scoped(cap), srv.URL, "purchase", &ev); err != nil {
		t.Fatalf("audit: %v", err)
	}
	e := cap.last()
	if e.Step != "audit" || e.Status != events.StatusOK {
		t.Fatalf("expected OK audit event, got %+v", e)
	}
	if e.Detail["of"] != "purchase" || e.Detail["logId"] != ev.Receipt.LogID {
		t.Fatalf("audit event missing of/logId: %+v", e.Detail)
	}
}

func TestAuditRejectsTamperedLogID(t *testing.T) {
	srv, _ := newTL(t)
	defer srv.Close()
	ev := sealStatement(t, srv.URL)
	ev.Receipt.LogID = "deadbeefdeadbeef" // claim a different log than the one that signed

	cap := &capture{}
	_ = attest.Audit(scoped(cap), srv.URL, "purchase", &ev)
	if e := cap.last(); e.Status != events.StatusFail {
		t.Fatalf("expected FAIL audit for tampered log id, got %+v", e)
	}
}

func TestAuditRejectsWrongLog(t *testing.T) {
	srv, _ := newTL(t)
	ev := sealStatement(t, srv.URL)
	srv.Close()
	// A different log with a different key — the receipt's log id will not match.
	other, _ := newTL(t)
	defer other.Close()
	cap := &capture{}
	_ = attest.Audit(scoped(cap), other.URL, "purchase", &ev)
	if e := cap.last(); e.Status != events.StatusFail {
		t.Fatalf("expected FAIL when audited against a different log, got %+v", e)
	}
}

func TestAuditNilEvidenceIsInfo(t *testing.T) {
	cap := &capture{}
	_ = attest.Audit(scoped(cap), "http://unused.invalid", "greet", nil)
	if e := cap.last(); e.Status != events.StatusInfo {
		t.Fatalf("nil evidence should be info, got %+v", e)
	}
}

func TestAuditNoTLURLIsInfo(t *testing.T) {
	srv, _ := newTL(t)
	defer srv.Close()
	ev := sealStatement(t, srv.URL)
	cap := &capture{}
	if err := attest.Audit(scoped(cap), "", "mandate", &ev); err != nil {
		t.Fatalf("audit: %v", err)
	}
	if e := cap.last(); e.Status != events.StatusInfo || e.Detail["logId"] != ev.Receipt.LogID {
		t.Fatalf("empty tlURL should emit info with the log id, got %+v", e)
	}
}
