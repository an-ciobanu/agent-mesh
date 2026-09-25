package tl

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
)

func TestServiceSealReturnsVerifiableReceipt(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	ts := httptest.NewServer(NewService(priv, zerolog.Nop()).Handler())
	defer ts.Close()

	// A signed statement (issuer distinct from the TL).
	issuer, _ := crypto.GenerateEd25519()
	statement, _ := crypto.SignCOSE1(issuer, []byte(`{"type":"greet.completed"}`))

	resp, err := http.Post(ts.URL+"/entries", "application/cose", bytes.NewReader(statement))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("seal status = %d", resp.StatusCode)
	}
	var rec domain.Receipt
	if err := json.NewDecoder(resp.Body).Decode(&rec); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// The receipt's COSE is signed by the TL and commits to the same root.
	claims, signer, err := crypto.VerifyCOSE1(rec.COSE)
	if err != nil {
		t.Fatalf("verify receipt cose: %v", err)
	}
	if !signer.Equal(priv.Public()) {
		t.Fatal("receipt not signed by the TL key")
	}
	var rc struct {
		EntryIndex int    `json:"entryIndex"`
		TreeSize   int    `json:"treeSize"`
		Root       []byte `json:"root"`
	}
	if err := json.Unmarshal(claims, &rc); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rc.Root, rec.Root) || rc.EntryIndex != rec.EntryIndex || rc.TreeSize != rec.TreeSize {
		t.Fatal("receipt COSE claims do not match receipt fields")
	}

	// The inclusion proof verifies against the receipt root.
	if !crypto.VerifyInclusion(crypto.LeafHash(statement), rec.EntryIndex, rec.TreeSize, rec.Proof, rec.Root) {
		t.Fatal("inclusion proof does not verify")
	}
}

func TestServiceRejectsEmptyStatement(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	ts := httptest.NewServer(NewService(priv, zerolog.Nop()).Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/entries", "application/cose", bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for empty statement, got %d", resp.StatusCode)
	}
}

// errReadCloser is an io.ReadCloser that always fails, used to exercise the
// "unreadable statement" branch of handleAppend without a real network fault.
type errReadCloser struct{}

func (errReadCloser) Read([]byte) (int, error) { return 0, errors.New("simulated read failure") }
func (errReadCloser) Close() error             { return nil }

func TestServiceRejectsUnreadableBody(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	svc := NewService(priv, zerolog.Nop())

	req := httptest.NewRequest(http.MethodPost, "/entries", errReadCloser{})
	rw := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rw, req)

	if rw.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for an unreadable body, got %d", rw.Code)
	}
}

// failingWriter is an http.ResponseWriter whose Write always fails, used to
// exercise the handlers' best-effort (logged, non-fatal) response-encoding
// error branches.
type failingWriter struct {
	header http.Header
}

func (w *failingWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *failingWriter) Write([]byte) (int, error) { return 0, errors.New("simulated write failure") }

func (w *failingWriter) WriteHeader(int) {}

func TestServiceHandlersToleratesResponseWriteFailure(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	svc := NewService(priv, zerolog.Nop())

	issuer, _ := crypto.GenerateEd25519()
	statement, _ := crypto.SignCOSE1(issuer, []byte(`{"type":"greet.completed"}`))

	reqs := []*http.Request{
		httptest.NewRequest(http.MethodPost, "/entries", bytes.NewReader(statement)),
		httptest.NewRequest(http.MethodGet, "/pubkey", nil),
		httptest.NewRequest(http.MethodGet, "/checkpoint", nil),
	}
	for _, req := range reqs {
		// Must not panic even though the response body cannot be written.
		svc.Handler().ServeHTTP(&failingWriter{}, req)
	}
}

func TestServiceRejectsOversizedStatement(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	ts := httptest.NewServer(NewService(priv, zerolog.Nop()).Handler())
	defer ts.Close()

	oversized := bytes.Repeat([]byte{0x01}, maxStatementBytes+100)
	resp, err := http.Post(ts.URL+"/entries", "application/cose", bytes.NewReader(oversized))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413 for oversized statement, got %d", resp.StatusCode)
	}

	// The rejected statement must not have been appended: a valid statement
	// sealed afterward should land at index 0 of a still-empty log.
	issuer, _ := crypto.GenerateEd25519()
	statement, _ := crypto.SignCOSE1(issuer, []byte(`{"type":"greet.completed"}`))
	resp2, err := http.Post(ts.URL+"/entries", "application/cose", bytes.NewReader(statement))
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	var rec domain.Receipt
	if err := json.NewDecoder(resp2.Body).Decode(&rec); err != nil {
		t.Fatal(err)
	}
	if rec.EntryIndex != 0 || rec.TreeSize != 1 {
		t.Fatalf("log was affected by rejected oversized statement: index=%d size=%d", rec.EntryIndex, rec.TreeSize)
	}
}

func TestServiceCheckpointReflectsLogState(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	ts := httptest.NewServer(NewService(priv, zerolog.Nop()).Handler())
	defer ts.Close()

	getCheckpoint := func() (treeSize int, root []byte) {
		resp, err := http.Get(ts.URL + "/checkpoint")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var cp struct {
			TreeSize int    `json:"treeSize"`
			Root     []byte `json:"root"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&cp); err != nil {
			t.Fatal(err)
		}
		return cp.TreeSize, cp.Root
	}

	size, root := getCheckpoint()
	if size != 0 {
		t.Fatalf("empty log: treeSize = %d, want 0", size)
	}
	if len(root) == 0 {
		t.Fatal("empty log: checkpoint root missing")
	}

	issuer, _ := crypto.GenerateEd25519()
	statement, _ := crypto.SignCOSE1(issuer, []byte(`{"type":"greet.completed"}`))
	resp, err := http.Post(ts.URL+"/entries", "application/cose", bytes.NewReader(statement))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	size, root = getCheckpoint()
	if size != 1 {
		t.Fatalf("after seal: treeSize = %d, want 1", size)
	}
	if len(root) == 0 {
		t.Fatal("after seal: checkpoint root missing")
	}
}

func TestServicePubKeyReturnsTLKey(t *testing.T) {
	priv, _ := crypto.GenerateEd25519()
	ts := httptest.NewServer(NewService(priv, zerolog.Nop()).Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/pubkey")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var jwk crypto.JWK
	if err := json.NewDecoder(resp.Body).Decode(&jwk); err != nil {
		t.Fatal(err)
	}
	want := crypto.PublicJWK(priv.Public().(ed25519.PublicKey))
	if jwk != want {
		t.Fatalf("pubkey = %+v, want %+v", jwk, want)
	}
}
