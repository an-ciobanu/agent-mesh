// Package attest verifies transparency evidence against a log and reports the
// result as an `audit` event on the caller's event scope. It is the shared
// "check the TL and log id from the peer's output" step used by greets,
// purchases, and mandate issuance: the peer hands over a signed statement plus an
// inclusion receipt, and the caller independently confirms — against the log's own
// key and advertised log id — that the peer really wrote what it claims.
package attest

import (
	"context"
	"strconv"

	"github.com/rs/zerolog"

	"github.com/an-ciobanu/agent-mesh/internal/audit"
	"github.com/an-ciobanu/agent-mesh/internal/comms/transparency"
	"github.com/an-ciobanu/agent-mesh/internal/crypto"
	"github.com/an-ciobanu/agent-mesh/internal/domain"
	"github.com/an-ciobanu/agent-mesh/internal/events"
)

// Audit fetches the transparency log's key from tlURL, verifies the evidence
// bundle (issuer signature, TL-signed receipt, log-id pin, inclusion proof), and
// emits an `audit` event tagged with `of` (e.g. "greet", "purchase", "mandate").
// It is best-effort: TL errors and verification failures emit a fail-status event
// and return the error, but a completed interaction is never rolled back on an
// audit failure. A nil evidence pointer or an empty tlURL degrades to an
// informational event rather than a failure.
func Audit(ctx context.Context, tlURL, of string, ev *domain.EvidenceBundle) error {
	if ev == nil {
		events.Emit(ctx, "audit", events.StatusInfo, map[string]string{"of": of, "note": "no evidence (peer not sealing)"})
		return nil
	}
	if tlURL == "" {
		events.Emit(ctx, "audit", events.StatusInfo, map[string]string{
			"of": of, "logId": ev.Receipt.LogID,
			"entryIndex": strconv.Itoa(ev.Receipt.EntryIndex), "treeSize": strconv.Itoa(ev.Receipt.TreeSize),
			"note": "sealed; no --transparency to audit",
		})
		return nil
	}
	tlPub, err := transparency.New(tlURL).FetchPubKey(ctx)
	if err != nil {
		events.Emit(ctx, "audit", events.StatusFail, map[string]string{"of": of, "error": "fetch TL pubkey: " + err.Error()})
		return err
	}
	auditorPriv, err := crypto.GenerateEd25519()
	if err != nil {
		events.Emit(ctx, "audit", events.StatusFail, map[string]string{"of": of, "error": "gen auditor key: " + err.Error()})
		return err
	}
	verdict, _, err := audit.New(domain.LocalANSName("auditor"), auditorPriv, zerolog.Nop()).Verify(ctx, *ev, tlPub)
	if err != nil {
		events.Emit(ctx, "audit", events.StatusFail, map[string]string{"of": of, "error": err.Error()})
		return err
	}
	status := events.StatusOK
	if verdict.Verdict != "valid" {
		status = events.StatusFail
	}
	events.Emit(ctx, "audit", status, map[string]string{
		"of": of, "verdict": verdict.Verdict, "logId": ev.Receipt.LogID,
		"entryIndex": strconv.Itoa(ev.Receipt.EntryIndex), "treeSize": strconv.Itoa(ev.Receipt.TreeSize),
	})
	return nil
}
