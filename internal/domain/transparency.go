package domain

import "context"

// Receipt is a transparency-log inclusion receipt for a submitted statement.
// Root and Proof JSON-encode as base64 (Go's default for []byte).
type Receipt struct {
	EntryIndex int      `json:"entryIndex"`
	TreeSize   int      `json:"treeSize"`
	Root       []byte   `json:"root"`
	Proof      [][]byte `json:"proof"`
	COSE       []byte   `json:"cose"` // TL-signed COSE_Sign1 over {entryIndex, treeSize, root}
}

// Transparency seals a signed statement into an append-only transparency log and
// returns a receipt proving its inclusion.
type Transparency interface {
	Seal(ctx context.Context, statement []byte) (Receipt, error)
}

// EvidenceBundle is what an auditor needs to verify an interaction: the signed
// statement (COSE_Sign1 bytes) and its transparency receipt.
type EvidenceBundle struct {
	Statement []byte  `json:"statement"`
	Receipt   Receipt `json:"receipt"`
}
