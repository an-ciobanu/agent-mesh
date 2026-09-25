// Package tl is agent-mesh's minimal SCITT-style transparency log.
package tl

import (
	"sync"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
)

// Log is an in-memory, append-only RFC 6962 Merkle log of statement bytes.
type Log struct {
	mu         sync.RWMutex
	statements [][]byte
	leaves     [][]byte
}

// NewLog returns an empty log.
func NewLog() *Log { return &Log{} }

// AppendAndProve appends statement and returns, atomically, its entry index, the
// resulting tree size, the tree root, and the inclusion proof for the new entry.
func (l *Log) AppendAndProve(statement []byte) (index, size int, root []byte, proof [][]byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	dup := append([]byte(nil), statement...)
	l.statements = append(l.statements, dup)
	l.leaves = append(l.leaves, crypto.LeafHash(dup))
	index = len(l.leaves) - 1
	size = len(l.leaves)
	root = crypto.MerkleRoot(l.leaves)
	proof = crypto.InclusionProof(l.leaves, index)
	return index, size, root, proof
}

// Size returns the number of entries.
func (l *Log) Size() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.leaves)
}

// Root returns the current Merkle root.
func (l *Log) Root() []byte {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return crypto.MerkleRoot(l.leaves)
}
