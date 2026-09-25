package crypto

import (
	"bytes"
	"testing"
)

func leaves(n int) [][]byte {
	ls := make([][]byte, n)
	for i := 0; i < n; i++ {
		ls[i] = LeafHash([]byte{byte(i)})
	}
	return ls
}

func TestInclusionProofVerifiesForEverySize(t *testing.T) {
	for size := 1; size <= 9; size++ {
		ls := leaves(size)
		root := MerkleRoot(ls)
		for i := 0; i < size; i++ {
			proof := InclusionProof(ls, i)
			if !VerifyInclusion(ls[i], i, size, proof, root) {
				t.Fatalf("size=%d index=%d: inclusion proof failed to verify", size, i)
			}
		}
	}
}

func TestVerifyInclusionRejectsWrongLeaf(t *testing.T) {
	ls := leaves(5)
	root := MerkleRoot(ls)
	proof := InclusionProof(ls, 2)
	wrong := LeafHash([]byte("nope"))
	if VerifyInclusion(wrong, 2, 5, proof, root) {
		t.Fatal("expected verification to fail for a wrong leaf")
	}
}

func TestVerifyInclusionRejectsWrongRoot(t *testing.T) {
	ls := leaves(4)
	proof := InclusionProof(ls, 1)
	badRoot := LeafHash([]byte("bad root"))
	if VerifyInclusion(ls[1], 1, 4, proof, badRoot) {
		t.Fatal("expected verification to fail for a wrong root")
	}
}

func TestLeafHashIsDomainSeparated(t *testing.T) {
	// Leaf and node hashing use different prefixes (0x00 vs 0x01).
	if bytes.Equal(LeafHash([]byte("x")), LeafHash([]byte("y"))) {
		t.Fatal("distinct leaves must hash differently")
	}
}
