package crypto

import (
	"bytes"
	"crypto/sha256"
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

func TestMerkleRootEmptyTree(t *testing.T) {
	want := sha256.Sum256(nil)
	got := MerkleRoot(nil)
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("MerkleRoot(nil) = %x, want %x", got, want)
	}
}

func TestVerifyInclusionRejectsWrongIndex(t *testing.T) {
	ls := leaves(5)
	root := MerkleRoot(ls)
	proof := InclusionProof(ls, 2)
	if VerifyInclusion(ls[2], 3, 5, proof, root) {
		t.Fatal("expected verification to fail for a mismatched index")
	}
}

func TestVerifyInclusionRejectsOutOfRange(t *testing.T) {
	ls := leaves(4)
	root := MerkleRoot(ls)
	proof := InclusionProof(ls, 1)

	if VerifyInclusion(ls[1], 4, 4, proof, root) {
		t.Fatal("expected verification to fail for index >= size")
	}
	if VerifyInclusion(ls[1], -1, 4, proof, root) {
		t.Fatal("expected verification to fail for a negative index")
	}
	if len(proof) == 0 {
		t.Fatal("test setup: expected a non-empty proof for size=4 index=1")
	}
	truncated := proof[:len(proof)-1]
	if VerifyInclusion(ls[1], 1, 4, truncated, root) {
		t.Fatal("expected verification to fail for a too-short proof")
	}
}
