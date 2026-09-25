package tl

import (
	"testing"

	"github.com/an-ciobanu/agent-mesh/internal/crypto"
)

func TestAppendAndProveIsConsistent(t *testing.T) {
	l := NewLog()
	s1 := []byte("statement-one")
	i1, size1, root1, proof1 := l.AppendAndProve(s1)
	if i1 != 0 || size1 != 1 {
		t.Fatalf("first entry: index=%d size=%d", i1, size1)
	}
	if !crypto.VerifyInclusion(crypto.LeafHash(s1), i1, size1, proof1, root1) {
		t.Fatal("first entry inclusion proof does not verify")
	}

	s2 := []byte("statement-two")
	i2, size2, root2, proof2 := l.AppendAndProve(s2)
	if i2 != 1 || size2 != 2 {
		t.Fatalf("second entry: index=%d size=%d", i2, size2)
	}
	if !crypto.VerifyInclusion(crypto.LeafHash(s2), i2, size2, proof2, root2) {
		t.Fatal("second entry inclusion proof does not verify")
	}
	if l.Size() != 2 {
		t.Fatalf("Size = %d, want 2", l.Size())
	}
}
