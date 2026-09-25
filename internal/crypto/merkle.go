package crypto

import (
	"bytes"
	"crypto/sha256"
)

// LeafHash returns the RFC 6962 leaf hash: SHA-256(0x00 || data).
func LeafHash(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	return h.Sum(nil)
}

// nodeHash returns the RFC 6962 interior node hash: SHA-256(0x01 || left || right).
func nodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// MerkleRoot computes the RFC 6962 Merkle Tree Hash over the given leaf hashes.
func MerkleRoot(leaves [][]byte) []byte {
	switch len(leaves) {
	case 0:
		s := sha256.Sum256(nil)
		return s[:]
	case 1:
		return leaves[0]
	}
	k := largestPowerOfTwoLessThan(len(leaves))
	return nodeHash(MerkleRoot(leaves[:k]), MerkleRoot(leaves[k:]))
}

// InclusionProof returns the RFC 6962 audit path for the leaf at index.
func InclusionProof(leaves [][]byte, index int) [][]byte {
	if index < 0 || index >= len(leaves) || len(leaves) <= 1 {
		return nil
	}
	k := largestPowerOfTwoLessThan(len(leaves))
	if index < k {
		return append(InclusionProof(leaves[:k], index), MerkleRoot(leaves[k:]))
	}
	return append(InclusionProof(leaves[k:], index-k), MerkleRoot(leaves[:k]))
}

// VerifyInclusion checks that leaf at index, in a tree of the given size with the
// supplied audit path, reproduces root (RFC 6962 §2.1.1).
//
// size only shapes how the audit path is traversed; it is not itself a
// cryptographic anchor. The root is what's actually verified, so callers must
// trust the (size, root) pair as a unit obtained from a source they trust (in
// this codebase, a TL receipt co-signs {entryIndex, treeSize, root} so the
// pair cannot be substituted independently).
func VerifyInclusion(leaf []byte, index, size int, proof [][]byte, root []byte) bool {
	if index < 0 || index >= size {
		return false
	}
	computed := leaf
	fn, sn := index, size-1
	pi := 0
	for sn > 0 {
		if pi >= len(proof) {
			return false
		}
		if fn%2 == 1 || fn == sn {
			computed = nodeHash(proof[pi], computed)
			// Terminates: this loop only has iterations to run when fn is
			// even, which (given the enclosing fn%2==1||fn==sn branch) means
			// fn==sn>0 here; each iteration halves both until fn goes odd or
			// reaches 0, bounding it by log2(sn).
			for fn%2 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			computed = nodeHash(computed, proof[pi])
		}
		pi++
		fn >>= 1
		sn >>= 1
	}
	return pi == len(proof) && bytes.Equal(computed, root)
}

// largestPowerOfTwoLessThan returns the largest power of two strictly less than n
// (n >= 2).
func largestPowerOfTwoLessThan(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}
