package core

import (
	"crypto/sha256"
	"errors"
	"math/bits"
)

// Hash is a SHA-256 hash in a Merkle tree (spec/checkpoint.md §2).
type Hash [sha256.Size]byte

// EmptyRoot is the root hash of the empty tree.
var EmptyRoot = Hash(sha256.Sum256(nil))

// LeafHash returns the RFC 9162 leaf hash of record bytes.
func LeafHash(record []byte) Hash {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(record)
	return Hash(h.Sum(nil))
}

func nodeHash(left, right Hash) Hash {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left[:])
	h.Write(right[:])
	return Hash(h.Sum(nil))
}

// split returns the largest power of two smaller than n, for n > 1.
func split(n uint64) uint64 {
	return 1 << (bits.Len64(n-1) - 1)
}

// Root returns the Merkle tree hash of the given leaf hashes.
func Root(leaves []Hash) Hash {
	switch n := uint64(len(leaves)); n {
	case 0:
		return EmptyRoot
	case 1:
		return leaves[0]
	default:
		k := split(n)
		return nodeHash(Root(leaves[:k]), Root(leaves[k:]))
	}
}

// InclusionProof returns the RFC 9162 audit path for leaves[index] in the
// tree formed by leaves.
func InclusionProof(leaves []Hash, index uint64) ([]Hash, error) {
	if index >= uint64(len(leaves)) {
		return nil, errors.New("index out of range")
	}
	return inclusion(leaves, index), nil
}

func inclusion(leaves []Hash, m uint64) []Hash {
	n := uint64(len(leaves))
	if n == 1 {
		return nil
	}
	k := split(n)
	if m < k {
		return append(inclusion(leaves[:k], m), Root(leaves[k:]))
	}
	return append(inclusion(leaves[k:], m-k), Root(leaves[:k]))
}

// ConsistencyProof returns the RFC 9162 consistency proof between the tree
// of the first oldSize leaves and the tree of all leaves.
func ConsistencyProof(leaves []Hash, oldSize uint64) ([]Hash, error) {
	n := uint64(len(leaves))
	if oldSize > n {
		return nil, errors.New("old size larger than tree size")
	}
	if oldSize == 0 || oldSize == n {
		return nil, nil
	}
	return subproof(leaves, oldSize, true), nil
}

func subproof(leaves []Hash, m uint64, complete bool) []Hash {
	n := uint64(len(leaves))
	if m == n {
		if complete {
			return nil
		}
		return []Hash{Root(leaves)}
	}
	k := split(n)
	if m <= k {
		return append(subproof(leaves[:k], m, complete), Root(leaves[k:]))
	}
	return append(subproof(leaves[k:], m-k, false), Root(leaves[:k]))
}

// VerifyInclusion checks an RFC 9162 inclusion proof (§2.1.3.2).
func VerifyInclusion(index, size uint64, leaf Hash, proof []Hash, root Hash) error {
	if index >= size {
		return errors.New("index out of range")
	}
	fn, sn := index, size-1
	r := leaf
	for _, p := range proof {
		if sn == 0 {
			return errors.New("inclusion proof too long")
		}
		if fn&1 == 1 || fn == sn {
			r = nodeHash(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = nodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return errors.New("inclusion proof too short")
	}
	if r != root {
		return errors.New("inclusion proof does not match root hash")
	}
	return nil
}

// VerifyConsistency checks an RFC 9162 consistency proof (§2.1.4.2).
func VerifyConsistency(oldSize, newSize uint64, oldRoot, newRoot Hash, proof []Hash) error {
	switch {
	case oldSize > newSize:
		return errors.New("old size larger than new size")
	case oldSize == newSize:
		if len(proof) != 0 {
			return errors.New("consistency proof between equal sizes must be empty")
		}
		if oldRoot != newRoot {
			return errors.New("root hashes differ at the same size")
		}
		return nil
	case oldSize == 0:
		if len(proof) != 0 {
			return errors.New("consistency proof from the empty tree must be empty")
		}
		return nil
	case len(proof) == 0:
		return errors.New("consistency proof is empty")
	}

	if oldSize&(oldSize-1) == 0 {
		proof = append([]Hash{oldRoot}, proof...)
	}
	fn, sn := oldSize-1, newSize-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := proof[0], proof[0]
	for _, c := range proof[1:] {
		if sn == 0 {
			return errors.New("consistency proof too long")
		}
		if fn&1 == 1 || fn == sn {
			fr = nodeHash(c, fr)
			sr = nodeHash(c, sr)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = nodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return errors.New("consistency proof too short")
	}
	if fr != oldRoot {
		return errors.New("consistency proof does not match old root hash")
	}
	if sr != newRoot {
		return errors.New("consistency proof does not match new root hash")
	}
	return nil
}
