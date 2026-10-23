package core

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Test vectors from RFC 6962 implementations
// (github.com/transparency-dev/merkle/testonly).
var (
	vectorLeaves = []string{"", "00", "10", "2021", "3031", "40414243",
		"5051525354555657", "606162636465666768696a6b6c6d6e6f"}
	vectorRoots = []string{
		"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
		"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
		"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
		"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
		"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
		"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
		"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
		"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
	}
)

func TestRootVectors(t *testing.T) {
	if got := hex.EncodeToString(EmptyRoot[:]); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("empty root = %s", got)
	}
	var leaves []Hash
	for i, in := range vectorLeaves {
		leaves = append(leaves, LeafHash(mustHex(t, in)))
		root := Root(leaves)
		if got := hex.EncodeToString(root[:]); got != vectorRoots[i] {
			t.Errorf("root of %d leaves = %s, want %s", i+1, got, vectorRoots[i])
		}
	}
}

func testLeaves(n int) []Hash {
	leaves := make([]Hash, n)
	for i := range leaves {
		leaves[i] = LeafHash(fmt.Appendf(nil, "leaf %d", i))
	}
	return leaves
}

// The proofs are generated recursively (RFC 9162 §2.1.3.1, §2.1.4.1) and
// verified iteratively (§2.1.3.2, §2.1.4.2), so agreement over many sizes
// cross-checks both algorithms.
func TestInclusionProofs(t *testing.T) {
	all := testLeaves(70)
	for n := 1; n <= len(all); n++ {
		leaves := all[:n]
		root := Root(leaves)
		for i := range n {
			proof, err := InclusionProof(leaves, uint64(i))
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyInclusion(uint64(i), uint64(n), leaves[i], proof, root); err != nil {
				t.Fatalf("size %d index %d: %v", n, i, err)
			}
			for j := range proof {
				bad := append([]Hash(nil), proof...)
				bad[j][0] ^= 1
				if VerifyInclusion(uint64(i), uint64(n), leaves[i], bad, root) == nil {
					t.Fatalf("size %d index %d: tampered proof element %d verified", n, i, j)
				}
			}
			if VerifyInclusion(uint64(i), uint64(n), all[n%len(all)], proof, root) == nil && all[n%len(all)] != leaves[i] {
				t.Fatalf("size %d index %d: wrong leaf verified", n, i)
			}
			if n > 1 && VerifyInclusion(uint64((i+1)%n), uint64(n), leaves[i], proof, root) == nil {
				t.Fatalf("size %d index %d: proof verified at wrong index", n, i)
			}
		}
	}
}

func TestConsistencyProofs(t *testing.T) {
	all := testLeaves(70)
	for n := 1; n <= len(all); n++ {
		newRoot := Root(all[:n])
		for m := 0; m <= n; m++ {
			oldRoot := Root(all[:m])
			proof, err := ConsistencyProof(all[:n], uint64(m))
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyConsistency(uint64(m), uint64(n), oldRoot, newRoot, proof); err != nil {
				t.Fatalf("%d -> %d: %v", m, n, err)
			}
			for j := range proof {
				bad := append([]Hash(nil), proof...)
				bad[j][0] ^= 1
				if VerifyConsistency(uint64(m), uint64(n), oldRoot, newRoot, bad) == nil {
					t.Fatalf("%d -> %d: tampered proof element %d verified", m, n, j)
				}
			}
			if m > 0 && m < n {
				wrong := oldRoot
				wrong[0] ^= 1
				if VerifyConsistency(uint64(m), uint64(n), wrong, newRoot, proof) == nil {
					t.Fatalf("%d -> %d: wrong old root verified", m, n)
				}
				if VerifyConsistency(uint64(m), uint64(n), oldRoot, wrong, proof) == nil {
					t.Fatalf("%d -> %d: wrong new root verified", m, n)
				}
			}
		}
	}
}

func TestProofArguments(t *testing.T) {
	leaves := testLeaves(4)
	if _, err := InclusionProof(leaves, 4); err == nil {
		t.Error("inclusion proof for index out of range")
	}
	if _, err := ConsistencyProof(leaves, 5); err == nil {
		t.Error("consistency proof for old size larger than tree")
	}
	if VerifyInclusion(4, 4, leaves[0], nil, Root(leaves)) == nil {
		t.Error("inclusion verified for index out of range")
	}
	if VerifyConsistency(5, 4, EmptyRoot, Root(leaves), nil) == nil {
		t.Error("consistency verified for shrinking tree")
	}
}
