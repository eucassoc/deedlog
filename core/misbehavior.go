package core

import (
	"encoding/base64"
	"errors"
	"fmt"
)

// MisbehaviorType identifies the proof format of spec/checkpoint.md §6.
const MisbehaviorType = "deedlog-misbehavior/v1"

// MisbehaviorProof shows that an operator signed two checkpoints that
// cannot both be true (spec/checkpoint.md §6).
type MisbehaviorProof struct {
	Type        string     `json:"type"`
	Checkpoints []string   `json:"checkpoints"`
	Receipt     string     `json:"receipt,omitempty"`
	Index       *uint64    `json:"index,omitempty"`
	LeafHashes  []string   `json:"leaf_hashes,omitempty"`
	Proofs      [][]string `json:"proofs,omitempty"`
}

// CheckMisbehavior verifies a proof of misbehavior against the operator's
// checkpoint key and, for proofs with a receipt, its receipt key (nil
// otherwise). It returns a description of the misbehavior if the proof
// holds, and an error if it does not prove anything.
func CheckMisbehavior(p MisbehaviorProof, operator, receiptKey *Verifier) (string, error) {
	if p.Type != MisbehaviorType {
		return "", fmt.Errorf("unsupported proof type %q", p.Type)
	}
	if p.Receipt != "" {
		return checkReceiptMisbehavior(p, operator, receiptKey)
	}
	if len(p.Checkpoints) != 2 {
		return "", errors.New("a proof needs exactly two checkpoints")
	}
	var cps [2]Checkpoint
	for i, note := range p.Checkpoints {
		c, err := VerifyCheckpoint([]byte(note), operator, nil, 0)
		if err != nil {
			return "", fmt.Errorf("checkpoint %d: %w", i+1, err)
		}
		cps[i] = c
	}
	a, b := cps[0], cps[1]
	if a.Origin != b.Origin {
		return "", errors.New("checkpoints are for different origins")
	}

	if a.Size == b.Size {
		if a.Root == b.Root {
			return "", errors.New("checkpoints are identical")
		}
		return fmt.Sprintf("%s signed two different root hashes for tree size %d", a.Origin, a.Size), nil
	}

	if p.Index == nil || len(p.LeafHashes) != 2 || len(p.Proofs) != 2 {
		return "", errors.New("checkpoints of different sizes need an index, two leaf hashes and two inclusion proofs")
	}
	index := *p.Index
	if index >= a.Size || index >= b.Size {
		return "", fmt.Errorf("index %d is not covered by both checkpoints", index)
	}
	var leaves [2]Hash
	for i := range 2 {
		leaf, err := decodeHash(p.LeafHashes[i])
		if err != nil {
			return "", fmt.Errorf("leaf hash %d: %w", i+1, err)
		}
		proof := make([]Hash, len(p.Proofs[i]))
		for j, s := range p.Proofs[i] {
			if proof[j], err = decodeHash(s); err != nil {
				return "", fmt.Errorf("proof %d: %w", i+1, err)
			}
		}
		if err := VerifyInclusion(index, cps[i].Size, leaf, proof, cps[i].Root); err != nil {
			return "", fmt.Errorf("proof %d: %w", i+1, err)
		}
		leaves[i] = leaf
	}
	if leaves[0] == leaves[1] {
		return "", fmt.Errorf("both checkpoints include the same record at index %d", index)
	}
	return fmt.Sprintf("%s signed checkpoints of sizes %d and %d with different records at index %d",
		a.Origin, a.Size, b.Size, index), nil
}

// BuildMisbehaviorProof compares two signed checkpoints and the leaf hashes
// of the chains they were taken from, and returns a proof of misbehavior if
// the operator signed inconsistent checkpoints. It returns an error if the
// checkpoints are consistent with each other.
func BuildMisbehaviorProof(noteA []byte, leavesA []Hash, noteB []byte, leavesB []Hash, operator *Verifier) (MisbehaviorProof, error) {
	p := MisbehaviorProof{Type: MisbehaviorType, Checkpoints: []string{string(noteA), string(noteB)}}
	a, err := VerifyCheckpoint(noteA, operator, nil, 0)
	if err != nil {
		return p, fmt.Errorf("checkpoint A: %w", err)
	}
	b, err := VerifyCheckpoint(noteB, operator, nil, 0)
	if err != nil {
		return p, fmt.Errorf("checkpoint B: %w", err)
	}
	if a.Size == b.Size && a.Root != b.Root {
		return p, nil
	}
	for i, pair := range []struct {
		c      Checkpoint
		leaves []Hash
	}{{a, leavesA}, {b, leavesB}} {
		if uint64(len(pair.leaves)) < pair.c.Size || Root(pair.leaves[:pair.c.Size]) != pair.c.Root {
			return p, fmt.Errorf("chain %c does not match its checkpoint", 'A'+i)
		}
	}
	n := min(a.Size, b.Size)
	for i := range n {
		if leavesA[i] == leavesB[i] {
			continue
		}
		proofA, _ := InclusionProof(leavesA[:a.Size], i)
		proofB, _ := InclusionProof(leavesB[:b.Size], i)
		p.Index = &i
		p.LeafHashes = []string{encodeHash(leavesA[i]), encodeHash(leavesB[i])}
		p.Proofs = [][]string{encodeHashes(proofA), encodeHashes(proofB)}
		return p, nil
	}
	return p, errors.New("checkpoints are consistent")
}

func encodeHash(h Hash) string { return base64.StdEncoding.EncodeToString(h[:]) }

func encodeHashes(hs []Hash) []string {
	out := make([]string, len(hs))
	for i, h := range hs {
		out[i] = encodeHash(h)
	}
	return out
}

func decodeHash(s string) (Hash, error) {
	b, err := decodeBase64(s)
	if err != nil || len(b) != len(Hash{}) {
		return Hash{}, fmt.Errorf("invalid hash %q", s)
	}
	return Hash(b), nil
}

// checkReceiptMisbehavior checks form 3 of spec/checkpoint.md §6.
func checkReceiptMisbehavior(p MisbehaviorProof, operator, receiptKey *Verifier) (string, error) {
	if receiptKey == nil {
		return "", errors.New("a proof with a receipt needs the operator's receipt key")
	}
	if len(p.Checkpoints) != 1 || p.Index == nil || len(p.LeafHashes) != 1 || len(p.Proofs) != 1 {
		return "", errors.New("a proof with a receipt needs one checkpoint, an index, a leaf hash and an inclusion proof")
	}
	r, err := VerifyReceipt([]byte(p.Receipt), receiptKey)
	if err != nil {
		return "", fmt.Errorf("receipt: %w", err)
	}
	c, err := VerifyCheckpoint([]byte(p.Checkpoints[0]), operator, nil, 0)
	if err != nil {
		return "", fmt.Errorf("checkpoint: %w", err)
	}
	if r.Origin != c.Origin {
		return "", errors.New("receipt and checkpoint are for different origins")
	}
	if *p.Index != r.Index {
		return "", errors.New("index differs from the receipt's")
	}
	if r.Index >= c.Size {
		return "", fmt.Errorf("index %d is not covered by the checkpoint of size %d", r.Index, c.Size)
	}
	leaf, err := decodeHash(p.LeafHashes[0])
	if err != nil {
		return "", err
	}
	proof := make([]Hash, len(p.Proofs[0]))
	for j, s := range p.Proofs[0] {
		if proof[j], err = decodeHash(s); err != nil {
			return "", err
		}
	}
	if err := VerifyInclusion(r.Index, c.Size, leaf, proof, c.Root); err != nil {
		return "", fmt.Errorf("inclusion proof: %w", err)
	}
	if leaf == r.LeafHash {
		return "", errors.New("the checkpoint includes the promised record")
	}
	return fmt.Sprintf("%s promised a record at index %d, but its checkpoint of size %d has a different record there",
		c.Origin, r.Index, c.Size), nil
}
