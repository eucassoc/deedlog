// Package verifier checks receipts for verification pages run by third
// parties: which operators and witnesses to trust comes from the page's
// registry, and what to check comes from the receipt (spec/checkpoint.md §7
// and §9).
package verifier

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/deedlog/deedlog/core"
)

// Registry is a verification page's trust configuration.
type Registry struct {
	Witnesses []string   `json:"witnesses"` // witness verifier keys
	Quorum    int        `json:"quorum"`    // cosignatures required
	Operators []Operator `json:"operators"`

	witnesses []*core.Verifier
	byOrigin  map[string]*Operator
}

// Operator is an operator the page knows.
type Operator struct {
	Name          string `json:"name"`           // shown to people
	Origin        string `json:"origin"`         // chain origin
	CheckpointKey string `json:"checkpoint_key"` // verifier key
	ReceiptKey    string `json:"receipt_key"`    // verifier key
	URL           string `json:"url"`            // publication base URL (§9)

	checkpointKey, receiptKey *core.Verifier
}

// ParseRegistry parses and validates a registry.
func ParseRegistry(b []byte) (*Registry, error) {
	var r Registry
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	for _, w := range r.Witnesses {
		v, err := core.NewVerifier(w)
		if err != nil {
			return nil, fmt.Errorf("registry witness %q: %w", w, err)
		}
		r.witnesses = append(r.witnesses, v)
	}
	if r.Quorum < 0 || r.Quorum > len(r.witnesses) {
		return nil, fmt.Errorf("registry quorum %d with %d witnesses", r.Quorum, len(r.witnesses))
	}
	r.byOrigin = make(map[string]*Operator)
	for i := range r.Operators {
		op := &r.Operators[i]
		var err error
		if op.checkpointKey, err = core.NewVerifier(op.CheckpointKey); err != nil {
			return nil, fmt.Errorf("registry operator %q: checkpoint key: %w", op.Origin, err)
		}
		if op.receiptKey, err = core.NewVerifier(op.ReceiptKey); err != nil {
			return nil, fmt.Errorf("registry operator %q: receipt key: %w", op.Origin, err)
		}
		if op.checkpointKey.Name() != op.Origin {
			return nil, fmt.Errorf("registry operator %q: checkpoint key is for %q", op.Origin, op.checkpointKey.Name())
		}
		if !strings.HasPrefix(op.URL, "https://") && !strings.HasPrefix(op.URL, "http://") {
			return nil, fmt.Errorf("registry operator %q: invalid URL", op.Origin)
		}
		r.byOrigin[op.Origin] = op
	}
	return &r, nil
}

// Receipt is a receipt whose signature has been verified against a known
// operator's receipt key.
type Receipt struct {
	Note     []byte
	Receipt  core.Receipt
	Operator *Operator
}

// OpenReceipt verifies a signed receipt against the registry.
func (r *Registry) OpenReceipt(note []byte) (*Receipt, error) {
	text, _, ok := strings.Cut(string(note), "\n\n")
	if !ok {
		return nil, errors.New("not a signed receipt")
	}
	parsed, err := core.ParseReceipt([]byte(text + "\n"))
	if err != nil {
		return nil, err
	}
	op, ok := r.byOrigin[parsed.Origin]
	if !ok {
		return nil, fmt.Errorf("this page does not know the operator of %q", parsed.Origin)
	}
	rc, err := core.VerifyReceipt(note, op.receiptKey)
	if err != nil {
		return nil, fmt.Errorf("the receipt's signature is not valid for %s: %w", op.Name, err)
	}
	return &Receipt{Note: note, Receipt: rc, Operator: op}, nil
}

// VerifyCheckpoint verifies a checkpoint published by the receipt's
// operator, with the registry's witnesses and quorum.
func (r *Registry) VerifyCheckpoint(rc *Receipt, note []byte) (core.Checkpoint, error) {
	c, err := core.VerifyCheckpoint(note, rc.Operator.checkpointKey, r.witnesses, r.Quorum)
	if err != nil {
		return c, fmt.Errorf("the published checkpoint is not valid: %w", err)
	}
	return c, nil
}

// Result is the outcome of checking a receipt.
type Result struct {
	Status         string                 `json:"status"` // included, pending or broken
	Origin         string                 `json:"origin"`
	Operator       string                 `json:"operator"`
	Index          uint64                 `json:"index"`
	CheckpointSize uint64                 `json:"checkpoint_size"`
	Misbehavior    *core.MisbehaviorProof `json:"misbehavior,omitempty"`
}

// Check checks a receipt against a checkpoint and, if the checkpoint covers
// the receipt, the proof text served by the operator (§9: the leaf hash,
// then the inclusion proof, one base64 hash per line).
func (r *Registry) Check(rc *Receipt, checkpointNote []byte, proofText string) (*Result, error) {
	c, err := r.VerifyCheckpoint(rc, checkpointNote)
	if err != nil {
		return nil, err
	}
	res := &Result{Origin: rc.Receipt.Origin, Operator: rc.Operator.Name, Index: rc.Receipt.Index, CheckpointSize: c.Size}
	var leaf core.Hash
	var proof []core.Hash
	if rc.Receipt.Index < c.Size {
		lines := strings.Fields(proofText)
		if len(lines) == 0 {
			return nil, errors.New("the operator returned no proof")
		}
		for i, line := range lines {
			b, err := base64.StdEncoding.DecodeString(line)
			if err != nil || len(b) != len(core.Hash{}) {
				return nil, fmt.Errorf("the operator returned a malformed proof (line %d)", i+1)
			}
			if i == 0 {
				leaf = core.Hash(b)
			} else {
				proof = append(proof, core.Hash(b))
			}
		}
	}
	status, mp, err := core.CheckReceipt(rc.Note, rc.Receipt, checkpointNote, c, leaf, proof)
	if err != nil {
		return nil, fmt.Errorf("the operator returned an invalid proof: %w", err)
	}
	switch status {
	case core.ReceiptIncluded:
		res.Status = "included"
	case core.ReceiptNotYetCovered:
		res.Status = "pending"
	case core.ReceiptBroken:
		res.Status = "broken"
		res.Misbehavior = mp
	}
	return res, nil
}
