package main

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/deedlog/deedlog/core"
	"github.com/deedlog/deedlog/examples/internal/demo"
)

// Check audits a seller's verified chain: every settled payment must be
// followed by a delivery, and no transaction may pay for two requests.
func Check(entries []demo.Entry) demo.Findings {
	var fs demo.Findings
	settled := make(map[string]demo.Entry)
	delivered := make(map[string]bool)
	for _, e := range entries {
		tx := e.Meta["tx"]
		switch e.Meta["event"] {
		case "payment_required":
		case "settled":
			if prev, ok := settled[tx]; ok {
				fs.Add(e.Line, "transaction %s already paid for %s at line %d", short(tx), prev.Meta["resource"], prev.Line)
				continue
			}
			settled[tx] = e
		case "delivered":
			s, ok := settled[tx]
			if !ok {
				fs.Add(e.Line, "delivery for transaction %s, which was not recorded as settled", short(tx))
				continue
			}
			if s.Meta["resource"] != e.Meta["resource"] {
				fs.Add(e.Line, "delivered %s for a payment for %s (line %d)", e.Meta["resource"], s.Meta["resource"], s.Line)
			}
			delivered[tx] = true
		default:
			fs.Add(e.Line, "unknown event %q", e.Meta["event"])
		}
	}
	for tx, s := range settled {
		if !delivered[tx] {
			fs.Add(s.Line, "payment %s for %s settled, but nothing was delivered", short(tx), s.Meta["resource"])
		}
	}
	return fs.Sorted()
}

func short(tx string) string {
	if len(tx) > 10 {
		return tx[:10]
	}
	return tx
}

// Dispute is what an arbiter needs to settle a dispute about a delivery:
// the buyer's receipt and the body it received, the seller's witnessed
// checkpoint, and the record the receipt points to with its inclusion
// proof, which the seller must produce.
type Dispute struct {
	Receipt    []byte
	Body       []byte
	Checkpoint []byte
	Record     []byte
	Proof      []core.Hash
}

// Arbitrate decides a dispute with the seller's public keys alone.
func Arbitrate(d Dispute, receiptKey, operator *core.Verifier, witnesses []*core.Verifier) (string, error) {
	r, err := core.VerifyReceipt(d.Receipt, receiptKey)
	if err != nil {
		return "", fmt.Errorf("receipt: %w", err)
	}
	c, err := core.VerifyCheckpoint(d.Checkpoint, operator, witnesses, len(witnesses))
	if err != nil {
		return "", fmt.Errorf("checkpoint: %w", err)
	}
	status, proof, err := core.CheckReceipt(d.Receipt, r, d.Checkpoint, c, core.LeafHash(d.Record), d.Proof)
	if err != nil {
		return "", err
	}
	switch status {
	case core.ReceiptNotYetCovered:
		return "", errors.New("the checkpoint does not cover the receipt yet; ask again after the next checkpoint")
	case core.ReceiptBroken:
		b, _ := json.Marshal(proof)
		return "", fmt.Errorf("the seller broke its receipt; proof of misbehavior: %s", b)
	}
	var rec core.Record
	if err := json.Unmarshal(d.Record, &rec); err != nil {
		return "", err
	}
	if rec.Meta["event"] != "delivered" {
		return "", fmt.Errorf("record %d is not a delivery", r.Index)
	}
	if rec.Subject.Digest["sha256"] != demo.Sum(d.Body) {
		return fmt.Sprintf("the body presented is NOT what the seller recorded delivering for transaction %s", rec.Meta["tx"]), nil
	}
	return fmt.Sprintf("the seller recorded delivering exactly this body for %s, paid by transaction %s",
		rec.Meta["resource"], rec.Meta["tx"]), nil
}
