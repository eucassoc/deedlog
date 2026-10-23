package main

import (
	"strings"
	"testing"

	"github.com/deedlog/deedlog/examples/internal/demo"
)

func TestDeliveredAndArbitrated(t *testing.T) {
	res, err := run(scenario{}, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer demo.CloseAll(res.witnesses)
	if len(res.findings) != 0 {
		t.Fatalf("findings: %v", res.findings)
	}
	p := res.purchases[0]
	if v, err := res.dispute(p, p.Body); err != nil || !strings.Contains(v, "exactly this body") {
		t.Fatalf("true body: %q, %v", v, err)
	}
	if v, err := res.dispute(p, []byte("{}")); err != nil || !strings.Contains(v, "NOT") {
		t.Fatalf("other body: %q, %v", v, err)
	}
	// The record of another purchase does not match the receipt.
	other, _ := res.seller.Line(1)
	d := Dispute{Receipt: p.Receipt, Body: p.Body, Checkpoint: res.checkpoint, Record: other}
	r, _ := receiptIndex(p.Receipt, res)
	_, d.Proof, _ = res.seller.Proof(r, res.seller.Size())
	if _, err := Arbitrate(d, res.seller.ReceiptKey(), res.seller.OperatorKey(), demo.Keys(res.witnesses)); err == nil {
		t.Fatal("a substituted record was accepted")
	}
}

func TestFailuresAreFound(t *testing.T) {
	res, err := run(scenario{fails: 3, repeatTx: true}, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer demo.CloseAll(res.witnesses)
	got := ""
	for _, f := range res.findings {
		got += f.String() + "\n"
	}
	for _, want := range []string{"already paid for", "settled, but nothing was delivered"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
}
