package main

import (
	"strings"
	"testing"
	"time"

	"github.com/deedlog/deedlog/core"
	"github.com/deedlog/deedlog/examples/internal/demo"
)

func TestSettles(t *testing.T) {
	res, err := run(scenario{}, 14)
	if err != nil {
		t.Fatal(err)
	}
	defer demo.CloseAll(res.witnesses)
	if len(res.findings) != 0 {
		t.Fatalf("findings: %v", res.findings)
	}
	receives, pays, accepted := 0, 0, 0
	for _, s := range res.statements {
		receives += s.Receives
		pays += s.Pays
		accepted += s.Accepted
	}
	if accepted == 0 || receives != pays {
		t.Fatalf("settlement does not balance: %+v", res.statements)
	}
	// The holder's receipts are for redemption records in the stores'
	// chains.
	n := 0
	for _, s := range res.stores {
		for _, note := range res.wallets[0].Receipts[s.ID] {
			r, err := core.VerifyReceipt(note, s.Log.ReceiptKey())
			if err != nil {
				t.Fatal(err)
			}
			line, err := s.Log.Line(r.Index)
			if err != nil || !strings.Contains(string(line), `"event":"redeemed"`) {
				t.Fatalf("receipt %d of %s: %s, %v", r.Index, s.ID, line, err)
			}
			n++
		}
	}
	if n == 0 {
		t.Fatal("wallet 0 holds no receipt")
	}
}

func TestFailuresAreFound(t *testing.T) {
	res, err := run(scenario{doubleSpend: true, offBook: true, expired: true}, 14)
	if err != nil {
		t.Fatal(err)
	}
	defer demo.CloseAll(res.witnesses)
	got := ""
	for _, f := range res.findings {
		got += f.String() + "\n"
	}
	for _, want := range []string{
		"bookshop.example: voucher already redeemed at cafe.example line",
		"bakery.example: voucher signed with bookshop.example's key, but bookshop.example never recorded issuing it",
		"cafe.example: voucher from bakery.example (line 2) expired",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if len(res.findings) != 3 {
		t.Errorf("want 3 findings, got\n%s", got)
	}
	receives, pays := 0, 0
	for _, s := range res.statements {
		receives += s.Receives
		pays += s.Pays
	}
	if receives != pays {
		t.Fatalf("settlement does not balance: %+v", res.statements)
	}
}

func TestStoreRejectsAtTheCounter(t *testing.T) {
	res, err := run(scenario{}, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer demo.CloseAll(res.witnesses)
	s, other := res.stores[0], res.stores[1]
	w, _ := NewWallet()
	v, err := s.Issue(w.Key())
	if err != nil {
		t.Fatal(err)
	}
	// Someone else's wallet cannot present the voucher.
	thief, _ := NewWallet()
	if err := thief.RedeemAt(other, v); err == nil || !strings.Contains(err.Error(), "holder") {
		t.Fatalf("thief: %v", err)
	}
	if err := w.RedeemAt(other, v); err != nil {
		t.Fatal(err)
	}
	// The same store does not take the same voucher twice.
	if err := w.RedeemAt(other, v); err == nil || !strings.Contains(err.Error(), "already") {
		t.Fatalf("second presentation: %v", err)
	}
	// An expired voucher is refused.
	s.Log.Clock.Advance(8 * 24 * time.Hour)
	v2, _ := s.Issue(w.Key())
	s.Log.Clock.Advance(8 * 24 * time.Hour)
	if err := w.RedeemAt(s, v2); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired: %v", err)
	}
}
