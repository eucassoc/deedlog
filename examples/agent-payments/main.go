// Command agent-payments runs the agent payments use case: an AI agent buys
// reports from an API that charges with x402; the seller records what was
// paid for and delivered, the buyer keeps receipts, and an arbiter settles a
// dispute about what was delivered.
//
// Payments are settled by a stand-in facilitator; no blockchain is used.
//
//	go run ./examples/agent-payments [-out DIR]
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"time"

	"github.com/deedlog/deedlog/core"
	"github.com/deedlog/deedlog/examples/internal/demo"
)

type scenario struct {
	name string
	// Report the seller fails to serve after settling payment, or 0.
	fails int
	// Whether the facilitator reports one transaction twice.
	repeatTx bool
}

type result struct {
	seller, agent *demo.Log
	witnesses     []*demo.Witness
	checkpoint    []byte
	purchases     []*Purchase
	findings      demo.Findings
}

func run(sc scenario, reports int) (*result, error) {
	start := time.Date(2026, 4, 1, 9, 0, 0, 0, time.UTC)
	seller, ws, err := demo.Start("api.example/reports", start, "witness.marketplace.example", "witness.auditor.example")
	if err != nil {
		return nil, err
	}
	res := &result{seller: seller, witnesses: ws}
	if res.agent, err = demo.NewLog("agent.example/purchases", seller.Clock); err != nil {
		return res, err
	}

	reportsAPI := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sc.fails != 0 && r.URL.Path == fmt.Sprintf("/reports/%d", sc.fails) {
			http.Error(w, "report generation failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"report":%q,"sales":[120,95,143]}`, r.URL.Path)
	})
	srv := httptest.NewServer(&Paywall{
		Price: Requirements{Scheme: "exact", Network: "base-sepolia", MaxAmountRequired: "10000",
			PayTo: "0xSeller", Asset: "0xUSDC"},
		Facilitator: &StandInFacilitator{Repeat: sc.repeatTx},
		Log:         seller,
		Next:        reportsAPI,
	})
	defer srv.Close()

	agent := &Client{HTTP: srv.Client(), Wallet: Wallet{Address: "0xAgent"}, Log: res.agent, MaxAmount: 50000}
	for i := 1; i <= reports; i++ {
		p, err := agent.Get(fmt.Sprintf("%s/reports/%d", srv.URL, i))
		if err != nil && p == nil {
			return res, err
		}
		res.purchases = append(res.purchases, p)
		seller.Clock.Advance(13 * time.Minute)
	}
	if res.checkpoint, err = seller.Checkpoint(context.Background(), ws...); err != nil {
		return res, err
	}
	entries, _, err := demo.Open(seller.Chain(), res.checkpoint, seller.OperatorKey(), demo.Keys(ws), len(ws))
	if err != nil {
		return res, err
	}
	res.findings = Check(entries)
	return res, nil
}

// dispute builds what the arbiter gets for a purchase, with the body the
// buyer presents.
func (res *result) dispute(p *Purchase, body []byte) (string, error) {
	d := Dispute{Receipt: p.Receipt, Body: body, Checkpoint: res.checkpoint}
	r, err := receiptIndex(p.Receipt, res)
	if err != nil {
		return "", err
	}
	// The seller must produce the record the receipt points to.
	if d.Record, err = res.seller.Line(r); err != nil {
		return "", err
	}
	if _, d.Proof, err = res.seller.Proof(r, res.seller.Size()); err != nil {
		return "", err
	}
	return Arbitrate(d, res.seller.ReceiptKey(), res.seller.OperatorKey(), demo.Keys(res.witnesses))
}

func main() {
	out := flag.String("out", "", "directory for the chains, checkpoints and keys (default: a new temporary directory)")
	flag.Parse()
	dir, err := demo.OutDir(*out, "agent-payments")
	if err != nil {
		log.Fatal(err)
	}
	for i, sc := range []scenario{
		{name: "seller's chain, every purchase delivered"},
		{name: "seller's chain, with a failed delivery and a reused transaction", fails: 3, repeatTx: true},
	} {
		res, err := run(sc, 5)
		if err != nil {
			log.Fatal(err)
		}
		demo.Header(os.Stdout, sc.name, res.seller, res.witnesses)
		res.findings.Print(os.Stdout)
		if i == 0 {
			p := res.purchases[1]
			fmt.Printf("\n  Dispute over %s, buyer presents the body it received:\n", p.Resource)
			verdict, err := res.dispute(p, p.Body)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("  %s\n", verdict)
			fmt.Println("\n  Buyer presents a different body:")
			if verdict, err = res.dispute(p, []byte(`{"report":"/reports/2","sales":[]}`)); err != nil {
				log.Fatal(err)
			}
			fmt.Printf("  %s\n", verdict)
		}
		sub := filepath.Join(dir, fmt.Sprint(i+1))
		if err := demo.Save(os.Stdout, sub, res.seller, res.witnesses); err != nil {
			log.Fatal(err)
		}
		if err := demo.SaveReceipt(sub, res.purchases[1].Receipt); err != nil {
			log.Fatal(err)
		}
		demo.CloseAll(res.witnesses)
	}
}

func receiptIndex(note []byte, res *result) (uint64, error) {
	r, err := core.VerifyReceipt(note, res.seller.ReceiptKey())
	return r.Index, err
}
