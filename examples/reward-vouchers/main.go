// Command reward-vouchers runs the reward vouchers use case: stores in a
// shared reward program issue fixed-value vouchers to customers' agents
// and accept each other's, recording both in their own chains without
// keeping any customer data; the program operator settles between stores
// from the chains alone.
//
//	go run ./examples/reward-vouchers [-out DIR]
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"os"
	"path/filepath"
	"time"

	"github.com/eucassoc/deedlog/examples/internal/demo"
)

var stores = []string{"bakery.example", "cafe.example", "bookshop.example"}

// scenario describes what goes wrong during the settlement period.
type scenario struct {
	name string
	// doubleSpend: one agent presents the same voucher at two stores.
	doubleSpend bool
	// offBook: one store issues a voucher without recording it.
	offBook bool
	// expired: one store accepts a voucher after it expired.
	expired bool
}

type result struct {
	stores     []*Store
	witnesses  []*demo.Witness
	wallets    []*Wallet
	program    []byte
	findings   demo.Findings
	statements []Statement
}

func run(sc scenario, days int) (*result, error) {
	clock := demo.NewClock(time.Date(2026, 4, 1, 9, 0, 0, 0, time.UTC))
	res := &result{}
	for _, id := range stores {
		s, err := NewStore(id, clock)
		if err != nil {
			return nil, err
		}
		res.stores = append(res.stores, s)
	}
	var logs []*demo.Log
	for _, s := range res.stores {
		logs = append(logs, s.Log)
	}
	for _, name := range []string{"witness.chamber.example", "witness.consumers.example"} {
		w, err := demo.StartWitness(name, logs...)
		if err != nil {
			return res, err
		}
		res.witnesses = append(res.witnesses, w)
	}
	p := Program{Name: "arcade.example", Value: 100, ValidDays: 7}
	for _, s := range res.stores {
		p.Stores = append(p.Stores, s.Member())
	}
	var err error
	if res.program, err = json.Marshal(p); err != nil {
		return res, err
	}
	for _, s := range res.stores {
		if err := s.Join(p, res.program); err != nil {
			return res, err
		}
	}
	for i := 0; i < 8; i++ {
		w, err := NewWallet()
		if err != nil {
			return res, err
		}
		res.wallets = append(res.wallets, w)
	}

	rng := rand.New(rand.NewPCG(1, 2))
	var kept, offBook, old []byte
	for day := 1; day <= days; day++ {
		if day == 1 {
			// A voucher kept aside until after it expires.
			if old, err = res.stores[0].Issue(res.wallets[2].Key()); err != nil {
				return res, err
			}
		}
		for _, w := range res.wallets {
			s := res.stores[rng.IntN(len(res.stores))]
			clock.Advance(7 * time.Minute)
			if rng.IntN(3) == 0 && w.Count() > 0 {
				if err := w.RedeemAt(s, w.Take(clock.Now())); err != nil {
					return res, err
				}
			}
			if rng.IntN(2) == 0 {
				v, err := s.Issue(w.Key())
				if err != nil {
					return res, err
				}
				w.Add(v)
			}
		}
		switch {
		case day == 5 && sc.doubleSpend:
			// The agent keeps a copy of the voucher it just spent, and
			// presents it again at another store.
			w := res.wallets[0]
			if kept = w.Take(clock.Now()); kept == nil {
				return res, fmt.Errorf("wallet 0 has no voucher on day %d", day)
			}
			if err := w.RedeemAt(res.stores[1], kept); err != nil {
				return res, err
			}
			clock.Advance(10 * time.Minute)
			if err := w.RedeemAt(res.stores[2], kept); err != nil {
				return res, err
			}
		case day == 7 && sc.offBook:
			if offBook, err = res.stores[2].issue(res.wallets[1].Key(), false); err != nil {
				return res, err
			}
		case day == 8 && sc.offBook:
			if err := res.wallets[1].RedeemAt(res.stores[0], offBook); err != nil {
				return res, err
			}
		case day == 12 && sc.expired:
			res.stores[1].SkipExpiry = true
			if err := res.wallets[2].RedeemAt(res.stores[1], old); err != nil {
				return res, err
			}
			res.stores[1].SkipExpiry = false
		}
		clock.Advance(24*time.Hour - time.Duration(len(res.wallets))*7*time.Minute)
	}

	// Settlement: the operator opens each store's witnessed chain and the
	// presentations it submits.
	var claims []*Claim
	for _, s := range res.stores {
		cp, err := s.Log.Checkpoint(context.Background(), res.witnesses...)
		if err != nil {
			return res, err
		}
		entries, _, err := demo.Open(s.Log.Chain(), cp, s.Log.OperatorKey(), demo.Keys(res.witnesses), len(res.witnesses))
		if err != nil {
			return res, err
		}
		claims = append(claims, &Claim{Store: s.ID, Entries: entries, Body: s.Log.Body})
	}
	res.findings, res.statements = Settle(res.program, claims)
	return res, nil
}

func main() {
	out := flag.String("out", "", "directory for the chains, checkpoints and keys (default: a new temporary directory)")
	flag.Parse()
	dir, err := demo.OutDir(*out, "reward-vouchers")
	if err != nil {
		log.Fatal(err)
	}
	for i, sc := range []scenario{
		{name: "two weeks of vouchers, settled"},
		{name: "with a voucher spent twice, one issued off the books and one accepted after expiry", doubleSpend: true, offBook: true, expired: true},
	} {
		res, err := run(sc, 14)
		if err != nil {
			log.Fatal(err)
		}
		records := 0
		for _, s := range res.stores {
			records += int(s.Log.Size())
		}
		fmt.Printf("== %s: %d records in %d chains, checkpoints cosigned by %d witnesses\n", sc.name, records, len(res.stores), len(res.witnesses))
		res.findings.Print(os.Stdout)
		fmt.Printf("\n  %-18s %8s %9s %6s %9s %9s\n", "settlement", "issued", "accepted", "own", "receives", "pays")
		for _, s := range res.statements {
			fmt.Printf("  %-18s %8d %9d %6d %9d %9d\n", s.Store, s.Issued, s.Accepted, s.Own, s.Receives, s.Pays)
		}
		sub := filepath.Join(dir, fmt.Sprint(i+1))
		for _, s := range res.stores {
			if err := demo.Save(os.Stdout, filepath.Join(sub, s.ID), s.Log, res.witnesses); err != nil {
				log.Fatal(err)
			}
			if rs := res.wallets[0].Receipts[s.ID]; len(rs) > 0 {
				if err := demo.SaveReceipt(filepath.Join(sub, s.ID), rs[0]); err != nil {
					log.Fatal(err)
				}
			}
		}
		demo.CloseAll(res.witnesses)
	}
}
