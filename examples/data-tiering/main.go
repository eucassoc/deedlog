// Command data-tiering runs the data tiering use case: submissions arrive
// through a contact form, move to an archive and are deleted on schedule,
// and an auditor checks the chain against the declared policy.
//
//	go run ./examples/data-tiering [-out DIR]
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/deedlog/deedlog/core"
	"github.com/deedlog/deedlog/examples/data-tiering/tiering"
	"github.com/deedlog/deedlog/examples/internal/demo"
)

const origin = "city.example/inquiries"

var policy = tiering.Policy{
	Tiers: []tiering.TierRule{
		{Name: "form-service", MaxAgeDays: 7, Next: "archive"},
		{Name: "archive", MaxAgeDays: 30},
	},
	InventoryEveryHours: 24,
}

// scenario describes what goes wrong, if anything.
type scenario struct {
	name string
	// Days on which the job moving data off the form service does not run.
	transferDown map[int]bool
	// Day on which no inventory is taken, or 0.
	skipInventory int
	// Day on which someone copies data into the archive by hand, or 0.
	handCopy int
}

type result struct {
	log        *demo.Log
	witnesses  []*demo.Witness
	checkpoint []byte
	policy     []byte
	receiptURL string
	findings   demo.Findings
}

func (r *result) close() { demo.CloseAll(r.witnesses) }

func run(sc scenario, days int) (*result, error) {
	ctx := context.Background()
	l, ws, err := demo.Start(origin, time.Date(2026, 4, 1, 9, 0, 0, 0, time.UTC), "witness.library.example", "witness.auditor.example")
	if err != nil {
		return nil, err
	}
	res := &result{log: l, witnesses: ws}
	clock := l.Clock

	rec := &tiering.Recorder{Log: l}
	if err := rec.Declare(policy); err != nil {
		return res, err
	}
	res.policy, _ = json.Marshal(policy)
	tiers := map[string]*tiering.Tier{"form-service": tiering.NewTier("form-service"), "archive": tiering.NewTier("archive")}
	hook := &tiering.Webhook{Tier: tiers["form-service"], Recorder: rec, Page: "https://verify.example/"}
	job := &tiering.Job{Policy: policy, Tiers: tiers, Recorder: rec, MoveAfter: 2 * 24 * time.Hour}

	n := 0
	for day := 1; day <= days; day++ {
		// Inquiries arrive through the form service's webhook.
		for i := 0; i < day%3+1; i++ {
			n++
			body := fmt.Sprintf(`{"name":"Resident %d","email":"r%d@example.com","message":"Question about waste collection"}`, n, n)
			w := httptest.NewRecorder()
			hook.ServeHTTP(w, httptest.NewRequest("POST", "/inquiries", strings.NewReader(body)))
			if w.Code != 200 {
				return res, fmt.Errorf("webhook: %s", w.Body)
			}
			if res.receiptURL == "" {
				var resp struct {
					ReceiptURL string `json:"receipt_url"`
				}
				json.Unmarshal(w.Body.Bytes(), &resp)
				res.receiptURL = resp.ReceiptURL
			}
			clock.Advance(37 * time.Minute)
		}
		if day == sc.handCopy {
			// An export copied into the archive by hand, outside the job.
			tiers["archive"].Put([]byte("inquiries-export.csv"), clock.Now())
		}

		clock.Advance(time.Duration(23-clock.Now().Hour()) * time.Hour)
		skip := map[string]bool{"form-service": sc.transferDown[day]}
		if err := job.Run(skip); err != nil {
			return res, err
		}
		if day != sc.skipInventory {
			if err := job.TakeInventory(); err != nil {
				return res, err
			}
		}
		// Weekly, and at the end, witnesses cosign a checkpoint.
		if day%7 == 0 || day == days {
			if res.checkpoint, err = l.Checkpoint(ctx, res.witnesses...); err != nil {
				return res, err
			}
		}
		clock.Advance(10 * time.Hour)
	}

	// The auditor's side: only public material.
	entries, _, err := demo.Open(l.Chain(), res.checkpoint, l.OperatorKey(), demo.Keys(ws), len(ws))
	if err != nil {
		return res, err
	}
	res.findings = tiering.Check(entries, res.policy)
	return res, nil
}

// followReceipt is what the person who submitted the form can do with the
// link they were given: check that the promise holds and see what happened
// to their submission since.
func followReceipt(w io.Writer, res *result) error {
	l := res.log
	note, err := core.ReceiptFromURL(res.receiptURL)
	if err != nil {
		return err
	}
	r, err := core.VerifyReceipt(note, l.ReceiptKey())
	if err != nil {
		return err
	}
	c, err := core.CheckpointOf(res.checkpoint)
	if err != nil {
		return err
	}
	leaf, proof, err := l.Proof(r.Index, c.Size)
	if err != nil {
		return err
	}
	status, _, err := core.CheckReceipt(note, r, res.checkpoint, c, leaf, proof)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "  receipt for record %d: %s in the witnessed checkpoint of size %d\n", r.Index, status, c.Size)

	entries, _, err := demo.Open(l.Chain(), res.checkpoint, l.OperatorKey(), nil, 0)
	if err != nil {
		return err
	}
	mine := entries[r.Index].Subject.Digest["hmac-sha256"]
	for _, e := range entries[r.Index:] {
		if e.Subject.Digest["hmac-sha256"] != mine {
			continue
		}
		where := e.Meta["tier"]
		if e.Meta["event"] == "moved" {
			where = e.Meta["from"] + " -> " + e.Meta["to"]
		}
		fmt.Fprintf(w, "  %s  %-8s %s (line %d)\n", e.CollectedAt.Format("2006-01-02"), e.Meta["event"], where, e.Line)
	}
	return nil
}

func main() {
	out := flag.String("out", "", "directory for the chains, checkpoints and keys (default: a new temporary directory)")
	flag.Parse()
	dir, err := demo.OutDir(*out, "data-tiering")
	if err != nil {
		log.Fatal(err)
	}

	scenarios := []scenario{
		{name: "as declared"},
		{
			name:          "with failures",
			transferDown:  map[int]bool{20: true, 21: true, 22: true, 23: true, 24: true, 25: true, 26: true, 27: true, 28: true},
			skipInventory: 40,
			handCopy:      45,
		},
	}
	for i, sc := range scenarios {
		res, err := run(sc, 60)
		if err != nil {
			log.Fatal(err)
		}
		demo.Header(os.Stdout, sc.name, res.log, res.witnesses)
		res.findings.Print(os.Stdout)
		if i == 0 {
			fmt.Println("\n  The first person's receipt link, followed:")
			if err := followReceipt(os.Stdout, res); err != nil {
				log.Fatal(err)
			}
		}
		sub := filepath.Join(dir, fmt.Sprint(i+1))
		if err := demo.Save(os.Stdout, sub, res.log, res.witnesses); err != nil {
			log.Fatal(err)
		}
		if note, err := core.ReceiptFromURL(res.receiptURL); err != nil || demo.SaveReceipt(sub, note) != nil {
			log.Fatal("cannot save the receipt")
		}
		res.close()
	}
}
