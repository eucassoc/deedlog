// Command municipal-data-platform runs the municipal data platform use
// case: residents give and withdraw consent, services request their data
// through the platform's API, and an auditor checks that every provision
// was covered by consent and stayed within its tenant.
//
//	go run ./examples/municipal-data-platform [-out DIR]
package main

import (
	"bytes"
	"context"
	"encoding/json"
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
	name             string
	ignoreWithdrawal bool
	looseScope       bool
}

type result struct {
	log        *demo.Log
	witnesses  []*demo.Witness
	checkpoint []byte
	withdrawal []byte // a resident's receipt for withdrawing consent
	findings   demo.Findings
}

const purpose = "childcare support eligibility"

func run(sc scenario, days int) (*result, error) {
	l, ws, err := demo.Start("platform.example/data", time.Date(2026, 4, 1, 9, 0, 0, 0, time.UTC),
		"witness.privacy-officer.city-a.example", "witness.privacy-officer.city-b.example")
	if err != nil {
		return nil, err
	}
	res := &result{log: l, witnesses: ws}
	p := &Platform{Recorder: &Recorder{Log: l}}
	p.Bugs.IgnoreWithdrawal, p.Bugs.LooseScope = sc.ignoreWithdrawal, sc.looseScope
	api := httptest.NewServer(p.Handler())
	defer api.Close()

	var residents []Consent
	for i := 1; i <= 6; i++ {
		c := Consent{Resident: fmt.Sprintf("city-a resident %d", i), Tenant: "city-a", Service: "childcare-support", Purpose: purpose}
		residents = append(residents, c)
		if _, err := p.Give(c); err != nil {
			return res, err
		}
	}

	request := func(req Request) error {
		body, _ := json.Marshal(req)
		resp, err := api.Client().Post(api.URL, "application/json", bytes.NewReader(body))
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusForbidden {
			return fmt.Errorf("data API: %s", resp.Status)
		}
		return nil
	}
	for day := 1; day <= days; day++ {
		l.Clock.Advance(24 * time.Hour)
		if day == 3 {
			if res.withdrawal, err = p.Withdraw(residents[2]); err != nil {
				return res, err
			}
		}
		for _, c := range residents {
			if err := request(Request{Service: c.Service, ServiceTenant: "city-a", Resident: c.Resident, Tenant: c.Tenant, Purpose: c.Purpose}); err != nil {
				return res, err
			}
		}
		// Another tenant's service tries a resident of city-a.
		if err := request(Request{Service: "mobility-app", ServiceTenant: "city-b", Resident: residents[0].Resident, Tenant: "city-a", Purpose: purpose}); err != nil {
			return res, err
		}
	}
	if res.checkpoint, err = l.Checkpoint(context.Background(), ws...); err != nil {
		return res, err
	}
	entries, _, err := demo.Open(l.Chain(), res.checkpoint, l.OperatorKey(), demo.Keys(ws), len(ws))
	if err != nil {
		return res, err
	}
	res.findings = Check(entries)
	return res, nil
}

// checkWithdrawal is what the resident, or a privacy officer on their
// behalf, does with the receipt for withdrawing consent: confirm that the
// withdrawal is in the witnessed record, where the platform can no longer
// remove it.
func (res *result) checkWithdrawal() (string, error) {
	r, err := core.VerifyReceipt(res.withdrawal, res.log.ReceiptKey())
	if err != nil {
		return "", err
	}
	c, err := core.VerifyCheckpoint(res.checkpoint, res.log.OperatorKey(), demo.Keys(res.witnesses), len(res.witnesses))
	if err != nil {
		return "", err
	}
	leaf, proof, err := res.log.Proof(r.Index, c.Size)
	if err != nil {
		return "", err
	}
	status, _, err := core.CheckReceipt(res.withdrawal, r, res.checkpoint, c, leaf, proof)
	return fmt.Sprintf("withdrawal receipt for record %d: %s in the checkpoint cosigned by both privacy officers", r.Index, status), err
}

func main() {
	out := flag.String("out", "", "directory for the chains, checkpoints and keys (default: a new temporary directory)")
	flag.Parse()
	dir, err := demo.OutDir(*out, "municipal-data-platform")
	if err != nil {
		log.Fatal(err)
	}
	for i, sc := range []scenario{
		{name: "consent respected"},
		{name: "a cached consent and a loose consent check", ignoreWithdrawal: true, looseScope: true},
	} {
		res, err := run(sc, 7)
		if err != nil {
			log.Fatal(err)
		}
		demo.Header(os.Stdout, sc.name, res.log, res.witnesses)
		res.findings.Print(os.Stdout)
		if i == 0 {
			msg, err := res.checkWithdrawal()
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("\n  %s\n", msg)
		}
		sub := filepath.Join(dir, fmt.Sprint(i+1))
		if err := demo.Save(os.Stdout, sub, res.log, res.witnesses); err != nil {
			log.Fatal(err)
		}
		if err := demo.SaveReceipt(sub, res.withdrawal); err != nil {
			log.Fatal(err)
		}
		demo.CloseAll(res.witnesses)
	}
}
