// Command environmental-value runs the proof of environmental value use
// case: meter readings are recorded, aggregated into monthly reports,
// verified, issued as certificates and claimed, and an auditor traces each
// certificate back to the readings behind it.
//
//	go run ./examples/environmental-value [-out DIR]
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/eucassoc/deedlog/core"
	"github.com/eucassoc/deedlog/examples/internal/demo"
)

type scenario struct {
	name string
	// kWh added to the second report.
	inflate float64
	// Readings from the first month counted again in the second report.
	doubleCount int
	// Whether a second company claims the first certificate.
	doubleClaim bool
}

type result struct {
	meter, mrv  *demo.Log
	witnesses   []*demo.Witness
	checkpoints [2][]byte
	findings    demo.Findings
}

func run(sc scenario) (*result, error) {
	clock := demo.NewClock(time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC))
	meterLog, err := demo.NewLog("solar.example/meters", clock)
	if err != nil {
		return nil, err
	}
	mrvLog, err := demo.NewLog("solar.example/mrv", clock)
	if err != nil {
		return nil, err
	}
	res := &result{meter: meterLog, mrv: mrvLog}
	for _, name := range []string{"witness.registry.example", "witness.verifier.example"} {
		w, err := demo.StartWitness(name, meterLog, mrvLog)
		if err != nil {
			return res, err
		}
		res.witnesses = append(res.witnesses, w)
	}
	metering, mrv := &Metering{Log: meterLog}, &MRV{Log: mrvLog}

	var months [2][]Ref
	var totals [2]float64
	seq := 0
	for m := 0; m < 2; m++ {
		for day := 0; day < 30; day++ {
			for _, meter := range []string{"pv-1", "pv-2", "pv-3"} {
				seq++
				r := Reading{Meter: meter, Seq: seq, KWh: 110 + float64(seq%17)}
				ref, err := metering.Record(r)
				if err != nil {
					return res, err
				}
				months[m] = append(months[m], ref)
				totals[m] += r.KWh
			}
			clock.Advance(24 * time.Hour)
		}
	}
	if sc.doubleCount > 0 {
		months[1] = append(months[1], months[0][:sc.doubleCount]...)
		for _, ref := range months[0][:sc.doubleCount] {
			// The double-counted readings are added to the total, so the
			// report adds up; only the trace reveals it.
			totals[1] += 110 + float64((int(ref.Index)+1)%17)
		}
	}
	totals[1] += sc.inflate

	ctx := context.Background()
	if res.checkpoints[0], err = meterLog.Checkpoint(ctx, res.witnesses...); err != nil {
		return res, err
	}
	var certs []string
	for m, period := range []string{"2026-04", "2026-05"} {
		report, err := mrv.Report(Report{Period: period, TotalKWh: totals[m], Inputs: months[m]})
		if err != nil {
			return res, err
		}
		stmt, err := mrv.Verified(Statement{Report: demo.Sum(report), VerifiedKWh: totals[m]}, "verifier.example")
		if err != nil {
			return res, err
		}
		id := fmt.Sprintf("REC-%s-%04d", period, m+1)
		if _, err := mrv.Issued(Certificate{ID: id, Statement: demo.Sum(stmt), MWh: int(math.Floor(totals[m] / 1000))}, "registry.example"); err != nil {
			return res, err
		}
		certs = append(certs, id)
	}
	if _, err := mrv.Claimed(Claim{Certificate: certs[0], Claimant: "maker.example", Year: 2026}); err != nil {
		return res, err
	}
	if sc.doubleClaim {
		if _, err := mrv.Claimed(Claim{Certificate: certs[0], Claimant: "retailer.example", Year: 2026}); err != nil {
			return res, err
		}
	}
	if res.checkpoints[1], err = mrvLog.Checkpoint(ctx, res.witnesses...); err != nil {
		return res, err
	}

	// The auditor's side: both chains against their witnessed checkpoints,
	// and the evidence bodies.
	keys := demo.Keys(res.witnesses)
	meterEntries, mc, err := demo.Open(meterLog.Chain(), res.checkpoints[0], meterLog.OperatorKey(), keys, len(keys))
	if err != nil {
		return res, err
	}
	_, leaves, err := core.VerifyLeaves(bytes.NewReader(meterLog.Chain()))
	if err != nil {
		return res, err
	}
	mrvEntries, _, err := demo.Open(mrvLog.Chain(), res.checkpoints[1], mrvLog.OperatorKey(), keys, len(keys))
	if err != nil {
		return res, err
	}
	body := func(d string) ([]byte, bool) {
		if b, ok := mrvLog.Body(d); ok {
			return b, true
		}
		return meterLog.Body(d)
	}
	res.findings = Check(mrvEntries, meterEntries, leaves[:mc.Size], body)
	return res, nil
}

func main() {
	out := flag.String("out", "", "directory for the chains, checkpoints and keys (default: a new temporary directory)")
	flag.Parse()
	dir, err := demo.OutDir(*out, "environmental-value")
	if err != nil {
		log.Fatal(err)
	}
	for i, sc := range []scenario{
		{name: "traceable to the readings"},
		{name: "an inflated report, double counting and a double claim", inflate: 1500, doubleCount: 6, doubleClaim: true},
	} {
		res, err := run(sc)
		if err != nil {
			log.Fatal(err)
		}
		demo.Header(os.Stdout, sc.name+" (MRV chain)", res.mrv, res.witnesses)
		res.findings.Print(os.Stdout)
		for _, l := range []*demo.Log{res.meter, res.mrv} {
			if err := demo.Save(os.Stdout, filepath.Join(dir, fmt.Sprint(i+1), filepath.Base(l.Origin)), l, res.witnesses); err != nil {
				log.Fatal(err)
			}
		}
		demo.CloseAll(res.witnesses)
	}
}
