package main

import (
	"encoding/base64"
	"encoding/json"
	"math"

	"github.com/deedlog/deedlog/core"
	"github.com/deedlog/deedlog/examples/internal/demo"
)

// Check traces every certificate in a verified MRV chain back to the
// readings in a verified metering chain: each report must add up its
// readings, each reading may count once, verification may not exceed the
// report, issuance may not exceed verification, and each certificate may
// be claimed once. meter holds the metering records covered by its
// checkpoint, with their leaf hashes; body returns evidence bodies by
// digest.
func Check(mrv, meter []demo.Entry, meterLeaves []core.Hash, body func(string) ([]byte, bool)) demo.Findings {
	var fs demo.Findings
	if len(meter) == 0 {
		fs.Add(0, "the metering chain is empty")
		return fs
	}
	meterOrigin := meter[0].Chain
	open := func(e demo.Entry, v any) bool {
		b, ok := body("sha256:" + e.Subject.Digest["sha256"])
		if !ok || json.Unmarshal(b, v) != nil {
			fs.Add(e.Line, "the evidence body is missing or malformed")
			return false
		}
		return true
	}
	counted := make(map[uint64]int) // reading index -> line of the report
	reports := make(map[string]Report)
	statements := make(map[string]Statement)
	certificates := make(map[string]bool)
	claimed := make(map[string]demo.Entry)

	for _, e := range mrv {
		digest := e.Subject.Digest["sha256"]
		switch e.Meta["event"] {
		case "report":
			var r Report
			if !open(e, &r) {
				continue
			}
			sum := 0.0
			for _, in := range r.Inputs {
				if in.Chain != meterOrigin || in.Index >= uint64(len(meter)) {
					fs.Add(e.Line, "input %s/%d is not covered by the metering checkpoint", in.Chain, in.Index)
					continue
				}
				if in.Leaf != base64.StdEncoding.EncodeToString(meterLeaves[in.Index][:]) {
					fs.Add(e.Line, "input %d does not match the metering record at that index", in.Index)
					continue
				}
				if line, ok := counted[in.Index]; ok {
					fs.Add(e.Line, "reading %d counted again; the report at line %d already counted it", in.Index, line)
					continue
				}
				counted[in.Index] = e.Line
				var rd Reading
				if b, ok := body("sha256:" + meter[in.Index].Subject.Digest["sha256"]); ok && json.Unmarshal(b, &rd) == nil {
					sum += rd.KWh
				}
			}
			if math.Abs(sum-r.TotalKWh) > 0.001 {
				fs.Add(e.Line, "report for %s claims %.1f kWh; its readings add up to %.1f kWh", r.Period, r.TotalKWh, sum)
			}
			reports[digest] = r
		case "verified":
			var s Statement
			if !open(e, &s) {
				continue
			}
			r, ok := reports[s.Report]
			if !ok {
				fs.Add(e.Line, "statement about a report that is not in the chain")
				continue
			}
			if s.VerifiedKWh > r.TotalKWh {
				fs.Add(e.Line, "verified %.1f kWh, more than the %.1f kWh reported", s.VerifiedKWh, r.TotalKWh)
			}
			statements[digest] = s
		case "issued":
			var c Certificate
			if !open(e, &c) {
				continue
			}
			s, ok := statements[c.Statement]
			if !ok {
				fs.Add(e.Line, "certificate %s rests on no verifier's statement in the chain", c.ID)
				continue
			}
			if float64(c.MWh)*1000 > s.VerifiedKWh {
				fs.Add(e.Line, "certificate %s for %d MWh, but %.1f kWh were verified", c.ID, c.MWh, s.VerifiedKWh)
			}
			certificates[c.ID] = true
		case "claimed":
			var c Claim
			if !open(e, &c) {
				continue
			}
			if !certificates[c.Certificate] {
				fs.Add(e.Line, "%s claims certificate %s, which was not issued in this chain", c.Claimant, c.Certificate)
				continue
			}
			if prev, ok := claimed[c.Certificate]; ok {
				fs.Add(e.Line, "%s claims certificate %s, already claimed by %s at line %d", c.Claimant, c.Certificate, prev.Source.ID, prev.Line)
				continue
			}
			claimed[c.Certificate] = e
		default:
			fs.Add(e.Line, "unknown event %q", e.Meta["event"])
		}
	}
	return fs.Sorted()
}
