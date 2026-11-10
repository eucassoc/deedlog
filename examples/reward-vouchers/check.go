package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/eucassoc/deedlog/examples/internal/demo"
)

// Claim is what a store submits for settlement: its verified chain and the
// presentations it recorded, looked up by digest. The operator checks the
// presentations against the chain, never the other way round.
type Claim struct {
	Store   string
	Entries []demo.Entry
	Body    func(digest string) ([]byte, bool)
}

// Statement is one store's side of the settlement.
type Statement struct {
	Store string
	// Issued is the number of vouchers the store recorded issuing.
	Issued int
	// Accepted is the number of other stores' vouchers it redeemed and is
	// paid for; Own the number of its own vouchers it took back.
	Accepted, Own int
	// Receives and Pays are the amounts settled, in the program's unit.
	Receives, Pays int
}

type redemption struct {
	claim *Claim
	entry demo.Entry
}

// Settle audits the stores' chains against the published program and the
// presentations they submit, and works out what each store receives and
// pays. A voucher is paid once: to the first store that recorded it, in
// time order across all chains. Every redemption that is not paid is a
// finding, tied to the chain line where it shows.
func Settle(program []byte, claims []*Claim) (demo.Findings, []Statement) {
	var fs demo.Findings
	var p Program
	issued := make(map[string]struct {
		store string
		line  int
	})
	stmt := make(map[string]*Statement)
	var rs []redemption
	for _, c := range claims {
		stmt[c.Store] = &Statement{Store: c.Store}
		if len(c.Entries) == 0 || c.Entries[0].Meta["event"] != "program" {
			fs.Add(1, "%s: the first record must declare the program", c.Store)
			continue
		}
		if err := demo.Declared(c.Entries[0], program, &p); err != nil {
			fs.Add(0, "%s: %v", c.Store, err)
			continue
		}
		for _, e := range c.Entries[1:] {
			switch e.Meta["event"] {
			case "issued":
				issued[e.Subject.Digest["sha256"]] = struct {
					store string
					line  int
				}{c.Store, e.Line}
				stmt[c.Store].Issued++
			case "redeemed":
				rs = append(rs, redemption{c, e})
			default:
				fs.Add(e.Line, "%s: unknown event %q", c.Store, e.Meta["event"])
			}
		}
	}
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].entry.CollectedAt.Before(rs[j].entry.CollectedAt) })

	paid := make(map[string]redemption)
	for _, r := range rs {
		store, e := r.claim.Store, r.entry
		raw, ok := r.claim.Body("sha256:" + e.Subject.Digest["sha256"])
		if !ok {
			fs.Add(e.Line, "%s: no presentation submitted for this redemption", store)
			continue
		}
		var signed Signed
		var pr presentation
		if json.Unmarshal(raw, &signed) != nil || json.Unmarshal(signed.Body, &pr) != nil {
			fs.Add(e.Line, "%s: the submitted presentation does not parse", store)
			continue
		}
		digest := demo.Sum(pr.Voucher)
		v, err := Verify(p, pr.Voucher)
		if err != nil {
			fs.Add(e.Line, "%s: %v", store, err)
			continue
		}
		if _, err := open(holderKey(v), raw); err != nil {
			fs.Add(e.Line, "%s: holder: %v", store, err)
			continue
		}
		if pr.Store != store || e.Meta["voucher"] != digest || e.Meta["issuer"] != v.Issuer {
			fs.Add(e.Line, "%s: the record does not describe the submitted presentation", store)
			continue
		}
		if _, ok := issued[digest]; !ok {
			fs.Add(e.Line, "%s: voucher signed with %s's key, but %s never recorded issuing it; off-book issuance or a stolen key",
				store, v.Issuer, v.Issuer)
			continue
		}
		if e.CollectedAt.After(v.Expires) {
			fs.Add(e.Line, "%s: voucher from %s (line %d) expired %s before it was redeemed",
				store, v.Issuer, issued[digest].line, age(e.CollectedAt.Sub(v.Expires)))
			continue
		}
		if first, ok := paid[digest]; ok {
			fs.Add(e.Line, "%s: voucher already redeemed at %s line %d; holder %s presented it twice",
				store, first.claim.Store, first.entry.Line, v.Holder[:8])
			continue
		}
		paid[digest] = r
		s := stmt[store]
		if v.Issuer == store {
			s.Own++
			continue
		}
		s.Accepted++
		s.Receives += v.Value
		if o, ok := stmt[v.Issuer]; ok {
			o.Pays += v.Value
		}
	}
	var out []Statement
	for _, c := range claims {
		out = append(out, *stmt[c.Store])
	}
	return fs.Sorted(), out
}

// age formats d in days and hours.
func age(d time.Duration) string {
	d = d.Round(time.Hour)
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd%02dh", int(d.Hours())/24, int(d.Hours())%24)
}
