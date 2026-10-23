package tiering

import (
	"fmt"
	"strconv"
	"time"

	"github.com/deedlog/deedlog/examples/internal/demo"
)

// Check applies the declared policy to a verified chain. It needs the
// published policy, but neither the HMAC key nor the submissions: items are
// followed by their keyed digests.
func Check(entries []demo.Entry, policy []byte) demo.Findings {
	var fs demo.Findings
	if len(entries) == 0 || entries[0].Meta["event"] != "policy" {
		fs.Add(1, "the first record must declare the policy")
		return fs
	}
	var p Policy
	if err := demo.Declared(entries[0], policy, &p); err != nil {
		fs.Add(0, "%v", err)
		return fs
	}
	every := time.Duration(p.InventoryEveryHours) * time.Hour

	type place struct {
		tier  string
		since time.Time
		line  int
	}
	items := make(map[string]*place)
	lastInventory := make(map[string]demo.Entry)
	for _, t := range p.Tiers {
		lastInventory[t.Name] = entries[0]
	}
	overdue := func(at place, now time.Time, line int, what string) {
		rule, _ := p.rule(at.tier)
		limit := time.Duration(rule.MaxAgeDays) * 24 * time.Hour
		if age := now.Sub(at.since); age > limit {
			fs.Add(line, "%s %s after %s; the policy allows %d days (entered at line %d)",
				what, at.tier, days(age), rule.MaxAgeDays, at.line)
		}
	}

	for _, e := range entries[1:] {
		h := e.Subject.Digest["hmac-sha256"]
		switch ev := e.Meta["event"]; ev {
		case "received":
			if _, ok := p.rule(e.Meta["tier"]); !ok {
				fs.Add(e.Line, "submission received in undeclared tier %q", e.Meta["tier"])
				continue
			}
			items[h] = &place{tier: e.Meta["tier"], since: e.CollectedAt, line: e.Line}
		case "moved", "deleted":
			from := e.Meta["from"]
			if ev == "deleted" {
				from = e.Meta["tier"]
			}
			at, ok := items[h]
			if !ok {
				fs.Add(e.Line, "%s a submission that was never recorded as received", ev)
				continue
			}
			if at.tier != from {
				fs.Add(e.Line, "%s from %s, but the submission is in %s (line %d)", ev, from, at.tier, at.line)
				continue
			}
			rule, _ := p.rule(from)
			if ev == "moved" && e.Meta["to"] != rule.Next {
				fs.Add(e.Line, "moved from %s to %s; the policy moves it to %q", from, e.Meta["to"], rule.Next)
			}
			if ev == "deleted" && rule.Next != "" {
				fs.Add(e.Line, "deleted from %s; the policy moves it to %s", from, rule.Next)
			}
			overdue(*at, e.CollectedAt, e.Line, map[string]string{"moved": "moved off", "deleted": "deleted from"}[ev])
			if ev == "deleted" {
				delete(items, h)
			} else {
				*at = place{tier: e.Meta["to"], since: e.CollectedAt, line: e.Line}
			}
		case "inventory":
			tier := e.Meta["tier"]
			last, ok := lastInventory[tier]
			if !ok {
				fs.Add(e.Line, "inventory of undeclared tier %q", tier)
				continue
			}
			if gap := e.CollectedAt.Sub(last.CollectedAt); gap > every+time.Hour {
				fs.Add(e.Line, "no inventory of %s for %s since line %d; the policy declares one every %d hours",
					tier, days(gap), last.Line, p.InventoryEveryHours)
			}
			lastInventory[tier] = e
			want := 0
			for _, at := range items {
				if at.tier == tier {
					want++
				}
			}
			if got, err := strconv.Atoi(e.Meta["count"]); err != nil || got != want {
				fs.Add(e.Line, "%s holds %s items, but the chain accounts for %d: data entered or left it unrecorded",
					tier, e.Meta["count"], want)
			}
		default:
			fs.Add(e.Line, "unknown event %q", ev)
		}
	}

	end := entries[len(entries)-1]
	for _, at := range items {
		overdue(*at, end.CollectedAt, at.line, "still in")
	}
	for tier, last := range lastInventory {
		if gap := end.CollectedAt.Sub(last.CollectedAt); gap > every+time.Hour {
			fs.Add(last.Line, "no inventory of %s after this line for %s", tier, days(gap))
		}
	}
	return fs.Sorted()
}

func days(d time.Duration) string {
	return fmt.Sprintf("%.1f days", d.Hours()/24)
}
