package main

import (
	"strconv"

	"github.com/deedlog/deedlog/examples/internal/demo"
)

// Check verifies a connector's verified chain against the protocol: data
// may be transferred only under a finalized agreement, and a transfer
// completes only after it started. Both sent and received messages count,
// so either side's chain shows a violation by either side.
func Check(entries []demo.Entry) demo.Findings {
	var fs demo.Findings
	type agreement struct {
		state string
		line  int
	}
	agreements := make(map[string]agreement)
	started := make(map[string]bool)
	for _, e := range entries {
		switch e.Meta["event"] {
		case "counterpart_checkpoint":
		case "message":
			id, process := e.Meta["agreement"], e.Meta["process"]
			switch e.Meta["state"] {
			case "AGREED", "VERIFIED", "FINALIZED", "TERMINATED":
				agreements[id] = agreement{e.Meta["state"], e.Line}
			case "STARTED":
				if a := agreements[id]; a.state != "FINALIZED" {
					what := "no agreement in this chain"
					if a.state != "" {
						what = "agreement " + a.state + " at line " + strconv.Itoa(a.line)
					}
					fs.Add(e.Line, "transfer %s started under %s (%s)", process, id, what)
				}
				started[process] = true
			case "COMPLETED":
				if !started[process] {
					fs.Add(e.Line, "transfer %s completed without starting", process)
				}
			}
		default:
			fs.Add(e.Line, "unknown event %q", e.Meta["event"])
		}
	}
	return fs.Sorted()
}
