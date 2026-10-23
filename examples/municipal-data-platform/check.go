package main

import "github.com/deedlog/deedlog/examples/internal/demo"

// Check verifies, on a verified chain, that every provision of data was
// preceded by consent that had not been withdrawn, and that no service
// received data of another tenant's residents. It needs no key: residents
// are followed by their pseudonyms.
func Check(entries []demo.Entry) demo.Findings {
	var fs demo.Findings
	type state struct {
		given bool
		line  int
	}
	consent := make(map[[4]string]state)
	scope := func(e demo.Entry) [4]string {
		return [4]string{e.Meta["resident"], e.Meta["tenant"], e.Meta["service"], e.Meta["purpose"]}
	}
	for _, e := range entries {
		switch e.Meta["event"] {
		case "consent":
			consent[scope(e)] = state{given: e.Meta["action"] == "given", line: e.Line}
		case "provided":
			if e.Meta["service_tenant"] != e.Meta["tenant"] {
				fs.Add(e.Line, "service %s of %s received data of a resident of %s",
					e.Meta["service"], e.Meta["service_tenant"], e.Meta["tenant"])
			}
			switch c, ok := consent[scope(e)]; {
			case !ok:
				fs.Add(e.Line, "data provided to %s for %q without consent", e.Meta["service"], e.Meta["purpose"])
			case !c.given:
				fs.Add(e.Line, "data provided to %s for %q after consent was withdrawn at line %d",
					e.Meta["service"], e.Meta["purpose"], c.line)
			}
		case "denied":
		default:
			fs.Add(e.Line, "unknown event %q", e.Meta["event"])
		}
	}
	return fs.Sorted()
}
