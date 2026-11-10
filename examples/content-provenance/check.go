package main

import "github.com/eucassoc/deedlog/examples/internal/demo"

// Check verifies a publisher's verified chain: every edit starts from an
// asset the chain already holds, and every published asset traces back to
// an ingest whose manifest was valid.
func Check(entries []demo.Entry) demo.Findings {
	var fs demo.Findings
	known := make(map[string]bool)
	for i, e := range entries {
		digest := e.Subject.Digest["sha256"]
		switch e.Meta["event"] {
		case "ingested":
		case "edited":
			if !known[e.Meta["input"]] {
				fs.Add(e.Line, "edit of an asset that was never ingested")
			}
		case "published":
			if !known[digest] {
				fs.Add(e.Line, "published an asset that was never ingested or edited")
				break
			}
			origin := history(entries[:i+1], e)[0]
			if origin.Meta["event"] == "ingested" && origin.Meta["validation"] != "valid" {
				fs.Add(e.Line, "published an asset whose source at line %d was ingested with %s", origin.Line, origin.Meta["validation"])
			}
		default:
			fs.Add(e.Line, "unknown event %q", e.Meta["event"])
		}
		known[digest] = true
	}
	return fs.Sorted()
}
