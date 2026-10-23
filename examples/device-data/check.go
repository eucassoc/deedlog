package main

import (
	"time"

	"github.com/deedlog/deedlog/core"
	"github.com/deedlog/deedlog/examples/internal/demo"
)

// Check verifies every recorded reading against the registry of device
// keys, and checks the devices' sequence numbers and declared cadence.
// body returns an evidence body by digest, from the operator's evidence
// store.
func Check(entries []demo.Entry, body func(digest string) ([]byte, bool), registry map[string]*core.Verifier, every time.Duration) demo.Findings {
	var fs demo.Findings
	type last struct {
		seq  uint64
		at   time.Time
		line int
	}
	devices := make(map[string]*last)
	for _, e := range entries {
		if e.Meta["event"] != "reading" {
			fs.Add(e.Line, "unknown event %q", e.Meta["event"])
			continue
		}
		digest := e.Subject.Digest["sha256"]
		b, ok := body("sha256:" + digest)
		if !ok || demo.Sum(b) != digest {
			fs.Add(e.Line, "the evidence body is missing")
			continue
		}
		key, ok := registry[e.Meta["device"]]
		if !ok {
			fs.Add(e.Line, "reading claims device %q, which is not registered", e.Meta["device"])
			continue
		}
		text, _, err := core.OpenNote(b, []*core.Verifier{key})
		if err != nil {
			fs.Add(e.Line, "reading %s of %s is not as the device signed it: %v", e.Meta["seq"], e.Meta["device"], err)
			continue
		}
		r, err := parseReading(text)
		if err != nil || r.Device != key.Name() {
			fs.Add(e.Line, "signed text is not a reading of %s", key.Name())
			continue
		}
		d := devices[r.Device]
		switch {
		case d == nil:
		case r.Seq <= d.seq:
			fs.Add(e.Line, "%s: reading %d again, after reading %d at line %d", r.Device, r.Seq, d.seq, d.line)
			continue
		case r.Seq != d.seq+1:
			fs.Add(e.Line, "%s: readings %d to %d missing since line %d", r.Device, d.seq+1, r.Seq-1, d.line)
		}
		devices[r.Device] = &last{seq: r.Seq, at: r.Time, line: e.Line}
	}
	if len(entries) > 0 {
		end := entries[len(entries)-1].CollectedAt
		for name, d := range devices {
			if gap := end.Sub(d.at); gap > every*3/2 {
				fs.Add(d.line, "%s: no reading after this line for %s; declared every %s", name, gap, every)
			}
		}
	}
	return fs.Sorted()
}
