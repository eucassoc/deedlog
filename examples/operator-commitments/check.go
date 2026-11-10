package main

import (
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/eucassoc/deedlog/examples/internal/demo"
)

// Check applies the published commitment to a verified chain. It needs no
// footage: segments are followed by their digests.
func Check(entries []demo.Entry, commitment []byte) demo.Findings {
	var fs demo.Findings
	if len(entries) == 0 || entries[0].Meta["event"] != "commitment" {
		fs.Add(1, "the first record must declare the commitment")
		return fs
	}
	var c Commitment
	if err := demo.Declared(entries[0], commitment, &c); err != nil {
		fs.Add(0, "%v", err)
		return fs
	}
	segment := time.Duration(c.SegmentSeconds) * time.Second
	retention := time.Duration(c.RetentionHours) * time.Hour

	type last struct {
		seq  uint64
		at   time.Time
		line int
	}
	cameras := make(map[string]*last)
	for _, id := range c.Cameras {
		cameras[id] = &last{at: entries[0].CollectedAt, line: entries[0].Line}
	}
	type capture struct {
		at   time.Time
		line int
	}
	held := make(map[string]capture)

	for _, e := range entries[1:] {
		d := e.Subject.Digest["sha256"]
		switch ev := e.Meta["event"]; ev {
		case "segment":
			cam, ok := cameras[e.Meta["camera"]]
			if !ok {
				fs.Add(e.Line, "segment from undeclared camera %q", e.Meta["camera"])
				continue
			}
			seq, err := strconv.ParseUint(e.Meta["seq"], 10, 64)
			if err != nil {
				fs.Add(e.Line, "segment without a sequence number")
				continue
			}
			if cam.seq != 0 && seq != cam.seq+1 {
				fs.Add(e.Line, "%s: segments %d to %d missing since line %d (%s without a record)",
					e.Meta["camera"], cam.seq+1, seq-1, cam.line, hm(e.CollectedAt.Sub(cam.at)))
			} else if gap := e.CollectedAt.Sub(cam.at); gap > segment*3/2 && cam.seq != 0 {
				fs.Add(e.Line, "%s: no segment for %s since line %d; declared every %s", e.Meta["camera"], hm(gap), cam.line, hm(segment))
			}
			*cam = last{seq: seq, at: e.CollectedAt, line: e.Line}
			held[d] = capture{e.CollectedAt, e.Line}
		case "processed":
			if !slices.ContainsFunc(c.Software, func(s Software) bool { return s.Digest == e.Meta["software"] }) {
				fs.Add(e.Line, "processing by software %s, which is not published", short(e.Meta["software"]))
			}
			if !slices.Contains(c.Outputs, e.Meta["output"]) {
				fs.Add(e.Line, "processing produced %q, which the commitment does not allow", e.Meta["output"])
			}
			if _, ok := held[e.Meta["input"]]; !ok {
				fs.Add(e.Line, "processing of footage that was not recorded as captured, or already deleted")
			}
		case "deleted":
			cp, ok := held[d]
			if !ok {
				fs.Add(e.Line, "deletion of footage that was not recorded as captured")
				continue
			}
			if age := e.CollectedAt.Sub(cp.at); age > retention {
				fs.Add(e.Line, "segment captured at line %d deleted after %s; the commitment allows %s", cp.line, hm(age), hm(retention))
			}
			delete(held, d)
		default:
			fs.Add(e.Line, "unknown event %q", ev)
		}
	}

	end := entries[len(entries)-1].CollectedAt
	for _, cp := range held {
		if age := end.Sub(cp.at); age > retention {
			fs.Add(cp.line, "segment still not deleted after %s; the commitment allows %s", hm(age), hm(retention))
		}
	}
	for id, cam := range cameras {
		if gap := end.Sub(cam.at); gap > segment*3/2 {
			fs.Add(cam.line, "%s: no segment after this line for %s", id, hm(gap))
		}
	}
	return fs.Sorted()
}

func short(digest string) string {
	if len(digest) > 12 {
		return digest[:12]
	}
	return fmt.Sprintf("%q", digest)
}

// hm formats d as hours and minutes.
func hm(d time.Duration) string {
	d = d.Round(time.Minute)
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
}
