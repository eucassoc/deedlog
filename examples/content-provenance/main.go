// Command content-provenance runs the content provenance use case: a
// newsroom records the assets it ingests, edits and publishes, so that a
// copy found later, even with its manifest stripped, can be traced back.
//
// Manifests are a stand-in for C2PA; see pipeline.go.
//
//	go run ./examples/content-provenance [-out DIR]
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/deedlog/deedlog/examples/internal/demo"
)

type scenario struct {
	name string
	// Whether the newsroom also publishes a wire photo whose manifest
	// failed validation, and an image that never went through ingest.
	shortcuts bool
}

type result struct {
	log        *demo.Log
	witnesses  []*demo.Witness
	checkpoint []byte
	published  []byte
	findings   demo.Findings
}

func crop(b []byte) []byte   { return append([]byte("cropped "), b...) }
func resize(b []byte) []byte { return append([]byte("1200px "), b...) }

func run(sc scenario) (*result, error) {
	l, ws, err := demo.Start("news.example/assets", time.Date(2026, 4, 1, 6, 0, 0, 0, time.UTC), "witness.archive.example", "witness.press-council.example")
	if err != nil {
		return nil, err
	}
	res := &result{log: l, witnesses: ws}
	n := &Newsroom{Log: l, Trusted: []string{"camera.agency.example", "newsroom.example"}}

	photo := []byte("flood at the river bank, 05:42")
	captured := Embed(photo, Manifest{Signer: "camera.agency.example", Action: "c2pa.created", ContentHash: demo.Sum(photo)})
	if err := n.Ingest(captured, "photographer upload"); err != nil {
		return res, err
	}
	l.Clock.Advance(40 * time.Minute)
	cropped, err := n.Edit(captured, "c2pa.cropped", crop)
	if err != nil {
		return res, err
	}
	resized, err := n.Edit(cropped, "c2pa.resized", resize)
	if err != nil {
		return res, err
	}
	l.Clock.Advance(20 * time.Minute)
	if err := n.Publish(resized, "https://news.example/2026/04/01/flood"); err != nil {
		return res, err
	}
	res.published = resized

	if sc.shortcuts {
		wire := []byte("crowd at the station")
		claimed := Embed(wire, Manifest{Signer: "unknown-app.example", Action: "c2pa.created", ContentHash: demo.Sum(wire)})
		if err := n.Ingest(claimed, "wire service"); err != nil {
			return res, err
		}
		edited, err := n.Edit(claimed, "c2pa.color_adjustments", resize)
		if err != nil {
			return res, err
		}
		if err := n.Publish(edited, "https://news.example/2026/04/01/station"); err != nil {
			return res, err
		}
		stray := []byte("archive photo, source unknown")
		out, err := n.Edit(Embed(stray, Manifest{Signer: "newsroom.example", ContentHash: demo.Sum(stray)}), "c2pa.cropped", crop)
		if err != nil {
			return res, err
		}
		if err := n.Publish(out, "https://news.example/2026/04/01/archive"); err != nil {
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

// lookup is what anyone can do with a file found elsewhere: trace it in the
// publisher's witnessed chain.
func (res *result) lookup(w io.Writer, what string, file []byte) error {
	entries, c, err := demo.Open(res.log.Chain(), res.checkpoint, res.log.OperatorKey(), demo.Keys(res.witnesses), len(res.witnesses))
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "\n  %s:\n", what)
	h, err := Trace(entries, file)
	if err != nil {
		fmt.Fprintf(w, "  %v\n", err)
		return nil
	}
	for _, e := range h {
		fmt.Fprintf(w, "  %s  %s (line %d)\n", e.CollectedAt.Format("2006-01-02 15:04"), describe(e), e.Line)
	}
	fmt.Fprintf(w, "  all within the checkpoint of size %d cosigned by %d witnesses\n", c.Size, len(res.witnesses))
	return nil
}

func main() {
	out := flag.String("out", "", "directory for the chains, checkpoints and keys (default: a new temporary directory)")
	flag.Parse()
	dir, err := demo.OutDir(*out, "content-provenance")
	if err != nil {
		log.Fatal(err)
	}
	for i, sc := range []scenario{
		{name: "every published asset traceable"},
		{name: "with shortcuts in the newsroom", shortcuts: true},
	} {
		res, err := run(sc)
		if err != nil {
			log.Fatal(err)
		}
		demo.Header(os.Stdout, sc.name, res.log, res.witnesses)
		res.findings.Print(os.Stdout)
		if i == 0 {
			if err := res.lookup(os.Stdout, "A copy found on social media, manifest stripped", Strip(res.published)); err != nil {
				log.Fatal(err)
			}
			doctored := bytes.Replace(Strip(res.published), []byte("flood"), []byte("riot"), 1)
			if err := res.lookup(os.Stdout, "A doctored copy", doctored); err != nil {
				log.Fatal(err)
			}
		}
		if err := demo.Save(os.Stdout, filepath.Join(dir, fmt.Sprint(i+1)), res.log, res.witnesses); err != nil {
			log.Fatal(err)
		}
		demo.CloseAll(res.witnesses)
	}
}
