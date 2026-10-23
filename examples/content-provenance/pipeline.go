package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/deedlog/deedlog/core"
	"github.com/deedlog/deedlog/examples/internal/demo"
)

// The sample stands in for C2PA with a minimal container: the asset's
// content followed by an embedded manifest. A real integration reads and
// validates manifests with a C2PA SDK, such as c2pa-rs or c2patool, and
// records the same events.

const manifestMarker = "\n--manifest--\n"

// Manifest is the stand-in for a C2PA manifest.
type Manifest struct {
	Signer      string `json:"signer"`
	Action      string `json:"action"` // c2pa.created, c2pa.edited, ...
	ContentHash string `json:"content_hash"`
	Ingredient  string `json:"ingredient,omitempty"` // sha256 of the input asset
}

// Embed returns the asset with its manifest embedded.
func Embed(content []byte, m Manifest) []byte {
	b, _ := json.Marshal(m)
	return slices.Concat(content, []byte(manifestMarker), b)
}

// Split separates an asset into its content and embedded manifest. A
// stripped asset has no manifest.
func Split(asset []byte) (content []byte, m *Manifest) {
	i := bytes.LastIndex(asset, []byte(manifestMarker))
	if i < 0 {
		return asset, nil
	}
	var man Manifest
	if json.Unmarshal(asset[i+len(manifestMarker):], &man) != nil {
		return asset, nil
	}
	return asset[:i], &man
}

// Strip removes the embedded manifest, as many platforms do on upload.
func Strip(asset []byte) []byte {
	content, _ := Split(asset)
	return content
}

// Newsroom is the integration point: the ingest, editing and publishing
// systems of a publisher call it. Each record carries the digest of the
// whole asset as the subject and the digest of its content without the
// manifest in meta, so that copies whose metadata was stripped can still be
// matched. Copies that were re-encoded need C2PA soft bindings (watermarks
// or fingerprints) instead.
type Newsroom struct {
	Log *demo.Log
	// Trusted are the manifest signers the newsroom accepts.
	Trusted []string
}

func (n *Newsroom) record(event string, asset []byte, meta map[string]string) error {
	content, _ := Split(asset)
	meta["event"], meta["content"] = event, demo.Sum(content)
	_, err := n.Log.Append(demo.Event{
		Source:    core.Source{Type: "newsroom", ID: event, Collector: "examples/content-provenance"},
		MediaType: "image/jpeg", Body: asset, Meta: meta,
	})
	return err
}

// Ingest records an asset as it arrives and validates its manifest. The
// validation result is recorded with it.
func (n *Newsroom) Ingest(asset []byte, from string) error {
	return n.record("ingested", asset, map[string]string{"from": from, "validation": n.validate(asset)})
}

func (n *Newsroom) validate(asset []byte) string {
	content, m := Split(asset)
	switch {
	case m == nil:
		return "no manifest"
	case m.ContentHash != demo.Sum(content):
		return "content does not match manifest"
	case !slices.Contains(n.Trusted, m.Signer):
		return "untrusted signer " + m.Signer
	}
	return "valid"
}

// Edit records an edit: the output, with a new manifest naming the input
// as its ingredient.
func (n *Newsroom) Edit(input []byte, action string, edit func([]byte) []byte) ([]byte, error) {
	content, _ := Split(input)
	out := edit(content)
	asset := Embed(out, Manifest{Signer: "newsroom.example", Action: action, ContentHash: demo.Sum(out), Ingredient: demo.Sum(input)})
	return asset, n.record("edited", asset, map[string]string{"input": demo.Sum(input), "action": action})
}

// Publish records the publication of an asset at a URL.
func (n *Newsroom) Publish(asset []byte, url string) error {
	return n.record("published", asset, map[string]string{"url": url})
}

// ErrUnknown means an asset is not in the chain.
var ErrUnknown = errors.New("not in the publisher's chain")

// Trace finds an asset, or a copy of it whose manifest was stripped, in a
// verified chain, and follows its history back to ingest.
func Trace(entries []demo.Entry, file []byte) ([]demo.Entry, error) {
	digest := demo.Sum(file)
	var at *demo.Entry
	for i := len(entries) - 1; i >= 0 && at == nil; i-- {
		e := &entries[i]
		if e.Subject.Digest["sha256"] == digest || e.Meta["content"] == digest {
			at = e
		}
	}
	if at == nil {
		return nil, ErrUnknown
	}
	return history(entries, *at), nil
}

// history follows an entry back through edits to the asset's first record.
func history(entries []demo.Entry, at demo.Entry) []demo.Entry {
	first := make(map[string]demo.Entry)
	for _, e := range entries {
		if _, seen := first[e.Subject.Digest["sha256"]]; !seen {
			first[e.Subject.Digest["sha256"]] = e
		}
	}
	h := []demo.Entry{at}
	for e := at; ; {
		next := e.Meta["input"]
		if e.Meta["event"] == "published" {
			next = e.Subject.Digest["sha256"]
		}
		prev, ok := first[next]
		if !ok || prev.Line >= e.Line {
			break
		}
		h = append(h, prev)
		e = prev
	}
	slices.Reverse(h)
	return h
}

func describe(e demo.Entry) string {
	switch e.Meta["event"] {
	case "ingested":
		return fmt.Sprintf("ingested from %s, manifest %s", e.Meta["from"], e.Meta["validation"])
	case "edited":
		return "edited: " + e.Meta["action"]
	case "published":
		return "published at " + e.Meta["url"]
	}
	return e.Meta["event"]
}
