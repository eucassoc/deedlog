package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/eucassoc/deedlog/examples/internal/demo"
)

func TestTrace(t *testing.T) {
	res, err := run(scenario{})
	if err != nil {
		t.Fatal(err)
	}
	defer demo.CloseAll(res.witnesses)
	if len(res.findings) != 0 {
		t.Fatalf("findings: %v", res.findings)
	}
	entries, _, err := demo.Open(res.log.Chain(), res.checkpoint, res.log.OperatorKey(), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range [][]byte{res.published, Strip(res.published)} {
		h, err := Trace(entries, file)
		if err != nil || len(h) != 4 || h[0].Meta["event"] != "ingested" || h[3].Meta["event"] != "published" {
			t.Fatalf("trace: %d entries, %v", len(h), err)
		}
	}
	if _, err := Trace(entries, bytes.ToUpper(Strip(res.published))); !errors.Is(err, ErrUnknown) {
		t.Fatalf("altered copy: %v", err)
	}
}

func TestShortcutsAreFound(t *testing.T) {
	res, err := run(scenario{shortcuts: true})
	if err != nil {
		t.Fatal(err)
	}
	defer demo.CloseAll(res.witnesses)
	got := ""
	for _, f := range res.findings {
		got += f.String() + "\n"
	}
	for _, want := range []string{"ingested with untrusted signer", "edit of an asset that was never ingested"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
}
