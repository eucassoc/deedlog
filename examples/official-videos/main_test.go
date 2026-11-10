package main

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/eucassoc/deedlog/examples/internal/demo"
	"github.com/eucassoc/deedlog/examples/official-videos/studio"
)

func TestAsDeclared(t *testing.T) {
	res, err := run(scenario{}, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer res.close()
	if len(res.findings) != 0 {
		t.Fatalf("findings: %v", res.findings)
	}
	var out bytes.Buffer
	if err := followReceipt(&out, res); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"included", "recipe \"highlights-v1\"", "rendered by engine.studio.example", "published at"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s", want, out.String())
		}
	}
}

func TestFailuresAreFound(t *testing.T) {
	res, err := run(scenario{generate: 1, otherApp: 2, unregistered: 3, forged: 4}, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer res.close()
	var out bytes.Buffer
	res.findings.Print(&out)
	for _, want := range []string{
		`operation "generate" (crowd scene added) is not allowed`,
		"published a video that the engine did not render",
		"footage that was never registered",
		"not signed by the engine",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s", want, out.String())
		}
	}
	// The first video's receipt shows its own problem.
	out.Reset()
	if err := followReceipt(&out, res); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "problem: line") {
		t.Errorf("no problem shown in\n%s", out.String())
	}
}

func TestEditedChainIsRejected(t *testing.T) {
	res, err := run(scenario{}, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer res.close()
	// Dropping the render record breaks the chain's links.
	lines := bytes.SplitAfter(res.log.Chain(), []byte("\n"))
	edited := bytes.Join(append(lines[:5:5], lines[6:]...), nil)
	if _, _, err := demo.Open(edited, res.checkpoint, res.log.OperatorKey(), nil, 0); err == nil || !strings.Contains(err.Error(), "line 6") {
		t.Fatalf("edited chain: %v", err)
	}
}

func TestRecipeMustMatch(t *testing.T) {
	res, err := run(scenario{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer res.close()
	entries, _, err := demo.Open(res.log.Chain(), res.checkpoint, res.log.OperatorKey(), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	// A recipe published later with "generate" added does not match the
	// one recorded.
	body := func(digest string) ([]byte, bool) {
		b, ok := res.log.Body(digest)
		if ok && bytes.Contains(b, []byte(`"allowed"`)) {
			b = bytes.Replace(b, []byte(`"logo"]`), []byte(`"logo","generate"]`), 1)
		}
		return b, ok
	}
	fs := studio.Check(entries, body, res.engine)
	if len(fs) == 0 || !strings.Contains(fs[0].String(), "does not match the recorded digest") {
		t.Fatalf("findings: %v", fs)
	}
	if err := followReceipt(io.Discard, res); err != nil {
		t.Fatal(err)
	}
}
