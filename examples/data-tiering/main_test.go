package main

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/eucassoc/deedlog/examples/data-tiering/tiering"
	"github.com/eucassoc/deedlog/examples/internal/demo"
)

func TestAsDeclared(t *testing.T) {
	res, err := run(scenario{}, 45)
	if err != nil {
		t.Fatal(err)
	}
	defer res.close()
	if len(res.findings) != 0 {
		t.Fatalf("findings: %v", res.findings)
	}
	if err := followReceipt(io.Discard, res); err != nil {
		t.Fatal(err)
	}
}

func TestFailuresAreFound(t *testing.T) {
	res, err := run(scenario{transferDown: map[int]bool{10: true, 11: true, 12: true, 13: true, 14: true, 15: true}, skipInventory: 20, handCopy: 25}, 30)
	if err != nil {
		t.Fatal(err)
	}
	defer res.close()
	var out bytes.Buffer
	res.findings.Print(&out)
	for _, want := range []string{"moved off form-service after", "no inventory of form-service", "data entered or left it unrecorded"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s", want, out.String())
		}
	}
}

func TestEditedChainIsRejected(t *testing.T) {
	res, err := run(scenario{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer res.close()
	// Dropping a late deletion record breaks the chain's links.
	lines := bytes.SplitAfter(res.log.Chain(), []byte("\n"))
	edited := bytes.Join(append(lines[:5:5], lines[6:]...), nil)
	if _, _, err := demo.Open(edited, res.checkpoint, res.log.OperatorKey(), nil, 0); err == nil || !strings.Contains(err.Error(), "line 6") {
		t.Fatalf("edited chain: %v", err)
	}
}

func TestPolicyMustMatch(t *testing.T) {
	res, err := run(scenario{}, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer res.close()
	entries, _, err := demo.Open(res.log.Chain(), res.checkpoint, res.log.OperatorKey(), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	laxer := bytes.Replace(res.policy, []byte(`"max_age_days":7`), []byte(`"max_age_days":70`), 1)
	fs := tiering.Check(entries, laxer)
	if len(fs) != 1 || !strings.Contains(fs[0].String(), "does not match the recorded digest") {
		t.Fatalf("findings: %v", fs)
	}
}
