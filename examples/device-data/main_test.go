package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/deedlog/deedlog/examples/internal/demo"
)

func TestHonestGateway(t *testing.T) {
	res, err := run(scenario{}, 6)
	if err != nil {
		t.Fatal(err)
	}
	defer demo.CloseAll(res.witnesses)
	if len(res.findings) != 0 {
		t.Fatalf("findings: %v", res.findings)
	}
}

func TestDishonestGateway(t *testing.T) {
	res, err := run(scenario{
		drop:  func(d string, seq uint64) bool { return d == "meter-18.energy.example" && seq == 5 },
		alter: func(d string, seq uint64) bool { return d == "meter-17.energy.example" && seq == 9 },
		forge: true,
	}, 6)
	if err != nil {
		t.Fatal(err)
	}
	defer demo.CloseAll(res.witnesses)
	var out bytes.Buffer
	res.findings.Print(&out)
	for _, want := range []string{
		"meter-18.energy.example: readings 5 to 5 missing",
		"reading 9 of meter-17.energy.example is not as the device signed it: signature by",
		"no signature from a known key",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s", want, out.String())
		}
	}
}
