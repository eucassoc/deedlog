package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/eucassoc/deedlog/examples/internal/demo"
)

func TestTraceable(t *testing.T) {
	res, err := run(scenario{})
	if err != nil {
		t.Fatal(err)
	}
	defer demo.CloseAll(res.witnesses)
	if len(res.findings) != 0 {
		t.Fatalf("findings: %v", res.findings)
	}
}

func TestFraudIsFound(t *testing.T) {
	for _, tc := range []struct {
		sc   scenario
		want string
	}{
		{scenario{inflate: 10}, "its readings add up to"},
		{scenario{doubleCount: 1}, "reading 0 counted again"},
		{scenario{doubleClaim: true}, "already claimed by maker.example"},
	} {
		res, err := run(tc.sc)
		if err != nil {
			t.Fatal(err)
		}
		demo.CloseAll(res.witnesses)
		var out bytes.Buffer
		res.findings.Print(&out)
		if !strings.Contains(out.String(), tc.want) {
			t.Errorf("%+v: missing %q in\n%s", tc.sc, tc.want, out.String())
		}
	}
}
