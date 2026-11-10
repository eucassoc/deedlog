package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/eucassoc/deedlog/examples/internal/demo"
)

func TestConsentRespected(t *testing.T) {
	res, err := run(scenario{}, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer demo.CloseAll(res.witnesses)
	if len(res.findings) != 0 {
		t.Fatalf("findings: %v", res.findings)
	}
	if msg, err := res.checkWithdrawal(); err != nil || !strings.Contains(msg, "included") {
		t.Fatalf("%q, %v", msg, err)
	}
	if bytes.Contains(res.log.Chain(), []byte("resident 1")) {
		t.Fatal("resident ID in the chain")
	}
}

func TestViolationsAreFound(t *testing.T) {
	res, err := run(scenario{ignoreWithdrawal: true, looseScope: true}, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer demo.CloseAll(res.witnesses)
	var out bytes.Buffer
	res.findings.Print(&out)
	for _, want := range []string{"of city-b received data of a resident of city-a", "to mobility-app", "after consent was withdrawn"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s", want, out.String())
		}
	}
}
