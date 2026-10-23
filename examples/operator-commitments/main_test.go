package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestAsPromised(t *testing.T) {
	res, err := run(scenario{}, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer closeAll(res)
	if len(res.findings) != 0 {
		t.Fatalf("findings: %v", res.findings)
	}
}

func TestBrokenPromisesAreFound(t *testing.T) {
	res, err := run(scenario{
		unrecorded:     [2]int{60, 70},
		unreleased:     [2]int{120, 125},
		faceMatch:      150,
		retentionStops: 1,
	}, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer closeAll(res)
	var out bytes.Buffer
	res.findings.Print(&out)
	for _, want := range []string{
		"station-south: segments 61 to 70 missing",
		"processing of footage that was not recorded as captured",
		"which is not published",
		`produced "face-match"`,
		"segment still not deleted after",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s", want, out.String())
		}
	}
}
