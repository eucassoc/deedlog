package main

import (
	"strings"
	"testing"
)

func TestCrossWitnessing(t *testing.T) {
	res, err := run(scenario{})
	if err != nil {
		t.Fatal(err)
	}
	for i, fs := range res.findings {
		if len(fs) != 0 {
			t.Fatalf("connector %d: %v", i, fs)
		}
	}
	held := res.provider.Held[res.consumer.Log.Origin]
	if err := audit(res.consumer.Log.Chain(), held, res.consumer.Log.OperatorKey()); err != nil {
		t.Fatalf("honest chain: %v", err)
	}
	rewritten, err := deny(res.consumer, "tp-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := audit(rewritten, held, res.consumer.Log.OperatorKey()); err == nil {
		t.Fatal("rewritten chain matches the held checkpoint")
	}
}

func TestTransferWithoutAgreement(t *testing.T) {
	res, err := run(scenario{terminate: true})
	if err != nil {
		t.Fatal(err)
	}
	for i, fs := range res.findings {
		if len(fs) != 1 || !strings.Contains(fs[0].Problem, "agreement TERMINATED") {
			t.Errorf("connector %d: %v", i, fs)
		}
	}
}
