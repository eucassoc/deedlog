package core

import (
	"bytes"
	"strings"
	"testing"
)

func newReceiptKey(t *testing.T, name string) (*Signer, *Verifier) {
	t.Helper()
	skey, vkey, err := GenerateKey(name)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := NewSigner(skey)
	v, _ := NewVerifier(vkey)
	return s, v
}

func TestReceiptIssueAndVerify(t *testing.T) {
	const origin = "city.example/cameras"
	signer, key := newReceiptKey(t, origin+"/receipts")
	r := Receipt{Origin: origin, Index: 7, LeafHash: LeafHash([]byte("record"))}
	note, err := IssueReceipt(r, signer)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyReceipt(note, key)
	if err != nil {
		t.Fatal(err)
	}
	if got != r {
		t.Fatalf("got %+v, want %+v", got, r)
	}

	if _, err := VerifyReceipt(bytes.Replace(note, []byte("\n7\n"), []byte("\n8\n"), 1), key); err == nil {
		t.Error("tampered receipt verified")
	}
	_, other := newReceiptKey(t, origin+"/receipts")
	if _, err := VerifyReceipt(note, other); err == nil {
		t.Error("receipt verified with another key")
	}
	checkpointKey, _ := newReceiptKey(t, origin)
	if _, err := IssueReceipt(r, checkpointKey); err == nil {
		t.Error("issued a receipt with the checkpoint key name")
	}
	// Even signed with the receipt key, checkpoint text is not a receipt,
	// and receipt text is not a checkpoint.
	cp, _ := signer.Sign(Checkpoint{Origin: origin, Size: 1, Root: r.LeafHash}.Text())
	if _, err := VerifyReceipt(cp, key); err == nil {
		t.Error("checkpoint text verified as a receipt")
	}
	if _, err := VerifyCheckpoint(note, key, nil, 0); err == nil {
		t.Error("receipt verified as a checkpoint")
	}
}

func TestParseReceipt(t *testing.T) {
	leaf := encodeHash(LeafHash(nil))
	tests := map[string]bool{
		"deedlog-receipt/v1\na.example/log\n0\n" + leaf + "\n":    true,
		"deedlog-receipt/v2\na.example/log\n0\n" + leaf + "\n":    false,
		"deedlog-receipt/v1\na.example/log\n01\n" + leaf + "\n":   false,
		"deedlog-receipt/v1\na example\n0\n" + leaf + "\n":        false,
		"deedlog-receipt/v1\na.example/log\n0\n" + leaf:           false,
		"deedlog-receipt/v1\na.example/log\n0\n" + leaf + "\nx\n": false,
	}
	for text, ok := range tests {
		if _, err := ParseReceipt([]byte(text)); (err == nil) != ok {
			t.Errorf("ParseReceipt(%q) error = %v, want ok = %v", text, err, ok)
		}
	}
}

func TestCheckReceipt(t *testing.T) {
	const origin = "city.example/cameras"
	opSigner, operator := newTestOperator(t, origin)
	rSigner, rKey := newReceiptKey(t, origin+"/receipts")

	honest := chainLeaves(t, origin, 6, -1, "")
	r := Receipt{Origin: origin, Index: 3, LeafHash: honest[3]}
	receipt, err := IssueReceipt(r, rSigner)
	if err != nil {
		t.Fatal(err)
	}
	check := func(leaves []Hash) (ReceiptStatus, *MisbehaviorProof, error) {
		t.Helper()
		c := Checkpoint{Origin: origin, Size: uint64(len(leaves)), Root: Root(leaves)}
		note, err := SignCheckpoint(c, opSigner)
		if err != nil {
			t.Fatal(err)
		}
		var proof []Hash
		leaf := Hash{}
		if r.Index < c.Size {
			proof, _ = InclusionProof(leaves, r.Index)
			leaf = leaves[r.Index]
		}
		return CheckReceipt(receipt, r, note, c, leaf, proof)
	}

	if s, _, err := check(honest); err != nil || s != ReceiptIncluded {
		t.Fatalf("honest chain: %v %v", s, err)
	}
	if s, _, err := check(honest[:3]); err != nil || s != ReceiptNotYetCovered {
		t.Fatalf("short chain: %v %v", s, err)
	}

	// The operator replaces record 3 and publishes a checkpoint.
	rewritten := chainLeaves(t, origin, 8, 3, "replaced")
	s, p, err := check(rewritten)
	if err != nil || s != ReceiptBroken || p == nil {
		t.Fatalf("rewritten chain: %v %v %v", s, p, err)
	}
	desc, err := CheckMisbehavior(*p, operator, rKey)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(desc, "index 3") {
		t.Fatalf("description %q", desc)
	}
	if _, err := CheckMisbehavior(*p, operator, nil); err == nil {
		t.Fatal("receipt proof checked without the receipt key")
	}

	// A forged proof claiming a different leaf must not verify.
	forged := *p
	forged.LeafHashes = []string{encodeHash(LeafHash([]byte("fake")))}
	if _, err := CheckMisbehavior(forged, operator, rKey); err == nil {
		t.Fatal("forged receipt proof verified")
	}
	// A bogus inclusion proof from the operator is an error, not a proof.
	c := Checkpoint{Origin: origin, Size: 6, Root: Root(honest)}
	note, _ := SignCheckpoint(c, opSigner)
	if _, _, err := CheckReceipt(receipt, r, note, c, LeafHash([]byte("fake")), nil); err == nil {
		t.Fatal("accepted a bogus inclusion proof")
	}
}
