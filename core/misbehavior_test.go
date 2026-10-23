package core

import (
	"bytes"
	"strings"
	"testing"
)

// chainLeaves writes n records to a chain and returns its leaf hashes,
// replacing record i's source ID with alt when alt is not empty.
func chainLeaves(t *testing.T, origin string, n, i int, alt string) []Hash {
	t.Helper()
	var buf bytes.Buffer
	w, err := NewWriter(&buf, origin)
	if err != nil {
		t.Fatal(err)
	}
	for j := range n {
		r := sampleRecord(j)
		if j == i && alt != "" {
			r.Source.ID = alt
		}
		if _, err := w.Append(r); err != nil {
			t.Fatal(err)
		}
	}
	_, leaves, err := VerifyLeaves(&buf)
	if err != nil {
		t.Fatal(err)
	}
	return leaves
}

func TestMisbehavior(t *testing.T) {
	const origin = "city.example/cameras"
	signer, operator := newTestOperator(t, origin)
	sign := func(leaves []Hash) []byte {
		t.Helper()
		note, err := SignCheckpoint(Checkpoint{Origin: origin, Size: uint64(len(leaves)), Root: Root(leaves)}, signer)
		if err != nil {
			t.Fatal(err)
		}
		return note
	}

	honest := chainLeaves(t, origin, 6, -1, "")
	rewritten := chainLeaves(t, origin, 9, 3, "rewritten")

	t.Run("rewritten history", func(t *testing.T) {
		p, err := BuildMisbehaviorProof(sign(honest), honest, sign(rewritten), rewritten, operator)
		if err != nil {
			t.Fatal(err)
		}
		if *p.Index != 3 {
			t.Fatalf("index = %d, want 3", *p.Index)
		}
		desc, err := CheckMisbehavior(p, operator, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(desc, "index 3") {
			t.Fatalf("description %q", desc)
		}
	})

	t.Run("same size, different roots", func(t *testing.T) {
		forked := chainLeaves(t, origin, 6, 5, "forked")
		p, err := BuildMisbehaviorProof(sign(honest), honest, sign(forked), forked, operator)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := CheckMisbehavior(p, operator, nil); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("consistent checkpoints prove nothing", func(t *testing.T) {
		longer := chainLeaves(t, origin, 9, -1, "")
		if _, err := BuildMisbehaviorProof(sign(honest), honest, sign(longer), longer, operator); err == nil {
			t.Fatal("built a proof from consistent checkpoints")
		}
		// A forged proof claiming a different leaf must not verify.
		i := uint64(2)
		proofA, _ := InclusionProof(honest, i)
		proofB, _ := InclusionProof(longer, i)
		fake := LeafHash([]byte("fake"))
		p := MisbehaviorProof{
			Type:        MisbehaviorType,
			Checkpoints: []string{string(sign(honest)), string(sign(longer))},
			Index:       &i,
			LeafHashes:  []string{encodeHash(honest[i]), encodeHash(fake)},
			Proofs:      [][]string{encodeHashes(proofA), encodeHashes(proofB)},
		}
		if _, err := CheckMisbehavior(p, operator, nil); err == nil {
			t.Fatal("forged proof verified")
		}
	})

	t.Run("checkpoints from another key prove nothing", func(t *testing.T) {
		other, _ := newTestOperator(t, origin)
		note, err := SignCheckpoint(Checkpoint{Origin: origin, Size: 6, Root: Root(rewritten[:6])}, other)
		if err != nil {
			t.Fatal(err)
		}
		p := MisbehaviorProof{Type: MisbehaviorType, Checkpoints: []string{string(sign(honest)), string(note)}}
		if _, err := CheckMisbehavior(p, operator, nil); err == nil {
			t.Fatal("proof with a checkpoint from another key verified")
		}
	})
}

func TestCheckCheckpoint(t *testing.T) {
	const origin = "city.example/cameras"
	var buf bytes.Buffer
	w, err := NewWriter(&buf, origin)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		if _, err := w.Append(sampleRecord(i)); err != nil {
			t.Fatal(err)
		}
	}
	s, leaves, err := VerifyLeaves(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	for size := range uint64(6) {
		c := Checkpoint{Origin: origin, Size: size, Root: Root(leaves[:size])}
		if err := CheckCheckpoint(s, leaves, c); err != nil {
			t.Errorf("size %d: %v", size, err)
		}
	}
	if CheckCheckpoint(s, leaves, Checkpoint{Origin: origin, Size: 6, Root: Root(leaves)}) == nil {
		t.Error("checkpoint larger than chain accepted")
	}
	if CheckCheckpoint(s, leaves, Checkpoint{Origin: "other.example", Size: 5, Root: Root(leaves)}) == nil {
		t.Error("checkpoint for another origin accepted")
	}
	if CheckCheckpoint(s, leaves, Checkpoint{Origin: origin, Size: 4, Root: Root(leaves)}) == nil {
		t.Error("checkpoint with wrong root accepted")
	}
}

func TestKeysWithPlusInBase64(t *testing.T) {
	for range 64 {
		skey, vkey, err := GenerateKey("k.example")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := NewSigner(skey); err != nil {
			t.Fatalf("NewSigner(%q): %v", skey, err)
		}
		if _, err := NewVerifier(vkey); err != nil {
			t.Fatalf("NewVerifier(%q): %v", vkey, err)
		}
	}
}
