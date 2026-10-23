package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

// Example from c2sp.org/signed-note.
func TestSignedNoteVector(t *testing.T) {
	v, err := NewVerifier("example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k")
	if err != nil {
		t.Fatal(err)
	}
	note := "This is an example message.\n\n— example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=\n"
	text, _, err := openNote([]byte(note), []*Verifier{v})
	if err != nil {
		t.Fatal(err)
	}
	if string(text) != "This is an example message.\n" {
		t.Fatalf("text = %q", text)
	}
	if _, _, err := openNote([]byte(strings.Replace(note, "example message", "example massage", 1)), []*Verifier{v}); err == nil {
		t.Fatal("modified note verified")
	}
}

func TestOpenNote(t *testing.T) {
	v, err := NewVerifier("example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k")
	if err != nil {
		t.Fatal(err)
	}
	note := "This is an example message.\n\n— example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=\n"
	text, signers, err := OpenNote([]byte(note), []*Verifier{v})
	if err != nil || string(text) != "This is an example message.\n" || len(signers) != 1 {
		t.Fatalf("OpenNote = %q, %d signers, %v", text, len(signers), err)
	}
	_, wvkey, err := GenerateWitnessKey("witness.example")
	if err != nil {
		t.Fatal(err)
	}
	w, err := NewVerifier(wvkey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenNote([]byte(note), []*Verifier{v, w}); err == nil {
		t.Fatal("OpenNote accepted a cosignature key")
	}
}

// A public witness key in the C2SP witness network, from
// github.com/transparency-dev/formats; checks the key ID computation for
// cosignature keys.
func TestWitnessKeyVector(t *testing.T) {
	v, err := NewVerifier("remora.n621.de+da77ade7+BOvN63jn/bLvkieywe8R6UYAtVtNbZpXh34x7onlmtw2")
	if err != nil {
		t.Fatal(err)
	}
	if v.Type() != SigCosignature {
		t.Fatalf("type = %#x", v.Type())
	}
}

type testWitness struct {
	name string
	priv ed25519.PrivateKey
	v    *Verifier
}

func newTestWitness(t *testing.T, name string) *testWitness {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	vkey := fmt.Sprintf("%s+%08x+%s", name, keyID(name, SigCosignature, pub),
		base64.StdEncoding.EncodeToString(append([]byte{SigCosignature}, pub...)))
	v, err := NewVerifier(vkey)
	if err != nil {
		t.Fatal(err)
	}
	return &testWitness{name: name, priv: priv, v: v}
}

// cosign appends a c2sp.org/tlog-cosignature Ed25519 cosignature.
func (w *testWitness) cosign(note []byte, ts uint64) []byte {
	text := note[:bytes.LastIndex(note, []byte("\n\n"))+1]
	msg := fmt.Appendf(nil, "cosignature/v1\ntime %d\n%s", ts, text)
	sig := binary.BigEndian.AppendUint32(nil, w.v.id)
	sig = binary.BigEndian.AppendUint64(sig, ts)
	sig = append(sig, ed25519.Sign(w.priv, msg)...)
	return fmt.Appendf(bytes.Clone(note), "— %s %s\n", w.name, base64.StdEncoding.EncodeToString(sig))
}

func newTestOperator(t *testing.T, origin string) (*Signer, *Verifier) {
	t.Helper()
	skey, vkey, err := GenerateKey(origin)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(vkey)
	if err != nil {
		t.Fatal(err)
	}
	return s, v
}

func TestCheckpointSignAndVerify(t *testing.T) {
	const origin = "city.example/cameras"
	signer, operator := newTestOperator(t, origin)
	w1, w2 := newTestWitness(t, "w1.example"), newTestWitness(t, "w2.example")
	leaves := testLeaves(5)
	cp := Checkpoint{Origin: origin, Size: 5, Root: Root(leaves)}

	note, err := SignCheckpoint(cp, signer)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyCheckpoint(note, operator, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got != cp {
		t.Fatalf("got %+v, want %+v", got, cp)
	}

	cosigned := w2.cosign(w1.cosign(note, 1_800_000_000), 1_800_000_001)
	witnesses := []*Verifier{w1.v, w2.v}
	if _, err := VerifyCheckpoint(cosigned, operator, witnesses, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCheckpoint(note, operator, witnesses, 1); err == nil {
		t.Fatal("quorum met without cosignatures")
	}

	// A cosignature with a different timestamp than signed must fail.
	lines := strings.Split(string(w1.cosign(note, 1_800_000_000)), "\n")
	last := lines[len(lines)-2]
	name, b64, _ := strings.Cut(strings.TrimPrefix(last, "— "), " ")
	raw, _ := base64.StdEncoding.DecodeString(b64)
	binary.BigEndian.PutUint64(raw[4:], 1_800_000_999)
	lines[len(lines)-2] = "— " + name + " " + base64.StdEncoding.EncodeToString(raw)
	if _, err := VerifyCheckpoint([]byte(strings.Join(lines, "\n")), operator, witnesses, 1); err == nil {
		t.Fatal("cosignature with altered timestamp verified")
	}
}

func TestVerifyCheckpointRejects(t *testing.T) {
	const origin = "city.example/cameras"
	signer, operator := newTestOperator(t, origin)
	_, stranger := newTestOperator(t, origin)
	_, otherOrigin := newTestOperator(t, "other.example/log")
	cp := Checkpoint{Origin: origin, Size: 1, Root: LeafHash([]byte("x"))}
	note, err := SignCheckpoint(cp, signer)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := VerifyCheckpoint(note, stranger, nil, 0); err == nil {
		t.Error("checkpoint verified with another operator key")
	}
	if _, err := VerifyCheckpoint(note, otherOrigin, nil, 0); err == nil {
		t.Error("checkpoint verified with key for another origin")
	}
	tampered := bytes.Replace(note, []byte("\n1\n"), []byte("\n2\n"), 1)
	if _, err := VerifyCheckpoint(tampered, operator, nil, 0); err == nil {
		t.Error("tampered checkpoint verified")
	}
	if _, err := SignCheckpoint(Checkpoint{Origin: "other.example/log", Size: 1}, signer); err == nil {
		t.Error("signed checkpoint for another origin")
	}

	ext, err := signer.Sign(append(cp.Text(), "extension\n"...))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCheckpoint(ext, operator, nil, 0); err == nil {
		t.Error("checkpoint with extension line verified")
	}
}

func TestParseCheckpoint(t *testing.T) {
	root := base64.StdEncoding.EncodeToString(EmptyRoot[:])
	tests := map[string]bool{
		"a.example/log\n0\n" + root + "\n":                     true,
		"a.example/log\n00\n" + root + "\n":                    false, // leading zero
		"a.example/log\n-1\n" + root + "\n":                    false,
		"a b\n0\n" + root + "\n":                               false, // space in origin
		"a+b\n0\n" + root + "\n":                               false, // plus in origin
		"a.example/log\n0\n" + root:                            false, // no final newline
		"a.example/log\n1\n" + root[:len(root)-1] + "Q\n":      false, // non-canonical base64
		"a.example/log\n0\n" + strings.Repeat("A", 43) + "=\n": false, // empty tree, wrong root
	}
	for text, ok := range tests {
		_, err := ParseCheckpoint([]byte(text))
		if (err == nil) != ok {
			t.Errorf("ParseCheckpoint(%q) error = %v, want ok = %v", text, err, ok)
		}
	}
}
