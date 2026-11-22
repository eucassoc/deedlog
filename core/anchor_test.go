package core

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"
)

// anchored builds a record chain of n records and an anchor chain that
// commits to it in the given intervals.
func anchored(t *testing.T, n int, bounds ...uint64) (records, outer []string, bodies [][]byte, entries []AnchorEntry) {
	t.Helper()
	const origin = "log.example/dlm"
	src := Source{Type: "test", ID: origin, Collector: "anchor_test"}
	var s Summary
	var lines [][]byte
	for i := range n {
		line, body, err := EventRecord(s, origin+"/records", Event{Source: src, Name: "thing.happened", Meta: []Field{{"item", fmt.Sprint(i)}}, At: time.Unix(1790000000+int64(i), 0)})
		if err != nil {
			t.Fatal(err)
		}
		s = s.Next(origin+"/records", line)
		lines = append(lines, line)
		records = append(records, string(line))
		bodies = append(bodies, body)
	}
	var o Summary
	from := uint64(0)
	for i, to := range bounds {
		e := AnchorEntry{Seq: uint64(i), Epoch: FormatEpoch(time.Unix(1790000000+600*int64(i+1), 0)), From: from, To: to,
			Nonce: fmt.Sprintf("%032x", i+1), Pad: fmt.Sprintf("%032x", 100+i)}
		made, err := Anchor(lines[from:to], AnchorTerms{Chain: origin + "/records", Epoch: e.Epoch, Nonce: e.Nonce, Pad: e.Pad})
		if err != nil {
			t.Fatal(err)
		}
		e.Size = made.Size
		line, _, err := EventRecord(o, origin, Event{Source: src, Name: AnchorEvent, Meta: AnchorMeta(e.Epoch, made.Commit), At: time.Unix(1790000000, 0)})
		if err != nil {
			t.Fatal(err)
		}
		o = o.Next(origin, line)
		outer = append(outer, string(line))
		entries = append(entries, e)
		from = to
	}
	return records, outer, bodies, entries
}

func chainOf(lines []string) *strings.Reader {
	return strings.NewReader(strings.Join(lines, "\n") + "\n")
}

func TestEventRecordVerifies(t *testing.T) {
	records, outer, bodies, _ := anchored(t, 4, 2, 4)
	for _, lines := range [][]string{records, outer} {
		if _, err := Verify(chainOf(lines)); err != nil {
			t.Fatal(err)
		}
	}
	if want := `{"event":"thing.happened","item":"0","at":"2026-09-21T14:13:20Z"}`; string(bodies[0]) != want {
		t.Fatalf("body = %s, want %s", bodies[0], want)
	}
	if _, _, err := EventRecord(Summary{}, "c", Event{Name: "e", Meta: []Field{{"k", "\xff"}}}); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
	if _, _, err := EventRecord(Summary{}, "", Event{Name: "e"}); err == nil {
		t.Fatal("empty chain ID accepted")
	}
}

func TestAnchorSizes(t *testing.T) {
	for k, want := range map[int]uint64{0: 1, 1: 1, 2: 2, 3: 4, 4: 4, 5: 8, 9: 16} {
		records, _, _, _ := anchored(t, k)
		var lines [][]byte
		for _, r := range records {
			lines = append(lines, []byte(r))
		}
		got, err := Anchor(lines, AnchorTerms{Chain: "c", Epoch: "2026-11-19T03:20:00Z", Nonce: "00", Pad: "00"})
		if err != nil || got.Size != want || uint64(len(got.Leaves)) != want {
			t.Errorf("%d records: size %d, %v; want %d", k, got.Size, err, want)
		}
	}
	if _, err := Anchor(nil, AnchorTerms{Pad: "xyz", Nonce: "00"}); err == nil {
		t.Error("a pad that is not hexadecimal was accepted")
	}
	if _, err := Anchor([][]byte{[]byte(`{"subject":{"digest":{"hmac-sha256":"00"}}}`)}, AnchorTerms{Pad: "00", Nonce: "00"}); err == nil {
		t.Error("a record without a SHA-256 subject digest was anchored")
	}
}

func TestVerifyAnchors(t *testing.T) {
	_, outer, _, _ := anchored(t, 3, 1, 3, 3)
	if _, _, anchors, err := VerifyAnchors(chainOf(outer)); err != nil || len(anchors) != 3 {
		t.Fatalf("VerifyAnchors = %d, %v", len(anchors), err)
	}
	records, _, _, _ := anchored(t, 3)
	wantLine := func(lines []string, line int) {
		t.Helper()
		_, _, _, err := VerifyAnchors(chainOf(lines))
		le, ok := err.(*LineError)
		if !ok || le.Line != line {
			t.Errorf("err = %v, want a failure at line %d", err, line)
		}
	}
	wantLine(records, 1) // not anchor records
	// Epochs that do not increase: the same interval anchored twice.
	const origin = "log.example/dlm"
	var o Summary
	var twice []string
	for range 2 {
		line, _, err := EventRecord(o, origin, Event{Name: AnchorEvent, Meta: AnchorMeta("2026-11-19T03:20:00Z", strings.Repeat("ab", 32))})
		if err != nil {
			t.Fatal(err)
		}
		o = o.Next(origin, line)
		twice = append(twice, string(line))
	}
	wantLine(twice, 2)
}

func TestCheckAnchored(t *testing.T) {
	records, outer, bodies, entries := anchored(t, 7, 3, 3, 6)
	_, _, anchors, err := VerifyAnchors(chainOf(outer))
	if err != nil {
		t.Fatal(err)
	}
	got, err := CheckAnchored(chainOf(records), anchors, 3, entries)
	if err != nil || got.Intervals != 3 || got.Anchored != 6 || got.Count != 7 {
		t.Fatalf("CheckAnchored = %+v, %v", got, err)
	}
	// A checkpoint that covers less: only those intervals are checked.
	if got, err := CheckAnchored(chainOf(records), anchors, 1, entries); err != nil || got.Anchored != 3 {
		t.Fatalf("CheckAnchored under a smaller checkpoint = %+v, %v", got, err)
	}
	refuse := func(name, want string, change func(e []AnchorEntry) []AnchorEntry) {
		t.Helper()
		_, err := CheckAnchored(chainOf(records), anchors, 3, change(append([]AnchorEntry{}, entries...)))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", name, err, want)
		}
	}
	refuse("an entry missing", "anchor record 2 (line 3 of the anchor chain) has none", func(e []AnchorEntry) []AnchorEntry { return e[:2] })
	refuse("a gap", "anchor record 2 (line 3 of the anchor chain): covers records from 4", func(e []AnchorEntry) []AnchorEntry { e[2].From = 4; return e })
	refuse("not from 0", "anchor record 0 (line 1 of the anchor chain): covers records from 1", func(e []AnchorEntry) []AnchorEntry { e[0].From = 1; return e })
	refuse("beyond the chain", "of a chain of 7", func(e []AnchorEntry) []AnchorEntry { e[2].To = 8; return e })
	refuse("fewer records", "anchor record 0 (line 1 of the anchor chain): records 0 to 2", func(e []AnchorEntry) []AnchorEntry { e[0].To, e[0].Size, e[1].From = 2, 0, 2; return e })
	refuse("another pad", "anchor record 1 (line 2 of the anchor chain): records 3 to 3", func(e []AnchorEntry) []AnchorEntry { e[1].Pad = "00"; return e })
	refuse("another size", "its entry says 2", func(e []AnchorEntry) []AnchorEntry { e[0].Size = 2; return e })
	refuse("another epoch", "its entry's 2026", func(e []AnchorEntry) []AnchorEntry { e[0].Epoch = "2026-01-01T00:00:00Z"; return e })

	lines := [][]byte{[]byte(records[3]), []byte(records[4]), []byte(records[5])}
	p, err := NewRecordProof(lines, 1, 2, AnchorTerms{Chain: "log.example/dlm/records", Epoch: entries[2].Epoch, Nonce: entries[2].Nonce, Pad: entries[2].Pad})
	if err != nil {
		t.Fatal(err)
	}
	subject := Hash(sha256.Sum256(bodies[4]))
	if err := CheckRecordProof(p, "log.example/dlm/records", subject, anchors, 3); err != nil {
		t.Fatal(err)
	}
	if err := CheckRecordProof(p, "log.example/dlm/records", subject, anchors, 2); err == nil {
		t.Error("accepted under a checkpoint that does not cover the anchor record")
	}
	if err := CheckRecordProof(p, "log.example/dlm/records", Hash(sha256.Sum256(bodies[3])), anchors, 3); err == nil {
		t.Error("accepted for another subject")
	}
}

func TestParseAnchorEntries(t *testing.T) {
	for _, in := range []string{
		`[{"seq":0,"epoch":"e","from":0,"to":2,"size":2,"nonce":"aa","pad":"bb"}]`,
		`{"origin":"o","chain":"c","records":[],"anchors":[{"seq":0,"epoch":"e","from":0,"to":2,"size":2,"nonce":"aa","pad":"bb"}]}`,
	} {
		got, err := ParseAnchorEntries([]byte(in))
		if err != nil || len(got) != 1 || got[0].To != 2 || got[0].Pad != "bb" {
			t.Errorf("ParseAnchorEntries(%s) = %+v, %v", in, got, err)
		}
	}
	if _, err := ParseAnchorEntries([]byte(`[{"seq":1}]`)); err == nil {
		t.Error("entries out of order accepted")
	}
}
