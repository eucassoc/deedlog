package core

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func sampleRecord(i int) Record {
	body := []byte(strings.Repeat("x", i+1))
	return Record{
		CollectedAt: time.Date(2026, 10, 22, 9, 0, i, 0, time.FixedZone("JST", 9*3600)),
		Source:      Source{Type: "test", ID: "unit", Collector: "chain_test"},
		Subject: Subject{
			MediaType: "text/plain",
			Size:      int64(len(body)),
			Digest:    map[string]string{"sha256": strings.TrimPrefix(Digest(body), "sha256:")},
		},
	}
}

func writeChain(t *testing.T, n int) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	w, err := NewWriter(&buf, "test-chain")
	if err != nil {
		t.Fatal(err)
	}
	var head string
	for i := range n {
		if head, err = w.Append(sampleRecord(i)); err != nil {
			t.Fatal(err)
		}
	}
	return &buf, head
}

func TestVerifyRoundTrip(t *testing.T) {
	buf, head := writeChain(t, 5)
	s, err := Verify(buf)
	if err != nil {
		t.Fatal(err)
	}
	if s.Chain != "test-chain" || s.Count != 5 || s.Head != head {
		t.Fatalf("got %+v, want chain test-chain, count 5, head %s", s, head)
	}
}

func TestVerifyWithoutTrailingNewline(t *testing.T) {
	buf, _ := writeChain(t, 3)
	trimmed := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	if _, err := Verify(bytes.NewReader(trimmed)); err != nil {
		t.Fatal(err)
	}
}

func TestResumeWriter(t *testing.T) {
	buf, _ := writeChain(t, 2)
	s, err := Verify(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	w, err := ResumeWriter(buf, s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(sampleRecord(2)); err != nil {
		t.Fatal(err)
	}
	s, err = Verify(buf)
	if err != nil {
		t.Fatal(err)
	}
	if s.Count != 3 {
		t.Fatalf("count = %d, want 3", s.Count)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	buf, _ := writeChain(t, 3)
	lines := strings.SplitAfter(buf.String(), "\n")

	tests := map[string]struct {
		chain string
		line  int
	}{
		"edited record": {
			chain: lines[0] + strings.Replace(lines[1], `"unit"`, `"edit"`, 1) + lines[2],
			line:  3,
		},
		"deleted record": {
			chain: lines[0] + lines[2],
			line:  2,
		},
		"reordered records": {
			chain: lines[1] + lines[0] + lines[2],
			line:  1,
		},
		"CRLF conversion": {
			chain: strings.ReplaceAll(buf.String(), "\n", "\r\n"),
			line:  1,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Verify(strings.NewReader(tt.chain))
			var le *LineError
			if !errors.As(err, &le) {
				t.Fatalf("err = %v, want *LineError", err)
			}
			if le.Line != tt.line {
				t.Fatalf("failed at line %d, want %d: %v", le.Line, tt.line, err)
			}
		})
	}
}

func TestVerifyEmpty(t *testing.T) {
	if _, err := Verify(strings.NewReader("")); err == nil {
		t.Fatal("empty chain verified")
	}
}

func TestAppendRejectsMissingDigest(t *testing.T) {
	w, err := NewWriter(&bytes.Buffer{}, "c")
	if err != nil {
		t.Fatal(err)
	}
	r := sampleRecord(0)
	r.Subject.Digest = nil
	if _, err := w.Append(r); err == nil {
		t.Fatal("record without digest was appended")
	}
}
