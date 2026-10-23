package core

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Writer appends records to a chain stored as JSON Lines.
//
// Each record is linked to its predecessor by the digest of the
// predecessor's exact serialized bytes, so verification never depends on
// re-encoding JSON.
type Writer struct {
	w     io.Writer
	chain string
	next  uint64
	head  string
}

// NewWriter starts a new chain with the given ID.
func NewWriter(w io.Writer, chainID string) (*Writer, error) {
	if chainID == "" {
		return nil, errors.New("chain ID must not be empty")
	}
	return &Writer{w: w, chain: chainID}, nil
}

// ResumeWriter continues an existing chain whose last record had sequence
// number nextSeq-1 and digest head, as reported by Verify.
func ResumeWriter(w io.Writer, s Summary) (*Writer, error) {
	if s.Chain == "" || !validDigest(s.Head) {
		return nil, errors.New("summary does not describe a verified chain")
	}
	return &Writer{w: w, chain: s.Chain, next: s.Count, head: s.Head}, nil
}

// Head returns the digest of the last appended record, or "" if none.
func (cw *Writer) Head() string { return cw.head }

// Append fills in the chain fields of r, writes it as one line and
// returns its digest.
func (cw *Writer) Append(r Record) (string, error) {
	if err := checkSubject(r.Subject); err != nil {
		return "", err
	}
	r.Spec = SpecVersion
	r.Chain = cw.chain
	r.Seq = cw.next
	r.Prev = cw.head
	r.CollectedAt = r.CollectedAt.UTC()

	line, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	if _, err := cw.w.Write(append(line, '\n')); err != nil {
		return "", err
	}
	cw.head = Digest(line)
	cw.next++
	return cw.head, nil
}

// Summary describes a verified chain.
type Summary struct {
	Chain string `json:"chain"`
	Count uint64 `json:"count"`
	Head  string `json:"head"`
	// Root is the base64 Merkle tree hash of all records
	// (spec/checkpoint.md §2).
	Root string `json:"root"`
}

// LineError reports a verification failure at a 1-based line number.
type LineError struct {
	Line int
	Err  error
}

func (e *LineError) Error() string { return fmt.Sprintf("line %d: %v", e.Line, e.Err) }
func (e *LineError) Unwrap() error { return e.Err }

// Verify reads a chain in JSON Lines form and checks that every record is
// well-formed, belongs to the same chain, has consecutive sequence numbers
// starting at 0, and links to the digest of the preceding line.
//
// Verify checks the integrity of the chain itself. It does not check
// evidence bodies against Subject.Digest, signatures or timestamps.
func Verify(r io.Reader) (Summary, error) {
	s, _, err := VerifyLeaves(r)
	return s, err
}

// VerifyLeaves is like Verify and also returns the Merkle leaf hashes of
// the records, for checking checkpoints and building proofs.
func VerifyLeaves(r io.Reader) (Summary, []Hash, error) {
	var s Summary
	var leaves []Hash
	br := bufio.NewReader(r)
	for n := 1; ; n++ {
		line, err := br.ReadBytes('\n')
		if err != nil && err != io.EOF {
			return s, nil, err
		}
		if len(line) == 0 && err == io.EOF {
			break
		}
		line = bytes.TrimSuffix(line, []byte("\n"))
		if err := verifyLine(&s, line); err != nil {
			return s, nil, &LineError{Line: n, Err: err}
		}
		leaves = append(leaves, LeafHash(line))
		if err == io.EOF {
			break
		}
	}
	if s.Count == 0 {
		return s, nil, errors.New("chain is empty")
	}
	root := Root(leaves)
	s.Root = base64.StdEncoding.EncodeToString(root[:])
	return s, leaves, nil
}

// CheckCheckpoint checks that a verified chain matches a verified
// checkpoint (spec/checkpoint.md §8, steps 3 to 5).
func CheckCheckpoint(s Summary, leaves []Hash, c Checkpoint) error {
	if s.Chain != c.Origin {
		return fmt.Errorf("chain ID %q does not match checkpoint origin %q", s.Chain, c.Origin)
	}
	if uint64(len(leaves)) < c.Size {
		return fmt.Errorf("chain has %d records, checkpoint covers %d", len(leaves), c.Size)
	}
	if Root(leaves[:c.Size]) != c.Root {
		return fmt.Errorf("the first %d records do not match the checkpoint root hash", c.Size)
	}
	return nil
}

func verifyLine(s *Summary, line []byte) error {
	if bytes.HasSuffix(line, []byte("\r")) {
		return errors.New("line ends with CR; the file may have been converted to CRLF")
	}
	var r Record
	if err := json.Unmarshal(line, &r); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if r.Spec != SpecVersion {
		return fmt.Errorf("unsupported spec %q", r.Spec)
	}
	if s.Count == 0 {
		if r.Chain == "" {
			return errors.New("chain ID is empty")
		}
		s.Chain = r.Chain
	} else if r.Chain != s.Chain {
		return fmt.Errorf("chain ID %q does not match %q", r.Chain, s.Chain)
	}
	if r.Seq != s.Count {
		return fmt.Errorf("sequence number %d, want %d", r.Seq, s.Count)
	}
	if r.Prev != s.Head {
		return fmt.Errorf("prev %q does not match digest of previous record %q", r.Prev, s.Head)
	}
	if err := checkSubject(r.Subject); err != nil {
		return err
	}
	s.Head = Digest(line)
	s.Count++
	return nil
}

// checkSubject requires at least one digest. A "sha256" digest, when
// present, must be well-formed; keyed digests such as "hmac-sha256" are
// opaque to the verifier because checking them needs the key.
func checkSubject(sub Subject) error {
	if len(sub.Digest) == 0 {
		return errors.New("subject has no digest")
	}
	if d, ok := sub.Digest["sha256"]; ok && !validDigest("sha256:"+d) {
		return fmt.Errorf("subject sha256 digest %q is not 64 lowercase hex characters", d)
	}
	return nil
}
