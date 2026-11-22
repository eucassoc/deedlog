package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"
)

// Anchoring keeps a chain of records with its operator and commits to it,
// one interval at a time, through a second, public chain
// (spec/anchoring.md).

// AnchorEvent is the event name of an anchor record.
const AnchorEvent = "chain.anchored"

const (
	anchorLeafPrefix  = "deedlog-anchor-leaf/v1\n"
	anchorBlindPrefix = "deedlog-anchor-blind/v1\n"
	anchorPadPrefix   = "deedlog-anchor-pad/v1\n"
	anchorCommitHead  = "deedlog-anchor/v1\n"
	epochLayout       = "2006-01-02T15:04:05Z"
)

// AnchorTerms are what an interval's commitment is made under: the chain
// field of the record chain, the epoch, and the interval's two secrets in
// hexadecimal.
type AnchorTerms struct {
	Chain string
	Epoch string
	Nonce string
	Pad   string
}

// Interval is the tree of one interval and its commitment.
type Interval struct {
	Size   uint64
	Root   Hash
	Commit string
	Leaves []Hash
}

// FormatEpoch returns t as an epoch: RFC 3339 in UTC, to the second.
func FormatEpoch(t time.Time) string { return t.UTC().Format(epochLayout) }

// AnchorBlind returns the blind of the record at position i of an interval.
func AnchorBlind(pad []byte, i uint32) Hash {
	h := sha256.New()
	h.Write([]byte(anchorBlindPrefix))
	h.Write(pad)
	h.Write(binary.BigEndian.AppendUint32(nil, i))
	return Hash(h.Sum(nil))
}

// AnchorLeaf returns the leaf that stands for a record: its blind, the
// digest of its subject and the SHA-256 of its record bytes.
func AnchorLeaf(blind, subject, record Hash) Hash {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write([]byte(anchorLeafPrefix))
	h.Write(blind[:])
	h.Write(subject[:])
	h.Write(record[:])
	return Hash(h.Sum(nil))
}

func anchorPadLeaf(pad []byte, j uint32) Hash {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write([]byte(anchorPadPrefix))
	h.Write(pad)
	h.Write(binary.BigEndian.AppendUint32(nil, j))
	return Hash(h.Sum(nil))
}

// AnchorCommit returns the commitment of an interval.
func AnchorCommit(chain, epoch string, size uint64, root Hash, nonce string) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%s%s\n%s\n%d\n%s\n%s\n", anchorCommitHead,
		chain, epoch, size, base64.StdEncoding.EncodeToString(root[:]), nonce))
	return hex.EncodeToString(sum[:])
}

func hexHash(what, s string) (Hash, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(Hash{}) {
		return Hash{}, fmt.Errorf("%s is not 64 hexadecimal characters", what)
	}
	return Hash(b), nil
}

// subjectOf returns the SHA-256 subject digest that record bytes name.
func subjectOf(line []byte) (Hash, error) {
	var r struct {
		Subject Subject `json:"subject"`
	}
	if err := json.Unmarshal(line, &r); err != nil {
		return Hash{}, fmt.Errorf("invalid JSON: %w", err)
	}
	d, ok := r.Subject.Digest["sha256"]
	if !ok || !validDigest("sha256:"+d) {
		return Hash{}, errors.New("the record names no SHA-256 digest of its subject")
	}
	return hexHash("subject digest", d)
}

// Anchor returns an interval's tree and commitment from the record bytes of
// the records it covers, which may be none.
func Anchor(lines [][]byte, t AnchorTerms) (Interval, error) {
	pad, err := hex.DecodeString(t.Pad)
	if err != nil {
		return Interval{}, errors.New("pad is not hexadecimal")
	}
	if _, err := hex.DecodeString(t.Nonce); err != nil {
		return Interval{}, errors.New("nonce is not hexadecimal")
	}
	if uint64(len(lines)) > 1<<31 {
		return Interval{}, errors.New("too many records for one interval")
	}
	size := uint64(1)
	for size < uint64(len(lines)) {
		size *= 2
	}
	leaves := make([]Hash, 0, size)
	for i, line := range lines {
		subject, err := subjectOf(line)
		if err != nil {
			return Interval{}, fmt.Errorf("record %d of the interval: %w", i, err)
		}
		leaves = append(leaves, AnchorLeaf(AnchorBlind(pad, uint32(i)), subject, sha256.Sum256(line)))
	}
	for j := uint64(len(lines)); j < size; j++ {
		leaves = append(leaves, anchorPadLeaf(pad, uint32(j)))
	}
	root := Root(leaves)
	return Interval{Size: size, Root: root, Commit: AnchorCommit(t.Chain, t.Epoch, size, root, t.Nonce), Leaves: leaves}, nil
}

// RecordProof shows that the operator committed to a record about a given
// subject, without showing the record (spec/anchoring.md §5).
type RecordProof struct {
	Seq    uint64   `json:"seq"`
	Epoch  string   `json:"epoch"`
	Size   uint64   `json:"size"`
	Index  uint64   `json:"index"`
	Path   []string `json:"path"`
	Nonce  string   `json:"nonce"`
	Blind  string   `json:"blind"`
	Record string   `json:"record"`
}

// NewRecordProof returns the proof for the record at position i of the
// interval whose records are lines and whose anchor record is at seq.
func NewRecordProof(lines [][]byte, i int, seq uint64, t AnchorTerms) (RecordProof, error) {
	if i < 0 || i >= len(lines) {
		return RecordProof{}, fmt.Errorf("no record %d in an interval of %d", i, len(lines))
	}
	made, err := Anchor(lines, t)
	if err != nil {
		return RecordProof{}, err
	}
	path, err := InclusionProof(made.Leaves, uint64(i))
	if err != nil {
		return RecordProof{}, err
	}
	pad, _ := hex.DecodeString(t.Pad)
	blind := AnchorBlind(pad, uint32(i))
	record := sha256.Sum256(lines[i])
	p := RecordProof{Seq: seq, Epoch: t.Epoch, Size: made.Size, Index: uint64(i), Path: []string{},
		Nonce: t.Nonce, Blind: hex.EncodeToString(blind[:]), Record: hex.EncodeToString(record[:])}
	for _, h := range path {
		p.Path = append(p.Path, base64.StdEncoding.EncodeToString(h[:]))
	}
	return p, nil
}

// Commit returns the commitment that a subject leads to under the proof.
// chain is the chain field of the record chain, and subject the SHA-256 of
// the bytes the record is about. The caller compares the result with the
// anchor record; CheckRecordProof does.
func (p RecordProof) Commit(chain string, subject Hash) (string, error) {
	blind, err := hexHash("blind", p.Blind)
	if err != nil {
		return "", err
	}
	record, err := hexHash("record", p.Record)
	if err != nil {
		return "", err
	}
	if p.Index >= p.Size {
		return "", fmt.Errorf("no leaf %d in a tree of %d", p.Index, p.Size)
	}
	// RFC 9162 §2.1.3.2, keeping the root instead of comparing it.
	fn, sn := p.Index, p.Size-1
	r := AnchorLeaf(blind, subject, record)
	for _, s := range p.Path {
		b, err := decodeBase64(s)
		if err != nil || len(b) != len(Hash{}) {
			return "", errors.New("malformed inclusion proof")
		}
		if sn == 0 {
			return "", errors.New("inclusion proof too long")
		}
		if fn&1 == 1 || fn == sn {
			r = nodeHash(Hash(b), r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = nodeHash(r, Hash(b))
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return "", errors.New("inclusion proof too short")
	}
	return AnchorCommit(chain, p.Epoch, p.Size, r, p.Nonce), nil
}

// AnchorRecord is what an anchor record says.
type AnchorRecord struct {
	Epoch  string
	Commit string
}

// AnchorMeta returns the fields of an anchor record, for EventRecord.
func AnchorMeta(epoch, commit string) []Field {
	return []Field{{"epoch", epoch}, {"commit", commit}}
}

// VerifyAnchors verifies an anchor chain as VerifyLeaves does, and checks
// that every record is an anchor record and that epochs increase. The
// anchor record with sequence number i is at index i of the result.
func VerifyAnchors(r io.Reader) (Summary, []Hash, []AnchorRecord, error) {
	var anchors []AnchorRecord
	var last time.Time
	s, leaves, err := verifyRecords(r, func(_ []byte, rec *Record) error {
		if rec.Meta["event"] != AnchorEvent {
			return fmt.Errorf("event is %q, not %q: not an anchor record", rec.Meta["event"], AnchorEvent)
		}
		a := AnchorRecord{Epoch: rec.Meta["epoch"], Commit: rec.Meta["commit"]}
		if !validDigest("sha256:" + a.Commit) {
			return fmt.Errorf("commit %q is not 64 lowercase hex characters", a.Commit)
		}
		t, err := time.Parse(epochLayout, a.Epoch)
		if err != nil {
			return fmt.Errorf("epoch %q is not RFC 3339 in UTC to the second", a.Epoch)
		}
		if len(anchors) > 0 && !t.After(last) {
			return fmt.Errorf("epoch %s does not come after %s", a.Epoch, anchors[len(anchors)-1].Epoch)
		}
		last = t
		anchors = append(anchors, a)
		return nil
	})
	if err != nil {
		return s, nil, nil, err
	}
	return s, leaves, anchors, nil
}

// CheckRecordProof checks a record proof against a verified anchor chain
// (spec/anchoring.md §5). chain is the chain field of the record chain,
// subject the SHA-256 of the bytes the record is about, and covered the
// tree size of the verified checkpoint of the anchor chain.
func CheckRecordProof(p RecordProof, chain string, subject Hash, anchors []AnchorRecord, covered uint64) error {
	if p.Seq >= uint64(len(anchors)) {
		return fmt.Errorf("the anchor chain has %d records; the proof is for anchor record %d", len(anchors), p.Seq)
	}
	if p.Seq >= covered {
		return fmt.Errorf("anchor record %d is not covered by the checkpoint, whose tree size is %d", p.Seq, covered)
	}
	a := anchors[p.Seq]
	where := fmt.Sprintf("anchor record %d (line %d of the anchor chain)", p.Seq, p.Seq+1)
	if a.Epoch != p.Epoch {
		return fmt.Errorf("%s: its epoch is %s, the proof's %s", where, a.Epoch, p.Epoch)
	}
	commit, err := p.Commit(chain, subject)
	if err != nil {
		return err
	}
	if commit != a.Commit {
		return fmt.Errorf("%s: the subject and the proof do not lead to its commitment", where)
	}
	return nil
}

// AnchorEntry is what the holder of a record chain needs for one anchor
// record (spec/anchoring.md §6): which records it covers, and the
// interval's secrets. Epoch and Size are optional; when present they must
// agree with the anchor record and the tree.
type AnchorEntry struct {
	Seq   uint64 `json:"seq"`
	Epoch string `json:"epoch,omitempty"`
	From  uint64 `json:"from"`
	To    uint64 `json:"to"`
	Size  uint64 `json:"size,omitempty"`
	Nonce string `json:"nonce"`
	Pad   string `json:"pad"`
}

// Anchored describes a record chain checked against its anchor chain.
type Anchored struct {
	Summary
	// Intervals is the number of anchor records checked.
	Intervals uint64 `json:"intervals"`
	// Anchored is the number of records they cover; later records are not
	// yet anchored.
	Anchored uint64 `json:"anchored"`
}

// CheckAnchored verifies a record chain and checks it against a verified
// anchor chain (spec/anchoring.md §6). covered is the tree size of the
// verified checkpoint of the anchor chain; entries are in the order of
// their anchor records.
func CheckAnchored(records io.Reader, anchors []AnchorRecord, covered uint64, entries []AnchorEntry) (Anchored, error) {
	s, lines, err := VerifyLines(records)
	if err != nil {
		return Anchored{Summary: s}, err
	}
	out := Anchored{Summary: s}
	if covered > uint64(len(anchors)) {
		return out, fmt.Errorf("the anchor chain has %d records, the checkpoint covers %d", len(anchors), covered)
	}
	if uint64(len(entries)) < covered {
		return out, fmt.Errorf("%d entries for %d anchor records: anchor record %d (line %d of the anchor chain) has none", len(entries), covered, len(entries), len(entries)+1)
	}
	for i := uint64(0); i < covered; i++ {
		e, a := entries[i], anchors[i]
		where := fmt.Sprintf("anchor record %d (line %d of the anchor chain)", i, i+1)
		if e.Seq != i {
			return out, fmt.Errorf("%s: its entry is for anchor record %d", where, e.Seq)
		}
		if e.From != out.Anchored {
			return out, fmt.Errorf("%s: covers records from %d, the one before ends at %d", where, e.From, out.Anchored)
		}
		if e.To < e.From || e.To > s.Count {
			return out, fmt.Errorf("%s: covers records %d to %d of a chain of %d", where, e.From, e.To, s.Count)
		}
		if e.Epoch != "" && e.Epoch != a.Epoch {
			return out, fmt.Errorf("%s: its epoch is %s, its entry's %s", where, a.Epoch, e.Epoch)
		}
		made, err := Anchor(lines[e.From:e.To], AnchorTerms{Chain: s.Chain, Epoch: a.Epoch, Nonce: e.Nonce, Pad: e.Pad})
		if err != nil {
			return out, fmt.Errorf("%s: %w", where, err)
		}
		if e.Size != 0 && e.Size != made.Size {
			return out, fmt.Errorf("%s: its tree has size %d, its entry says %d", where, made.Size, e.Size)
		}
		if made.Commit != a.Commit {
			return out, fmt.Errorf("%s: records %d to %d of %s (lines %s) do not lead to its commitment", where, e.From, e.To, s.Chain, lineRange(e.From, e.To))
		}
		out.Intervals++
		out.Anchored = e.To
	}
	return out, nil
}

func lineRange(from, to uint64) string {
	if to == from {
		return "none"
	}
	return strconv.FormatUint(from+1, 10) + " to " + strconv.FormatUint(to, 10)
}

// ParseAnchorEntries reads entries from JSON: an array, or an object with
// the array under "anchors", as an operator's service hands them out.
func ParseAnchorEntries(b []byte) ([]AnchorEntry, error) {
	var entries []AnchorEntry
	if bytes.HasPrefix(bytes.TrimSpace(b), []byte("{")) {
		var wrapped struct {
			Anchors []AnchorEntry `json:"anchors"`
		}
		if err := json.Unmarshal(b, &wrapped); err != nil {
			return nil, err
		}
		entries = wrapped.Anchors
	} else if len(bytes.TrimSpace(b)) > 0 {
		if err := json.Unmarshal(b, &entries); err != nil {
			return nil, err
		}
	}
	for i, e := range entries {
		if e.Seq != uint64(i) {
			return nil, fmt.Errorf("entry %d is for anchor record %d; entries must be in order, one per anchor record", i, e.Seq)
		}
	}
	return entries, nil
}
