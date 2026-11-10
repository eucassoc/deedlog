// Package demo holds the plumbing shared by the runnable use-case samples:
// an operator's chain with its keys, in-process witnesses speaking the
// c2sp.org/tlog-witness protocol, and verification helpers.
//
// It is internal to the examples. Products embed the core, witness and
// publish packages directly; see each example for where the calls go.
package demo

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/eucassoc/deedlog/core"
	"github.com/eucassoc/deedlog/witness"
)

// Clock is a simulated clock, so that samples can cover weeks in a second.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

// NewClock returns a clock set to t.
func NewClock(t time.Time) *Clock { return &Clock{t: t.UTC()} }

// Now returns the current simulated time.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// Advance moves the clock forward by d.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// Log is an operator's chain held in memory, with the operator's checkpoint
// and receipt keys and a key for keyed digests. A product keeps the chain in
// a file or database instead; the calls are the same.
type Log struct {
	Origin string
	Clock  *Clock

	mu      sync.Mutex
	buf     bytes.Buffer
	w       *core.Writer
	leaves  []core.Hash
	op      *core.Signer
	opVKey  string
	rcpt    *core.Signer
	rcptKey string
	hmacKey []byte
	bodies  map[string][]byte
	latest  []byte
}

// NewLog creates a chain with fresh keys.
func NewLog(origin string, clock *Clock) (*Log, error) {
	l := &Log{Origin: origin, Clock: clock, bodies: make(map[string][]byte)}
	var err error
	if l.op, l.opVKey, err = signer(origin); err != nil {
		return nil, err
	}
	if l.rcpt, l.rcptKey, err = signer(origin + "/receipts"); err != nil {
		return nil, err
	}
	l.hmacKey = make([]byte, 32)
	if _, err := rand.Read(l.hmacKey); err != nil {
		return nil, err
	}
	if l.w, err = core.NewWriter(&l.buf, origin); err != nil {
		return nil, err
	}
	return l, nil
}

func signer(name string) (*core.Signer, string, error) {
	skey, vkey, err := core.GenerateKey(name)
	if err != nil {
		return nil, "", err
	}
	s, err := core.NewSigner(skey)
	return s, vkey, err
}

// Event is one piece of evidence to append.
type Event struct {
	Source    core.Source
	MediaType string
	Body      []byte
	// Keyed digests the body with HMAC-SHA-256 instead of SHA-256, for
	// bodies containing personal or other low-entropy data (spec §6).
	Keyed bool
	Meta  map[string]string
}

// Append records e and returns its index in the chain. The evidence body is
// kept by the operator, never in the chain.
func (l *Log) Append(e Event) (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	alg, digest := "sha256", Sum(e.Body)
	if e.Keyed {
		alg, digest = "hmac-sha256", l.hmac(e.Body)
	}
	before := l.buf.Len()
	if _, err := l.w.Append(core.Record{
		CollectedAt: l.Clock.Now(),
		Source:      e.Source,
		Subject:     core.Subject{MediaType: e.MediaType, Size: int64(len(e.Body)), Digest: map[string]string{alg: digest}},
		Meta:        e.Meta,
	}); err != nil {
		return 0, err
	}
	line := bytes.TrimSuffix(l.buf.Bytes()[before:], []byte("\n"))
	l.leaves = append(l.leaves, core.LeafHash(line))
	l.bodies[alg+":"+digest] = bytes.Clone(e.Body)
	return uint64(len(l.leaves) - 1), nil
}

// HMAC returns the keyed digest that Append records for body.
func (l *Log) HMAC(body []byte) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.hmac(body)
}

func (l *Log) hmac(body []byte) string {
	m := hmac.New(sha256.New, l.hmacKey)
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

// Sum returns the hex SHA-256 of b, as recorded in subject digests.
func Sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// Body returns an evidence body by its digest ("sha256:<hex>" or
// "hmac-sha256:<hex>").
func (l *Log) Body(digest string) ([]byte, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.bodies[digest]
	return b, ok
}

// Chain returns the chain in JSON Lines form.
func (l *Log) Chain() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return bytes.Clone(l.buf.Bytes())
}

// Size returns the number of records.
func (l *Log) Size() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return uint64(len(l.leaves))
}

// OperatorKey returns the verifier key of the operator's checkpoints.
func (l *Log) OperatorKey() *core.Verifier { return l.op.Verifier() }

// ReceiptKey returns the verifier key of the operator's receipts.
func (l *Log) ReceiptKey() *core.Verifier { return l.rcpt.Verifier() }

// Receipt issues a signed receipt for the record at index.
func (l *Log) Receipt(index uint64) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if index >= uint64(len(l.leaves)) {
		return nil, fmt.Errorf("no record %d", index)
	}
	return core.IssueReceipt(core.Receipt{Origin: l.Origin, Index: index, LeafHash: l.leaves[index]}, l.rcpt)
}

// Checkpoint signs a checkpoint of the whole chain and has every witness
// cosign it. The result is also kept as the latest checkpoint.
func (l *Log) Checkpoint(ctx context.Context, witnesses ...*Witness) ([]byte, error) {
	l.mu.Lock()
	leaves := append([]core.Hash(nil), l.leaves...)
	l.mu.Unlock()
	note, err := core.SignCheckpoint(core.Checkpoint{Origin: l.Origin, Size: uint64(len(leaves)), Root: core.Root(leaves)}, l.op)
	if err != nil {
		return nil, err
	}
	var cl witness.Client
	for _, w := range witnesses {
		// Starting from size 0 lets the witness tell us, with 409, the size
		// it cosigned last; the client then retries with the right proof.
		if note, err = cl.Cosign(ctx, witness.Witness{Key: w.Key(), URL: w.URL()}, note, leaves, l.op.Verifier(), 0); err != nil {
			return nil, fmt.Errorf("witness %s: %w", w.Name, err)
		}
	}
	l.mu.Lock()
	l.latest = note
	l.mu.Unlock()
	return note, nil
}

// Latest returns the latest checkpoint, or nil.
func (l *Log) Latest() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.latest
}

// Proof returns the leaf hash at index and its inclusion proof in the tree
// of the given size, as served by the publication API.
func (l *Log) Proof(index, size uint64) (core.Hash, []core.Hash, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if size > uint64(len(l.leaves)) || index >= size {
		return core.Hash{}, nil, fmt.Errorf("no record %d in a tree of size %d", index, size)
	}
	p, err := core.InclusionProof(l.leaves[:size], index)
	return l.leaves[index], p, err
}

// Witness is a witness server running in-process over HTTP, speaking
// c2sp.org/tlog-witness exactly as a public witness would.
type Witness struct {
	Name string
	srv  *httptest.Server
	key  *core.Verifier
	vkey string
}

// StartWitness starts a witness for the given chains.
func StartWitness(name string, logs ...*Log) (*Witness, error) {
	skey, vkey, err := core.GenerateWitnessKey(name)
	if err != nil {
		return nil, err
	}
	s, err := core.NewSigner(skey)
	if err != nil {
		return nil, err
	}
	known := make(map[string]*core.Verifier)
	for _, l := range logs {
		known[l.Origin] = l.OperatorKey()
	}
	srv := httptest.NewServer(&witness.Server{Signer: s, Logs: known, Store: &witness.MemoryStore{}})
	return &Witness{Name: name, srv: srv, key: s.Verifier(), vkey: vkey}, nil
}

// URL returns the witness's submission prefix.
func (w *Witness) URL() string { return w.srv.URL }

// Key returns the witness's cosignature verifier key.
func (w *Witness) Key() *core.Verifier { return w.key }

// Close stops the witness.
func (w *Witness) Close() { w.srv.Close() }

// Entry is a verified record with its line number in the chain file.
type Entry struct {
	Line int
	core.Record
}

// Finding is a problem a use-case check found, tied to a chain line.
type Finding struct {
	Line    int
	Problem string
}

func (f Finding) String() string {
	if f.Line == 0 {
		return f.Problem
	}
	return fmt.Sprintf("line %d: %s", f.Line, f.Problem)
}

// Findings collects findings in line order.
type Findings []Finding

// Add appends a finding.
func (fs *Findings) Add(line int, format string, args ...any) {
	*fs = append(*fs, Finding{Line: line, Problem: fmt.Sprintf(format, args...)})
}

// Sorted returns the findings ordered by line.
func (fs Findings) Sorted() Findings {
	out := append(Findings(nil), fs...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Line < out[j].Line })
	return out
}

// Open verifies a chain and a checkpoint cosigned by a quorum of witnesses,
// and returns the records the checkpoint covers. This is the generic part of
// every use-case check; the use-case rules then run on the entries.
func Open(chain, checkpoint []byte, operator *core.Verifier, witnesses []*core.Verifier, quorum int) ([]Entry, core.Checkpoint, error) {
	s, leaves, err := core.VerifyLeaves(bytes.NewReader(chain))
	if err != nil {
		return nil, core.Checkpoint{}, err
	}
	c, err := core.VerifyCheckpoint(checkpoint, operator, witnesses, quorum)
	if err != nil {
		return nil, core.Checkpoint{}, err
	}
	if err := core.CheckCheckpoint(s, leaves, c); err != nil {
		return nil, core.Checkpoint{}, err
	}
	var entries []Entry
	for i, line := range bytes.SplitAfter(chain, []byte("\n")) {
		if uint64(i) >= c.Size {
			break
		}
		var r core.Record
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, core.Checkpoint{}, &core.LineError{Line: i + 1, Err: err}
		}
		entries = append(entries, Entry{Line: i + 1, Record: r})
	}
	return entries, c, nil
}

// Declared checks that body is the evidence of the entry, by its SHA-256
// digest, and decodes it as JSON into v. Samples use it for declarations
// such as a retention policy or a cadence, published by the operator and
// recorded as the first entry of the chain.
func Declared(e Entry, body []byte, v any) error {
	if e.Subject.Digest["sha256"] != Sum(body) {
		return &core.LineError{Line: e.Line, Err: fmt.Errorf("published declaration does not match the recorded digest")}
	}
	if err := json.Unmarshal(body, v); err != nil {
		return &core.LineError{Line: e.Line, Err: fmt.Errorf("declaration: %w", err)}
	}
	return nil
}

// ServeURL and PageURL are where the files written by Files can be served
// for the verification page in web/: the chain with dlog serve, and the page
// with the registry.json written alongside.
const (
	ServeURL = "http://localhost:8081"
	PageURL  = "http://localhost:8080/"
)

// Files writes the chain, its latest checkpoint, the public keys and a
// registry for the verification page into dir, so that the result can be
// checked with dlog or in the browser, and returns the command to run in
// dir.
func Files(dir string, l *Log, witnesses []*Witness) (string, error) {
	files := map[string][]byte{
		"chain.jsonl":   l.Chain(),
		"checkpoint":    l.Latest(),
		"operator.vkey": []byte(l.opVKey + "\n"),
		"receipts.vkey": []byte(l.rcptKey + "\n"),
	}
	at := func(name string) string { return filepath.Join(dir, name) }
	cmd := "dlog verify -checkpoint checkpoint -key operator.vkey"
	registry := map[string]any{"quorum": len(witnesses), "witnesses": []string{}, "operators": []map[string]string{{
		"name": l.Origin, "origin": l.Origin, "checkpoint_key": l.opVKey, "receipt_key": l.rcptKey, "url": ServeURL,
	}}}
	for _, w := range witnesses {
		name := strings.NewReplacer("/", "_", ".", "_").Replace(w.Name) + ".vkey"
		files[name] = []byte(w.vkey + "\n")
		cmd += " -witness " + name
		registry["witnesses"] = append(registry["witnesses"].([]string), w.vkey)
	}
	cmd += fmt.Sprintf(" -quorum %d chain.jsonl", len(witnesses))
	reg, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		return "", err
	}
	files["registry.json"] = append(reg, '\n')
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	for name, b := range files {
		if err := os.WriteFile(at(name), b, 0o644); err != nil {
			return "", err
		}
	}
	return cmd, nil
}

// SaveReceipt writes a receipt into dir, both as a signed note and as a
// link to the verification page.
func SaveReceipt(dir string, note []byte) error {
	if err := os.WriteFile(filepath.Join(dir, "receipt"), note, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "receipt.url"), []byte(core.ReceiptURL(PageURL, note)+"\n"), 0o644)
}

// OutDir returns dir, or a new temporary directory if dir is empty.
func OutDir(dir, example string) (string, error) {
	if dir != "" {
		return dir, os.MkdirAll(dir, 0o755)
	}
	return os.MkdirTemp("", "deedlog-"+example+"-")
}

// Print writes findings, or that there are none. Findings that differ only
// in numbers are shown once, with a count, so that one failure repeated for
// many records does not hide the others.
func (fs Findings) Print(w io.Writer) {
	if len(fs) == 0 {
		fmt.Fprintln(w, "  no findings: the chain matches every declared rule")
		return
	}
	numbers := regexp.MustCompile(`[0-9][0-9.:-]*`)
	var kinds []string
	first := make(map[string]Finding)
	count := make(map[string]int)
	for _, f := range fs {
		k := numbers.ReplaceAllString(f.Problem, "#")
		if count[k] == 0 {
			kinds = append(kinds, k)
			first[k] = f
		}
		count[k]++
	}
	for _, k := range kinds {
		fmt.Fprintf(w, "  %s\n", first[k])
		if n := count[k] - 1; n > 0 {
			fmt.Fprintf(w, "      ... and %d similar\n", n)
		}
	}
}

// Start creates a chain with fresh keys, a clock set to start, and
// in-process witnesses for the chain.
func Start(origin string, start time.Time, witnesses ...string) (*Log, []*Witness, error) {
	l, err := NewLog(origin, NewClock(start))
	if err != nil {
		return nil, nil, err
	}
	var ws []*Witness
	for _, name := range witnesses {
		w, err := StartWitness(name, l)
		if err != nil {
			CloseAll(ws)
			return nil, nil, err
		}
		ws = append(ws, w)
	}
	return l, ws, nil
}

// CloseAll stops the witnesses.
func CloseAll(ws []*Witness) {
	for _, w := range ws {
		w.Close()
	}
}

// Keys returns the witnesses' verifier keys.
func Keys(ws []*Witness) []*core.Verifier {
	var keys []*core.Verifier
	for _, w := range ws {
		keys = append(keys, w.Key())
	}
	return keys
}

// Header prints the title of a scenario's outcome.
func Header(w io.Writer, title string, l *Log, ws []*Witness) {
	fmt.Fprintf(w, "== %s: %d records, checkpoint cosigned by %d witnesses\n", title, l.Size(), len(ws))
}

// Save writes a scenario's files into dir and prints how to check them.
func Save(w io.Writer, dir string, l *Log, ws []*Witness) error {
	cmd, err := Files(dir, l, ws)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "\n  Files in %s; check the chain itself there with\n  %s\n\n", dir, cmd)
	return nil
}

// Line returns the exact bytes of the record at index, without the newline.
func (l *Log) Line(index uint64) ([]byte, error) {
	lines := bytes.Split(bytes.TrimSuffix(l.Chain(), []byte("\n")), []byte("\n"))
	if index >= uint64(len(lines)) {
		return nil, fmt.Errorf("no record %d", index)
	}
	return lines[index], nil
}

// Rewrite replaces the chain with only the records keep accepts, relinked
// so that the new chain verifies on its own. It exists to show what happens
// when an operator rewrites history: witnesses refuse to cosign the result.
func (l *Log) Rewrite(keep func(core.Record) bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	var buf bytes.Buffer
	w, err := core.NewWriter(&buf, l.Origin)
	if err != nil {
		return err
	}
	for _, line := range bytes.Split(bytes.TrimSuffix(l.buf.Bytes(), []byte("\n")), []byte("\n")) {
		var r core.Record
		if err := json.Unmarshal(line, &r); err != nil {
			return err
		}
		if keep(r) {
			if _, err := w.Append(r); err != nil {
				return err
			}
		}
	}
	sum, leaves, err := core.VerifyLeaves(bytes.NewReader(buf.Bytes()))
	if err != nil {
		return err
	}
	l.buf.Reset()
	l.buf.Write(buf.Bytes())
	if l.w, err = core.ResumeWriter(&l.buf, sum); err != nil {
		return err
	}
	l.leaves = leaves
	return nil
}
