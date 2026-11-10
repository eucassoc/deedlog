package verifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eucassoc/deedlog/core"
	"github.com/eucassoc/deedlog/publish"
)

const origin = "city.example/cameras"

type operator struct {
	dir                  string
	cpSigner, rcptSigner *core.Signer
	witness              *core.Signer
	cpVkey, rcptVkey     string
	witnessVkey          string
	srv                  *httptest.Server
}

func key(t *testing.T, gen func(string) (string, string, error), name string) (*core.Signer, string) {
	t.Helper()
	skey, vkey, err := gen(name)
	if err != nil {
		t.Fatal(err)
	}
	s, err := core.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	return s, vkey
}

func newOperator(t *testing.T) *operator {
	op := &operator{dir: t.TempDir()}
	op.cpSigner, op.cpVkey = key(t, core.GenerateKey, origin)
	op.rcptSigner, op.rcptVkey = key(t, core.GenerateKey, origin+"/receipts")
	op.witness, op.witnessVkey = key(t, core.GenerateWitnessKey, "witness.example/w1")
	op.srv = httptest.NewServer(&publish.Handler{
		Chain: filepath.Join(op.dir, "chain.jsonl"), Checkpoint: filepath.Join(op.dir, "checkpoint")})
	t.Cleanup(op.srv.Close)
	return op
}

// publish writes a chain of n records (record 2 replaced if alt is set) and
// its checkpoint, cosigned by the witness if cosign is set.
func (op *operator) publish(t *testing.T, n int, alt string, cosign bool) []core.Hash {
	t.Helper()
	var buf bytes.Buffer
	w, _ := core.NewWriter(&buf, origin)
	for i := range n {
		id := "camera-1"
		if i == 2 && alt != "" {
			id = alt
		}
		w.Append(core.Record{CollectedAt: time.Date(2026, 10, 22, 0, 0, i, 0, time.UTC),
			Source:  core.Source{Type: "camera", ID: id, Collector: "test"},
			Subject: core.Subject{MediaType: "video/mp4", Size: 1, Digest: map[string]string{"sha256": strings.Repeat("ab", 32)}}})
	}
	_, leaves, err := core.VerifyLeaves(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	c := core.Checkpoint{Origin: origin, Size: uint64(n), Root: core.Root(leaves)}
	note, _ := core.SignCheckpoint(c, op.cpSigner)
	if cosign {
		line, _ := core.Cosign(c, op.witness, time.Now())
		note = append(note, line...)
	}
	os.WriteFile(filepath.Join(op.dir, "chain.jsonl"), buf.Bytes(), 0o644)
	os.WriteFile(filepath.Join(op.dir, "checkpoint"), note, 0o644)
	return leaves
}

func (op *operator) registry(t *testing.T, quorum int) *Registry {
	t.Helper()
	b, _ := json.Marshal(map[string]any{
		"witnesses": []string{op.witnessVkey},
		"quorum":    quorum,
		"operators": []map[string]string{{
			"name": "City cameras", "origin": origin, "checkpoint_key": op.cpVkey,
			"receipt_key": op.rcptVkey, "url": op.srv.URL}},
	})
	r, err := ParseRegistry(b)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func get(t *testing.T, url string) (string, int) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Error("missing CORS header")
	}
	b, _ := io.ReadAll(resp.Body)
	return string(b), resp.StatusCode
}

// check runs what a verification page does: open the receipt, fetch the
// checkpoint and, if needed, the proof, and check.
func check(t *testing.T, r *Registry, receiptURL string) (*Result, error) {
	t.Helper()
	note, err := core.ReceiptFromURL(receiptURL)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := r.OpenReceipt(note)
	if err != nil {
		return nil, err
	}
	cp, _ := get(t, rc.Operator.URL+"/checkpoint")
	c, err := r.VerifyCheckpoint(rc, []byte(cp))
	if err != nil {
		return nil, err
	}
	var proof string
	if rc.Receipt.Index < c.Size {
		proof, _ = get(t, fmt.Sprintf("%s/proof?index=%d&size=%d", rc.Operator.URL, rc.Receipt.Index, c.Size))
	}
	return r.Check(rc, []byte(cp), proof)
}

func TestReceiptLifecycle(t *testing.T) {
	op := newOperator(t)
	honest := op.publish(t, 4, "", true)
	receipt, err := core.IssueReceipt(core.Receipt{Origin: origin, Index: 2, LeafHash: honest[2]}, op.rcptSigner)
	if err != nil {
		t.Fatal(err)
	}
	url := core.ReceiptURL("https://verify.example/", receipt)

	op.publish(t, 2, "", true)
	if res, err := check(t, op.registry(t, 1), url); err != nil || res.Status != "pending" {
		t.Fatalf("pending: %+v %v", res, err)
	}
	op.publish(t, 4, "", true)
	if res, err := check(t, op.registry(t, 1), url); err != nil || res.Status != "included" {
		t.Fatalf("included: %+v %v", res, err)
	}

	// The operator rewrites record 2. Witnesses would refuse to cosign, so a
	// page requiring a cosignature rejects the checkpoint outright...
	op.publish(t, 5, "camera-2", false)
	if _, err := check(t, op.registry(t, 1), url); err == nil || !strings.Contains(err.Error(), "checkpoint") {
		t.Fatalf("uncosigned rewrite: %v", err)
	}
	// ...and even a page that trusts the operator alone proves the breach.
	res, err := check(t, op.registry(t, 0), url)
	if err != nil || res.Status != "broken" || res.Misbehavior == nil {
		t.Fatalf("broken: %+v %v", res, err)
	}
	cpKey, _ := core.NewVerifier(op.cpVkey)
	rKey, _ := core.NewVerifier(op.rcptVkey)
	if _, err := core.CheckMisbehavior(*res.Misbehavior, cpKey, rKey); err != nil {
		t.Fatal(err)
	}
}

func TestOpenReceiptRejects(t *testing.T) {
	op := newOperator(t)
	r := op.registry(t, 0)
	leaf := core.LeafHash([]byte("x"))
	other, _ := key(t, core.GenerateKey, origin+"/receipts")
	forged, _ := core.IssueReceipt(core.Receipt{Origin: origin, Index: 0, LeafHash: leaf}, other)
	if _, err := r.OpenReceipt(forged); err == nil {
		t.Error("receipt signed by an unknown key opened")
	}
	stranger, _ := key(t, core.GenerateKey, "other.example/log/receipts")
	unknown, _ := core.IssueReceipt(core.Receipt{Origin: "other.example/log", Index: 0, LeafHash: leaf}, stranger)
	if _, err := r.OpenReceipt(unknown); err == nil || !strings.Contains(err.Error(), "does not know") {
		t.Errorf("unknown operator: %v", err)
	}
}

func TestPublishProofLimits(t *testing.T) {
	op := newOperator(t)
	op.publish(t, 4, "", true)
	for _, q := range []string{"index=0&size=5", "index=4&size=4", "index=x&size=4"} {
		if _, code := get(t, op.srv.URL+"/proof?"+q); code == http.StatusOK {
			t.Errorf("proof?%s served", q)
		}
	}
	if body, code := get(t, op.srv.URL+"/proof?index=1&size=3"); code != http.StatusOK || len(strings.Fields(body)) != 3 {
		t.Errorf("proof: %d %q", code, body)
	}
}

func TestReceiptURL(t *testing.T) {
	note := []byte("deedlog-receipt/v1\na.example/log\n0\nAAAA\n\n— k sig+/=\n")
	u := core.ReceiptURL("https://verify.example/page#old", note)
	if !strings.HasPrefix(u, "https://verify.example/page#r=") || strings.ContainsAny(u[len("https://verify.example/page#r="):], "+/=") {
		t.Fatalf("url %q", u)
	}
	got, err := core.ReceiptFromURL(u)
	if err != nil || !bytes.Equal(got, note) {
		t.Fatalf("round trip: %q %v", got, err)
	}
}
