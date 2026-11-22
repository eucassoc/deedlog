package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eucassoc/deedlog/core"
)

func dlog(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return stdout.String(), stderr.String(), code
}

func writeChain(t *testing.T, path, origin string, n int, alt string) {
	t.Helper()
	var buf bytes.Buffer
	w, err := core.NewWriter(&buf, origin)
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		id := "camera-1"
		if i == 2 && alt != "" {
			id = alt
		}
		_, err := w.Append(core.Record{
			CollectedAt: time.Date(2026, 10, 22, 0, 0, i, 0, time.UTC),
			Source:      core.Source{Type: "test", ID: id, Collector: "main_test"},
			Subject: core.Subject{MediaType: "text/plain", Size: 1,
				Digest: map[string]string{"sha256": strings.Repeat("ab", 32)}},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCheckpointWorkflow(t *testing.T) {
	dir := t.TempDir()
	p := func(name string) string { return filepath.Join(dir, name) }
	const origin = "city.example/cameras"

	if out, errOut, code := dlog(t, "keygen", "-name", origin, "-out", p("op")); code != 0 {
		t.Fatalf("keygen: %s %s", out, errOut)
	}
	if info, err := os.Stat(p("op.key")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("op.key: %v %v", info, err)
	}
	if _, _, code := dlog(t, "keygen", "-name", origin, "-out", p("op")); code == 0 {
		t.Fatal("keygen overwrote an existing key")
	}

	writeChain(t, p("chain.jsonl"), origin, 4, "")
	cp, errOut, code := dlog(t, "checkpoint", "-key", p("op.key"), p("chain.jsonl"))
	if code != 0 {
		t.Fatal(errOut)
	}
	if err := os.WriteFile(p("cp4"), []byte(cp), 0o644); err != nil {
		t.Fatal(err)
	}

	// The chain grows after the checkpoint; it still verifies.
	writeChain(t, p("chain.jsonl"), origin, 6, "")
	out, errOut, code := dlog(t, "verify", "-checkpoint", p("cp4"), "-key", p("op.vkey"), p("chain.jsonl"))
	if code != 0 {
		t.Fatal(errOut)
	}
	if !strings.Contains(out, `"checkpoint_size": 4`) {
		t.Fatalf("verify output: %s", out)
	}

	// The operator rewrites record 2 and signs a new checkpoint.
	writeChain(t, p("rewritten.jsonl"), origin, 6, "camera-2")
	if _, errOut, code := dlog(t, "verify", "-checkpoint", p("cp4"), "-key", p("op.vkey"), p("rewritten.jsonl")); code != 1 {
		t.Fatalf("rewritten chain verified against old checkpoint: %s", errOut)
	}
	cp6, _, _ := dlog(t, "checkpoint", "-key", p("op.key"), p("rewritten.jsonl"))
	if err := os.WriteFile(p("cp6"), []byte(cp6), 0o644); err != nil {
		t.Fatal(err)
	}

	proof, errOut, code := dlog(t, "misbehavior", "build", "-key", p("op.vkey"),
		p("chain.jsonl"), p("cp4"), p("rewritten.jsonl"), p("cp6"))
	if code != 0 {
		t.Fatal(errOut)
	}
	if err := os.WriteFile(p("proof.json"), []byte(proof), 0o644); err != nil {
		t.Fatal(err)
	}
	out, errOut, code = dlog(t, "misbehavior", "check", "-key", p("op.vkey"), p("proof.json"))
	if code != 0 || !strings.Contains(out, "MISBEHAVIOR PROVEN") {
		t.Fatalf("check: %s %s", out, errOut)
	}
}

func TestProve(t *testing.T) {
	dir := t.TempDir()
	chain := filepath.Join(dir, "chain.jsonl")
	writeChain(t, chain, "a.example/log", 5, "")
	out, errOut, code := dlog(t, "prove", "-index", "1", chain)
	if code != 0 || len(strings.Fields(out)) != 3 {
		t.Fatalf("inclusion proof: %q %s", out, errOut)
	}
	out, errOut, code = dlog(t, "prove", "-old", "3", "-size", "5", chain)
	if code != 0 || len(strings.Fields(out)) == 0 {
		t.Fatalf("consistency proof: %q %s", out, errOut)
	}
	if _, _, code := dlog(t, "prove", "-index", "1", "-old", "2", chain); code != 2 {
		t.Fatal("prove accepted both -index and -old")
	}
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"nope"}, {"verify"}, {"checkpoint", "x"}, {"misbehavior"}} {
		if _, _, code := dlog(t, args...); code != 2 {
			t.Errorf("dlog %v: exit %d, want 2", args, code)
		}
	}
}

func TestTimestampCommand(t *testing.T) {
	tsaDir := filepath.Join("..", "..", "core", "testdata", "tsa")
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(tsaDir, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	text := read("checkpoint.txt")
	roots := filepath.Join(tsaDir, "local-root.pem")

	if _, err := verifyTimestampFile(filepath.Join(tsaDir, "local.tsr"), text, roots); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyTimestampFile(filepath.Join(tsaDir, "local.tsr"), []byte("other\n"), roots); err == nil {
		t.Fatal("time-stamp verified for other data")
	}

	// A TSA that replays an old response is caught by the nonce check.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.Write(read("local.tsr"))
	}))
	defer srv.Close()
	dir := t.TempDir()
	cp := filepath.Join(dir, "checkpoint")
	note := append(append(bytes.Clone(text), '\n'), "— city.example/cameras AAAAAA==\n"...)
	if err := os.WriteFile(cp, note, 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "checkpoint.tsr")
	_, errOut, code := dlog(t, "timestamp", "-tsa", srv.URL, "-out", out, "-tsa-roots", roots, cp)
	if code != 1 || !strings.Contains(errOut, "nonce") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("response was saved despite the nonce mismatch")
	}
}

func TestCosignWithWitness(t *testing.T) {
	dir := t.TempDir()
	p := func(name string) string { return filepath.Join(dir, name) }
	const origin = "city.example/cameras"
	for _, args := range [][]string{
		{"keygen", "-name", origin, "-out", p("op")},
		{"keygen", "-witness", "-name", "witness.example/w1", "-out", p("w1")},
		{"keygen", "-witness", "-name", "witness.example/w2", "-out", p("w2")},
	} {
		if _, errOut, code := dlog(t, args...); code != 0 {
			t.Fatal(errOut)
		}
	}
	if _, _, err := newWitnessServer([]string{"-key", p("op.key"), "-log", p("op.vkey"), "-state", p("s")}); err == nil {
		t.Fatal("witness started with an operator key")
	}
	var urls []string
	for _, w := range []string{"w1", "w2"} {
		srv, _, err := newWitnessServer([]string{"-key", p(w + ".key"), "-log", p("op.vkey"), "-state", p(w + ".state")})
		if err != nil {
			t.Fatal(err)
		}
		ts := httptest.NewServer(srv)
		t.Cleanup(ts.Close)
		urls = append(urls, ts.URL)
	}

	writeChain(t, p("chain.jsonl"), origin, 5, "")
	cp, _, _ := dlog(t, "checkpoint", "-key", p("op.key"), p("chain.jsonl"))
	os.WriteFile(p("cp"), []byte(cp), 0o644)
	out, errOut, code := dlog(t, "cosign", "-key", p("op.vkey"), "-quorum", "2",
		"-witness", p("w1.vkey")+"="+urls[0], "-witness", p("w2.vkey")+"="+urls[1],
		"-out", p("cp.cosigned"), p("chain.jsonl"), p("cp"))
	if code != 0 {
		t.Fatalf("%s %s", out, errOut)
	}
	if _, errOut, code := dlog(t, "verify", "-checkpoint", p("cp.cosigned"), "-key", p("op.vkey"),
		"-witness", p("w1.vkey"), "-witness", p("w2.vkey"), "-quorum", "2", p("chain.jsonl")); code != 0 {
		t.Fatal(errOut)
	}
	if state, err := os.ReadFile(p("w1.state")); err != nil || !strings.HasPrefix(string(state), origin+"\n5\n") {
		t.Fatalf("witness state %q %v", state, err)
	}

	// The operator rewrites the chain; both witnesses refuse.
	writeChain(t, p("rewritten.jsonl"), origin, 7, "camera-2")
	cp2, _, _ := dlog(t, "checkpoint", "-key", p("op.key"), p("rewritten.jsonl"))
	os.WriteFile(p("cp2"), []byte(cp2), 0o644)
	out, _, code = dlog(t, "cosign", "-key", p("op.vkey"),
		"-witness", p("w1.vkey")+"="+urls[0], "-witness", p("w2.vkey")+"="+urls[1],
		"-out", p("cp2.cosigned"), p("rewritten.jsonl"), p("cp2"))
	if code != 1 || strings.Count(out, "not consistent") != 2 {
		t.Fatalf("exit %d: %s", code, out)
	}
}

func TestReceiptWorkflow(t *testing.T) {
	dir := t.TempDir()
	p := func(name string) string { return filepath.Join(dir, name) }
	const origin = "city.example/cameras"
	dlog(t, "keygen", "-name", origin, "-out", p("op"))
	if _, errOut, code := dlog(t, "keygen", "-name", origin+"/receipts", "-out", p("rk")); code != 0 {
		t.Fatal(errOut)
	}

	writeChain(t, p("chain.jsonl"), origin, 4, "")
	receipt, errOut, code := dlog(t, "receipt", "issue", "-key", p("rk.key"), "-index", "2", p("chain.jsonl"))
	if code != 0 {
		t.Fatal(errOut)
	}
	os.WriteFile(p("receipt"), []byte(receipt), 0o644)
	link, _, code := dlog(t, "receipt", "issue", "-key", p("rk.key"), "-index", "2", "-url", "https://verify.example/", p("chain.jsonl"))
	if note, err := core.ReceiptFromURL(strings.TrimSpace(link)); code != 0 || err != nil || string(note) != receipt {
		t.Fatalf("receipt URL %q: %v", link, err)
	}
	if _, _, code := dlog(t, "receipt", "issue", "-key", p("op.key"), "-index", "2", p("chain.jsonl")); code == 0 {
		t.Fatal("issued a receipt with the checkpoint key")
	}

	checkpoint := func(chain, out string) {
		cp, errOut, code := dlog(t, "checkpoint", "-key", p("op.key"), p(chain))
		if code != 0 {
			t.Fatal(errOut)
		}
		os.WriteFile(p(out), []byte(cp), 0o644)
	}
	check := func(cp string, source ...string) (string, int) {
		args := append([]string{"receipt", "check", "-receipt", p("receipt"), "-receipt-key", p("rk.vkey"),
			"-checkpoint", p(cp), "-key", p("op.vkey")}, source...)
		out, errOut, code := dlog(t, args...)
		return out + errOut, code
	}

	// Not yet covered: the operator checkpoints only the first two records.
	writeChain(t, p("short.jsonl"), origin, 2, "")
	checkpoint("short.jsonl", "cp2")
	if out, code := check("cp2", "-chain", p("short.jsonl")); code != 3 {
		t.Fatalf("short: exit %d: %s", code, out)
	}

	// Included, checked from the chain and from a proof the operator hands out.
	checkpoint("chain.jsonl", "cp4")
	if out, code := check("cp4", "-chain", p("chain.jsonl")); code != 0 || !strings.Contains(out, "INCLUDED") {
		t.Fatalf("included: exit %d: %s", code, out)
	}
	proof, _, _ := dlog(t, "prove", "-index", "2", "-leaf", p("chain.jsonl"))
	os.WriteFile(p("proof"), []byte(proof), 0o644)
	if out, code := check("cp4", "-proof", p("proof")); code != 0 {
		t.Fatalf("included with proof: exit %d: %s", code, out)
	}

	// Broken: the operator replaces record 2.
	writeChain(t, p("rewritten.jsonl"), origin, 5, "camera-2")
	checkpoint("rewritten.jsonl", "cp5")
	out, code := check("cp5", "-chain", p("rewritten.jsonl"), "-out", p("misbehavior.json"))
	if code != 4 || !strings.Contains(out, "MISBEHAVIOR PROVEN") {
		t.Fatalf("broken: exit %d: %s", code, out)
	}
	out, errOut, code = dlog(t, "misbehavior", "check", "-key", p("op.vkey"), "-receipt-key", p("rk.vkey"), p("misbehavior.json"))
	if code != 0 || !strings.Contains(out, "MISBEHAVIOR PROVEN") {
		t.Fatalf("misbehavior check: exit %d: %s %s", code, out, errOut)
	}
}

func TestAnchorWorkflow(t *testing.T) {
	dir := t.TempDir()
	p := func(name string) string { return filepath.Join(dir, name) }
	const origin = "city.example/inquiries"
	ok := func(args ...string) string {
		t.Helper()
		out, errOut, code := dlog(t, args...)
		if code != 0 {
			t.Fatalf("dlog %s: exit %d: %s", strings.Join(args, " "), code, errOut)
		}
		return out
	}
	fails := func(want string, args ...string) {
		t.Helper()
		_, errOut, code := dlog(t, args...)
		if code != 1 || !strings.Contains(errOut, want) {
			t.Fatalf("dlog %s: exit %d, %q; want %q", strings.Join(args, " "), code, errOut, want)
		}
	}
	var s core.Summary
	var bodies [][]byte
	add := func(n int) {
		f, err := os.OpenFile(p("records.jsonl"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		for range n {
			line, body, err := core.EventRecord(s, origin+"/records", core.Event{
				Source: core.Source{Type: "test", ID: origin, Collector: "main_test"},
				Name:   "data.received", Meta: []core.Field{{Key: "item", Value: strings.Repeat("a", int(s.Count)+1)}},
				At: time.Date(2026, 11, 1, 9, 0, int(s.Count), 0, time.UTC),
			})
			if err != nil {
				t.Fatal(err)
			}
			s = s.Next(origin+"/records", line)
			bodies = append(bodies, body)
			f.Write(append(line, '\n'))
		}
	}
	anchorAt := func(epoch string) string {
		return ok("anchor", "add", "-records", p("records.jsonl"), "-secrets", p("secrets.json"), "-origin", origin, "-epoch", epoch, p("anchors.jsonl"))
	}

	fails("give -origin", "anchor", "add", "-records", p("records.jsonl"), "-secrets", p("secrets.json"), p("anchors.jsonl"))
	// Nothing recorded yet: an anchor record is deposited all the same.
	if out := anchorAt("2026-11-01T09:00:00Z"); !strings.Contains(out, `"size": 1`) || !strings.Contains(out, `"records": "city.example/inquiries/records"`) {
		t.Fatalf("anchor add: %s", out)
	}
	add(3)
	anchorAt("2026-11-01T09:10:00Z")
	add(2)
	anchorAt("2026-11-01T09:20:00Z")
	add(1)
	fails("does not come after", "anchor", "add", "-records", p("records.jsonl"), "-secrets", p("secrets.json"), "-epoch", "2026-11-01T09:20:00Z", p("anchors.jsonl"))
	if info, err := os.Stat(p("secrets.json")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("secrets.json: %v %v", info, err)
	}

	// The anchor chain is a chain like any other: checkpointed and verified.
	ok("keygen", "-name", origin, "-out", p("op"))
	if err := os.WriteFile(p("cp"), []byte(ok("checkpoint", "-key", p("op.key"), p("anchors.jsonl"))), 0o644); err != nil {
		t.Fatal(err)
	}
	cp := []string{"-checkpoint", p("cp"), "-key", p("op.vkey")}
	ok(append(append([]string{"verify"}, cp...), p("anchors.jsonl"))...)

	verify := append(append([]string{"anchor", "verify", "-records", p("records.jsonl"), "-secrets", p("secrets.json")}, cp...), p("anchors.jsonl"))
	out := ok(verify...)
	for _, want := range []string{`"count": 6`, `"intervals": 3`, `"anchored": 5`, `"checkpoint_size": 3`} {
		if !strings.Contains(out, want) {
			t.Fatalf("anchor verify: %s lacks %s", out, want)
		}
	}

	proof := ok("anchor", "prove", "-secrets", p("secrets.json"), "-index", "4", p("records.jsonl"))
	if !strings.HasPrefix(proof, `{"seq":2,"epoch":"2026-11-01T09:20:00Z","size":2,"index":1,"path":["`) {
		t.Fatalf("anchor prove: %s", proof)
	}
	os.WriteFile(p("proof.json"), []byte(proof), 0o644)
	os.WriteFile(p("body"), bodies[4], 0o644)
	os.WriteFile(p("other"), bodies[3], 0o644)
	check := func(subject string) []string {
		return append(append([]string{"anchor", "check", "-proof", p("proof.json"), "-subject", p(subject)}, cp...), p("anchors.jsonl"))
	}
	ok(check("body")...)
	fails("anchor record 2 (line 3 of the anchor chain)", check("other")...)
	fails("not anchored yet", "anchor", "prove", "-secrets", p("secrets.json"), "-index", "5", p("records.jsonl"))

	// One more interval, not yet under the checkpoint: its proof must wait.
	anchorAt("2026-11-01T09:30:00Z")
	os.WriteFile(p("proof.json"), []byte(ok("anchor", "prove", "-secrets", p("secrets.json"), "-index", "5", p("records.jsonl"))), 0o644)
	os.WriteFile(p("body"), bodies[5], 0o644)
	fails("not covered by the checkpoint", check("body")...)

	// A record changed, and the chain linked again behind it.
	b, _ := os.ReadFile(p("records.jsonl"))
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	lines[1] = strings.Replace(lines[1], `"collector":"main_test"`, `"collector":"someone"`, 1)
	for i := 2; i < len(lines); i++ {
		j := strings.Index(lines[i], `"prev":"`) + len(`"prev":"`)
		lines[i] = lines[i][:j] + core.Digest([]byte(lines[i-1])) + lines[i][j+71:]
	}
	os.WriteFile(p("records.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o644)
	ok("verify", p("records.jsonl"))
	fails("anchor record 1 (line 2 of the anchor chain): records 0 to 3", verify...)
}
