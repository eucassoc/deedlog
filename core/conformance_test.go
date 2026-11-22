package core_test

// The conformance vectors, testdata/conformance/vectors.json, are what the Go
// and the JavaScript implementation are both held to: from the inputs in the
// file, each must produce the outputs in the file, byte for byte, and accept
// or refuse what the file says is to be accepted or refused. This test
// builds the whole file from the inputs below and compares; js/test does the
// same from the inputs it reads from the file.
//
//	go test ./core -run TestConformance -update
//
// rewrites the file. Do that only for a deliberate change, and read the
// diff: a changed output is a changed format.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/eucassoc/deedlog/core"
	"github.com/eucassoc/deedlog/witness"
)

var update = flag.Bool("update", false, "rewrite testdata/conformance/vectors.json")

const vectorsPath = "../testdata/conformance/vectors.json"

type keyPair struct {
	Skey string `json:"skey"`
	Vkey string `json:"vkey"`
}

type eventInput struct {
	Event string      `json:"event"`
	Meta  [][2]string `json:"meta"`
	At    string      `json:"at"`
}

type madeRecords struct {
	Chain  string        `json:"chain"`
	Source core.Source   `json:"source"`
	Events []eventInput  `json:"events"`
	Lines  []string      `json:"lines"`
	Bodies []string      `json:"bodies"`
	Heads  []string      `json:"heads"`
	Leaves []string      `json:"leaves"`
	Roots  []string      `json:"roots"`
	Proofs merkleVectors `json:"proofs"`
}

type merkleVectors struct {
	Inclusion   []inclusionVector   `json:"inclusion"`
	Consistency []consistencyVector `json:"consistency"`
}

type inclusionVector struct {
	Index uint64   `json:"index"`
	Size  uint64   `json:"size"`
	Proof []string `json:"proof"`
}

type consistencyVector struct {
	Old   uint64   `json:"old"`
	New   uint64   `json:"new"`
	Proof []string `json:"proof"`
}

type chainVector struct {
	Name  string   `json:"name"`
	Lines []string `json:"lines"`
	// Accepted chains.
	Count uint64 `json:"count,omitempty"`
	Head  string `json:"head,omitempty"`
	Root  string `json:"root,omitempty"`
	// Refused chains: the first line at which verification fails; 0 when
	// the chain is refused as a whole.
	Line *int `json:"line,omitempty"`
}

type interval struct {
	Seq    uint64 `json:"seq"`
	Epoch  string `json:"epoch"`
	From   uint64 `json:"from"`
	To     uint64 `json:"to"`
	Nonce  string `json:"nonce"`
	Pad    string `json:"pad"`
	At     string `json:"at"`
	Size   uint64 `json:"size"`
	Root   string `json:"root"`
	Commit string `json:"commit"`
	Line   string `json:"line"`
}

type recordProofVector struct {
	Record uint64 `json:"record"`
	Body   string `json:"body"`
	Proof  string `json:"proof"`
}

type anchoring struct {
	Origin    string              `json:"origin"`
	Chain     string              `json:"chain"`
	Source    core.Source         `json:"source"`
	Intervals []interval          `json:"intervals"`
	Proofs    []recordProofVector `json:"proofs"`
	Refused   []refusedProof      `json:"refused"`
}

type refusedProof struct {
	Name  string `json:"name"`
	Body  string `json:"body"`
	Chain string `json:"chain"`
	Proof string `json:"proof"`
}

type checkpointVector struct {
	Size uint64 `json:"size"`
	Text string `json:"text"`
	Note string `json:"note"`
	// The witness's cosignature line at Time, and the note with it.
	Time     int64  `json:"time"`
	Cosigned string `json:"cosigned"`
}

type noteVector struct {
	Name   string `json:"name"`
	Note   string `json:"note"`
	Quorum int    `json:"quorum"`
	OK     bool   `json:"ok"`
}

type witnessStep struct {
	Name string `json:"name"`
	Body string `json:"body"`
	Time int64  `json:"time"`
	// The answer. The body is compared for 200 (the cosignature line) and
	// 409 (the size held); the wording of errors is not part of the format.
	Status   int    `json:"status"`
	Response string `json:"response,omitempty"`
}

type vectors struct {
	About       []string            `json:"about"`
	Keys        map[string]keyPair  `json:"keys"`
	Names       map[string][]string `json:"names"`
	Records     madeRecords         `json:"records"`
	Accepted    []chainVector       `json:"accepted"`
	Refused     []chainVector       `json:"refused"`
	Anchoring   anchoring           `json:"anchoring"`
	Checkpoints []checkpointVector  `json:"checkpoints"`
	Notes       []noteVector        `json:"notes"`
	Witness     []witnessStep       `json:"witness"`
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func b64(h core.Hash) string { return base64.StdEncoding.EncodeToString(h[:]) }

func b64s(hs []core.Hash) []string {
	out := []string{}
	for _, h := range hs {
		out = append(out, b64(h))
	}
	return out
}

// testKey derives a key from a label, so that the vectors are the same on
// every run. These keys are published here and protect nothing.
func testKey(name string, typ byte, label string) keyPair {
	seed := sha256.Sum256([]byte("deedlog conformance test key: " + label))
	pub := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{'\n', typ})
	h.Write(pub)
	id := hex.EncodeToString(h.Sum(nil)[:4])
	enc := func(b []byte) string { return base64.StdEncoding.EncodeToString(append([]byte{typ}, b...)) }
	return keyPair{Skey: "PRIVATE+KEY+" + name + "+" + id + "+" + enc(seed[:]), Vkey: name + "+" + id + "+" + enc(pub)}
}

func secret(label string) string {
	sum := sha256.Sum256([]byte("deedlog conformance test secret: " + label))
	return hex.EncodeToString(sum[:16])
}

func fields(meta [][2]string) []core.Field {
	var out []core.Field
	for _, kv := range meta {
		out = append(out, core.Field{Key: kv[0], Value: kv[1]})
	}
	return out
}

const (
	origin      = "log.example/conformance"
	recordsName = origin + "/records"
)

var events = []eventInput{
	{"data.received", [][2]string{{"item", "3f2a"}, {"form", "contact"}, {"by", "site"}}, "2026-11-01T09:00:00.000Z"},
	{"data.decrypted", [][2]string{{"item", "3f2a"}, {"by", "support-agent"}}, "2026-11-01T09:03:21.987Z"},
	{"rule.adopted", [][2]string{{"rule", "handle-inquiry"}, {"title", "お問い合わせには3日以内に対応する"}, {"source", "お問い合わせ対応規程 第4条"}}, "2026-11-01T09:10:00Z"},
	{"note.added", [][2]string{{"text", "a \"quoted\" \\ backslash, a <tag> & an ampersand"}}, "2026-11-01T09:11:00Z"},
	{"note.added", [][2]string{{"text", "tab\there, newline\nhere, bell\x07, escape\x1b, del\x7f"}}, "2026-11-01T09:12:00Z"},
	{"note.added", [][2]string{{"text", "line separator  paragraph separator  emoji 🗝️ é"}}, "2026-11-01T09:13:00Z"},
	{"keys.ordered", [][2]string{{"b", "1"}, {"10", "ten"}, {"a", "2"}, {"2", "two"}, {"007", "not an index"}, {"4294967294", "an index"}, {"4294967295", "not an index"}, {"0", "zero"}}, "2026-11-01T09:14:00Z"},
	{"keys.repeated", [][2]string{{"a", "first"}, {"b", "kept"}, {"a", "last"}, {"c", "dropped"}, {"c", ""}}, "2026-11-01T09:15:00Z"},
	{"keys.reserved", [][2]string{{"event", "ignored"}, {"at", "kept in meta, replaced in the body"}, {"empty", ""}, {"__proto__", "a key like any other"}}, "2026-11-01T09:16:00Z"},
	{"data.answered", [][2]string{{"item", "3f2a"}, {"outcome", "replied"}}, "2026-11-01T09:17:00Z"},
	{"data.deleted", [][2]string{{"item", "3f2a"}, {"rows", "1"}, {"verified", "absent"}}, "2026-11-01T23:59:59.999Z"},
	{"audit.viewed", nil, "2026-11-02T00:00:00Z"},
}

// rawChain links records given as JSON objects, as some other writer might
// have written them; mutate changes record i before it is linked.
func rawChain(n int, mutate func(i int, r map[string]any)) []string {
	var lines []string
	prev := ""
	for i := range n {
		r := map[string]any{
			"spec": core.SpecVersion, "chain": "other.example/log", "seq": i,
			"collected_at": fmt.Sprintf("2026-11-03T00:00:%02dZ", i),
			"source":       map[string]any{"type": "test", "id": "x", "collector": "conformance"},
			"subject":      map[string]any{"media_type": "text/plain", "size": 1, "digest": map[string]any{"sha256": strings.Repeat("ab", 32)}},
		}
		if prev != "" {
			r["prev"] = prev
		}
		if mutate != nil {
			mutate(i, r)
		}
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(r); err != nil {
			panic(err)
		}
		line := strings.TrimSuffix(b.String(), "\n")
		lines = append(lines, line)
		prev = core.Digest([]byte(line))
	}
	return lines
}

func build() vectors {
	v := vectors{
		About: []string{
			"Conformance vectors for deedlog: the Go implementation (core/) and the JavaScript one (js/) must both",
			"produce every output here from the inputs here, byte for byte, and accept or refuse what is marked so.",
			"Built by core/conformance_test.go (go test ./core -run TestConformance -update); see docs/implementations.md.",
			"The keys are derived from fixed labels and are public: they protect nothing.",
		},
		Keys: map[string]keyPair{
			"operator":  testKey(origin, core.SigEd25519, "operator"),
			"witness":   testKey("witness.example/conformance", core.SigCosignature, "witness"),
			"stranger":  testKey("other.example/log", core.SigEd25519, "stranger"),
			"imposter":  testKey(origin, core.SigEd25519, "imposter"),
			"bystander": testKey("bystander.example", core.SigCosignature, "bystander"),
		},
		Names: map[string][]string{
			"valid":   {"log.example/conformance", "city.example/cameras/2026", "例.example/記録", "a", strings.Repeat("a", 255)},
			"invalid": {"", "with space", "with+plus", "tab\there", "line\nbreak", "nbsp here", "ideographic　space", "next\u0085line", "line separator", strings.Repeat("a", 256), strings.Repeat("あ", 86)},
		},
	}

	// Records made from events.
	r := &v.Records
	r.Chain = recordsName
	r.Source = core.Source{Type: "conformance", ID: origin, Collector: "conformance 1"}
	r.Events = events
	var s core.Summary
	var lines [][]byte
	var leaves []core.Hash
	r.Roots = []string{b64(core.Root(nil))}
	for _, e := range events {
		line, body, err := core.EventRecord(s, recordsName, core.Event{Source: r.Source, Name: e.Event, Meta: fields(e.Meta), At: must(time.Parse(time.RFC3339, e.At))})
		if err != nil {
			panic(err)
		}
		s = s.Next(recordsName, line)
		lines = append(lines, line)
		leaves = append(leaves, core.LeafHash(line))
		r.Lines = append(r.Lines, string(line))
		r.Bodies = append(r.Bodies, string(body))
		r.Heads = append(r.Heads, s.Head)
		r.Leaves = append(r.Leaves, b64(core.LeafHash(line)))
		r.Roots = append(r.Roots, b64(core.Root(leaves)))
	}
	n := uint64(len(leaves))
	for size := uint64(1); size <= n; size++ {
		for index := uint64(0); index < size; index++ {
			r.Proofs.Inclusion = append(r.Proofs.Inclusion, inclusionVector{index, size, b64s(must(core.InclusionProof(leaves[:size], index)))})
		}
		for old := uint64(0); old <= size; old++ {
			r.Proofs.Consistency = append(r.Proofs.Consistency, consistencyVector{old, size, b64s(must(core.ConsistencyProof(leaves[:size], old)))})
		}
	}

	// Chains a verifier accepts, whoever wrote them.
	accept := func(name string, lines []string) {
		s, _, err := core.VerifyLeaves(strings.NewReader(strings.Join(lines, "\n") + "\n"))
		if err != nil {
			panic(fmt.Sprintf("%s: %v", name, err))
		}
		v.Accepted = append(v.Accepted, chainVector{Name: name, Lines: lines, Count: s.Count, Head: s.Head, Root: s.Root})
	}
	accept("records made from events", r.Lines)
	{
		var b bytes.Buffer
		w := must(core.NewWriter(&b, "city.example/cameras"))
		for i := range 5 {
			must(w.Append(core.Record{
				CollectedAt: time.Date(2026, 10, 22, 0, 0, i, 123456789*(i%2), time.UTC),
				Source:      core.Source{Type: "syslog", ID: "camera-<1>&2", Collector: "conformance"},
				Subject:     core.Subject{MediaType: "text/plain", Size: int64(i), Digest: map[string]string{"sha256": strings.Repeat("ab", 32)}, URI: "s3://bucket/key"},
				Meta:        map[string]string{"zeta": "last", "alpha": "first", "note": "sorted keys, <escaped> &  "},
			}))
		}
		accept("records written by core.Writer: sorted meta, HTML escapes, fractional seconds", strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n"))
	}
	accept("fields a verifier does not know, and a keyed digest only", rawChain(3, func(i int, r map[string]any) {
		r["extension"] = map[string]any{"anything": []int{1, 2, 3}}
		if i == 1 {
			r["subject"] = map[string]any{"media_type": "text/plain", "size": 11, "digest": map[string]any{"hmac-sha256": strings.Repeat("cd", 32)}}
		}
	}))

	// Chains a verifier refuses, and the line at which it must.
	refuse := func(name string, lines []string, line int) {
		_, _, err := core.VerifyLeaves(strings.NewReader(strings.Join(lines, "\n")))
		var le *core.LineError
		got := 0
		switch {
		case err == nil:
			panic(name + ": accepted")
		case asLineError(err, &le):
			got = le.Line
		}
		if got != line {
			panic(fmt.Sprintf("%s: refused at line %d, want %d: %v", name, got, line, err))
		}
		v.Refused = append(v.Refused, chainVector{Name: name, Lines: lines, Line: &line})
	}
	good := rawChain(5, nil)
	edit := func(i int, old, new string) []string {
		out := append([]string{}, good...)
		if !strings.Contains(out[i], old) {
			panic("nothing to edit: " + old)
		}
		out[i] = strings.Replace(out[i], old, new, 1)
		return out
	}
	refuse("no records", []string{}, 0)
	refuse("a record changed: the next one no longer links to it", edit(2, `"id":"x"`, `"id":"y"`), 4)
	refuse("a record removed", append(append([]string{}, good[:2]...), good[3:]...), 3)
	refuse("two records swapped", []string{good[0], good[2], good[1], good[3], good[4]}, 2)
	refuse("the first record removed", good[1:], 1)
	refuse("an unknown spec", rawChain(3, func(i int, r map[string]any) {
		if i == 1 {
			r["spec"] = "deedlog/v9"
		}
	}), 2)
	refuse("no chain name", rawChain(2, func(i int, r map[string]any) { r["chain"] = "" }), 1)
	refuse("another chain's record", rawChain(3, func(i int, r map[string]any) {
		if i == 2 {
			r["chain"] = "other.example/elsewhere"
		}
	}), 3)
	refuse("a sequence number repeated", rawChain(3, func(i int, r map[string]any) {
		if i == 2 {
			r["seq"] = 1
		}
	}), 3)
	refuse("a subject without a digest", rawChain(3, func(i int, r map[string]any) {
		if i == 1 {
			r["subject"] = map[string]any{"media_type": "text/plain", "size": 1, "digest": map[string]any{}}
		}
	}), 2)
	refuse("a SHA-256 digest in capitals", rawChain(3, func(i int, r map[string]any) {
		if i == 2 {
			r["subject"] = map[string]any{"media_type": "text/plain", "size": 1, "digest": map[string]any{"sha256": strings.Repeat("AB", 32)}}
		}
	}), 3)
	refuse("a line that is not JSON", []string{good[0], "{not json", good[2]}, 2)
	refuse("an empty line", []string{good[0], "", good[1]}, 2)
	refuse("a line that is JSON null", []string{good[0], "null"}, 2)
	refuse("a line that is a JSON array", []string{good[0], "[]"}, 2)
	refuse("lines ending in CR", []string{good[0] + "\r", good[1] + "\r"}, 1)

	// Anchoring: the records above, committed to over four intervals.
	a := &v.Anchoring
	a.Origin, a.Chain = origin, recordsName
	a.Source = core.Source{Type: "conformance", ID: origin, Collector: "conformance 1"}
	var outer core.Summary
	var outerLeaves []core.Hash
	var outerLines []string
	for i, x := range []struct {
		from, to uint64
		epoch    string
	}{{0, 3, "2026-11-01T09:10:00Z"}, {3, 3, "2026-11-01T09:20:00Z"}, {3, 8, "2026-11-01T09:30:00Z"}, {8, 9, "2026-11-01T09:40:00Z"}, {9, 10, "2026-11-01T09:50:00Z"}} {
		iv := interval{Seq: uint64(i), Epoch: x.epoch, From: x.from, To: x.to, Nonce: secret(fmt.Sprint("nonce ", i)), Pad: secret(fmt.Sprint("pad ", i)), At: x.epoch}
		terms := core.AnchorTerms{Chain: recordsName, Epoch: iv.Epoch, Nonce: iv.Nonce, Pad: iv.Pad}
		made := must(core.Anchor(lines[x.from:x.to], terms))
		iv.Size, iv.Root, iv.Commit = made.Size, b64(made.Root), made.Commit
		line, _, err := core.EventRecord(outer, origin, core.Event{Source: a.Source, Name: core.AnchorEvent, Meta: core.AnchorMeta(iv.Epoch, iv.Commit), At: must(time.Parse(time.RFC3339, iv.At))})
		if err != nil {
			panic(err)
		}
		iv.Line = string(line)
		outer = outer.Next(origin, line)
		outerLeaves = append(outerLeaves, core.LeafHash(line))
		outerLines = append(outerLines, iv.Line)
		a.Intervals = append(a.Intervals, iv)
		for j := x.from; j < x.to; j++ {
			p := must(core.NewRecordProof(lines[x.from:x.to], int(j-x.from), iv.Seq, terms))
			a.Proofs = append(a.Proofs, recordProofVector{Record: j, Body: r.Bodies[j], Proof: string(must(json.Marshal(p)))})
		}
	}
	accept("the anchor chain", outerLines)
	{
		first := a.Proofs[0]
		var p core.RecordProof
		if err := json.Unmarshal([]byte(first.Proof), &p); err != nil {
			panic(err)
		}
		alter := func(name string, body, chain string, change func(p *core.RecordProof)) {
			q := p
			q.Path = append([]string{}, p.Path...)
			if change != nil {
				change(&q)
			}
			a.Refused = append(a.Refused, refusedProof{Name: name, Body: body, Chain: chain, Proof: string(must(json.Marshal(q)))})
		}
		alter("another subject", first.Body+" ", recordsName, nil)
		alter("another record chain", first.Body, origin+"/other", nil)
		alter("another interval's epoch", first.Body, recordsName, func(p *core.RecordProof) { p.Epoch = a.Intervals[1].Epoch })
		alter("another interval", first.Body, recordsName, func(p *core.RecordProof) { p.Seq = 2; p.Epoch = a.Intervals[2].Epoch })
		alter("another nonce", first.Body, recordsName, func(p *core.RecordProof) { p.Nonce = secret("another") })
		alter("another blind", first.Body, recordsName, func(p *core.RecordProof) { p.Blind = strings.Repeat("00", 32) })
		alter("another record", first.Body, recordsName, func(p *core.RecordProof) { p.Record = strings.Repeat("00", 32) })
		alter("another place", first.Body, recordsName, func(p *core.RecordProof) { p.Index = 1 })
		alter("another size", first.Body, recordsName, func(p *core.RecordProof) { p.Size = 8 })
		alter("a path cut short", first.Body, recordsName, func(p *core.RecordProof) { p.Path = p.Path[:1] })
		alter("an anchor record that does not exist", first.Body, recordsName, func(p *core.RecordProof) { p.Seq = 99 })
	}

	// Checkpoints of the anchor chain, and the witness's cosignatures.
	operator := must(core.NewSigner(v.Keys["operator"].Skey))
	wsigner := must(core.NewSigner(v.Keys["witness"].Skey))
	const t0 = 1793500000
	checkpoint := func(size uint64) core.Checkpoint {
		return core.Checkpoint{Origin: origin, Size: size, Root: core.Root(outerLeaves[:size])}
	}
	for size := uint64(1); size <= outer.Count; size++ {
		c := checkpoint(size)
		note := must(core.SignCheckpoint(c, operator))
		tm := int64(t0 + 600*size)
		v.Checkpoints = append(v.Checkpoints, checkpointVector{Size: size, Text: string(c.Text()), Note: string(note),
			Time: tm, Cosigned: string(note) + must(core.Cosign(c, wsigner, time.Unix(tm, 0)))})
	}

	// Notes a verifier with the operator's and the witness's key accepts or refuses.
	last := v.Checkpoints[len(v.Checkpoints)-1]
	sign := func(key string, text string) string {
		return string(must(must(core.NewSigner(v.Keys[key].Skey)).Sign([]byte(text))))
	}
	sigLine := func(note string) string { return note[strings.LastIndex(note, "\n\n")+2:] }
	cosigLine := sigLine(last.Cosigned)
	cosigLine = cosigLine[strings.Index(cosigLine, "\n")+1:]
	bystander := must(core.NewSigner(v.Keys["bystander"].Skey))
	addNote := func(name, note string, quorum int, ok bool) {
		v.Notes = append(v.Notes, noteVector{name, note, quorum, ok})
	}
	addNote("signed by the operator", last.Note, 0, true)
	addNote("signed by the operator, cosigned by the witness", last.Cosigned, 1, true)
	addNote("a signature from a key the verifier does not know is ignored", last.Cosigned+must(core.Cosign(checkpoint(outer.Count), bystander, time.Unix(t0, 0))), 1, true)
	addNote("the same cosignature twice is one witness", last.Cosigned+cosigLine, 1, true)
	addNote("no cosignature, one required", last.Note, 1, false)
	addNote("the size changed after signing", strings.Replace(last.Note, fmt.Sprintf("\n%d\n", last.Size), fmt.Sprintf("\n%d\n", last.Size+1), 1), 0, false)
	addNote("the cosignature of another checkpoint", last.Note+sigLine(v.Checkpoints[0].Cosigned)[strings.Index(sigLine(v.Checkpoints[0].Cosigned), "\n")+1:], 1, false)
	addNote("signed by another key under the operator's name", sign("imposter", last.Text), 0, false)
	addNote("only the witness signed", last.Text+"\n"+cosigLine, 1, false)
	addNote("an extension line", sign("operator", last.Text+"extension\n"), 0, false)
	addNote("a size with a leading zero", sign("operator", strings.Replace(last.Text, fmt.Sprintf("\n%d\n", last.Size), fmt.Sprintf("\n0%d\n", last.Size), 1)), 0, false)
	addNote("an empty tree with a root that is not the empty tree's", sign("operator", fmt.Sprintf("%s\n0\n%s\n", origin, b64(outerLeaves[0]))), 0, false)
	addNote("the empty tree", sign("operator", string(core.Checkpoint{Origin: origin, Root: core.EmptyRoot}.Text())), 0, true)
	addNote("a root that is not canonical base64", sign("operator", fmt.Sprintf("%s\n1\n%s\n", origin, strings.TrimSuffix(b64(outerLeaves[0]), "=")+"\n")), 0, false)
	addNote("no signature at all", last.Text, 0, false)

	// A witness, asked in turn. It starts knowing the operator and nothing else.
	srv := &witness.Server{Signer: wsigner, Logs: map[string]*core.Verifier{origin: must(core.NewVerifier(v.Keys["operator"].Vkey))}, Store: &witness.MemoryStore{}}
	ask := func(name string, body string, tm int64) {
		srv.Now = func() time.Time { return time.Unix(tm, 0) }
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/add-checkpoint", strings.NewReader(body)))
		step := witnessStep{Name: name, Body: body, Time: tm, Status: rec.Code}
		if rec.Code == http.StatusOK || rec.Code == http.StatusConflict {
			step.Response = rec.Body.String()
		}
		v.Witness = append(v.Witness, step)
	}
	request := func(old, size uint64, note string) string {
		body := fmt.Sprintf("old %d\n", old)
		for _, h := range must(core.ConsistencyProof(outerLeaves[:size], old)) {
			body += b64(h) + "\n"
		}
		return body + "\n" + note
	}
	cp := func(size uint64) string { return v.Checkpoints[size-1].Note }
	forked := func() string {
		other := append([]core.Hash{}, outerLeaves[:4]...)
		other[1] = core.LeafHash([]byte("another history"))
		return string(must(core.SignCheckpoint(core.Checkpoint{Origin: origin, Size: 4, Root: core.Root(other)}, operator)))
	}()
	ask("the first checkpoint", request(0, 2, cp(2)), t0+1)
	ask("the same checkpoint again, from the size held", request(2, 2, cp(2)), t0+2)
	ask("from a size the witness does not hold: it says which it holds", request(0, 4, cp(4)), t0+3)
	ask("from the size held, with the proof", request(2, 4, cp(4)), t0+4)
	ask("another history of the same size", request(4, 4, forked), t0+5)
	ask("a proof that does not fit", "old 4\n"+b64(outerLeaves[0])+"\n\n"+cp(5), t0+6)
	ask("an older checkpoint than the one held", request(4, 4, cp(4))[:0]+"old 4\n\n"+cp(3), t0+7)
	ask("a log the witness does not know", "old 0\n\n"+sign("stranger", "other.example/log\n1\n"+b64(outerLeaves[0])+"\n"), t0+8)
	ask("not signed by the operator's key", request(4, 5, sign("imposter", v.Checkpoints[4].Text)), t0+9)
	ask("no empty line", "old 4\n"+cp(5), t0+10)
	ask("a malformed size line", "old four\n\n"+cp(5), t0+11)
	ask("a size with a leading zero", "old 04\n\n"+cp(5), t0+12)
	ask("a proof line that is not a hash", "old 4\nAAAA\n\n"+cp(5), t0+13)
	ask("growing to the last checkpoint", request(4, 5, cp(5)), t0+14)
	return v
}

func asLineError(err error, le **core.LineError) bool {
	for err != nil {
		if e, ok := err.(*core.LineError); ok {
			*le = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func TestConformance(t *testing.T) {
	v := build()
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	if *update {
		if err := os.MkdirAll("../testdata/conformance", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vectorsPath, b.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b.Bytes(), want) {
		got := strings.Split(b.String(), "\n")
		for i, line := range strings.Split(string(want), "\n") {
			if i >= len(got) || got[i] != line {
				t.Fatalf("%s line %d differs from what this implementation produces:\n file: %s\n here: %s", vectorsPath, i+1, line, at(got, i))
			}
		}
		t.Fatalf("%s is shorter than what this implementation produces", vectorsPath)
	}
	check(t, v)
}

func at(lines []string, i int) string {
	if i < len(lines) {
		return lines[i]
	}
	return "(nothing)"
}

// check verifies what build did not already verify by producing it: that
// the outputs are accepted, and the refusals refused.
func check(t *testing.T, v vectors) {
	for _, name := range v.Names["valid"] {
		if !core.ValidKeyName(name) {
			t.Errorf("name %q refused", name)
		}
	}
	for _, name := range v.Names["invalid"] {
		if core.ValidKeyName(name) {
			t.Errorf("name %q accepted", name)
		}
	}

	// Merkle proofs verify against the roots.
	r := v.Records
	hash := func(s string) core.Hash { return core.Hash(must(base64.StdEncoding.DecodeString(s))) }
	hashes := func(ss []string) []core.Hash {
		var out []core.Hash
		for _, s := range ss {
			out = append(out, hash(s))
		}
		return out
	}
	for _, p := range r.Proofs.Inclusion {
		if err := core.VerifyInclusion(p.Index, p.Size, hash(r.Leaves[p.Index]), hashes(p.Proof), hash(r.Roots[p.Size])); err != nil {
			t.Errorf("inclusion %d in %d: %v", p.Index, p.Size, err)
		}
	}
	for _, p := range r.Proofs.Consistency {
		if err := core.VerifyConsistency(p.Old, p.New, hash(r.Roots[p.Old]), hash(r.Roots[p.New]), hashes(p.Proof)); err != nil {
			t.Errorf("consistency %d to %d: %v", p.Old, p.New, err)
		}
	}

	// Anchoring: the anchor chain, the whole record chain, and every proof.
	a := v.Anchoring
	var outer []string
	var entries []core.AnchorEntry
	for _, iv := range a.Intervals {
		outer = append(outer, iv.Line)
		entries = append(entries, core.AnchorEntry{Seq: iv.Seq, Epoch: iv.Epoch, From: iv.From, To: iv.To, Size: iv.Size, Nonce: iv.Nonce, Pad: iv.Pad})
	}
	_, _, anchors, err := core.VerifyAnchors(strings.NewReader(strings.Join(outer, "\n") + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	covered := uint64(len(anchors))
	got, err := core.CheckAnchored(strings.NewReader(strings.Join(r.Lines, "\n")+"\n"), anchors, covered, entries)
	if err != nil {
		t.Fatal(err)
	}
	if got.Intervals != covered || got.Anchored != a.Intervals[len(a.Intervals)-1].To || got.Count != uint64(len(r.Lines)) {
		t.Errorf("CheckAnchored = %+v", got)
	}
	for i := range r.Lines[:got.Anchored] {
		changed := append([]string{}, r.Lines...)
		changed[i] = strings.Replace(changed[i], `"type":"conformance"`, `"type":"conformancf"`, 1)
		relinked := relink(changed)
		if _, err := core.CheckAnchored(strings.NewReader(strings.Join(relinked, "\n")+"\n"), anchors, covered, entries); err == nil {
			t.Errorf("record %d changed and the chain relinked: still accepted", i)
		}
	}
	for _, p := range a.Proofs {
		var proof core.RecordProof
		if err := json.Unmarshal([]byte(p.Proof), &proof); err != nil {
			t.Fatal(err)
		}
		if err := core.CheckRecordProof(proof, a.Chain, sha256.Sum256([]byte(p.Body)), anchors, covered); err != nil {
			t.Errorf("proof of record %d: %v", p.Record, err)
		}
		if err := core.CheckRecordProof(proof, a.Chain, sha256.Sum256([]byte(p.Body)), anchors, proof.Seq); err == nil {
			t.Errorf("proof of record %d accepted under a checkpoint that does not cover its anchor record", p.Record)
		}
	}
	for _, p := range a.Refused {
		var proof core.RecordProof
		if err := json.Unmarshal([]byte(p.Proof), &proof); err != nil {
			t.Fatal(err)
		}
		if err := core.CheckRecordProof(proof, p.Chain, sha256.Sum256([]byte(p.Body)), anchors, covered); err == nil {
			t.Errorf("proof accepted: %s", p.Name)
		}
	}

	// Notes.
	operator := must(core.NewVerifier(v.Keys["operator"].Vkey))
	w := must(core.NewVerifier(v.Keys["witness"].Vkey))
	for _, c := range v.Checkpoints {
		got, err := core.VerifyCheckpoint([]byte(c.Cosigned), operator, []*core.Verifier{w}, 1)
		if err != nil || got.Size != c.Size || string(got.Text()) != c.Text {
			t.Errorf("checkpoint %d: %+v, %v", c.Size, got, err)
		}
	}
	for _, n := range v.Notes {
		_, err := core.VerifyCheckpoint([]byte(n.Note), operator, []*core.Verifier{w}, n.Quorum)
		if (err == nil) != n.OK {
			t.Errorf("note %q: accepted %v, want %v (%v)", n.Name, err == nil, n.OK, err)
		}
	}
}

// relink rewrites the prev of every record after a changed one, as someone
// rewriting the chain would.
func relink(lines []string) []string {
	out := []string{lines[0]}
	for _, line := range lines[1:] {
		i := strings.Index(line, `"prev":"sha256:`) + len(`"prev":"`)
		out = append(out, line[:i]+core.Digest([]byte(out[len(out)-1]))+line[i+71:])
	}
	return out
}
