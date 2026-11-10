package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/eucassoc/deedlog/core"
	"github.com/eucassoc/deedlog/examples/internal/demo"
	"github.com/eucassoc/deedlog/examples/official-videos/studio"
)

// Verifier is the checking site, run independently of the fan club. It
// holds the fan club's and the engine's public keys and the witnesses it
// trusts, fetches what the fan club publishes, and checks everything
// itself; nothing the fan club serves is trusted as is.
type Verifier struct {
	ClubURL string // the fan club's publication API
	Keys    func() (operator, receipts, engine *core.Verifier, witnesses []*core.Verifier)

	mu       sync.Mutex
	lastGood []byte // the latest cosigned checkpoint this site has seen
}

// Step is one stage in the making of a video.
type Step struct {
	Date  string `json:"date"`
	Title string `json:"title"`
	Note  string `json:"note,omitempty"`
	Kind  string `json:"kind"` // done, late
}

// Status is what the checking site tells the fan.
type Status struct {
	Title     string   `json:"title"`
	URL       string   `json:"url"`
	Verdict   string   `json:"verdict"` // ok, warning, bad, tampered
	Headline  string   `json:"headline"`
	Detail    string   `json:"detail"`
	Steps     []Step   `json:"steps"`
	Allowed   []string `json:"allowed,omitempty"`
	Witnesses []string `json:"witnesses"`
	Club      *Notice  `json:"club,omitempty"`
	Proof     string   `json:"proof,omitempty"` // proof of misbehavior, JSON
}

// Notice is a highlighted box on the page.
type Notice struct {
	Kind  string   `json:"kind"` // ok, bad
	Title string   `json:"title"`
	Lines []string `json:"lines"`
}

var opNames = map[string]string{
	studio.Trim:     "トリミング",
	studio.Crop:     "クロップ",
	studio.Concat:   "結合",
	studio.Music:    "BGM",
	studio.Logo:     "ロゴ・ジングル",
	studio.Generate: "AIによる場面の生成",
}

func opName(k string) string {
	if n, ok := opNames[k]; ok {
		return n
	}
	return k
}

func jtime(t time.Time) string {
	return fmt.Sprintf("%d月%d日 %d:%02d", t.Month(), t.Day(), t.Hour(), t.Minute())
}

func (v *Verifier) fetch(path string) ([]byte, error) {
	resp, err := http.Get(strings.TrimSuffix(v.ClubURL, "/") + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", path, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

// Check checks the receipt next to a video against what the fan club
// publishes.
func (v *Verifier) Check(receiptNote []byte) (*Status, error) {
	operator, receipts, engine, witnesses := v.Keys()
	r, err := core.VerifyReceipt(receiptNote, receipts)
	if err != nil {
		return nil, errors.New("このリンクは、ファンクラブの署名と一致しません")
	}
	st := &Status{}
	for _, n := range witnessNames {
		st.Witnesses = append(st.Witnesses, n[1])
	}

	cpNote, err := v.fetch("/deedlog/checkpoint")
	if err != nil {
		return nil, err
	}
	chain, err := v.fetch("/deedlog/chain")
	if err != nil {
		return nil, err
	}

	// The checkpoint must be signed by the fan club and cosigned by both
	// witnesses. One signed by the fan club alone is still its own
	// statement, so it is used to show what the fan club now claims.
	c, err := core.VerifyCheckpoint(cpNote, operator, witnesses, len(witnesses))
	cosigned := err == nil
	if !cosigned {
		if c, err = core.VerifyCheckpoint(cpNote, operator, nil, 0); err != nil {
			return nil, errors.New("ファンクラブの公開記録に、ファンクラブの署名がありません")
		}
	}
	sum, leaves, err := core.VerifyLeaves(bytes.NewReader(chain))
	if err != nil || core.CheckCheckpoint(sum, leaves, c) != nil {
		return v.tampered(st, "ファンクラブが公開している記録の中身が、ファンクラブ自身の署名した要約と一致しません。", ""), nil
	}

	v.mu.Lock()
	if cosigned {
		v.lastGood = cpNote
	}
	lastGood := v.lastGood
	v.mu.Unlock()

	var leaf core.Hash
	if r.Index < uint64(len(leaves)) {
		leaf = leaves[r.Index]
	}
	status, proof, err := core.CheckReceipt(receiptNote, r, cpNote, c, leaf, mustProof(leaves[:c.Size], r.Index, c.Size))
	if err != nil {
		return nil, err
	}
	if !cosigned || status == core.ReceiptBroken {
		detail := ""
		if !cosigned {
			detail = "ファンクラブが公開している記録は、ファン有志の会と監査法人（連署サーバー）の確認を得られていません。"
			if lastGood != nil {
				if old, err := core.VerifyCheckpoint(lastGood, operator, witnesses, len(witnesses)); err == nil && core.CheckCheckpoint(sum, leaves, old) != nil {
					detail += fmt.Sprintf("以前この確認サイトが確かめた記録（%d件）とも一致しません。記録が書き換えられています。", old.Size)
				}
			}
		}
		var p string
		if status == core.ReceiptBroken {
			b, _ := json.MarshalIndent(proof, "", "  ")
			p = string(b)
			detail += "この動画のリンクが約束した記録が、別の記録に差し替えられています。下の証明は、ファンクラブの署名だけで誰でも検証できます。"
		}
		return v.tampered(st, detail, p), nil
	}
	if status == core.ReceiptNotYetCovered {
		return nil, errors.New("この動画の記録は、まだ連署サーバーの確認を受けていません。しばらくしてから確かめてください")
	}

	entries, err := entriesOf(chain, c.Size)
	if err != nil {
		return nil, err
	}
	body := v.bodies()
	pub := entries[r.Index]
	st.Title, st.URL = pub.Meta["title"], pub.Meta["url"]
	rd, err := studio.Trace(entries, body, engine, r.Index)
	if err != nil {
		return nil, err
	}
	v.steps(st, pub, rd, engine)
	v.clubWide(st, entries, body, engine)
	return st, nil
}

// bodies returns published evidence bodies, fetched once per check.
func (v *Verifier) bodies() studio.Body {
	cache := make(map[string][]byte)
	return func(digest string) ([]byte, bool) {
		if b, ok := cache[digest]; ok {
			return b, b != nil
		}
		b, err := v.fetch("/deedlog/evidence/" + digest)
		if err != nil {
			b = nil
		}
		cache[digest] = b
		return b, b != nil
	}
}

func mustProof(leaves []core.Hash, index, size uint64) []core.Hash {
	if index >= size {
		return nil
	}
	p, _ := core.InclusionProof(leaves, index)
	return p
}

func entriesOf(chain []byte, size uint64) ([]demo.Entry, error) {
	var entries []demo.Entry
	for i, line := range bytes.Split(bytes.TrimSuffix(chain, []byte("\n")), []byte("\n")) {
		if uint64(i) >= size {
			break
		}
		var r core.Record
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, err
		}
		entries = append(entries, demo.Entry{Line: i + 1, Record: r})
	}
	return entries, nil
}

func (v *Verifier) tampered(st *Status, detail, proof string) *Status {
	st.Verdict, st.Headline, st.Detail, st.Proof = "tampered", "記録の書き換えが見つかりました", detail, proof
	return st
}

// steps shows how the video was made, from its footage to its
// publication.
func (v *Verifier) steps(st *Status, pub demo.Entry, rd *studio.Render, engine *core.Verifier) {
	published := Step{Date: jtime(pub.CollectedAt), Title: "公開", Note: st.URL, Kind: "done"}
	if rd == nil {
		st.Verdict, st.Headline = "bad", "制作工程の記録がありません"
		st.Detail = "この動画には、生成エンジンが署名した制作記録がありません。撮影素材から公開レシピどおりに作られたかどうか、確かめられません。"
		st.Steps = []Step{
			{Title: "撮影素材・編集", Note: "生成エンジンの署名付き記録がありません。ほかのアプリで編集された可能性があります", Kind: "late"},
			published,
		}
		return
	}

	for i, in := range rd.Statement.Inputs {
		found := false
		for _, c := range rd.Clips {
			if c.Subject.Digest["sha256"] == in {
				t, _ := time.Parse(time.RFC3339, c.Meta["shot_at"])
				st.Steps = append(st.Steps, Step{Date: jtime(c.CollectedAt), Title: fmt.Sprintf("撮影素材 %d を登録", i+1), Note: fmt.Sprintf("カメラ %s、%s撮影", c.Meta["camera"], jtime(t)), Kind: "done"})
				found = true
				break
			}
		}
		if !found {
			st.Steps = append(st.Steps, Step{Title: fmt.Sprintf("撮影素材 %d", i+1), Note: "登録されていない素材が使われています", Kind: "late"})
		}
	}
	if rd.Recipe != nil {
		st.Steps = append(st.Steps, Step{Title: "公開レシピ「" + rd.Recipe.Name + "」", Note: "素材にない場面は作らず、決められた加工だけを行うルールです", Kind: "done"})
		for _, k := range rd.Recipe.Allowed {
			st.Allowed = append(st.Allowed, opName(k))
		}
	} else {
		st.Steps = append(st.Steps, Step{Title: "公開レシピ", Note: "公開されていないレシピで編集されています", Kind: "late"})
	}
	var done, extra []string
	for _, op := range rd.Statement.Ops {
		if rd.Recipe != nil && !slices.Contains(rd.Recipe.Allowed, op.Kind) {
			extra = append(extra, opName(op.Kind)+"（"+op.Detail+"）")
		} else {
			done = append(done, opName(op.Kind))
		}
	}
	render := Step{Date: jtime(rd.Entry.CollectedAt), Title: "生成エンジンで編集", Note: engineDisplay + "の署名：" + strings.Join(done, "、"), Kind: "done"}
	if len(extra) > 0 {
		render.Kind = "late"
		render.Note += "。レシピにない加工：" + strings.Join(extra, "、")
	}
	st.Steps = append(st.Steps, render, published)

	switch {
	case len(extra) > 0:
		st.Verdict, st.Headline = "warning", "公開レシピにない加工が含まれています"
		st.Detail = "この動画には、撮影素材にない場面が加えられています：" + strings.Join(extra, "、") + "。生成エンジンが署名した制作記録で確かめました。"
	case len(rd.Problems) > 0:
		st.Verdict, st.Headline = "warning", "制作記録に問題があります"
		st.Detail = "公開レシピどおりに作られたとは確かめられません。下の記録を確認してください。"
	default:
		st.Verdict, st.Headline = "ok", "公開レシピどおりに作られた公式動画です"
		st.Detail = "撮影時に登録された素材だけを使い、公開レシピで認められた加工だけで作られたことを、生成エンジンの署名付き記録で確かめました。"
	}
}

// clubWide checks every video the fan club published.
func (v *Verifier) clubWide(st *Status, entries []demo.Entry, body studio.Body, engine *core.Verifier) {
	published := 0
	for _, e := range entries {
		if e.Meta["event"] == "published" {
			published++
		}
	}
	n := &Notice{Title: fmt.Sprintf("このファンクラブの公式動画すべて（%d本）", published)}
	fs := studio.Check(entries, body, engine)
	if len(fs) == 0 {
		n.Kind = "ok"
		n.Lines = []string{"すべての動画が、登録された素材から公開レシピどおりに作られています。"}
		st.Club = n
		return
	}
	kinds := []struct{ prefix, label string }{
		{"is not allowed by recipe", "レシピにない加工"},
		{"engine did not render", "生成エンジンを通さずに公開"},
		{"never registered", "登録されていない素材"},
		{"not signed by the engine", "生成エンジンの署名がない制作記録"},
	}
	count := make(map[string]map[int]bool)
	for _, f := range fs {
		for _, k := range kinds {
			if strings.Contains(f.Problem, k.prefix) {
				if count[k.label] == nil {
					count[k.label] = make(map[int]bool)
				}
				count[k.label][f.Line] = true
				break
			}
		}
	}
	n.Kind = "bad"
	for _, k := range kinds {
		if c := len(count[k.label]); c > 0 {
			n.Lines = append(n.Lines, fmt.Sprintf("%s：%d本", k.label, c))
		}
	}
	st.Club = n
}

// ServeHTTP serves the checking site's API.
func (v *Verifier) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	note, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("r"))
	if err != nil {
		http.Error(w, "リンクの形式が正しくありません", http.StatusBadRequest)
		return
	}
	st, err := v.Check(note)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(st)
}
