package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/deedlog/deedlog/core"
	"github.com/deedlog/deedlog/examples/data-tiering/tiering"
	"github.com/deedlog/deedlog/examples/internal/demo"
)

// Verifier is the third-party checking site. It holds the city's public
// keys and the witnesses it trusts, fetches what the city publishes, and
// checks everything itself; nothing the city serves is trusted as is.
type Verifier struct {
	CityURL string // the city's publication API
	Keys    func() (operator, receipts *core.Verifier, witnesses []*core.Verifier)
	News    func() time.Time // when the breach was announced, if it was

	mu       sync.Mutex
	lastGood []byte // the latest cosigned checkpoint this site has seen
}

// Step is one event in the life of an inquiry.
type Step struct {
	Date  string `json:"date"`
	Title string `json:"title"`
	Note  string `json:"note,omitempty"`
	Kind  string `json:"kind"` // done, late, waiting
}

// Status is what the checking site tells the resident.
type Status struct {
	Number    string   `json:"number"`
	Verdict   string   `json:"verdict"` // ok, pending, warning, tampered
	Headline  string   `json:"headline"`
	Detail    string   `json:"detail"`
	Steps     []Step   `json:"steps"`
	Witnesses []string `json:"witnesses"`
	CheckedAt string   `json:"checked_at"`
	Breach    *Notice  `json:"breach,omitempty"`
	City      *Notice  `json:"city,omitempty"`
	Proof     string   `json:"proof,omitempty"` // proof of misbehavior, JSON
}

// Notice is a highlighted box on the page.
type Notice struct {
	Kind  string   `json:"kind"` // ok, bad
	Title string   `json:"title"`
	Lines []string `json:"lines"`
}

func jday(t time.Time) string { return fmt.Sprintf("%d月%d日", t.Month(), t.Day()) }

func (v *Verifier) fetch(path string) ([]byte, error) {
	resp, err := http.Get(strings.TrimSuffix(v.CityURL, "/") + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", path, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

// Check checks a receipt against what the city publishes.
func (v *Verifier) Check(receiptNote []byte) (*Status, error) {
	operator, receipts, witnesses := v.Keys()
	r, err := core.VerifyReceipt(receiptNote, receipts)
	if err != nil {
		return nil, errors.New("この控えは、あおば台市の署名と一致しません")
	}
	st := &Status{Number: fmt.Sprintf("R-%06d", r.Index)}
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
	policy, err := v.fetch("/deedlog/policy")
	if err != nil {
		return nil, err
	}

	// The checkpoint must be signed by the city and cosigned by both
	// witnesses. A checkpoint signed by the city alone is still the city's
	// own statement, so it is used to show what the city now claims.
	c, err := core.VerifyCheckpoint(cpNote, operator, witnesses, len(witnesses))
	cosigned := err == nil
	if !cosigned {
		if c, err = core.VerifyCheckpoint(cpNote, operator, nil, 0); err != nil {
			return nil, errors.New("市の公開記録に、市の署名がありません")
		}
	}
	sum, leaves, err := core.VerifyLeaves(bytes.NewReader(chain))
	if err != nil || core.CheckCheckpoint(sum, leaves, c) != nil {
		return v.tampered(st, "市が公開している記録の中身が、市自身の署名した要約と一致しません。", ""), nil
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
	if !cosigned {
		detail := "市が公開している記録は、図書館と監査法人（連署サーバー）の確認を得られていません。"
		if lastGood != nil {
			if old, err := core.VerifyCheckpoint(lastGood, operator, witnesses, len(witnesses)); err == nil && core.CheckCheckpoint(sum, leaves, old) != nil {
				detail += fmt.Sprintf("以前この確認サイトが確かめた記録（%d件）とも一致しません。記録が書き換えられています。", old.Size)
			}
		}
		var p string
		if status == core.ReceiptBroken {
			b, _ := json.MarshalIndent(proof, "", "  ")
			p = string(b)
			detail += "あなたの控えが約束した記録も、別の記録に差し替えられています。下の証明は、市の署名だけで誰でも検証できます。"
		}
		return v.tampered(st, detail, p), nil
	}

	entries, err := entriesOf(chain, c.Size)
	if err != nil {
		return nil, err
	}
	st.CheckedAt = jday(entries[len(entries)-1].CollectedAt) + "の記録まで"
	if status == core.ReceiptNotYetCovered {
		st.Verdict, st.Headline = "pending", "受付済み・第三者の確認待ち"
		st.Detail = "市は毎日23時に、その日の記録を図書館と監査法人に確認してもらっています。確認が済むと、ここに表示されます。"
		st.Steps = []Step{{Date: "", Title: "受付", Note: "確認待ち", Kind: "waiting"}}
		return st, nil
	}
	if status == core.ReceiptBroken {
		b, _ := json.MarshalIndent(proof, "", "  ")
		return v.tampered(st, "あなたの控えが約束した記録が、別の記録に差し替えられています。", string(b)), nil
	}

	v.timeline(st, entries, r.Index)
	v.cityWide(st, entries, policy)
	return st, nil
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

// timeline follows the resident's inquiry through the city's records, by
// its keyed digest; the site never sees the inquiry itself.
func (v *Verifier) timeline(st *Status, entries []demo.Entry, index uint64) {
	mine := entries[index].Subject.Digest["hmac-sha256"]
	end := entries[len(entries)-1].CollectedAt
	received := entries[index].CollectedAt
	var leftForm time.Time
	deleted := false
	for _, e := range entries[index:] {
		if e.Subject.Digest["hmac-sha256"] != mine {
			continue
		}
		switch e.Meta["event"] {
		case "received":
			st.Steps = append(st.Steps, Step{Date: jday(e.CollectedAt), Title: "受付", Note: "外部のフォームサービスで受け付けました", Kind: "done"})
		case "moved":
			leftForm = e.CollectedAt
			days := e.CollectedAt.Sub(received).Hours() / 24
			s := Step{Date: jday(e.CollectedAt), Title: "市の庁内システムへ移動", Note: fmt.Sprintf("外部のフォームサービスから削除（受付から%.0f日）", days), Kind: "done"}
			if days > 7 {
				s.Kind, s.Note = "late", fmt.Sprintf("約束の7日を過ぎて移動（受付から%.0f日）", days)
			}
			st.Steps = append(st.Steps, s)
		case "deleted":
			deleted = true
			st.Steps = append(st.Steps, Step{Date: jday(e.CollectedAt), Title: "削除", Note: "市の庁内システムからも削除しました", Kind: "done"})
		}
	}
	if leftForm.IsZero() {
		days := end.Sub(received).Hours() / 24
		if days > 7 {
			st.Steps = append(st.Steps, Step{Title: "市の庁内システムへ移動", Note: fmt.Sprintf("約束の7日を過ぎても、外部のフォームサービスに残っています（受付から%.0f日）", days), Kind: "late"})
		} else {
			st.Steps = append(st.Steps, Step{Date: jday(received.AddDate(0, 0, 7)) + "まで", Title: "市の庁内システムへ移動", Note: "外部のフォームサービスから移す予定", Kind: "waiting"})
		}
	}
	if !deleted {
		st.Steps = append(st.Steps, Step{Title: "削除", Note: "移動から30日後に削除する予定", Kind: "waiting"})
	}

	late := false
	for _, s := range st.Steps {
		late = late || s.Kind == "late"
	}
	if late {
		st.Verdict, st.Headline = "warning", "市の約束が守られていません"
		st.Detail = "あなたのお問い合わせは、約束の期間を過ぎて外部のフォームサービスに置かれていました。"
	} else if deleted {
		st.Verdict, st.Headline = "ok", "約束どおりに削除されました"
		st.Detail = "あなたのお問い合わせは、市の約束どおりに移され、削除されたことを、記録で確かめました。"
	} else {
		st.Verdict, st.Headline = "ok", "約束どおりに扱われています"
		st.Detail = "あなたのお問い合わせが、ここまで市の約束どおりに扱われていることを、記録で確かめました。"
	}

	if breach := v.News(); !breach.IsZero() && !breach.Before(received) {
		n := &Notice{Title: jday(breach) + "に公表された、フォームサービスへの不正アクセスについて"}
		switch {
		case !leftForm.IsZero() && leftForm.Before(breach):
			n.Kind = "ok"
			n.Lines = []string{
				fmt.Sprintf("あなたのお問い合わせは、公表より前の%sに、フォームサービスから移されていました。", jday(leftForm)),
				"市の記録の上では、不正アクセスの時点でフォームサービスに残っていなかったことになります。",
			}
		default:
			n.Kind = "bad"
			n.Lines = []string{
				fmt.Sprintf("あなたのお問い合わせは、公表の時点でフォームサービスに残っていました（受付から%.0f日、約束は7日）。", breach.Sub(received).Hours()/24),
				"流出した可能性があります。市に問い合わせるときは、この画面と控えを示してください。",
			}
		}
		n.Lines = append(n.Lines, "※ フォームサービス側のバックアップなど、市のシステムの外にあるコピーは、この記録では確認できません。")
		st.Breach = n
	}
}

// cityWide checks the whole chain against the city's published policy.
func (v *Verifier) cityWide(st *Status, entries []demo.Entry, policy []byte) {
	fs := tiering.Check(entries, policy)
	received := 0
	for _, e := range entries {
		if e.Meta["event"] == "received" {
			received++
		}
	}
	n := &Notice{Title: fmt.Sprintf("あおば台市全体（お問い合わせ%d件）", received)}
	if len(fs) == 0 {
		n.Kind = "ok"
		n.Lines = []string{"すべてのお問い合わせが、公開された約束どおりに扱われています。"}
		st.City = n
		return
	}
	kinds := []struct{ prefix, label string }{
		{"moved off", "外部サービスからの移動が遅れた"},
		{"still in form-service", "期限を過ぎて外部サービスに残っている"},
		{"deleted from", "削除が遅れた"},
		{"still in archive", "期限を過ぎて保管されている"},
		{"no inventory", "保管状況の確認が抜けた"},
		{"holds", "記録にないデータが見つかった"},
	}
	count := make(map[string]int)
	for _, f := range fs {
		for _, k := range kinds {
			if strings.Contains(f.Problem, k.prefix) {
				count[k.label]++
				break
			}
		}
	}
	n.Kind = "bad"
	for _, k := range kinds {
		if c := count[k.label]; c > 0 {
			n.Lines = append(n.Lines, fmt.Sprintf("%s：%d件", k.label, c))
		}
	}
	st.City = n
}

// ServeHTTP serves the checking site's API.
func (v *Verifier) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	note, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("r"))
	if err != nil {
		http.Error(w, "控えの形式が正しくありません", http.StatusBadRequest)
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
