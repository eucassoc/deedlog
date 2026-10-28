package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/deedlog/deedlog/core"
	"github.com/deedlog/deedlog/examples/internal/demo"
	"github.com/deedlog/deedlog/examples/official-videos/studio"
)

const (
	origin     = "fanclub.asagiri.example/official-videos"
	engineName = "engine.sample-studio.example"
)

var recipe = studio.Recipe{
	Name:    "ハイライト編集 v1",
	Allowed: []string{studio.Trim, studio.Crop, studio.Concat, studio.Music, studio.Logo},
	Assets:  map[string]string{"logo.png": demo.Sum([]byte("logo")), "jingle.wav": demo.Sum([]byte("jingle")), "bgm-01.mp3": demo.Sum([]byte("bgm-01"))},
}

var edits = []studio.Op{
	{Kind: studio.Trim, Detail: "各素材の見どころ8秒"},
	{Kind: studio.Crop, Detail: "縦型9:16、顔切れ補正"},
	{Kind: studio.Concat},
	{Kind: studio.Music, Detail: "bgm-01.mp3"},
	{Kind: studio.Logo, Detail: "logo.png、jingle.wav"},
}

// witnessNames are the two parties, independent of the fan club, that
// cosign its checkpoints, by key name and display name.
var witnessNames = [][2]string{
	{"witness.fan-council.asagiri.example", "ファン有志の会（会員代表）"},
	{"witness.sample-audit.example", "サンプル監査法人"},
}

// engineDisplay is the party running the rendering engine.
const engineDisplay = "サンプル映像制作（生成エンジン）"

// Video is a video on the fan club site.
type Video struct {
	N        int
	Title    string
	Desc     string
	Date     time.Time
	Duration string
	Index    uint64 // record of its publication
	Receipt  []byte
}

// World is the simulated fan club: its shoots, the rendering engine run by
// a production company, the official site and its chain with two
// witnesses. Each action of the demo panel is one day.
type World struct {
	mu        sync.Mutex
	log       *demo.Log
	witnesses []*demo.Witness
	engine    *studio.Engine
	engineKey *core.Verifier
	studio    *studio.Studio
	recipe    string // digest of the declared recipe

	clips    [][]byte // registered and not yet used
	shoots   int
	videos   []*Video
	tampered bool
}

func NewWorld() (*World, error) {
	w := &World{}
	return w, w.reset()
}

func (w *World) reset() error {
	demo.CloseAll(w.witnesses)
	var names []string
	for _, n := range witnessNames {
		names = append(names, n[0])
	}
	l, ws, err := demo.Start(origin, time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC), names...)
	if err != nil {
		return err
	}
	w.log, w.witnesses = l, ws
	if w.engine, w.engineKey, err = studio.NewEngine(engineName); err != nil {
		return err
	}
	w.studio = &studio.Studio{Log: l, Engine: w.engine}
	w.clips, w.shoots, w.videos, w.tampered = nil, 0, nil, false
	if w.recipe, err = w.studio.Declare(recipe); err != nil {
		return err
	}
	// One video is already on the site when the story begins.
	if err := w.shoot(); err != nil {
		return err
	}
	return w.publish(scenes[0], edits, false)
}

// Reset starts the story over.
func (w *World) Reset() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.reset()
}

// Close stops the witnesses.
func (w *World) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	demo.CloseAll(w.witnesses)
}

var shootNames = []string{"公開練習", "ロードワーク", "記者会見", "計量", "前日調整"}

// shoot registers three clips as they come off the cameras.
func (w *World) shoot() error {
	w.shoots++
	for i := range 3 {
		clip := studio.Video(fmt.Sprintf("%s clip %d", shootNames[(w.shoots-1)%len(shootNames)], i+1))
		if err := w.studio.Register(clip, fmt.Sprintf("cam-%d", i%2+1), w.log.Clock.Now()); err != nil {
			return err
		}
		w.clips = append(w.clips, clip)
		w.log.Clock.Advance(25 * time.Minute)
	}
	w.log.Clock.Advance(2 * time.Hour)
	return nil
}

type scene struct{ title, desc, duration string }

var scenes = []scene{
	{"公開スパーリング ハイライト", "タイトル戦に向けた公開スパーリングの見どころをまとめました。", "0:45"},
	{"記者会見 ダイジェスト", "タイトル戦の記者会見から、意気込みを語る場面をお届けします。", "0:52"},
	{"早朝ロードワーク密着", "夜明け前の河川敷でのロードワークに密着しました。", "0:38"},
	{"計量後インタビュー", "計量をパスした直後の表情とコメントです。", "0:41"},
	{"試合前日の最終調整", "試合前日、ジムでの最終調整の様子です。", "0:36"},
}

// publish renders the unused clips, or has them edited outside the
// engine, and publishes the result.
func (w *World) publish(sc scene, ops []studio.Op, otherApp bool) error {
	if len(w.clips) == 0 {
		if err := w.shoot(); err != nil {
			return err
		}
	}
	var video []byte
	var err error
	if otherApp {
		video = studio.Video("edited in another app")
	} else if video, err = w.studio.Render(w.recipe, w.clips, ops); err != nil {
		return err
	}
	w.clips = nil
	w.log.Clock.Advance(time.Hour)
	n := len(w.videos) + 1
	index, err := w.studio.Publish(video, fmt.Sprintf("https://fanclub.asagiri.example/videos/%d", n), sc.title)
	if err != nil {
		return err
	}
	receipt, err := w.log.Receipt(index)
	if err != nil {
		return err
	}
	w.videos = append(w.videos, &Video{N: n, Title: sc.title, Desc: sc.desc, Date: w.log.Clock.Now(), Duration: sc.duration, Index: index, Receipt: receipt})
	if err := w.checkpoint(); err != nil {
		return err
	}
	// The next action happens the next morning.
	now := w.log.Clock.Now()
	w.log.Clock.Advance(time.Date(now.Year(), now.Month(), now.Day()+1, 9, 0, 0, 0, time.UTC).Sub(now))
	return nil
}

func (w *World) next() scene {
	return scenes[len(w.videos)%len(scenes)]
}

// PublishAsDeclared shoots, renders under the recipe and publishes.
func (w *World) PublishAsDeclared() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.publish(w.next(), edits, false)
}

// PublishGenerated has the engine add a scene the footage does not
// contain. The engine reports it, as it reports every operation.
func (w *World) PublishGenerated() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	sc := w.next()
	sc.title += "（会場の熱気）"
	ops := append(edits[:len(edits):len(edits)], studio.Op{Kind: studio.Generate, Detail: "満員の観客席と歓声をAIで生成"})
	return w.publish(sc, ops, false)
}

// PublishOtherApp publishes a video edited in another app, without the
// engine.
func (w *World) PublishOtherApp() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	sc := w.next()
	sc.title += "（特別編集）"
	return w.publish(sc, nil, true)
}

// checkpoint has the witnesses cosign the chain. After the fan club
// rewrote its chain, they refuse, and it can only publish a checkpoint
// signed by itself.
func (w *World) checkpoint() error {
	if !w.tampered {
		_, err := w.log.Checkpoint(context.Background(), w.witnesses...)
		return err
	}
	_, err := w.log.Checkpoint(context.Background())
	return err
}

// Tamper has the fan club rewrite its chain without the records of the
// videos that break the recipe, and publish the result.
func (w *World) Tamper() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	entries, _, err := demo.Open(w.log.Chain(), w.log.Latest(), w.log.OperatorKey(), nil, 0)
	if err != nil {
		return err
	}
	drop := make(map[int]bool)
	for _, f := range studio.Check(entries, w.body, w.engineKey) {
		e := entries[f.Line-1]
		drop[f.Line] = true
		// Also the publication of a video whose render was dropped.
		if out := e.Meta["output"]; out != "" {
			for _, p := range entries {
				if p.Subject.Digest["sha256"] == out && p.Meta["event"] == "published" {
					drop[p.Line] = true
				}
			}
		}
	}
	line := 0
	if err := w.log.Rewrite(func(core.Record) bool { line++; return !drop[line] }); err != nil {
		return err
	}
	w.tampered = true
	return w.checkpoint()
}

// body returns the bodies the fan club publishes: its recipe and the
// engine's statements. Clips and videos are not served by digest.
func (w *World) body(digest string) ([]byte, bool) {
	b, ok := w.log.Body(digest)
	if !ok {
		return nil, false
	}
	if _, err := studio.ParseStatement(b, w.engineKey); err == nil || digest == "sha256:"+w.recipe {
		return b, true
	}
	return nil, false
}

// Evidence serves a published body by digest.
func (w *World) Evidence(digest string) ([]byte, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.body(digest)
}

// Videos returns the videos on the site, newest first.
func (w *World) Videos() []Video {
	w.mu.Lock()
	defer w.mu.Unlock()
	var vs []Video
	for i := len(w.videos) - 1; i >= 0; i-- {
		vs = append(vs, *w.videos[i])
	}
	return vs
}

// Now returns the simulated time.
func (w *World) Now() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.log.Clock.Now()
}

// Published returns what the fan club publishes for anyone to check: its
// latest checkpoint and its chain (records hold only digests).
func (w *World) Published() (checkpoint, chain []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.log.Latest(), w.log.Chain()
}

// Keys returns the public keys a verifier needs.
func (w *World) Keys() (operator, receipts, engine *core.Verifier, witnesses []*core.Verifier) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.log.OperatorKey(), w.log.ReceiptKey(), w.engineKey, demo.Keys(w.witnesses)
}
