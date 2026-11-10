// Command official-videos runs the official videos use case: footage is
// registered as it is shot, a rendering engine edits it under a published
// recipe and signs what it did, the official account publishes the result,
// and anyone checks each video against the recipe.
//
//	go run ./examples/official-videos [-out DIR]
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/eucassoc/deedlog/core"
	"github.com/eucassoc/deedlog/examples/internal/demo"
	"github.com/eucassoc/deedlog/examples/official-videos/studio"
)

const (
	origin     = "fanclub.example/official-videos"
	engineName = "engine.studio.example"
)

// recipe allows only edits that keep to the footage: trimming, cropping,
// joining clips, and adding the club's logo, jingle and music.
func recipe() studio.Recipe {
	return studio.Recipe{
		Name:    "highlights-v1",
		Allowed: []string{studio.Trim, studio.Crop, studio.Concat, studio.Music, studio.Logo},
		Assets:  map[string]string{"logo.png": demo.Sum([]byte("logo")), "jingle.wav": demo.Sum([]byte("jingle")), "bgm-01.mp3": demo.Sum([]byte("bgm-01"))},
	}
}

var edits = []studio.Op{
	{Kind: studio.Trim, Detail: "best 8 seconds of each clip"},
	{Kind: studio.Crop, Detail: "9:16, face kept in frame"},
	{Kind: studio.Concat},
	{Kind: studio.Music, Detail: "bgm-01.mp3"},
	{Kind: studio.Logo, Detail: "logo.png, jingle.wav"},
}

// scenario describes what goes wrong, if anything, on given days.
type scenario struct {
	name string
	// Day on which the engine is asked to add a scene the footage lacks.
	generate int
	// Day on which a video edited in another app is published.
	otherApp int
	// Day on which a clip from outside the shoot is used.
	unregistered int
	// Day on which the account signs a statement itself, not the engine.
	forged int
}

type result struct {
	log        *demo.Log
	witnesses  []*demo.Witness
	engine     *core.Verifier
	checkpoint []byte
	receipt    []byte // for the first video
	findings   demo.Findings
}

func (r *result) close() { demo.CloseAll(r.witnesses) }

func run(sc scenario, days int) (*result, error) {
	ctx := context.Background()
	l, ws, err := demo.Start(origin, time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC), "witness.fan-council.example", "witness.auditor.example")
	if err != nil {
		return nil, err
	}
	engine, engineKey, err := studio.NewEngine(engineName)
	if err != nil {
		return nil, err
	}
	res := &result{log: l, witnesses: ws, engine: engineKey}
	st := &studio.Studio{Log: l, Engine: engine}
	clock := l.Clock

	rd, err := st.Declare(recipe())
	if err != nil {
		return res, err
	}
	for day := 1; day <= days; day++ {
		// The shoot: each clip is registered as it comes off the camera.
		var clips [][]byte
		for i := range 4 {
			clip := studio.Video(fmt.Sprintf("clip %d of day %d", i+1, day))
			if err := st.Register(clip, fmt.Sprintf("cam-%d", i%2+1), clock.Now()); err != nil {
				return res, err
			}
			clips = append(clips, clip)
			clock.Advance(20 * time.Minute)
		}
		clock.Advance(3 * time.Hour)

		// Editing and publication.
		var video []byte
		ops := edits
		switch day {
		case sc.otherApp:
			video = studio.Video("edited in another app")
		case sc.forged:
			fake, _, err := studio.NewEngine(engineName)
			if err != nil {
				return res, err
			}
			var statement []byte
			if video, statement, err = fake.Render(rd, clips[:3], ops); err != nil {
				return res, err
			}
			if err := st.RecordStatement(statement, demo.Sum(video), rd); err != nil {
				return res, err
			}
		default:
			in := clips[:3]
			if day == sc.unregistered {
				in = append([][]byte{studio.Video("stock footage")}, clips[:2]...)
			}
			if day == sc.generate {
				ops = append(ops[:len(ops):len(ops)], studio.Op{Kind: studio.Generate, Detail: "crowd scene added"})
			}
			if video, err = st.Render(rd, in, ops); err != nil {
				return res, err
			}
		}
		clock.Advance(time.Hour)
		index, err := st.Publish(video, fmt.Sprintf("https://fanclub.example/videos/%d", day), fmt.Sprintf("Day %d highlights", day))
		if err != nil {
			return res, err
		}
		if res.receipt == nil {
			if res.receipt, err = l.Receipt(index); err != nil {
				return res, err
			}
		}
		if res.checkpoint, err = l.Checkpoint(ctx, ws...); err != nil {
			return res, err
		}
		clock.Advance(19 * time.Hour)
	}

	// Anyone's side: the chain, the checkpoint, the published recipe and
	// statements, and the engine's public key.
	entries, _, err := demo.Open(l.Chain(), res.checkpoint, l.OperatorKey(), demo.Keys(ws), len(ws))
	if err != nil {
		return res, err
	}
	res.findings = studio.Check(entries, l.Body, engineKey)
	return res, nil
}

// followReceipt is what a fan can do with the link next to a video: check
// that the account's promise holds and see how the video was made.
func followReceipt(w io.Writer, res *result) error {
	l := res.log
	r, err := core.VerifyReceipt(res.receipt, l.ReceiptKey())
	if err != nil {
		return err
	}
	c, err := core.CheckpointOf(res.checkpoint)
	if err != nil {
		return err
	}
	leaf, proof, err := l.Proof(r.Index, c.Size)
	if err != nil {
		return err
	}
	status, _, err := core.CheckReceipt(res.receipt, r, res.checkpoint, c, leaf, proof)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "  receipt for record %d: %s in the witnessed checkpoint of size %d\n", r.Index, status, c.Size)

	entries, _, err := demo.Open(l.Chain(), res.checkpoint, l.OperatorKey(), nil, 0)
	if err != nil {
		return err
	}
	rd, err := studio.Trace(entries, l.Body, res.engine, r.Index)
	if err != nil {
		return err
	}
	if rd == nil {
		fmt.Fprintln(w, "  the engine did not render this video")
		return nil
	}
	at := func(e demo.Entry) string { return e.CollectedAt.Format("2006-01-02 15:04") }
	if rd.Recipe != nil {
		fmt.Fprintf(w, "  %s  recipe %q declared: %s (line %d)\n", at(entries[rd.RecipeLine-1]), rd.Recipe.Name, strings.Join(rd.Recipe.Allowed, ", "), rd.RecipeLine)
	}
	for _, c := range rd.Clips {
		fmt.Fprintf(w, "  %s  clip registered from %s (line %d)\n", at(c), c.Meta["camera"], c.Line)
	}
	var ops []string
	for _, op := range rd.Statement.Ops {
		ops = append(ops, op.Kind)
	}
	fmt.Fprintf(w, "  %s  rendered by %s: %s (line %d)\n", at(rd.Entry), res.engine.Name(), strings.Join(ops, ", "), rd.Entry.Line)
	pub := entries[r.Index]
	fmt.Fprintf(w, "  %s  published at %s (line %d)\n", at(pub), pub.Meta["url"], pub.Line)
	for _, p := range rd.Problems {
		fmt.Fprintf(w, "  problem: %s\n", p)
	}
	return nil
}

func main() {
	out := flag.String("out", "", "directory for the chains, checkpoints and keys (default: a new temporary directory)")
	flag.Parse()
	dir, err := demo.OutDir(*out, "official-videos")
	if err != nil {
		log.Fatal(err)
	}

	scenarios := []scenario{
		{name: "as declared"},
		{name: "with failures", generate: 2, otherApp: 3, unregistered: 4, forged: 5},
	}
	for i, sc := range scenarios {
		res, err := run(sc, 5)
		if err != nil {
			log.Fatal(err)
		}
		demo.Header(os.Stdout, sc.name, res.log, res.witnesses)
		res.findings.Print(os.Stdout)
		if i == 0 {
			fmt.Println("\n  The receipt next to the first video, followed:")
			if err := followReceipt(os.Stdout, res); err != nil {
				log.Fatal(err)
			}
		}
		sub := filepath.Join(dir, fmt.Sprint(i+1))
		if err := demo.Save(os.Stdout, sub, res.log, res.witnesses); err != nil {
			log.Fatal(err)
		}
		if err := demo.SaveReceipt(sub, res.receipt); err != nil {
			log.Fatal(err)
		}
		res.close()
	}
}
