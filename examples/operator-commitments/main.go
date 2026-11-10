// Command operator-commitments runs the verifiable operator commitments use
// case: a city's cameras record every segment, published software counts
// people, footage is deleted after the retention period, and anyone can
// check the chain against the published commitment.
//
//	go run ./examples/operator-commitments [-out DIR]
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/eucassoc/deedlog/examples/internal/demo"
)

const origin = "city.example/cameras"

var (
	counter    = Software{Name: "people-counter 1.4.0", Digest: demo.Sum([]byte("people-counter 1.4.0")), Source: "https://code.city.example/people-counter/releases/1.4.0"}
	unreleased = Software{Name: "people-counter 1.4.1-hotfix", Digest: demo.Sum([]byte("people-counter 1.4.1-hotfix"))}

	commitment = Commitment{
		Cameras:        []string{"station-north", "station-south"},
		SegmentSeconds: 60,
		RetentionHours: 6,
		Software:       []Software{counter},
		Outputs:        []string{"people-count"},
	}
)

// scenario describes what the operator does differently from its promise.
type scenario struct {
	name string
	// Minutes of the day during which station-south's segments are not
	// recorded.
	unrecorded [2]int
	// Minutes during which an unpublished build processes footage.
	unreleased [2]int
	// Minute at which a run produces a face match, or 0.
	faceMatch int
	// Hour from which the retention job stops running, or 0.
	retentionStops int
}

func in(m int, r [2]int) bool { return m >= r[0] && m < r[1] }

type result struct {
	log        *demo.Log
	witnesses  []*demo.Witness
	checkpoint []byte
	findings   demo.Findings
}

func closeAll(r *result) { demo.CloseAll(r.witnesses) }

func run(sc scenario, hours int) (*result, error) {
	ctx := context.Background()
	l, ws, err := demo.Start(origin, time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), "witness.privacy-office.city.example", "witness.residents.example")
	if err != nil {
		return nil, err
	}
	res := &result{log: l, witnesses: ws}
	rec := &Recorder{Log: l}
	if err := rec.Declare(commitment); err != nil {
		return res, err
	}
	storage := &Storage{}
	var cameras []*Camera
	for _, id := range commitment.Cameras {
		cameras = append(cameras, &Camera{ID: id})
	}

	for m := 0; m < hours*60; m++ {
		l.Clock.Advance(time.Minute)
		for _, cam := range cameras {
			record := !(cam.ID == "station-south" && in(m, sc.unrecorded))
			footage, err := cam.Capture(rec, storage, record)
			if err != nil {
				return res, err
			}
			sw, kind := counter, "people-count"
			if in(m, sc.unreleased) {
				sw = unreleased
			}
			if sc.faceMatch != 0 && m == sc.faceMatch && cam.ID == "station-north" {
				kind = "face-match"
			}
			if err := rec.Processed(sw, kind, footage, Count(footage)); err != nil {
				return res, err
			}
		}
		if m%10 == 9 && (sc.retentionStops == 0 || m < sc.retentionStops*60) {
			// Every 10 minutes, with a margin so nothing outlives retention.
			cutoff := l.Clock.Now().Add(-time.Duration(commitment.RetentionHours)*time.Hour + 15*time.Minute)
			if err := storage.Expire(cutoff, rec); err != nil {
				return res, err
			}
		}
		if m%60 == 59 {
			if res.checkpoint, err = l.Checkpoint(ctx, ws...); err != nil {
				return res, err
			}
		}
	}

	// Anyone's side: the published commitment, the chain and a checkpoint
	// cosigned by both witnesses.
	published, _ := json.Marshal(commitment)
	entries, _, err := demo.Open(l.Chain(), res.checkpoint, l.OperatorKey(), demo.Keys(ws), len(ws))
	if err != nil {
		return res, err
	}
	res.findings = Check(entries, published)
	return res, nil
}

func main() {
	out := flag.String("out", "", "directory for the chains, checkpoints and keys (default: a new temporary directory)")
	flag.Parse()
	dir, err := demo.OutDir(*out, "operator-commitments")
	if err != nil {
		log.Fatal(err)
	}
	scenarios := []scenario{
		{name: "as promised"},
		{
			name:           "breaking the promise",
			unrecorded:     [2]int{13 * 60, 13*60 + 20},
			unreleased:     [2]int{15 * 60, 15*60 + 30},
			faceMatch:      16 * 60,
			retentionStops: 18,
		},
	}
	for i, sc := range scenarios {
		res, err := run(sc, 24)
		if err != nil {
			log.Fatal(err)
		}
		demo.Header(os.Stdout, sc.name, res.log, res.witnesses)
		res.findings.Print(os.Stdout)
		if err := demo.Save(os.Stdout, filepath.Join(dir, fmt.Sprint(i+1)), res.log, res.witnesses); err != nil {
			log.Fatal(err)
		}
		demo.CloseAll(res.witnesses)
	}
}
