package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/eucassoc/deedlog/core"
	"github.com/eucassoc/deedlog/examples/internal/demo"
)

// Commitment is what the operator promises in public. It is published and
// recorded as the first entry of the chain.
type Commitment struct {
	Cameras        []string   `json:"cameras"`
	SegmentSeconds int        `json:"segment_seconds"`
	RetentionHours int        `json:"retention_hours"`
	Software       []Software `json:"software"`
	// Outputs are the only kinds of output processing may produce.
	Outputs []string `json:"outputs"`
}

// Software identifies a published build of the processing software.
type Software struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
	Source string `json:"source"`
}

func src(typ, id string) core.Source {
	return core.Source{Type: typ, ID: id, Collector: "examples/operator-commitments"}
}

// Recorder is the integration point. The camera gateway, the processing
// pipeline and the storage's retention job call it.
type Recorder struct {
	Log *demo.Log
}

// Declare records the commitment. It must be the first record.
func (r *Recorder) Declare(c Commitment) error {
	body, err := json.Marshal(c)
	if err != nil {
		return err
	}
	_, err = r.Log.Append(demo.Event{Source: src("operator", "operator"), MediaType: "application/json", Body: body,
		Meta: map[string]string{"event": "commitment"}})
	return err
}

// Segment records a footage segment as it is captured. Only its digest
// enters the chain; the footage stays in storage.
func (r *Recorder) Segment(camera string, seq uint64, footage []byte) error {
	_, err := r.Log.Append(demo.Event{Source: src("camera", camera), MediaType: "video/mp4", Body: footage,
		Meta: map[string]string{"event": "segment", "camera": camera, "seq": strconv.FormatUint(seq, 10)}})
	return err
}

// Processed records one processing run: which software ran on which
// segment, and what it produced.
func (r *Recorder) Processed(sw Software, kind string, input, output []byte) error {
	_, err := r.Log.Append(demo.Event{Source: src("edge", sw.Name), MediaType: "application/json", Body: output,
		Meta: map[string]string{"event": "processed", "software": sw.Digest, "input": demo.Sum(input), "output": kind}})
	return err
}

// Deleted records the deletion of a segment.
func (r *Recorder) Deleted(footage []byte) error {
	_, err := r.Log.Append(demo.Event{Source: src("storage", "footage"), MediaType: "video/mp4", Body: footage,
		Meta: map[string]string{"event": "deleted"}})
	return err
}

// Storage keeps footage until the retention job deletes it.
type Storage struct {
	mu       sync.Mutex
	segments map[string]stored
}

type stored struct {
	footage []byte
	at      time.Time
}

func (s *Storage) put(footage []byte, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.segments == nil {
		s.segments = make(map[string]stored)
	}
	s.segments[demo.Sum(footage)] = stored{footage, at}
}

// Expire deletes segments captured before cutoff, recording each deletion.
func (s *Storage) Expire(cutoff time.Time, r *Recorder) error {
	s.mu.Lock()
	var due []stored
	for k, v := range s.segments {
		if v.at.Before(cutoff) {
			due = append(due, v)
			delete(s.segments, k)
		}
	}
	s.mu.Unlock()
	sort.Slice(due, func(i, j int) bool { return due[i].at.Before(due[j].at) })
	for _, v := range due {
		if err := r.Deleted(v.footage); err != nil {
			return err
		}
	}
	return nil
}

// Camera stands in for a camera and its gateway: every segment is stored
// and recorded with the camera's own sequence number.
type Camera struct {
	ID  string
	seq uint64
}

// Capture produces the next segment.
func (c *Camera) Capture(r *Recorder, s *Storage, record bool) ([]byte, error) {
	c.seq++
	footage := fmt.Appendf(nil, "%s segment %d", c.ID, c.seq)
	s.put(footage, r.Log.Clock.Now())
	if !record {
		return footage, nil
	}
	return footage, r.Segment(c.ID, c.seq, footage)
}

// Count stands in for the published people-counting software. Its output
// is an aggregate and identifies no one.
func Count(footage []byte) []byte {
	return fmt.Appendf(nil, `{"people":%d}`, len(footage)%7)
}
