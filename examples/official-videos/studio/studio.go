// Package studio is where the calls go when an official video is produced:
// footage is registered as it is shot, a published recipe says which edits
// are allowed, a rendering engine edits the footage and signs a statement of
// what it did, and the official account publishes the result.
package studio

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/eucassoc/deedlog/core"
	"github.com/eucassoc/deedlog/examples/internal/demo"
)

// Recipe is the published editing rule: the operations the engine may
// apply and the assets (logos, jingles, music) it may add. Nothing else
// may appear in an official video but the registered footage.
type Recipe struct {
	Name    string   `json:"name"`
	Allowed []string `json:"allowed"`
	// Assets are the files the engine may add, by name, with their SHA-256.
	Assets map[string]string `json:"assets,omitempty"`
}

// Operations an engine reports. Generate is never in a recipe for official
// videos: it stands for anything that creates a scene the footage does not
// contain.
const (
	Trim     = "trim"
	Crop     = "crop"
	Concat   = "concat"
	Music    = "music"
	Logo     = "logo"
	Generate = "generate"
)

// Op is one operation the engine applied.
type Op struct {
	Kind   string `json:"op"`
	Detail string `json:"detail,omitempty"`
}

// Statement is what the engine signs for each video it renders. It holds
// digests only, so it can be published.
type Statement struct {
	Recipe string   `json:"recipe"` // SHA-256 of the recipe
	Inputs []string `json:"inputs"` // SHA-256 of each clip
	Ops    []Op     `json:"ops"`
	Output string   `json:"output"` // SHA-256 of the video
}

// statementHeader is the first line of the signed statement. Source
// signatures in records are planned in the specification; until then the
// engine signs its statements as signed notes, which are the evidence
// bodies.
const statementHeader = "sample-render-statement/v1"

func (s Statement) text() []byte {
	b, _ := json.Marshal(s)
	return fmt.Appendf(nil, "%s\n%s\n", statementHeader, b)
}

// ParseStatement opens a signed statement with the engine's key.
func ParseStatement(note []byte, engine *core.Verifier) (Statement, error) {
	text, _, err := core.OpenNote(note, []*core.Verifier{engine})
	if err != nil {
		return Statement{}, err
	}
	head, body, ok := bytes.Cut(text, []byte("\n"))
	if !ok || string(head) != statementHeader {
		return Statement{}, errors.New("not a render statement")
	}
	var s Statement
	if err := json.Unmarshal(body, &s); err != nil {
		return Statement{}, fmt.Errorf("render statement: %w", err)
	}
	return s, nil
}

// Engine renders videos and signs what it did with its own key. It is run
// by a party other than the official account, so that its statements are
// not the account's own word.
type Engine struct {
	key *core.Signer
}

// NewEngine creates an engine and returns its public key for the registry.
func NewEngine(name string) (*Engine, *core.Verifier, error) {
	skey, _, err := core.GenerateKey(name)
	if err != nil {
		return nil, nil, err
	}
	s, err := core.NewSigner(skey)
	if err != nil {
		return nil, nil, err
	}
	return &Engine{key: s}, s.Verifier(), nil
}

// Render edits the clips with the given operations and returns the video
// and the signed statement. The engine reports every operation it applied,
// including those the recipe does not allow; checking them is the
// verifier's job.
func (e *Engine) Render(recipe string, clips [][]byte, ops []Op) (video, statement []byte, err error) {
	s := Statement{Recipe: recipe, Ops: ops}
	for _, c := range clips {
		s.Inputs = append(s.Inputs, demo.Sum(c))
	}
	video = Video(fmt.Sprintf("rendered from %d clips with %d operations", len(clips), len(ops)))
	s.Output = demo.Sum(video)
	statement, err = e.key.Sign(s.text())
	return video, statement, err
}

// Video returns a stand-in for a video file: unique bytes with a label. A
// real engine produces an MP4; only its digest is recorded.
func Video(label string) []byte {
	nonce := make([]byte, 16)
	rand.Read(nonce)
	return fmt.Appendf(nil, "sample-video\n%s\n%x\n", label, nonce)
}

// Studio is the official account's side: it records each step in its
// chain. Clip and video files stay with the account; the recipe and the
// engine's statements are published with the chain.
type Studio struct {
	Log    *demo.Log
	Engine *Engine
}

func (s *Studio) append(event, mediaType string, body []byte, meta map[string]string) (uint64, error) {
	meta["event"] = event
	return s.Log.Append(demo.Event{
		Source:    core.Source{Type: "studio", ID: event, Collector: "examples/official-videos"},
		MediaType: mediaType, Body: body, Meta: meta,
	})
}

// Declare publishes a recipe and records it. It returns the recipe's
// digest, which renders refer to.
func (s *Studio) Declare(r Recipe) (string, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	_, err = s.append("recipe", "application/json", b, map[string]string{"name": r.Name})
	return demo.Sum(b), err
}

// Register records a clip as it comes off the camera.
func (s *Studio) Register(clip []byte, camera string, shotAt time.Time) error {
	_, err := s.append("registered", "video/mp4", clip, map[string]string{"camera": camera, "shot_at": shotAt.UTC().Format(time.RFC3339)})
	return err
}

// Render has the engine edit registered clips under a recipe, and records
// the engine's signed statement.
func (s *Studio) Render(recipe string, clips [][]byte, ops []Op) ([]byte, error) {
	video, statement, err := s.Engine.Render(recipe, clips, ops)
	if err != nil {
		return nil, err
	}
	return video, s.RecordStatement(statement, demo.Sum(video), recipe)
}

// RecordStatement records a signed render statement as received.
func (s *Studio) RecordStatement(statement []byte, output, recipe string) error {
	_, err := s.append("rendered", "text/plain; charset=utf-8", statement, map[string]string{"output": output, "recipe": recipe})
	return err
}

// Publish records the publication of a video and returns its index, for
// the receipt shown next to the video.
func (s *Studio) Publish(video []byte, url, title string) (uint64, error) {
	return s.append("published", "video/mp4", video, map[string]string{"url": url, "title": title})
}
