package studio

import (
	"fmt"
	"slices"

	"github.com/eucassoc/deedlog/core"
	"github.com/eucassoc/deedlog/examples/internal/demo"
)

// Body returns a published evidence body by its digest ("sha256:<hex>").
// Recipes and render statements are published; clips and videos need not
// be.
type Body func(digest string) ([]byte, bool)

// Render is a verified render: its record, the engine's statement, and
// what is wrong with it.
type Render struct {
	Entry     demo.Entry
	Statement Statement
	Recipe    *Recipe
	// RecipeLine is the line of the recipe's declaration, or 0.
	RecipeLine int
	Clips      []demo.Entry
	Problems   demo.Findings
}

type state struct {
	engine  *core.Verifier
	body    Body
	recipes map[string]demo.Entry
	recipe  map[string]*Recipe
	clips   map[string]demo.Entry
	renders map[string]*Render
	fs      demo.Findings
}

func newState(body Body, engine *core.Verifier) *state {
	return &state{engine: engine, body: body, recipes: make(map[string]demo.Entry), recipe: make(map[string]*Recipe),
		clips: make(map[string]demo.Entry), renders: make(map[string]*Render)}
}

func (s *state) add(e demo.Entry) {
	digest := e.Subject.Digest["sha256"]
	switch e.Meta["event"] {
	case "recipe":
		b, ok := s.body("sha256:" + digest)
		if !ok {
			s.fs.Add(e.Line, "the recipe %q is not published", e.Meta["name"])
			return
		}
		var r Recipe
		if err := demo.Declared(e, b, &r); err != nil {
			s.fs.Add(e.Line, "recipe: %v", err)
			return
		}
		s.recipes[digest], s.recipe[digest] = e, &r
	case "registered":
		if _, seen := s.clips[digest]; !seen {
			s.clips[digest] = e
		}
	case "rendered":
		s.render(e, digest)
	case "published":
		if _, ok := s.renders[digest]; !ok {
			s.fs.Add(e.Line, "published a video that the engine did not render")
		}
	default:
		s.fs.Add(e.Line, "unknown event %q", e.Meta["event"])
	}
}

func (s *state) render(e demo.Entry, digest string) {
	b, ok := s.body("sha256:" + digest)
	if !ok || demo.Sum(b) != digest {
		s.fs.Add(e.Line, "the render statement is not published")
		return
	}
	st, err := ParseStatement(b, s.engine)
	if err != nil {
		s.fs.Add(e.Line, "render statement not signed by the engine %s: %v", s.engine.Name(), err)
		return
	}
	r := &Render{Entry: e, Statement: st}
	problem := func(format string, args ...any) {
		r.Problems.Add(e.Line, format, args...)
		s.fs.Add(e.Line, format, args...)
	}
	if d, ok := s.recipes[st.Recipe]; ok {
		r.Recipe, r.RecipeLine = s.recipe[st.Recipe], d.Line
	} else {
		problem("rendered under a recipe that was never declared")
	}
	for i, in := range st.Inputs {
		if c, ok := s.clips[in]; ok {
			r.Clips = append(r.Clips, c)
		} else {
			problem("input %d is footage that was never registered", i+1)
		}
	}
	if r.Recipe != nil {
		for _, op := range st.Ops {
			if !slices.Contains(r.Recipe.Allowed, op.Kind) {
				problem("operation %q (%s) is not allowed by recipe %q at line %d", op.Kind, op.Detail, r.Recipe.Name, r.RecipeLine)
			}
		}
	}
	s.renders[st.Output] = r
}

// Check checks an official account's verified chain: every published video
// was rendered by the engine, from registered footage, with only the
// operations its declared recipe allows.
func Check(entries []demo.Entry, body Body, engine *core.Verifier) demo.Findings {
	s := newState(body, engine)
	for _, e := range entries {
		s.add(e)
	}
	return s.fs.Sorted()
}

// Trace follows the published video at index back through its render to
// its recipe and footage. It returns nil if the video was not rendered by
// the engine.
func Trace(entries []demo.Entry, body Body, engine *core.Verifier, index uint64) (*Render, error) {
	if index >= uint64(len(entries)) || entries[index].Meta["event"] != "published" {
		return nil, fmt.Errorf("record %d is not a published video", index)
	}
	s := newState(body, engine)
	for _, e := range entries[:index+1] {
		s.add(e)
	}
	return s.renders[entries[index].Subject.Digest["sha256"]], nil
}
