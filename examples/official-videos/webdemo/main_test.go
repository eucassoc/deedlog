package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStory(t *testing.T) {
	world, err := NewWorld()
	if err != nil {
		t.Fatal(err)
	}
	defer world.Close()
	s := &site{world: world, verifyURL: "http://verify.invalid"}
	club := httptest.NewServer(s.club())
	defer club.Close()
	s.clubURL = club.URL
	v := &Verifier{ClubURL: club.URL, Keys: world.Keys}

	check := func(receipt []byte, verdict string) *Status {
		t.Helper()
		st, err := v.Check(receipt)
		if err != nil {
			t.Fatal(err)
		}
		if st.Verdict != verdict {
			t.Fatalf("verdict %q, want %q: %+v", st.Verdict, verdict, st)
		}
		return st
	}
	latest := func() []byte { return world.Videos()[0].Receipt }

	// The video already on the site, and one more, keep to the recipe.
	first := latest()
	if st := check(first, "ok"); len(st.Steps) != 6 || st.Club.Kind != "ok" {
		t.Fatalf("steps %+v, club %+v", st.Steps, st.Club)
	}
	if err := world.PublishAsDeclared(); err != nil {
		t.Fatal(err)
	}
	check(latest(), "ok")

	// A scene the footage lacks shows in the engine's own statement.
	if err := world.PublishGenerated(); err != nil {
		t.Fatal(err)
	}
	generated := latest()
	if st := check(generated, "warning"); !strings.Contains(st.Detail, "AIによる場面の生成") || st.Club.Kind != "bad" {
		t.Fatalf("detail %q, club %+v", st.Detail, st.Club)
	}
	check(first, "ok")

	// A video edited outside the engine has no record of how it was made.
	if err := world.PublishOtherApp(); err != nil {
		t.Fatal(err)
	}
	check(latest(), "bad")

	// The fan club rewrites its chain to hide both.
	if err := world.Tamper(); err != nil {
		t.Fatal(err)
	}
	if st := check(generated, "tampered"); st.Proof == "" {
		t.Fatal("no proof of misbehavior")
	}
	check(first, "tampered")

	if err := world.Reset(); err != nil {
		t.Fatal(err)
	}
	if len(world.Videos()) != 1 {
		t.Fatalf("%d videos after reset", len(world.Videos()))
	}
}
