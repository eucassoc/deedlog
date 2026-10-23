package main

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestStory(t *testing.T) {
	world, err := NewWorld()
	if err != nil {
		t.Fatal(err)
	}
	defer world.Close()
	s := &site{world: world, verifyURL: "http://verify.invalid"}
	city := httptest.NewServer(s.city())
	defer city.Close()
	s.cityURL = city.URL
	v := &Verifier{CityURL: city.URL, Keys: world.Keys, News: func() time.Time { return world.State().BreachAt }}

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

	// The city keeps its promise; the breach comes after the inquiry left
	// the form service.
	_, receipt, err := world.Submit("山田 花子", "hanako@example.com", "質問")
	if err != nil {
		t.Fatal(err)
	}
	check(receipt, "pending")
	if err := world.Advance(7); err != nil {
		t.Fatal(err)
	}
	world.Breach()
	if st := check(receipt, "ok"); st.Breach == nil || st.Breach.Kind != "ok" || st.City.Kind != "ok" {
		t.Fatalf("breach %+v, city %+v", st.Breach, st.City)
	}
	if err := world.Advance(31); err != nil {
		t.Fatal(err)
	}
	if st := check(receipt, "ok"); !strings.Contains(st.Headline, "削除") {
		t.Fatalf("headline %q", st.Headline)
	}

	// The transfer job is broken when the breach comes.
	if err := world.Reset(); err != nil {
		t.Fatal(err)
	}
	_, receipt, err = world.Submit("佐藤 一郎", "ichiro@example.com", "依頼")
	if err != nil {
		t.Fatal(err)
	}
	world.SetTransferDown(true)
	if err := world.Advance(9); err != nil {
		t.Fatal(err)
	}
	world.Breach()
	if st := check(receipt, "warning"); st.Breach == nil || st.Breach.Kind != "bad" || st.City.Kind != "bad" {
		t.Fatalf("breach %+v, city %+v", st.Breach, st.City)
	}

	// The city rewrites its chain to hide it.
	if err := world.Tamper(); err != nil {
		t.Fatal(err)
	}
	if st := check(receipt, "tampered"); st.Proof == "" {
		t.Fatal("no proof of misbehavior")
	}
}
