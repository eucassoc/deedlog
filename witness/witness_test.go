package witness

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eucassoc/deedlog/core"
)

const origin = "city.example/cameras"

type fixture struct {
	signer   *core.Signer
	operator *core.Verifier
	witness  Witness
	server   *Server
	client   *Client
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	skey, vkey, err := core.GenerateKey(origin)
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := core.NewSigner(skey)
	operator, _ := core.NewVerifier(vkey)
	wskey, wvkey, err := core.GenerateWitnessKey("witness.example/w1")
	if err != nil {
		t.Fatal(err)
	}
	wsigner, err := core.NewSigner(wskey)
	if err != nil {
		t.Fatal(err)
	}
	wkey, err := core.NewVerifier(wvkey)
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{Signer: wsigner, Logs: map[string]*core.Verifier{origin: operator}, Store: &MemoryStore{},
		Now: func() time.Time { return time.Unix(1_800_000_000, 0) }}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return &fixture{signer: signer, operator: operator, witness: Witness{Key: wkey, URL: ts.URL + "/witness/"},
		server: srv, client: &Client{HTTP: ts.Client()}}
}

func leaves(n int, variant string) []core.Hash {
	hs := make([]core.Hash, n)
	for i := range hs {
		hs[i] = core.LeafHash(fmt.Appendf(nil, "record %d", i))
		if variant != "" && i >= 2 {
			hs[i] = core.LeafHash(fmt.Appendf(nil, "%s record %d", variant, i))
		}
	}
	return hs
}

func (f *fixture) sign(t *testing.T, ls []core.Hash) []byte {
	t.Helper()
	note, err := core.SignCheckpoint(core.Checkpoint{Origin: origin, Size: uint64(len(ls)), Root: core.Root(ls)}, f.signer)
	if err != nil {
		t.Fatal(err)
	}
	return note
}

func (f *fixture) cosign(t *testing.T, ls []core.Hash, oldSize uint64) ([]byte, error) {
	t.Helper()
	return f.client.Cosign(context.Background(), f.witness, f.sign(t, ls), ls, f.operator, oldSize)
}

func TestCosignGrowingChain(t *testing.T) {
	f := newFixture(t)
	for _, n := range []int{3, 3, 8, 21} {
		// The client starts from 0 every time; the witness answers 409 with
		// its size and the client retries with a consistency proof.
		cosigned, err := f.cosign(t, leaves(n, ""), 0)
		if err != nil {
			t.Fatalf("size %d: %v", n, err)
		}
		c, err := core.VerifyCheckpoint(cosigned, f.operator, []*core.Verifier{f.witness.Key}, 1)
		if err != nil {
			t.Fatalf("size %d: %v", n, err)
		}
		if c.Size != uint64(n) {
			t.Fatalf("size %d: cosigned size %d", n, c.Size)
		}
	}
}

func TestCosignRejectsRewrittenHistory(t *testing.T) {
	f := newFixture(t)
	if _, err := f.cosign(t, leaves(5, ""), 0); err != nil {
		t.Fatal(err)
	}
	_, err := f.cosign(t, leaves(9, "rewritten"), 0)
	if !errors.Is(err, ErrInconsistent) {
		t.Fatalf("err = %v, want ErrInconsistent", err)
	}
	// Same size, different root.
	_, err = f.cosign(t, leaves(5, "forked"), 5)
	if !errors.Is(err, ErrInconsistent) {
		t.Fatalf("err = %v, want ErrInconsistent", err)
	}
	if c, _, _ := f.server.Store.Latest(origin); c.Size != 5 || c.Root != core.Root(leaves(5, "")) {
		t.Fatalf("witness state changed to %+v", c)
	}
}

func TestCosignStaleAndUnknown(t *testing.T) {
	f := newFixture(t)
	if _, err := f.cosign(t, leaves(8, ""), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.cosign(t, leaves(5, ""), 0); !errors.Is(err, ErrStale) {
		t.Fatalf("err = %v, want ErrStale", err)
	}

	f.server.Logs = map[string]*core.Verifier{}
	if _, err := f.cosign(t, leaves(9, ""), 8); !errors.Is(err, ErrUnknownLog) {
		t.Fatalf("err = %v, want ErrUnknownLog", err)
	}
}

func TestCosignRequiresMatchingChain(t *testing.T) {
	f := newFixture(t)
	note := f.sign(t, leaves(4, ""))
	if _, err := f.client.Cosign(context.Background(), f.witness, note, leaves(4, "other"), f.operator, 0); err == nil {
		t.Fatal("cosigned with a chain that does not match the checkpoint")
	}
}

func TestServerProtocolErrors(t *testing.T) {
	f := newFixture(t)
	note := f.sign(t, leaves(3, ""))
	post := func(body []byte) int {
		resp, err := http.Post(strings.TrimSuffix(f.witness.URL, "/")+"/add-checkpoint", "text/plain", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	tests := []struct {
		name string
		body []byte
		want int
	}{
		{"no separator", note, http.StatusBadRequest},
		{"bad old line", append([]byte("old x\n\n"), note...), http.StatusBadRequest},
		{"leading zero", append([]byte("old 00\n\n"), note...), http.StatusBadRequest},
		{"old larger", append([]byte("old 4\n\n"), note...), http.StatusBadRequest},
		{"proof from 0", append([]byte("old 0\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\n"), note...), http.StatusUnprocessableEntity},
		{"bad signature", append([]byte("old 0\n\n"), bytes.Replace(note, []byte("\n3\n"), []byte("\n2\n"), 1)...), http.StatusForbidden},
	}
	for _, tt := range tests {
		if got := post(tt.body); got != tt.want {
			t.Errorf("%s: status %d, want %d", tt.name, got, tt.want)
		}
	}
}

// Concurrent submissions must never roll the witness back to a smaller tree.
func TestServerConcurrentSubmissions(t *testing.T) {
	f := newFixture(t)
	all := leaves(40, "")
	var wg sync.WaitGroup
	for n := 1; n <= 40; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			f.cosign(t, all[:n], 0) // stale submissions are expected to fail
		}(n)
	}
	wg.Wait()
	c, _, _ := f.server.Store.Latest(origin)
	if _, err := f.cosign(t, all, 0); err != nil {
		t.Fatalf("final submission after size %d: %v", c.Size, err)
	}
	if c, _, _ := f.server.Store.Latest(origin); c.Size != 40 {
		t.Fatalf("final size %d", c.Size)
	}
}

func TestAddCosignaturesIgnoresUnknownKeys(t *testing.T) {
	f := newFixture(t)
	ls := leaves(3, "")
	note := f.sign(t, ls)
	c, _ := core.VerifyCheckpoint(note, f.operator, nil, 0)
	line, err := core.Cosign(c, f.server.Signer, time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	otherSkey, _, _ := core.GenerateWitnessKey("other.example/w")
	other, _ := core.NewSigner(otherSkey)
	otherLine, _ := core.Cosign(c, other, time.Unix(1_800_000_000, 0))
	out, err := core.AddCosignatures(note, []byte(otherLine+line), f.operator, f.witness.Key)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("other.example")) {
		t.Fatal("cosignature from an unconfigured key was kept")
	}
	if _, err := core.AddCosignatures(note, []byte(otherLine), f.operator, f.witness.Key); err == nil {
		t.Fatal("accepted a response without the witness's cosignature")
	}
}

func TestFileStore(t *testing.T) {
	path := t.TempDir() + "/state"
	s, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	a := core.Checkpoint{Origin: "a.example/log", Size: 3, Root: core.Root(leaves(3, ""))}
	b := core.Checkpoint{Origin: "b.example/log", Size: 0, Root: core.EmptyRoot}
	for _, c := range []core.Checkpoint{a, b, {Origin: a.Origin, Size: 5, Root: core.Root(leaves(5, ""))}} {
		if err := s.Put(c); err != nil {
			t.Fatal(err)
		}
	}
	reopened, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if c, ok, _ := reopened.Latest(a.Origin); !ok || c.Size != 5 {
		t.Fatalf("a: %+v %v", c, ok)
	}
	if c, ok, _ := reopened.Latest(b.Origin); !ok || c != b {
		t.Fatalf("b: %+v %v", c, ok)
	}
}
