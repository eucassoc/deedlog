package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/eucassoc/deedlog/core"
	"github.com/eucassoc/deedlog/examples/internal/demo"
)

func TestWithinPolicy(t *testing.T) {
	res, err := run([][]Call{routine, routine})
	if err != nil {
		t.Fatal(err)
	}
	defer demo.CloseAll(res.witnesses)
	if len(res.findings) != 0 {
		t.Fatalf("findings: %v", res.findings)
	}
}

func TestBeyondPolicy(t *testing.T) {
	res, err := run([][]Call{routine, beyond})
	if err != nil {
		t.Fatal(err)
	}
	defer demo.CloseAll(res.witnesses)
	if len(res.findings) != 1 || !strings.Contains(res.findings[0].Problem, `"delete_records", which the policy does not allow`) {
		t.Fatalf("findings: %v", res.findings)
	}
	rewritten, err := hide(res.log.Chain(), res.log.Origin, "delete_records")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := core.Verify(bytes.NewReader(rewritten)); err != nil {
		t.Fatalf("rewritten chain should verify on its own: %v", err)
	}
	if _, _, err := demo.Open(rewritten, res.checkpoint, res.log.OperatorKey(), demo.Keys(res.witnesses), 2); err == nil {
		t.Fatal("rewritten chain matches the witnessed checkpoint")
	}
}

func testFileLog(t *testing.T) (*FileLog, string) {
	dir := t.TempDir()
	first, err := PolicyEvent([]byte(`{"agent":"assistant-1","tools":["Read"]}`))
	if err != nil {
		t.Fatal(err)
	}
	l, err := OpenFileLog(filepath.Join(dir, "agent.jsonl"), "example.com/agents", filepath.Join(dir, "agent.hmac"))
	if err != nil {
		t.Fatal(err)
	}
	l.First = &first
	return l, filepath.Join(dir, "agent.jsonl")
}

func TestHook(t *testing.T) {
	l, path := testFileLog(t)
	pre := `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Read","tool_use_id":"toolu_1","tool_input":{"file_path":"a.txt"}}`
	post := `{"session_id":"s1","hook_event_name":"PostToolUse","tool_name":"Read","tool_use_id":"toolu_1","tool_input":{"file_path":"a.txt"},"tool_response":{"content":"secret"}}`
	for _, in := range []string{pre, post} {
		if err := Hook(strings.NewReader(in), "assistant-1", l); err != nil {
			t.Fatal(err)
		}
	}
	chain, _ := os.ReadFile(path)
	if bytes.Contains(chain, []byte("secret")) || bytes.Contains(chain, []byte("a.txt")) {
		t.Fatal("tool input or output leaked into the chain")
	}
	entries, err := entriesOf(chain)
	if err != nil {
		t.Fatal(err)
	}
	if fs := Check(entries, []byte(`{"agent":"assistant-1","tools":["Read"]}`)); len(fs) != 0 {
		t.Fatalf("findings: %v", fs)
	}
}

func TestHookBlocksWhenNotRecorded(t *testing.T) {
	l, path := testFileLog(t)
	if err := os.WriteFile(path, []byte("not a chain\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	in := `{"hook_event_name":"PreToolUse","tool_name":"Read","tool_use_id":"toolu_1","tool_input":{}}`
	if err := Hook(strings.NewReader(in), "assistant-1", l); !errors.Is(err, errBlock) {
		t.Fatalf("got %v, want a blocking error", err)
	}
}

func TestParallelRecording(t *testing.T) {
	l, path := testFileLog(t)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := l.Record(CallEvent("assistant-1", "Read", "x", []byte("{}"))); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	chain, _ := os.ReadFile(path)
	s, err := core.Verify(bytes.NewReader(chain))
	if err != nil || s.Count != 21 {
		t.Fatalf("chain: %d records, %v", s.Count, err)
	}
}
