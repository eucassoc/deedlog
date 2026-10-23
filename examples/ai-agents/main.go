// Command ai-agents records what AI agents do with their tools, through an
// MCP proxy or Claude Code hooks, and checks the record against the tools
// the agent's operator declared.
//
//	go run ./examples/ai-agents [-out DIR]          simulated runs
//	go run ./examples/ai-agents proxy -chain FILE -key FILE -policy FILE -- SERVER [ARGS...]
//	go run ./examples/ai-agents hook  -chain FILE -key FILE -policy FILE   (reads hook input on stdin)
//	go run ./examples/ai-agents check -chain FILE -policy FILE
//	go run ./examples/ai-agents fake-server
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/deedlog/deedlog/core"
	"github.com/deedlog/deedlog/examples/internal/demo"
)

func main() {
	log.SetFlags(0)
	args := os.Args[1:]
	cmd := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "":
		err = simulate(args)
	case "proxy":
		err = proxy(args)
	case "hook":
		err = hook(args)
	case "check":
		err = check(args)
	case "fake-server":
		err = ServeFake(os.Stdin, os.Stdout)
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if errors.Is(err, errBlock) {
		// Exit status 2 makes Claude Code block the tool call and show
		// stderr to the agent.
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}

// fileFlags are shared by proxy and hook.
type fileFlags struct {
	chain, key, policy, origin *string
}

func newFileFlags(fs *flag.FlagSet) fileFlags {
	return fileFlags{
		chain:  fs.String("chain", "agent.jsonl", "chain file"),
		key:    fs.String("key", "agent.hmac", "HMAC key file, created if missing; keep it secret"),
		policy: fs.String("policy", "policy.json", "published policy, recorded first when the chain is created"),
		origin: fs.String("origin", "example.com/agents", "chain ID"),
	}
}

func (f fileFlags) open() (*FileLog, string, error) {
	body, err := os.ReadFile(*f.policy)
	if err != nil {
		return nil, "", err
	}
	first, err := PolicyEvent(body)
	if err != nil {
		return nil, "", err
	}
	l, err := OpenFileLog(*f.chain, *f.origin, *f.key)
	if err != nil {
		return nil, "", err
	}
	l.First = &first
	return l, first.Source.ID, nil
}

func proxy(args []string) error {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	ff := newFileFlags(fs)
	fs.Parse(args)
	if fs.NArg() == 0 {
		return errors.New("usage: proxy [flags] -- SERVER [ARGS...]")
	}
	l, agent, err := ff.open()
	if err != nil {
		return err
	}
	server := exec.Command(fs.Arg(0), fs.Args()[1:]...)
	server.Stderr = os.Stderr
	toServer, err := server.StdinPipe()
	if err != nil {
		return err
	}
	fromServer, err := server.StdoutPipe()
	if err != nil {
		return err
	}
	if err := server.Start(); err != nil {
		return err
	}
	p := &Proxy{Agent: agent, Recorder: l}
	perr := p.Run(os.Stdin, os.Stdout, toServer, fromServer)
	if err := server.Wait(); err != nil && perr == nil {
		perr = err
	}
	return perr
}

func hook(args []string) error {
	fs := flag.NewFlagSet("hook", flag.ExitOnError)
	ff := newFileFlags(fs)
	fs.Parse(args)
	l, agent, err := ff.open()
	if err != nil {
		return fmt.Errorf("%w: %v", errBlock, err)
	}
	return Hook(os.Stdin, agent, l)
}

func check(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	chainPath := fs.String("chain", "agent.jsonl", "chain file")
	policyPath := fs.String("policy", "policy.json", "published policy")
	fs.Parse(args)
	chain, err := os.ReadFile(*chainPath)
	if err != nil {
		return err
	}
	policy, err := os.ReadFile(*policyPath)
	if err != nil {
		return err
	}
	s, err := core.Verify(bytes.NewReader(chain))
	if err != nil {
		return err
	}
	entries, err := entriesOf(chain)
	if err != nil {
		return err
	}
	fmt.Printf("%s: %d records, chain intact (anchor it with dlog checkpoint and dlog cosign)\n", s.Chain, s.Count)
	findings := Check(entries, policy)
	findings.Print(os.Stdout)
	if len(findings) > 0 {
		os.Exit(1)
	}
	return nil
}

// entriesOf parses a chain that has already been verified.
func entriesOf(chain []byte) ([]demo.Entry, error) {
	var entries []demo.Entry
	for i, line := range bytes.Split(bytes.TrimSuffix(chain, []byte("\n")), []byte("\n")) {
		var r core.Record
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, &core.LineError{Line: i + 1, Err: err}
		}
		entries = append(entries, demo.Entry{Line: i + 1, Record: r})
	}
	return entries, nil
}

// memRecorder records into a demo.Log.
type memRecorder struct{ *demo.Log }

func (m memRecorder) Record(e demo.Event) error {
	_, err := m.Append(e)
	return err
}

var policy = Policy{Agent: "assistant-1", Tools: []string{"search_docs", "send_email"}}

type result struct {
	log        *demo.Log
	witnesses  []*demo.Witness
	checkpoint []byte
	policy     []byte
	findings   demo.Findings
}

// session runs the scripted agent against the fake server through the
// proxy, recording into l.
func session(l *demo.Log, calls []Call) error {
	agentR, agentW := io.Pipe()     // agent -> proxy
	toAgentR, toAgentW := io.Pipe() // proxy -> agent
	serverR, serverW := io.Pipe()   // proxy -> server
	fromSrvR, fromSrvW := io.Pipe() // server -> proxy

	go func() {
		ServeFake(serverR, fromSrvW)
		fromSrvW.Close()
	}()
	agentErr := make(chan error, 1)
	go func() {
		agentErr <- Agent(agentW, toAgentR, calls)
		io.Copy(io.Discard, toAgentR)
	}()
	p := &Proxy{Agent: policy.Agent, Recorder: memRecorder{l}}
	err := p.Run(agentR, toAgentW, serverW, fromSrvR)
	toAgentW.Close()
	return errors.Join(err, <-agentErr)
}

func run(days [][]Call) (*result, error) {
	l, ws, err := demo.Start("example.com/agents", time.Date(2026, 4, 1, 9, 0, 0, 0, time.UTC),
		"witness.audit.example", "witness.industry.example")
	if err != nil {
		return nil, err
	}
	res := &result{log: l, witnesses: ws}
	res.policy, _ = json.Marshal(policy)
	first, err := PolicyEvent(res.policy)
	if err != nil {
		return res, err
	}
	if _, err := l.Append(first); err != nil {
		return res, err
	}
	for _, calls := range days {
		if err := session(l, calls); err != nil {
			return res, err
		}
		if res.checkpoint, err = l.Checkpoint(context.Background(), ws...); err != nil {
			return res, err
		}
		l.Clock.Advance(24 * time.Hour)
	}
	entries, _, err := demo.Open(l.Chain(), res.checkpoint, l.OperatorKey(), demo.Keys(ws), len(ws))
	if err != nil {
		return res, err
	}
	res.findings = Check(entries, res.policy)
	return res, nil
}

var (
	routine = []Call{
		{"search_docs", map[string]string{"query": "travel expense rules"}},
		{"send_email", map[string]string{"to": "team@example.com", "subject": "Summary"}},
	}
	beyond = []Call{
		{"search_docs", map[string]string{"query": "inactive customers"}},
		{"delete_records", map[string]string{"table": "customers", "where": "inactive"}},
	}
)

// hide rewrites a chain without the records of calls to tool, relinking
// the rest so that the chain itself verifies, as an operator trying to
// cover up afterwards would.
func hide(chain []byte, origin, tool string) ([]byte, error) {
	var out bytes.Buffer
	w, err := core.NewWriter(&out, origin)
	if err != nil {
		return nil, err
	}
	entries, err := entriesOf(chain)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.Meta["tool"] != tool {
			if _, err := w.Append(e.Record); err != nil {
				return nil, err
			}
		}
	}
	return out.Bytes(), nil
}

func simulate(args []string) error {
	fs := flag.NewFlagSet("ai-agents", flag.ExitOnError)
	out := fs.String("out", "", "directory for the chains, checkpoints and keys (default: a new temporary directory)")
	fs.Parse(args)
	dir, err := demo.OutDir(*out, "ai-agents")
	if err != nil {
		return err
	}
	runs := []struct {
		name string
		days [][]Call
	}{
		{"within policy", [][]Call{routine, routine, routine}},
		{"beyond policy", [][]Call{routine, beyond, routine}},
	}
	for i, r := range runs {
		res, err := run(r.days)
		if err != nil {
			return err
		}
		demo.Header(os.Stdout, r.name, res.log, res.witnesses)
		res.findings.Print(os.Stdout)
		if i == 1 {
			// Rewriting the chain afterwards does not help: it no longer
			// matches the checkpoint the witnesses cosigned.
			rewritten, err := hide(res.log.Chain(), res.log.Origin, "delete_records")
			if err != nil {
				return err
			}
			_, _, err = demo.Open(rewritten, res.checkpoint, res.log.OperatorKey(), demo.Keys(res.witnesses), len(res.witnesses))
			fmt.Printf("\n  The chain rewritten without the delete_records call, against the witnessed checkpoint:\n  %v\n", err)
		}
		if err := demo.Save(os.Stdout, filepath.Join(dir, fmt.Sprint(i+1)), res.log, res.witnesses); err != nil {
			return err
		}
		demo.CloseAll(res.witnesses)
	}
	return nil
}
