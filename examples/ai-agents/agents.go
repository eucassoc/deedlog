package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sync"

	"github.com/deedlog/deedlog/core"
	"github.com/deedlog/deedlog/examples/internal/demo"
)

// Policy is what the agent's operator declares: which agent, and which
// tools it may use. It is published and recorded as the first entry.
type Policy struct {
	Agent string   `json:"agent"`
	Tools []string `json:"tools"`
}

// errBlock marks a failure that must stop the agent's action.
var errBlock = errors.New("not recorded, so blocked")

// Recorder appends events to a chain: a FileLog in the proxy and the hook,
// a demo.Log in the simulated runs.
type Recorder interface {
	Record(demo.Event) error
}

func source(agent string) core.Source {
	return core.Source{Type: "ai-agent", ID: agent, Collector: "examples/ai-agents"}
}

// PolicyEvent is the declaration recorded first. The body is the published
// policy document itself, byte for byte, so that anyone holding the
// document can match it to the record.
func PolicyEvent(body []byte) (demo.Event, error) {
	var p Policy
	if err := json.Unmarshal(body, &p); err != nil || p.Agent == "" {
		return demo.Event{}, errors.New("policy must be JSON with an agent and its tools")
	}
	return demo.Event{Source: core.Source{Type: "operator", ID: p.Agent, Collector: "examples/ai-agents"},
		MediaType: "application/json", Body: body, Meta: map[string]string{"event": "policy"}}, nil
}

// CallEvent records a tool call. The arguments may contain personal data,
// so the record holds only the HMAC of the exact message bytes.
func CallEvent(agent, tool, id string, message []byte) demo.Event {
	return demo.Event{Source: source(agent), MediaType: "application/json", Body: message, Keyed: true,
		Meta: map[string]string{"event": "tool_call", "tool": tool, "id": id}}
}

// ResultEvent records a tool result.
func ResultEvent(agent, tool, id string, isError bool, message []byte) demo.Event {
	meta := map[string]string{"event": "tool_result", "tool": tool, "id": id}
	if isError {
		meta["error"] = "true"
	}
	return demo.Event{Source: source(agent), MediaType: "application/json", Body: message, Keyed: true, Meta: meta}
}

// Proxy sits between an agent and an MCP server on the stdio transport,
// where each JSON-RPC message is one line. It forwards every line unchanged
// and records tools/call requests and their responses.
type Proxy struct {
	Agent    string
	Recorder Recorder

	mu      sync.Mutex
	pending map[string]string // JSON-RPC id -> tool name
	err     error
}

type rpcMessage struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params struct {
		Name string `json:"name"`
	} `json:"params"`
	Result struct {
		IsError bool `json:"isError"`
	} `json:"result"`
	Error json.RawMessage `json:"error"`
}

// Run copies agent→server and server→agent until both directions end.
// A message that cannot be recorded is not forwarded: the agent gets no
// tool result rather than an unrecorded one.
func (p *Proxy) Run(fromAgent io.Reader, toAgent io.Writer, toServer io.WriteCloser, fromServer io.Reader) error {
	p.pending = make(map[string]string)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer toServer.Close()
		p.pipe(fromAgent, toServer, p.request)
	}()
	go func() {
		defer wg.Done()
		p.pipe(fromServer, toAgent, p.response)
	}()
	wg.Wait()
	return p.err
}

func (p *Proxy) pipe(r io.Reader, w io.Writer, inspect func([]byte) error) {
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			if rerr := inspect(bytes.TrimSuffix(line, []byte("\n"))); rerr != nil {
				p.fail(rerr)
				return
			}
			if _, werr := w.Write(line); werr != nil {
				return
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				p.fail(err)
			}
			return
		}
	}
}

func (p *Proxy) fail(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err == nil {
		p.err = err
	}
}

func (p *Proxy) request(line []byte) error {
	var m rpcMessage
	if json.Unmarshal(line, &m) != nil || m.Method != "tools/call" || m.ID == nil {
		return nil
	}
	p.mu.Lock()
	p.pending[string(m.ID)] = m.Params.Name
	p.mu.Unlock()
	e := CallEvent(p.Agent, m.Params.Name, string(m.ID), line)
	e.Meta["via"] = "mcp-proxy"
	return p.Recorder.Record(e)
}

func (p *Proxy) response(line []byte) error {
	var m rpcMessage
	if json.Unmarshal(line, &m) != nil || m.Method != "" || m.ID == nil {
		return nil
	}
	p.mu.Lock()
	tool, ok := p.pending[string(m.ID)]
	delete(p.pending, string(m.ID))
	p.mu.Unlock()
	if !ok {
		return nil
	}
	e := ResultEvent(p.Agent, tool, string(m.ID), m.Result.IsError || m.Error != nil, line)
	e.Meta["via"] = "mcp-proxy"
	return p.Recorder.Record(e)
}
