package main

import (
	"slices"

	"github.com/deedlog/deedlog/examples/internal/demo"
)

// Check applies the declared policy to a verified chain. It needs neither
// the HMAC key nor the tool arguments.
func Check(entries []demo.Entry, policy []byte) demo.Findings {
	var fs demo.Findings
	if len(entries) == 0 || entries[0].Meta["event"] != "policy" {
		fs.Add(1, "the first record must declare the policy")
		return fs
	}
	var p Policy
	if err := demo.Declared(entries[0], policy, &p); err != nil {
		fs.Add(0, "%v", err)
		return fs
	}
	pending := make(map[string]demo.Entry)
	key := func(e demo.Entry) string { return e.Meta["via"] + "\x00" + e.Meta["session"] + "\x00" + e.Meta["id"] }
	for _, e := range entries[1:] {
		if e.Source.ID != p.Agent {
			fs.Add(e.Line, "record from agent %q, but the policy is for %q", e.Source.ID, p.Agent)
		}
		switch ev := e.Meta["event"]; ev {
		case "tool_call":
			if !slices.Contains(p.Tools, e.Meta["tool"]) {
				fs.Add(e.Line, "call to tool %q, which the policy does not allow", e.Meta["tool"])
			}
			pending[key(e)] = e
		case "tool_result":
			call, ok := pending[key(e)]
			if !ok {
				fs.Add(e.Line, "result of tool %q without a recorded call", e.Meta["tool"])
				continue
			}
			if call.Meta["tool"] != e.Meta["tool"] {
				fs.Add(e.Line, "result for tool %q answers a call to %q (line %d)", e.Meta["tool"], call.Meta["tool"], call.Line)
			}
			delete(pending, key(e))
		default:
			fs.Add(e.Line, "unknown event %q", ev)
		}
	}
	// Claude Code runs PostToolUse hooks only for tools that succeeded, so
	// only the proxy is expected to record a result for every call.
	for _, call := range pending {
		if call.Meta["via"] == "mcp-proxy" {
			fs.Add(call.Line, "call to tool %q has no recorded result", call.Meta["tool"])
		}
	}
	return fs.Sorted()
}
