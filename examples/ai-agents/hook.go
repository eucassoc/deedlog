package main

import (
	"encoding/json"
	"fmt"
	"io"
)

// hookInput is the part of a Claude Code hook's input that is recorded
// (https://code.claude.com/docs/en/hooks).
type hookInput struct {
	SessionID     string          `json:"session_id"`
	HookEventName string          `json:"hook_event_name"`
	ToolName      string          `json:"tool_name"`
	ToolUseID     string          `json:"tool_use_id"`
	ToolInput     json.RawMessage `json:"tool_input"`
	ToolResponse  json.RawMessage `json:"tool_response"`
}

// Hook records a Claude Code PreToolUse or PostToolUse hook input read
// from r. The digests cover the exact bytes of tool_input and
// tool_response as Claude Code sent them.
//
// For PreToolUse, a failure to record is returned as errBlock: the caller
// exits 2, and Claude Code blocks the tool call, so that no tool runs
// unrecorded.
func Hook(r io.Reader, agent string, rec Recorder) error {
	var in hookInput
	if err := json.NewDecoder(r).Decode(&in); err != nil {
		return fmt.Errorf("hook input: %w", err)
	}
	var err error
	switch in.HookEventName {
	case "PreToolUse":
		e := CallEvent(agent, in.ToolName, in.ToolUseID, in.ToolInput)
		e.Meta["via"], e.Meta["session"] = "claude-code-hook", in.SessionID
		if err = rec.Record(e); err != nil {
			return fmt.Errorf("%w: %v", errBlock, err)
		}
	case "PostToolUse":
		e := ResultEvent(agent, in.ToolName, in.ToolUseID, false, in.ToolResponse)
		e.Meta["via"], e.Meta["session"] = "claude-code-hook", in.SessionID
		err = rec.Record(e)
	default:
		err = fmt.Errorf("unsupported hook event %q", in.HookEventName)
	}
	return err
}
