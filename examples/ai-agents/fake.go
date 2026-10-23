package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
)

// ServeFake is a minimal MCP server on the stdio transport with three
// tools, standing in for a real one in the samples.
func ServeFake(r io.Reader, w io.Writer) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(nil, 1<<20)
	enc := json.NewEncoder(w)
	for sc.Scan() {
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Name      string            `json:"name"`
				Arguments map[string]string `json:"arguments"`
			} `json:"params"`
		}
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil || m.ID == nil {
			continue // notifications need no answer
		}
		var result any
		switch m.Method {
		case "initialize":
			result = map[string]any{
				"protocolVersion": "2025-06-18",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]string{"name": "fake-office-tools", "version": "0.1"},
			}
		case "tools/list":
			var tools []map[string]any
			for _, name := range []string{"search_docs", "send_email", "delete_records"} {
				tools = append(tools, map[string]any{"name": name, "inputSchema": map[string]string{"type": "object"}})
			}
			result = map[string]any{"tools": tools}
		case "tools/call":
			text := map[string]string{
				"search_docs":    "3 documents found",
				"send_email":     "sent",
				"delete_records": "deleted 120 records",
			}[m.Params.Name]
			result = map[string]any{
				"content": []map[string]string{{"type": "text", "text": text}},
				"isError": text == "",
			}
		default:
			if err := enc.Encode(map[string]any{"jsonrpc": "2.0", "id": m.ID,
				"error": map[string]any{"code": -32601, "message": "method not found"}}); err != nil {
				return err
			}
			continue
		}
		if err := enc.Encode(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": result}); err != nil {
			return err
		}
	}
	return sc.Err()
}

// Call is one tool call made by the scripted agent.
type Call struct {
	Tool string
	Args map[string]string
}

// Agent is a scripted MCP client standing in for an AI agent: it
// initializes the session and makes its calls one after another.
func Agent(toServer io.WriteCloser, fromServer io.Reader, calls []Call) error {
	defer toServer.Close()
	enc := json.NewEncoder(toServer)
	br := bufio.NewReader(fromServer)
	send := func(id int, method string, params any) error {
		if err := enc.Encode(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); err != nil {
			return err
		}
		if _, err := br.ReadBytes('\n'); err != nil {
			return fmt.Errorf("%s: no response: %w", method, err)
		}
		return nil
	}
	if err := send(1, "initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
		"clientInfo": map[string]string{"name": "scripted-agent", "version": "0.1"}}); err != nil {
		return err
	}
	if err := enc.Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); err != nil {
		return err
	}
	for i, c := range calls {
		if err := send(i+2, "tools/call", map[string]any{"name": c.Tool, "arguments": c.Args}); err != nil {
			return err
		}
	}
	return nil
}
