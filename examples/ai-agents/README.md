# Use case: AI agents and automations

> Status: runnable sample. `go run ./examples/ai-agents`

AI agents and low-code automations act with real credentials: they read
documents, send email, change records. Their operators are asked to show that
an agent did only what it was meant to. Agent logs are usually kept by the
same operator, on the same systems the agent can reach.

deedlog records every tool call where it passes, in a chain anchored by
witnesses, so neither the agent nor its operator can quietly remove a call
afterwards.

## What is recorded

| Event | Subject |
|---|---|
| Policy | The published policy: the agent, and the tools it may use |
| Tool call | HMAC of the exact request bytes, with the tool name |
| Tool result | HMAC of the exact response bytes, with whether it failed |

Arguments and results often contain personal or confidential data, so the
chain holds only keyed digests. The operator keeps the HMAC key, and can prove
what a call contained by disclosing the message and the key to an auditor.

## Two places to record

**An MCP proxy.** The proxy sits between the agent and an MCP server on the
stdio transport, forwards every message unchanged, and records `tools/call`
requests and their responses. Configure the agent to start the proxy instead
of the server:

```json
{
  "mcpServers": {
    "office-tools": {
      "command": "ai-agents",
      "args": ["proxy", "-chain", "agent.jsonl", "-key", "agent.hmac", "-policy", "policy.json",
               "--", "office-tools-server"]
    }
  }
}
```

**Claude Code hooks.** A `PreToolUse` hook records each call before it runs,
and a `PostToolUse` hook records its result. If a call cannot be recorded, the
hook exits with status 2 and Claude Code blocks it, so no tool runs
unrecorded.

```json
{
  "hooks": {
    "PreToolUse":  [{"matcher": "*", "hooks": [{"type": "command", "command": "ai-agents hook -chain agent.jsonl -key agent.hmac -policy policy.json"}]}],
    "PostToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "ai-agents hook -chain agent.jsonl -key agent.hmac -policy policy.json"}]}]
  }
}
```

The policy is a JSON document such as
`{"agent":"assistant-1","tools":["search_docs","send_email"]}`. It is recorded
byte for byte as the first entry when the chain is created. Anchor the chain
on a schedule with `dlog checkpoint` and `dlog cosign`, and check it with:

```sh
go build -o ai-agents ./examples/ai-agents
./ai-agents check -chain agent.jsonl -policy policy.json
```

## Run the sample

```sh
go run ./examples/ai-agents
```

A scripted agent works through the proxy against a stand-in MCP server for
three days, with two witnesses cosigning a checkpoint each day. On the second
run it also deletes customer records, which its policy does not allow:

```
line 8: call to tool "delete_records", which the policy does not allow
```

The sample then rewrites the chain without that call. The rewritten chain is
internally consistent, but it no longer matches the checkpoint the witnesses
cosigned:

```
chain has 11 records, checkpoint covers 13
```

To try the proxy by hand, with the stand-in server:

```sh
go build -o ai-agents ./examples/ai-agents
echo '{"agent":"assistant-1","tools":["search_docs"]}' > policy.json
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_docs","arguments":{}}}' \
  | ./ai-agents proxy -- ./ai-agents fake-server
./ai-agents check
```

| File | Shows |
|---|---|
| [agents.go](agents.go) | The MCP proxy and the recorded events |
| [hook.go](hook.go) | The Claude Code hook |
| [filelog.go](filelog.go) | Appending to a chain file with `core.Writer`, safely from parallel hooks |
| [check.go](check.go) | The check against the declared policy |
| [fake.go](fake.go), [main.go](main.go) | The stand-in server, the scripted agent and the scenario |

## What remains outside

deedlog records; it does not enforce. Use the agent's permission settings to
stop calls the policy does not allow, and deedlog to show what was called.
Actions that bypass the proxy or the hooks, such as an agent calling an API
directly with a credential it holds, are not recorded; keep such credentials
away from the agent, or record at the API as well.
