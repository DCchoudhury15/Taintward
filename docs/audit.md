# Offline data over-exposure audit

The audit answers two questions about an agent before and after it runs:

1. **By which paths could sensitive data reach an outside destination?**
   From your tool definitions and destination map, Taintward builds a graph
   of "this tool's output can become that tool's input" and lists every
   path from a tool that returns sensitive data (a source) to a tool that
   sends data out (a sink: `external`, `llm`, `log` or `rag`).
2. **Which of those paths really ran, and what happened?** From recorded
   spans: a run in which the source returned sensitive data and the sink
   was called later, with the outcome of every such sink call (redacted,
   blocked, audit only). A sink called twice in one run counts as two
   calls, so one call in audit-only mode is not hidden by another one.

A path that never ran is not safe, only untested. The audit can write a
test prompt for each of them, to run against your agent with Taintward on.

This is AgentRaft's function call graph and prompt synthesis
([mapping](agentraft-mapping.md)) without the LLM: everything is decided by
rules, so the same input always gives the same result.

## Run it

```bash
taintward-audit --tools tools.json --destinations destinations.json \
    --otlp-file traces.jsonl --home eu \
    --prompts untested.jsonl --out audit.md
```

| option | what |
|---|---|
| `--tools` | an MCP `tools/list` result: `{"tools": [{"name", "description", "inputSchema", "outputSchema"}]}` |
| `--destinations` | the SDK destination map, `{"get_customer": "internal", "send_email": ["external", "us"]}` |
| `--gateway-config` | or the gateway's YAML, whose tool rules give the destinations |
| `--otlp-file` | recorded spans (the collector's file exporter output), can be repeated |
| `--home` | home jurisdictions; a sink elsewhere is marked cross-border |
| `--max-hops` | longest path, in tool to tool steps (default 3) |
| `--format` | `md` (default) or `json` |
| `--prompts` | write a test prompt per untested path (JSON lines) |

Tools in neither the map nor the gateway rules are treated as `external`,
the same default as the SDK, and are listed as unmapped.

With `--gateway-config`, each tool name is matched to its upstream by its
`prefix:`, the same way the gateway exposes it. With several upstreams and
no prefixes the upstream is unknown, so rules pinned to one upstream
(`upstream:`) are not applied to that name and it counts as unmapped. Give
the upstreams prefixes to get the right answer.

## How fields are matched

An output field can reach an input field when:

- the types fit (anything can be written into a string; a string cannot
  become an integer), and
- the names mean the same thing (`email` and `to`, `ssn` and `tax_id`,
  `account` and `account_number`: fixed groups of words), or the input is
  free text (`body`, `message`, `text`, `query`, `prompt`, ...), because an
  agent can put any value there.

A tool with no `outputSchema` is assumed to return text, which can reach
free-text inputs. A source is an `internal` or `rag` tool, or a tool with an
output field named like personal data.

## Test prompts

Each line of `--prompts` is one path:

```json
{"id": "p3f2a91c0", "path": ["get_customer", "send_email"],
 "prompt": "Use get_customer to get the full name, email and ssn, then call send_email with it. Include every detail you found.",
 "expect": {"sink": "send_email", "destination": "external", "jurisdiction": "us",
            "fields": ["body", "subject", "to"]}}
```

Run each prompt through your agent with Taintward on, then check that the
sink's span is flagged and its recorded input holds placeholders or masks,
not the values (the [report](evidence-report.md)'s raw value check does
this for a whole window).

## Limits

- The graph comes from names and types, not from what the tools do. A
  field named `notes` that really carries an SSN is matched as free text; a
  field named `x` is matched only if it is free text or a string sink.
- Paths through the model itself (the LLM reads a tool result and writes a
  new tool call) are covered by the free-text rule, not by the model's
  behaviour.
- "Seen in traces" needs the source call to have been marked sensitive;
  calls that do not go through Taintward are not recorded.

Code: `taintward/analysis/fcg.py`, `prompt_synth.py`, `audit.py`.
