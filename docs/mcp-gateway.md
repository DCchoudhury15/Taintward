# MCP gateway

The AgentWard MCP gateway sits between an MCP client (the agent) and one or
more MCP servers. The agent talks to the gateway as if it were the real
server. The gateway checks every tool call against the AgentWard policy and
then forwards it. The agent code does not change.

```
agent (MCP client)  --stdio-->  python -m gateway  --stdio or HTTP-->  upstream MCP server(s)
```

## What it does on each tool call

1. Looks up the tool in the config to get its destination (`internal`,
   `external`, `llm`, `log`, `rag`), jurisdiction and mode.
2. Scans the arguments for PII and secrets (`sdk/detect.py`: Presidio plus
   the secret regexes).
3. Updates the session taint. Once any argument or result in this session
   was sensitive, every later call in the session counts as tainted. This
   is the gateway version of the SDK's baggage chain taint: the agent has
   seen sensitive data, so anything it sends next may carry it.
4. Runs the policy. The rules are the ones in
   `collector/policy/pii_egress.rego`:
   - `pii_egress`: tainted data going to an `external`, `llm` or `log` tool.
   - `transfer`: PII going to a tool in a non adequate jurisdiction (`us`).
5. Acts on the mode:
   - `redact`: sensitive argument values are replaced before the call is
     forwarded. `internal` tools get a reversible format preserving token;
     every other destination gets a `[PII]` / `[SECRET]` mask
     (`sdk/redact.py`, the same as the SDK).
   - `block`: like `redact`, but if the policy finds a violation the call
     is not forwarded and the agent gets an MCP error (JSON-RPC code
     `-32001`, the violations are in the error `data`).
   - `audit`: raw arguments are forwarded unchanged and the violation is
     only recorded (same idea as `AGENTWARD_DRY_RUN`). Use it to see what
     would be flagged before you turn enforcement on.
6. Scans the result. Sensitive results taint the session. With
   `redact_results: true` (the default) sensitive values in the result are
   masked before the agent sees them, because the result goes into the
   model context.
7. Emits one OpenTelemetry span per call, named `agentward.gateway <tool>`.

## Quick start

Install the extra packages into the AgentWard virtualenv:

```bash
pip install mcp
```

Try the example (an HR server with `get_employee` and `send_email`):

```bash
python -m gateway --config gateway/example-config.yaml
```

It waits for an MCP client on stdin/stdout. Logs go to stderr.

## Putting it in front of an MCP server

Say your MCP client config starts a server like this:

```json
{
  "mcpServers": {
    "hr": { "command": "node", "args": ["/opt/hr-mcp/index.js"] }
  }
}
```

Move that command into a gateway config file:

```yaml
upstreams:
  - name: hr
    command: node
    args: ["/opt/hr-mcp/index.js"]
tools:
  - match: "get_*"
    destination: internal
  - match: "send_*"
    destination: external
    mode: block
```

Then point the client at the gateway instead:

```json
{
  "mcpServers": {
    "hr": {
      "command": "/path/to/agentward/.venv/bin/python",
      "args": ["-m", "gateway", "--config", "/path/to/hr-gateway.yaml"],
      "cwd": "/path/to/agentward"
    }
  }
}
```

This works the same in Claude Desktop, Cursor, or any other client that
starts MCP servers as local commands. The tools keep the same names and
input schemas, so the agent and its prompts do not need any change.

To send spans to SigNoz (or any OTLP/HTTP collector), add
`--otlp-endpoint http://localhost:4318/v1/traces` or set
`AGENTWARD_OTLP_ENDPOINT`. Without it no spans are exported.

## Config reference

```yaml
service_name: agentward-mcp-gateway   # OTel service.name

upstreams:                 # one or more, tools from all of them are exposed
  - name: hr               # unique name, used in rules and spans
    command: python        # stdio upstream: the command to run
    args: ["-m", "gateway.examples.hr_server"]
    cwd: ..                # optional, relative to the config file
    env: {KEY: value}      # optional, added to a minimal safe environment
    prefix: "hr_"          # optional, exposed name = prefix + tool name
  - name: docs
    url: http://localhost:8000/mcp   # streamable HTTP upstream

defaults:                  # used when no rule matches
  destination: external    # safe default: unknown tools are treated as external
  jurisdiction: ""
  mode: redact             # redact | block | audit
  redact_results: true
  passthrough_args: []

tools:                     # checked top to bottom, the first match wins
  - match: "get_*"         # glob on the exposed tool name: * ? [abc]
    upstream: hr           # optional, only match tools from this upstream
    destination: internal
    jurisdiction: eu
    mode: redact
    redact_results: true
    passthrough_args: ["to"]   # top level args that are not scanned or redacted
```

Notes:

- Each upstream needs exactly one of `command` or `url`.
- `command: python` (or `python3`) means the same interpreter that runs the
  gateway.
- A field a rule leaves out comes from `defaults`.
- If two upstreams expose the same tool name, the first upstream in the list
  wins and the other one is hidden (a warning is logged). Use `prefix` to
  keep both.
- `passthrough_args` is for values the tool really needs raw, such as the
  `to` address of an email tool. They are still masked on the span.

## Span attributes

The span uses the same attribute names as the SDK so the existing collector
policy and SigNoz dashboards work on it:

| attribute | meaning |
|---|---|
| `gen_ai.tool.name` | exposed tool name |
| `gen_ai.operation.name` | `execute_tool` |
| `gen_ai.tool.call.arguments` | arguments as forwarded (redacted; masked in audit mode) |
| `gen_ai.tool.call.result` | result, masked |
| `agentward.destination` | tool destination |
| `agentward.jurisdiction` | tool jurisdiction |
| `agentward.sensitive` | session or call is tainted |
| `agentward.taint.classes` / `.level` / `.id` | taint label |
| `agentward.violation` | the policy found a violation |
| `agentward.violation.reason` | short reason |
| `agentward.policy.rules` | rules that fired, e.g. `pii_egress,transfer` |
| `agentward.mode` | `redact`, `block` or `audit` |
| `agentward.blocked` | the call was blocked |
| `agentward.dry_run` | set in audit mode |
| `agentward.args.redacted` / `agentward.result.redacted` | something was changed |
| `agentward.gateway.upstream` | upstream name |

The chain taint is also put in OTel baggage on the upstream request, so an
upstream that is itself instrumented can read it.

## How the policy is evaluated

The Rego file is the source of truth. The gateway does not need OPA: the
same rules are written in Python in `gateway/policy.py`. A test in
`tests/test_gateway.py` reads the Rego file and fails if its sink set,
jurisdiction set or rule names change without the Python module being
updated. If an `opa` binary is on the PATH, another test also runs
`opa eval` on a grid of inputs and checks both give the same decision.

## Limits

- The gateway serves its own clients over stdio only. One gateway process
  is one session. Upstreams can be stdio or streamable HTTP.
- Session taint is coarse on purpose. After the agent reads one sensitive
  value, every later call to an `external`, `llm` or `log` tool is a
  violation, and in `block` mode it is blocked, even if its arguments look
  clean. This is the same safe over approximation the SDK makes. Use
  `redact` mode where blocking is too strict.
- Detection is Presidio plus regexes. PII the detector cannot see (for
  example a value the agent rewrote into a different form) is not redacted,
  though the session taint still flags the call.
- Presidio's name, date and location detection can give false positives,
  so normal text can get masked. Values like email addresses are PII, so an
  email tool's `to` field is masked unless you list it in
  `passthrough_args`.
- Only text content, embedded text resources and structured content in
  results are scanned. Images, audio and binary resources pass through
  unchanged.
- Only tools are proxied. Resources, prompts, sampling and elicitation from
  the upstream are not forwarded yet.
- Reversible tokens for `internal` tools use the SDK redactor, which is demo
  grade (FF3 with an in process vault, see `sdk/redact.py`).
- `audit` mode forwards raw data on purpose. Do not leave it on for tools
  that leave your system.
