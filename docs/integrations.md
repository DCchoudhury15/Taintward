# Framework integrations

`sdk/integrations/` lets you protect an existing agent without putting
`@instrument_tool(...)` on every tool. You write one map of tool names to
destinations, then pass your tools, your model or your LLM client through an
adapter. The adapters use the same gate as `@instrument_tool`
(`sdk.instrumentation.GuardedCall`, which calls `sdk.detect` and
`sdk.redact.redact_payload`), so detection and redaction behave the same.

## Setup

```python
from sdk import integrations as agentward

agentward.init(
    "hr-agent",                       # service.name in SigNoz
    destinations={
        "search_db": "internal",
        "cache_record": "internal",
        "send_email": ("external", "us"),           # (destination, jurisdiction)
        "notify": {"destination": "external", "allow": ["to"]},
    },
)
```

- `endpoint` sets the OTLP/HTTP traces URL (default `http://localhost:4318/v1/traces`).
- `console=True` also prints spans.
- `llm_jurisdiction="us"` tags LLM request spans.
- `tracer=...` uses your own tracer and skips the global tracing setup (useful
  in tests, or when the app already set up OpenTelemetry).

Destinations are `internal`, `external`, `llm`, `log` and `rag`. A typo raises
`ValueError` at startup.

### Tools that are not in the map

They are treated as `external`. An unknown tool may send data anywhere, so it
gets the non-reversible mask (`[PII]`, `[SECRET]`) and its span is flagged when
the run has touched sensitive data. Marking a tool `internal` is an explicit
choice to trust it with reversible tokens. If you forget a trusted tool, it
only sees masks; if the default were `internal`, a forgotten tool would get
data it should not. You can change the default with `default_destination=`.

### The `allow` list

`allow` names tool arguments that pass through unredacted, for example the
recipient address of an email tool (an email address is PII, so it would be
masked otherwise). Use it only for arguments the tool really needs. The values
are still scanned, so the taint label and the violation flag stay correct.

### One run, one trace

```python
with agentward.run("hr-agent.run"):
    agent.invoke(...)
```

`run()` creates one root span for the run and starts with a clean taint slate.
It also keeps the run's taint visible across the threads and asyncio tasks
that frameworks use to run tools, so a later tool or LLM call in the same run
is still flagged after an earlier tool read sensitive data. Without `run()`,
redaction still works (it is based on what is detected in each input), but the
chain taint can be lost between tools.

## LangChain and LangGraph

```python
tools = agentward.wrap_langchain_tools([search_db, cache_record, send_email])
model = agentward.protect_langchain_model(ChatOpenAI(model="gpt-4o-mini"))
agent = create_agent(model, tools)          # or langgraph create_react_agent
```

- `wrap_langchain_tools(tools, mapping=None)` returns protected copies. Each copy
  keeps the name, description, args schema, `return_direct`,
  `response_format` and callbacks, and is still an instance of the original
  class (for example `StructuredTool`). The originals are not changed.
  `mapping` adds or overrides entries of the `init()` map.
- The tool input is redacted before LangChain callbacks and before the tool
  body run. Injected arguments (graph state, `ToolRuntime`, tool call id) are
  passed through untouched.
- `protect_langchain_model(model)` returns a protected copy of the chat model.
  Every request (user text, tool results, earlier tool call arguments) is
  redacted for the `llm` destination before it reaches the provider, and a
  `chat <model>` span is recorded. `bind_tools()` on the copy keeps the
  protection. `invoke`, `ainvoke`, `batch`, `stream` and `astream` are covered.

Why not a callback handler: LangChain callbacks only see the input; they
cannot change what the tool or the provider receives. Redaction has to sit in
the call path, so the adapter wraps the objects.

## OpenAI Agents SDK

```python
from agents import Agent, Runner, set_default_openai_client
from openai import AsyncOpenAI

client = agentward.protect_openai(AsyncOpenAI())
set_default_openai_client(client)           # the agent's model calls are redacted

agent = Agent(name="hr", tools=agentward.wrap_function_tools([search_db, send_email]))
with agentward.run("hr.run"):
    await Runner.run(agent, "...")
```

- `wrap_function_tools(tools, mapping=None)` returns protected copies of
  `FunctionTool` objects (what `@function_tool` makes). Name, description,
  JSON schema, strict mode, guardrails, approval and timeout settings are kept.
  The JSON arguments from the model are redacted, then the original tool runs
  with the redacted JSON.
- Hosted tools (web search, file search, MCP servers, computer use) are
  returned unchanged. They do not run in this process, so there is nothing to
  redact here; their data goes through the LLM request, which the protected
  client covers.

## Plain OpenAI and Anthropic clients

```python
client = agentward.protect_openai(OpenAI())          # or AsyncOpenAI()
client = agentward.protect_anthropic(Anthropic())    # or AsyncAnthropic()
```

This patches the client object in place (calling it twice is safe):

- OpenAI: `client.chat.completions.create` (`messages`) and
  `client.responses.create` (`input`, `instructions`)
- Anthropic: `client.messages.create` (`messages`, `system`)

Each request is redacted for the `llm` destination. Protocol fields such as
`role`, `type`, ids, `tool_call_id`, `tool_use_id`, tool names and base64
image data are left as they are, so requests stay valid. The span records the
redacted request, the masked response, `gen_ai.provider.name`,
`gen_ai.request.model` and token usage.

## What the spans carry

| attribute | meaning |
| --- | --- |
| `agentward.destination` | `internal`, `external`, `llm`, `log` or `rag` |
| `agentward.jurisdiction` | from the map (or `llm_jurisdiction` for LLM spans) |
| `agentward.taint.classes`, `agentward.taint.level`, `agentward.sensitive` | taint of the call |
| `agentward.violation` | a tainted run reached an external, llm or log sink |
| `agentward.redacted` | the gate changed what the sink received |
| `agentward.framework` | `langchain`, `openai-agents`, `openai.chat`, `openai.responses`, `anthropic` |
| `gen_ai.tool.name`, `gen_ai.operation.name` | tool spans (`execute_tool`) and LLM spans (`chat`) |
| `gen_ai.tool.call.arguments` / `gen_ai.input.messages` | input after redaction |
| `gen_ai.tool.call.result` / `gen_ai.output.messages` | output, masked |

## Limits

- The LLM gets masks, not tokens. Because `llm` is a masked destination, a
  model that reads a tool result sees `[PII]`, so it cannot pass the reversible
  token on to an internal tool. Internal tools get tokens when the value
  reaches them directly (for example from user input or another tool's
  arguments).
- Detection is the same as the rest of the SDK. Data that is changed into a
  form the detectors do not recognize is not redacted; the chain taint still
  flags the run (see `docs/spike-llm-hop.md`). False positives also apply, for
  example an email address is masked unless it is in `allow`.
- Tool outputs are not redacted when they return to your code. They are
  redacted when they are sent on: to the LLM by the protected model or client,
  or to another tool by its own gate.
- Streaming responses: the request is redacted and recorded, but the streamed
  output is not scanned.
- Not covered: LangChain `generate()` called directly with message lists,
  OpenAI `with_raw_response` / `with_streaming_response`, OpenAI and Anthropic
  `beta` endpoints, embeddings, other LLM providers, and other clients you
  create without `protect_*`.
- The OpenAI Agents SDK has its own tracing, which by default uploads tool
  arguments to OpenAI. Turn it off with `set_tracing_disabled(True)` or set
  `RunConfig(trace_include_sensitive_data=False)`.
- LangChain callbacks that are attached to a protected model see the redacted
  request; callbacks on an unprotected model or tool see raw data.
- Every LLM request scans the whole message history again, so long
  conversations cost more detection time.

## Packages used for the tests

`langchain-core 1.7.0`, `langchain 1.4.7`, `langgraph 1.2.17`,
`openai-agents 0.24.0`, `openai 3.6.0`, `anthropic 1.2.0`. The tests in
`tests/test_integrations.py` run offline with fake models and mocked HTTP, and
skip a framework that is not installed.
