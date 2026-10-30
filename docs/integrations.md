# Framework integrations

`taintward/sdk/integrations/` lets you protect an existing agent without putting
`@instrument_tool(...)` on every tool. You write one map of tool names to
destinations, then pass your tools, your model or your LLM client through an
adapter. The adapters use the same gate as `@instrument_tool`
(`taintward.sdk.instrumentation.GuardedCall`, which calls `taintward.sdk.detect` and
`taintward.sdk.redact.redact_payload`), so detection and redaction behave the same.

## Install

| framework | extra | tools | model |
|---|---|---|---|
| LangChain, LangGraph | `langchain` | `wrap_langchain_tools` | `protect_langchain_model` |
| OpenAI Agents SDK | `openai-agents` | `wrap_function_tools` | `protect_openai` |
| CrewAI | `crewai` | `wrap_crewai_tools` | `protect_crewai_llm` |
| LlamaIndex | `llamaindex` | `wrap_llamaindex_tools` | `protect_llamaindex_llm` |
| Pydantic AI | `pydantic-ai` | `wrap_pydantic_ai_tools`, `wrap_pydantic_ai_toolset` | `protect_pydantic_ai_model` |
| Google ADK | `google-adk` | `wrap_adk_tools` | `protect_adk_model` |
| LiteLLM | `litellm` | | `protect_litellm`, proxy `TaintwardGuardrail` |
| OpenAI, Anthropic clients | `llm` | | `protect_openai`, `protect_anthropic` |

```bash
pip install "taintward[crewai]"      # or any extra above
python -m spacy download en_core_web_sm
```

Every name above is also on the top level package (`taintward.wrap_crewai_tools`).

## Setup

```python
from taintward.sdk import integrations as taintward

taintward.init(
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
- `placeholders=False` sends `[PII]` masks to the LLM instead of placeholders
  (see [Placeholders](#placeholders-the-model-can-still-do-its-job)).
  `placeholder_vault=` and `placeholder_ttl=` keep placeholders of long
  conversations in a vault.
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
with taintward.run("hr-agent.run"):
    agent.invoke(...)
```

`run()` creates one root span for the run and starts with a clean taint slate.
It also keeps the run's taint visible across the threads and asyncio tasks
that frameworks use to run tools, so a later tool or LLM call in the same run
is still flagged after an earlier tool read sensitive data. Without `run()`,
redaction still works (it is based on what is detected in each input), but the
chain taint can be lost between tools.

## Placeholders: the model can still do its job

With plain masks the model gets `[PII]` and loses the meaning of the task.
"Write to [PII] about her tax form" does not say who the letter is for, and two
different people both look like `[PII]`. So by default the integrations send
**placeholders** to the LLM instead of masks, and swap them back on the way
out.

Before (masks, `placeholders=False`):

```text
user    : Remind Alice Lee (alice.lee@example.com) that her tax form is missing.
to LLM  : Remind [PII] ([PII]) that her tax form is missing.
model   : Done: I emailed [PII] at [PII].           <- useless to the user
email to: [PII]                                     <- the email goes nowhere
```

After (placeholders, the default):

```text
user    : Remind Alice Lee (alice.lee@example.com) that her tax form is missing.
to LLM  : Remind <PERSON_1> (<EMAIL_1>) that her tax form is missing.
model   : send_email(to="<EMAIL_1>", body="Hi <PERSON_1>, your tax form is missing.")
          Done: I emailed <PERSON_1> at <EMAIL_1>.
email to: alice.lee@example.com       (the "to" argument is in the tool's allow list)
email   : Hi [PII], your tax form is missing.   (external body: still masked)
user    : Done: I emailed Alice Lee at alice.lee@example.com.
```

`python demo/langgraph_example.py` runs this example (`--masks` shows the
old behaviour).

### How it works

1. **Going to the LLM.** Every sensitive value is replaced by a typed,
   numbered placeholder: `<PERSON_1>`, `<SSN_1>`, `<EMAIL_2>`, `<AWS_KEY_1>`.
   In one run the same value always gets the same placeholder and a new value
   gets the next number, so the model sees the same `<PERSON_1>` in every
   turn.
2. **The map stays local.** The map from placeholder to real value lives in
   memory for the run (`taintward.run(...)`). It is never sent to the
   provider, never written to a span, and it is cleared when the run ends.
   Outside `run()`, each LLM call gets its own fresh map, so two users never
   share one.
3. **Coming back from the LLM.** The protected model or client restores the
   model's answer before your code sees it: the text, and the arguments of
   every tool call (OpenAI JSON argument strings, Anthropic `tool_use.input`,
   LangChain `tool_calls`). JSON stays valid even if a real value has quotes
   in it. Spacing and case variants like `< PERSON_1 >` or `<person_1>` are
   restored too. Placeholders the model made up (for example `<PERSON_7>`
   when there is no seventh person) are left as they are.
4. **Going to a tool.** A tool always gets what it would get if the model had
   written the real value. If a placeholder is still in the arguments (for
   example from a streamed answer that was not restored), the wrapped tool
   swaps it for the real value first. Then the normal destination gate runs:

| tool destination | what the tool receives for `<SSN_1>` |
| --- | --- |
| `internal` | the reversible FF1 token of the real SSN |
| `external`, `log`, `rag` | the mask `[PII]` |
| argument in the tool's `allow` list | the real SSN |

Why an internal tool gets the token and not the raw value: that is the rule
for internal sinks everywhere else in Taintward. The internal store can
still match and join on the token, `get_redactor().reverse(token)` gives the
real value back where it is truly needed, and the store never holds raw PII.
If a tool needs the real value (a database query by name, say), put that
argument in its `allow` list. That is an explicit, reviewable decision.

Why an external tool gets the mask and not the placeholder: a placeholder
means nothing outside this process, and the external side should not learn
how many people or keys the conversation is about. The mask is also what
external sinks got before, so turning placeholders on does not send an
external tool anything new, except in the arguments you put in its `allow`
list (which is what `allow` is for).

The gate also redacts every value the map already knows, even where the
detector would miss it in a new context. A bare `Alice Lee` in a log line is
masked because the map saw that name earlier in the run.

### Long conversations

For a conversation that spans many runs (a chat app), pass a vault and a
conversation id:

```python
from taintward.sdk.vault import get_vault

taintward.init("hr-agent", destinations={...},
               placeholder_vault=get_vault("sqlite:///var/lib/taintward/vault.db"),
               placeholder_ttl=7 * 24 * 3600)

with taintward.run("turn", conversation_id=chat_id):
    ...
```

The placeholders are stored through the normal vault API (encrypted at rest
with `SQLiteVault`). Vault keys hold only keyed hashes (HMAC) of the value and
the conversation id, never the value itself. Each entry is tagged with the
conversation, so `PlaceholderMap.forget_conversation()` erases all of them.

### Turning it off

```python
taintward.init("hr-agent", destinations={...}, placeholders=False)
```

The LLM then gets `[PII]` / `[SECRET]` masks again and nothing is restored.
The decorator path (`@instrument_tool`) does not use placeholders.

### What placeholders still reveal

- **The type of data.** `<SSN_1>` tells the provider that the user shared an
  SSN. A mask (`[PII]`) said a little less.
- **How many values and which ones repeat.** `<PERSON_1>` and `<PERSON_2>`
  are two people; `<PERSON_1>` in turn 1 and turn 5 is the same person.
- **Context.** The text around a placeholder is sent as it is. "Her tax form,
  <PERSON_1>, the CFO of our Berlin office" may be enough for the model to
  guess who it is. Placeholders hide the value, not the story.
- **Only detected values are replaced.** A value the detector does not find
  (and that the map has not seen before) goes to the provider as it is, same
  as with masks.
- **Restore trusts the run's map.** If text that reaches the model contains a
  placeholder (for example a web page with `<SSN_1>` in it) and the model
  copies it into its answer, it is restored for the caller of that run. The
  caller only ever gets values from its own run, and tools still get only
  what their destination allows.

## LangChain and LangGraph

```python
tools = taintward.wrap_langchain_tools([search_db, cache_record, send_email])
model = taintward.protect_langchain_model(ChatOpenAI(model="gpt-4o-mini"))
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

client = taintward.protect_openai(AsyncOpenAI())
set_default_openai_client(client)           # the agent's model calls are redacted

agent = Agent(name="hr", tools=taintward.wrap_function_tools([search_db, send_email]))
with taintward.run("hr.run"):
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
client = taintward.protect_openai(OpenAI())          # or AsyncOpenAI()
client = taintward.protect_anthropic(Anthropic())    # or AsyncAnthropic()
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

## CrewAI

```python
from crewai import LLM, Agent

agent = Agent(role="support", goal="...", backstory="...",
              llm=taintward.protect_crewai_llm(LLM(model="gpt-4.1")),
              tools=taintward.wrap_crewai_tools([search_db, send_email]))
with taintward.run("support.run"):
    crew.kickoff()
```

- `wrap_crewai_tools(tools, mapping=None)` returns protected copies of CrewAI
  tools (`BaseTool` subclasses and `@tool` functions). Only `_run` / `_arun`
  change, which CrewAI calls for every tool use, so the args schema,
  caching, usage limits and `result_as_answer` stay the same.
- `protect_crewai_llm(llm)` returns a protected copy of `crewai.LLM` or any
  `BaseLLM`. `call` / `acall` send the messages redacted and restore the
  answer before CrewAI parses it, so `Action Input` reaches the wrapped tool
  with real values. Tools that CrewAI runs inside `call` (native function
  calling) see the same placeholder map.

## LlamaIndex

```python
from llama_index.core.agent.workflow import FunctionAgent
from llama_index.llms.openai import OpenAI

agent = FunctionAgent(tools=taintward.wrap_llamaindex_tools([search_tool, email_tool]),
                      llm=taintward.protect_llamaindex_llm(OpenAI(model="gpt-4.1")))
with taintward.run("support.run"):
    await agent.run(user_msg="...")
```

- `wrap_llamaindex_tools(tools, mapping=None)` protects `FunctionTool`,
  `QueryEngineTool` or any LlamaIndex tool through `call` / `acall`. A
  workflow `Context` argument is passed through untouched.
- `protect_llamaindex_llm(llm)` covers `chat`, `achat`, `complete`,
  `acomplete` and their `stream_*` versions, and so also
  `chat_with_tools` and the agents. Text blocks, tool call blocks and
  `additional_kwargs` (OpenAI style tool calls) are redacted and restored.
  In a stream each chunk's message (the text so far) is restored, so the
  last chunk is complete. `response.raw` keeps the provider's own
  response, with placeholders.

## Pydantic AI

```python
from pydantic_ai import Agent

agent = Agent(taintward.protect_pydantic_ai_model("openai:gpt-4.1"),
              toolsets=[taintward.wrap_pydantic_ai_tools([search_db, send_email])])
with taintward.run("support.run"):
    result = await agent.run("...")
```

- `protect_pydantic_ai_model(model)` returns a `TaintwardModel`, a Pydantic
  AI `WrapperModel` around a model object or name. Prompts, instructions,
  tool results, retry prompts and earlier responses are redacted; the
  response is restored (text, thinking, tool call arguments). One
  instruction line is added to the request's `instructions`.
- `wrap_pydantic_ai_tools(tools)` builds a `FunctionToolset` and wraps it;
  `wrap_pydantic_ai_toolset(toolset)` wraps any toolset, MCP servers
  included. Each call goes through the gate after Pydantic AI validated the
  arguments.
- Tools added with `@agent.tool` are in the agent's own toolset and are not
  covered. Pass them to `wrap_pydantic_ai_tools` instead.

## Google ADK

```python
from google.adk.agents import LlmAgent

agent = LlmAgent(name="support",
                 model=taintward.protect_adk_model("gemini-2.5-flash"),
                 tools=taintward.wrap_adk_tools([search_db, send_email, mcp_toolset]))
with taintward.run("support.run"):
    async for event in runner.run_async(...):
        ...
```

- `wrap_adk_tools(tools, mapping=None)` takes what `LlmAgent(tools=...)`
  takes: functions (made into `FunctionTool`), `BaseTool` objects and
  toolsets such as `McpToolset`, whose tools are wrapped as they are listed.
  The `ToolContext` is passed through untouched.
- `protect_adk_model(model)` takes a `BaseLlm` or a model name and covers
  `generate_content_async`: text parts, function call arguments, function
  responses and the system instruction are redacted, and every response is
  restored, streamed chunks included.

## LiteLLM

SDK:

```python
import litellm

taintward.protect_litellm()          # patches litellm.completion and acompletion
resp = litellm.completion(model="gpt-4.1", messages=[...])
```

Call them as `litellm.completion(...)`: a name imported with `from litellm
import completion` before the patch is not covered. The response is
restored like the OpenAI client's.

Proxy: add the guardrail to the proxy config and install `taintward` in the
proxy's environment.

```yaml
guardrails:
  - guardrail_name: taintward
    litellm_params:
      guardrail: taintward.sdk.integrations.litellm.TaintwardGuardrail
      mode: [pre_call, post_call]
      default_on: true
```

`pre_call` redacts `messages` before the provider gets them and records the
span; `post_call` puts the real values back into the answer for the client.
The placeholder map of each request stays in the proxy's memory between the
two hooks (at most 10,000 requests in flight, oldest dropped first) and is
never sent anywhere. Streaming requests get masks instead of placeholders,
because the guardrail does not restore a stream.

## What the spans carry

| attribute | meaning |
| --- | --- |
| `taintward.destination` | `internal`, `external`, `llm`, `log` or `rag` |
| `taintward.jurisdiction` | from the map (or `llm_jurisdiction` for LLM spans) |
| `taintward.taint.classes`, `taintward.taint.level`, `taintward.sensitive` | taint of the call |
| `taintward.violation` | a tainted run reached an external, llm or log sink |
| `taintward.redacted` | the gate changed what the sink received |
| `taintward.framework` | `langchain`, `openai-agents`, `openai.chat`, `openai.responses`, `anthropic` |
| `gen_ai.tool.name`, `gen_ai.operation.name` | tool spans (`execute_tool`) and LLM spans (`chat`) |
| `gen_ai.tool.call.arguments` / `gen_ai.input.messages` | input after redaction |
| `gen_ai.tool.call.result` / `gen_ai.output.messages` | output, masked |
| `taintward.args_redacted` | the stored tool arguments are already redacted, so the collector keeps them (and their reversible tokens) as they are |
| `taintward.taint.source_span` | span id of the call that first found the sensitive data |
| `taintward.tool.error` | the sink raised; the message with sensitive data masked |

A sink that raises still gets its violation flag, and the exception event
on the span has its message and stack trace masked.

A wrapped tool that calls another wrapped tool takes on the inner call's
taint. If the inner tool returns an SSN and the outer one returns a clean
summary, the next external call is still a violation.

## Settings

All on/off settings accept `1`, `true`, `yes`, `on` and `0`, `false`, `no`,
`off` (any case). Any other value keeps the default and logs a warning.

| variable | default | meaning |
| --- | --- | --- |
| `TAINTWARD_DRY_RUN` | off | record violations but pass raw arguments to sinks (spans are still masked) |
| `TAINTWARD_MASK_IN_SDK` | on | mask tool I/O on spans in the process; turn off when a sidecar collector masks |
| `TAINTWARD_FAIL_CLOSED` | off | refuse calls to non-internal sinks while detection is degraded |

## Detection health

If spaCy or Presidio fail to load, detection does not stop. It logs one
ERROR and falls back to regex-only detection: SSNs, cards, emails, phone
numbers, IBANs, IP addresses and every secret pattern are still found, but
names and places are not. `taintward.sdk.detect.health()` returns
`{"ok": bool, "mode": "full" | "regex_only" | "broken", "error": str | None}`.
With `TAINTWARD_FAIL_CLOSED=1` a degraded SDK raises
`DetectionDegradedError` for external, llm, log and rag sinks, and the
gateway refuses those calls.

## Limits

- The LLM never gets reversible tokens. It gets placeholders (default) or
  masks. When the model passes a placeholder to an internal tool, the tool
  gets the reversible token of the real value (see Placeholders above).
- Streaming: with `stream=True` (OpenAI, Anthropic) or LangChain
  `stream()` / `astream()`, the request uses placeholders but the streamed
  chunks are not restored, because a placeholder can be split across chunks.
  Collect the text and call `taintward.restore(text)` inside the same
  `run()`. Tool calls built from a stream are still fine: wrapped tools
  restore placeholders in their arguments.
- Placeholders across processes: the in-memory map belongs to one process.
  With a vault, two processes writing new placeholders for the same
  conversation at the same moment can pick the same number. Serve one
  conversation from one process at a time.
- Allow-listed arguments reach the tool unredacted, but the copy stored on
  the span is redacted as for a `log` sink.
- Detection is the same as the rest of the SDK. Data that is changed into a
  form the detectors do not recognize is not redacted; the chain taint still
  flags the run (see `docs/spike-llm-hop.md`). False positives also apply, for
  example an email address is masked unless it is in `allow`.
- Tool outputs are not redacted when they return to your code. They are
  redacted when they are sent on: to the LLM by the protected model or client,
  or to another tool by its own gate.
- Streaming responses: the request is redacted and recorded, but the streamed
  output is not scanned (and not restored, see above).
- Streaming in the newer adapters: LlamaIndex and Google ADK restore
  streamed chunks (a placeholder split across two chunks is complete in
  the last one); Pydantic AI `run_stream` and LiteLLM `stream=True` keep
  placeholders in the stream (the proxy guardrail sends masks instead).
- Google ADK writes model requests, responses and tool arguments onto its
  own spans (`gcp.vertex.agent.*`) as ADK sees them, which is after
  Taintward restored them, so with real values. ADK 1.14 has no setting to
  turn this off. The Taintward collector drops those attributes by default
  (`drop_attributes`, see [Collector](guides/collector.md)); if ADK's traces
  go to a backend some other way, drop them there.
- CrewAI, LlamaIndex and LiteLLM have their own callbacks and logging
  (LiteLLM success callbacks, LlamaIndex callback handlers, CrewAI events)
  that run inside the model call. They see the redacted request and the
  model's answer with placeholders. Tool callbacks see what the tool got.
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

`crewai 1.15.33`, `llama-index-core 0.14.25`, `pydantic-ai-slim 2.63.0`,
`google-adk 1.14.1`, `litellm 1.106.6`, pinned in `constraints-adapters.txt`.
`tests/test_integrations_frameworks.py` runs each framework's own agent loop
(a Crew, a `ReActAgent`, a Pydantic AI `Agent`, an ADK `InMemoryRunner`) or
`litellm.completion` with a scripted model, offline. The `adapter-tests` CI
job installs them.
