"""Offline tests for taintward.sdk.integrations (no API keys, no network).

Framework tests use fake models / mocked HTTP transports and are skipped when
the framework is not installed. They check that:

  * the raw SSN and AWS key never reach an external tool or an outgoing LLM
    request,
  * internal tools receive the reversible token (not the raw value, not a mask),
  * the LLM gets stable placeholders (<SSN_1>) by default, masks when
    placeholders are turned off (end-to-end placeholder tests are in
    tests/test_placeholders.py),
  * spans carry the destination, taint, violation and gen_ai.* attributes,
  * no raw secret is stored on any span.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json

import pytest
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from taintward.sdk import instrumentation as instr
from taintward.sdk import integrations as aw
from taintward.sdk.integrations import ToolPolicy, Ward

SSN = "234-12-1234"
AWS = "AKIAIOSFODNN7EXAMPLE"
RECORD = f"alice ssn {SSN} key {AWS}"
RAW = (SSN, AWS)


def _has(mod: str) -> bool:
    return importlib.util.find_spec(mod) is not None


needs_langchain = pytest.mark.skipif(
    not (_has("langchain_core") and _has("langgraph")), reason="langchain/langgraph not installed")
needs_agents = pytest.mark.skipif(not _has("agents"), reason="openai-agents not installed")
needs_openai = pytest.mark.skipif(
    not (_has("openai") and _has("httpx")), reason="openai not installed")
needs_anthropic = pytest.mark.skipif(
    not (_has("anthropic") and _has("httpx")), reason="anthropic not installed")


@pytest.fixture
def otel():
    provider = TracerProvider(resource=Resource.create({"service.name": "test"}))
    exporter = InMemorySpanExporter()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    yield provider.get_tracer("taintward"), exporter
    provider.shutdown()


@pytest.fixture
def ward(otel):
    tracer, _ = otel
    return Ward(
        {"lookup": "internal", "store": "internal", "send_email": ("external", "us")},
        tracer=tracer,
        llm_jurisdiction="us",
    )


def _spans(exporter, name=None):
    spans = exporter.get_finished_spans()
    return [s for s in spans if name is None or s.name == name]


def _assert_no_raw_in_spans(exporter):
    for s in exporter.get_finished_spans():
        blob = json.dumps(dict(s.attributes or {}), default=str)
        for raw in RAW:
            assert raw not in blob, f"raw value stored on span {s.name}"


def _assert_internal_token(value: str):
    """Internal tools get a format-preserving token: SSN shape, not raw, not a mask."""
    assert SSN not in value and AWS not in value
    assert "[PII]" not in value
    token = value.split("ssn ", 1)[1].split()[0]
    assert len(token) == len(SSN) and token[3] == "-" and token[6] == "-"
    try:  # exact reversal, when the redactor exposes it
        from taintward.sdk.redact import get_redactor
        rev = get_redactor().reverse(token)
    except Exception:
        rev = None
    if rev is not None:
        assert rev == SSN


# ---------------------------------------------------------------------------
# Core: policy map, init, async decorator
# ---------------------------------------------------------------------------


class TestPolicy:
    def test_unmapped_tool_defaults_to_external(self):
        w = Ward({"search_db": "internal"})
        assert w.policy_for("search_db").destination == "internal"
        assert w.policy_for("something_new").destination == "external"
        assert aw.DEFAULT_DESTINATION == "external"

    def test_policy_forms(self):
        w = Ward({
            "a": "log",
            "b": ("external", "eu"),
            "c": {"destination": "rag", "allow": ["q"]},
            "d": ToolPolicy("internal"),
        })
        assert w.policy_for("a") == ToolPolicy("log")
        assert w.policy_for("b") == ToolPolicy("external", "eu")
        assert w.policy_for("c").allow == frozenset({"q"})
        assert w.policy_for("d").destination == "internal"

    def test_typo_in_destination_is_rejected(self):
        with pytest.raises(ValueError):
            Ward({"x": "intrenal"})

    def test_overrides_merge_over_base_map(self):
        w = Ward({"a": "internal"}).with_overrides({"b": "log"})
        assert w.policy_for("a").destination == "internal"
        assert w.policy_for("b").destination == "log"

    def test_init_with_tracer_sets_global(self, otel):
        tracer, _ = otel
        w = aw.init("svc", destinations={"t": "internal"}, tracer=tracer)
        assert aw.get_ward() is w
        assert w.policy_for("t").destination == "internal"


class TestAsyncDecorator:
    def test_async_tool_is_redacted_and_traced(self, otel):
        tracer, exporter = otel
        seen = {}

        @instr.instrument_tool("ext", destination=instr.DEST_EXTERNAL, tracer=tracer)
        async def ext(payload: str) -> str:
            await asyncio.sleep(0)
            seen["payload"] = payload
            return "ok"

        assert asyncio.run(ext(RECORD)) == "ok"
        assert SSN not in seen["payload"] and AWS not in seen["payload"]
        span = _spans(exporter, "ext")[0]
        assert span.attributes["taintward.violation"] is True
        assert span.attributes["taintward.redacted"] is True
        _assert_no_raw_in_spans(exporter)

    def test_run_box_carries_taint_across_copied_contexts(self, otel):
        """A tool run inside a copied context (as LangChain/LangGraph do) still
        taints the next tool of the same run."""
        import contextvars
        tracer, exporter = otel

        @instr.instrument_tool("src", destination=instr.DEST_INTERNAL, tracer=tracer)
        def src() -> str:
            return RECORD

        @instr.instrument_tool("sink", destination=instr.DEST_EXTERNAL, tracer=tracer)
        def sink(text: str) -> str:
            return "sent"

        instr.begin_run("r", tracer=tracer)
        try:
            contextvars.copy_context().run(src)
            sink("nothing sensitive in this text")
        finally:
            instr.end_run()
        span = _spans(exporter, "sink")[0]
        assert span.attributes["taintward.violation"] is True
        assert "pii" in span.attributes["taintward.taint.classes"]
        assert instr.current_taint() is None  # clean slate after the run


# ---------------------------------------------------------------------------
# LangChain / LangGraph
# ---------------------------------------------------------------------------


def _lc_tools(seen):
    from langchain_core.tools import tool

    @tool
    def lookup(employee: str) -> str:
        """Look up an employee record."""
        return RECORD

    @tool
    def send_email(to: str, body: str) -> str:
        """Send an email to an external address."""
        seen["send_email"] = {"to": to, "body": body}
        return "sent"

    @tool
    def store(record: str) -> str:
        """Store a record in the internal cache."""
        seen["store"] = record
        return "stored"

    return [lookup, send_email, store]


def _fake_model(script, requests):
    from langchain_core.language_models.fake_chat_models import (
        FakeMessagesListChatModel,
    )
    from langchain_core.messages import AIMessage

    class FakeToolModel(FakeMessagesListChatModel):
        def bind_tools(self, tools, **kwargs):
            return self

        def _generate(self, messages, stop=None, run_manager=None, **kwargs):
            requests.append(list(messages))  # what the provider would receive
            return super()._generate(messages, stop=stop, run_manager=run_manager, **kwargs)

    responses = []
    for i, step in enumerate(script):
        if step is None:
            responses.append(AIMessage("done"))
        else:
            responses.append(AIMessage("", tool_calls=[
                {"name": n, "args": a, "id": f"call_{i}_{j}"} for j, (n, a) in enumerate(step)
            ]))
    return FakeToolModel(responses=responses)


LC_SCRIPT = [
    [("lookup", {"employee": "alice"})],
    [("send_email", {"to": "auditor@example.com", "body": f"ssn {SSN} key {AWS}"})],
    [("store", {"record": f"ssn {SSN} key {AWS}"})],
    None,
]


def _build_agent(builder, model, tools):
    if builder == "langchain.create_agent":
        agents = pytest.importorskip("langchain.agents")
        return agents.create_agent(model, tools)
    import warnings

    from langgraph.prebuilt import create_react_agent
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # deprecated in favor of create_agent
        return create_react_agent(model, tools)


def _request_text(requests) -> str:
    return json.dumps([[(m.type, m.content, getattr(m, "tool_calls", None)) for m in r]
                       for r in requests], default=str)


@needs_langchain
class TestLangChain:
    def test_wrapped_tools_keep_identity_and_schema(self, ward):
        from langchain_core.tools import StructuredTool
        seen = {}
        originals = _lc_tools(seen)
        wrapped = aw.Ward.wrap_langchain_tools(ward, originals)
        for o, w in zip(originals, wrapped):
            assert isinstance(w, StructuredTool)
            assert w.name == o.name and w.description == o.description
            assert w.args == o.args
            assert w.tool_call_schema.model_json_schema() == o.tool_call_schema.model_json_schema()
            assert type(o) is StructuredTool  # original object untouched
        # wrapping twice does not stack wrappers
        again = ward.wrap_langchain_tools(wrapped)
        assert type(again[0]).__mro__[1] is StructuredTool

    def test_direct_invoke_redacts_per_destination(self, ward, otel):
        _, exporter = otel
        seen = {}
        _lookup, send_email, store = ward.wrap_langchain_tools(_lc_tools(seen))
        send_email.invoke({"to": "auditor@example.com", "body": RECORD})
        store.invoke({"record": RECORD})
        assert SSN not in seen["send_email"]["body"] and AWS not in seen["send_email"]["body"]
        assert "[PII]" in seen["send_email"]["body"] and "[SECRET]" in seen["send_email"]["body"]
        _assert_internal_token(seen["store"])
        span = _spans(exporter, "send_email")[0]
        assert span.attributes["taintward.destination"] == "external"
        assert span.attributes["taintward.jurisdiction"] == "us"
        assert span.attributes["gen_ai.tool.name"] == "send_email"
        assert span.attributes["taintward.violation"] is True
        _assert_no_raw_in_spans(exporter)

    def test_allow_list_passes_named_arg_unredacted(self, otel):
        tracer, _ = otel
        seen = {}
        w = Ward({"send_email": {"destination": "external", "allow": ["to"]}}, tracer=tracer)
        send_email = w.wrap_langchain_tools(_lc_tools(seen))[1]
        send_email.invoke({"to": "auditor@example.com", "body": RECORD})
        assert seen["send_email"]["to"] == "auditor@example.com"
        assert SSN not in seen["send_email"]["body"]

    @pytest.mark.parametrize("builder", ["langchain.create_agent", "langgraph.create_react_agent"])
    def test_agent_loop(self, ward, otel, builder):
        _, exporter = otel
        seen, requests = {}, []
        model = ward.protect_langchain_model(_fake_model(LC_SCRIPT, requests))
        agent = _build_agent(builder, model, ward.wrap_langchain_tools(_lc_tools(seen)))
        with ward.run("lg.run"):
            out = agent.invoke({"messages": [("user", f"my ssn is {SSN}, email it")]})
        assert out["messages"][-1].content == "done"

        # external tool + every LLM request: no raw values
        body = seen["send_email"]["body"]
        assert SSN not in body and AWS not in body
        text = _request_text(requests)
        assert len(requests) == 4
        for raw in RAW:
            assert raw not in text
        # placeholders (on by default) instead of masks, stable across turns
        assert "<SSN_1>" in text and "<AWS_KEY_1>" in text
        assert "[PII]" not in text and "<SSN_2>" not in text
        # internal tool: reversible token
        _assert_internal_token(seen["store"])

        chat_spans = [s for s in _spans(exporter) if s.name.startswith("chat ")]
        assert len(chat_spans) == 4
        for s in chat_spans:
            assert s.attributes["taintward.destination"] == "llm"
            assert s.attributes["gen_ai.operation.name"] == "chat"
            assert s.attributes["taintward.jurisdiction"] == "us"
        email = _spans(exporter, "send_email")[0]
        assert email.attributes["taintward.violation"] is True
        assert set(email.attributes["taintward.taint.classes"].split(",")) == {"pii", "secret"}
        assert "taintward.violation" not in _spans(exporter, "store")[0].attributes
        # one trace for the whole run
        assert len({s.context.trace_id for s in _spans(exporter)}) == 1
        _assert_no_raw_in_spans(exporter)

    def test_agent_loop_with_placeholders_off_uses_masks(self, otel):
        tracer, exporter = otel
        w = Ward({"lookup": "internal", "store": "internal", "send_email": "external"},
                 tracer=tracer, placeholders=False)
        seen, requests = {}, []
        model = w.protect_langchain_model(_fake_model(LC_SCRIPT, requests))
        agent = _build_agent("langgraph.create_react_agent", model,
                             w.wrap_langchain_tools(_lc_tools(seen)))
        with w.run("lg.masks"):
            agent.invoke({"messages": [("user", f"my ssn is {SSN}, email it")]})
        text = _request_text(requests)
        for raw in RAW:
            assert raw not in text
        assert "[PII]" in text and "[SECRET]" in text
        assert "<SSN_1>" not in text
        _assert_internal_token(seen["store"])
        _assert_no_raw_in_spans(exporter)

    def test_agent_loop_async(self, ward, otel):
        _, exporter = otel
        seen, requests = {}, []
        model = ward.protect_langchain_model(_fake_model(LC_SCRIPT, requests))
        agent = _build_agent("langgraph.create_react_agent", model,
                             ward.wrap_langchain_tools(_lc_tools(seen)))

        async def go():
            with ward.run("lg.arun"):
                return await agent.ainvoke({"messages": [("user", f"ssn {SSN}")]})

        asyncio.run(go())
        assert SSN not in seen["send_email"]["body"]
        for raw in RAW:
            assert raw not in _request_text(requests)
        _assert_internal_token(seen["store"])
        _assert_no_raw_in_spans(exporter)

    def test_stream_path_is_redacted(self, ward, otel):
        from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
        from langchain_core.messages import AIMessage
        _, exporter = otel
        captured = []

        class Rec(GenericFakeChatModel):
            def _stream(self, messages, stop=None, run_manager=None, **kwargs):
                captured.append(messages)
                yield from super()._stream(messages, stop=stop, run_manager=run_manager, **kwargs)

        model = ward.protect_langchain_model(Rec(messages=iter([AIMessage("ok")])))
        "".join(c.content for c in model.stream(f"key {AWS}"))
        assert AWS not in str(captured)
        assert any(s.attributes.get("taintward.destination") == "llm" for s in _spans(exporter))
        _assert_no_raw_in_spans(exporter)


# ---------------------------------------------------------------------------
# Mocked provider HTTP (OpenAI / Anthropic wire format)
# ---------------------------------------------------------------------------


def _chat_completion(model, step, n):
    if step is None:
        msg, reason = {"role": "assistant", "content": "done"}, "stop"
    else:
        msg = {"role": "assistant", "content": None, "tool_calls": [
            {"id": f"call_{n}_{i}", "type": "function",
             "function": {"name": name, "arguments": json.dumps(args)}}
            for i, (name, args) in enumerate(step)]}
        reason = "tool_calls"
    return {"id": f"cc_{n}", "object": "chat.completion", "created": 0, "model": model,
            "choices": [{"index": 0, "message": msg, "finish_reason": reason}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}}


def _openai_handler(bodies, script=None):
    import httpx

    def handler(request):
        body = json.loads(request.content)
        bodies.append(body)
        if request.url.path.endswith("/responses"):
            return httpx.Response(200, json={
                "id": "resp_1", "object": "response", "created_at": 0, "model": body["model"],
                "status": "completed", "parallel_tool_calls": True, "tool_choice": "auto",
                "tools": [], "output": [{
                    "type": "message", "id": "msg_1", "role": "assistant", "status": "completed",
                    "content": [{"type": "output_text", "text": "ok", "annotations": []}]}]})
        step = script[len(bodies) - 1] if script else None
        return httpx.Response(200, json=_chat_completion(body["model"], step, len(bodies)))

    return handler


@needs_openai
class TestOpenAIClient:
    def _client(self, bodies):
        import httpx
        import openai
        return openai.OpenAI(api_key="test", base_url="http://fake.local/v1",
                             http_client=httpx.Client(transport=httpx.MockTransport(
                                 _openai_handler(bodies))))

    def test_chat_completions_request_is_redacted(self, ward, otel):
        _, exporter = otel
        bodies = []
        client = ward.protect_openai(self._client(bodies))
        ward.protect_openai(client)  # idempotent
        resp = client.chat.completions.create(model="gpt-test", messages=[
            {"role": "system", "content": "you are an HR bot"},
            {"role": "user", "content": f"my ssn is {SSN}"},
            {"role": "assistant", "content": None, "tool_calls": [{
                "id": "call_1", "type": "function",
                "function": {"name": "lookup", "arguments": json.dumps({"q": AWS})}}]},
            {"role": "tool", "tool_call_id": "call_1", "content": RECORD},
        ])
        assert resp.choices[0].message.content == "done"
        sent = json.dumps(bodies[0])
        for raw in RAW:
            assert raw not in sent
        # protocol fields survive untouched
        assert bodies[0]["messages"][3]["tool_call_id"] == "call_1"
        assert bodies[0]["messages"][2]["tool_calls"][0]["function"]["name"] == "lookup"
        span = _spans(exporter, "chat gpt-test")[0]
        a = span.attributes
        assert a["taintward.destination"] == "llm"
        assert a["gen_ai.provider.name"] == "openai"
        assert a["gen_ai.request.model"] == "gpt-test"
        assert a["gen_ai.usage.input_tokens"] == 11
        assert a["taintward.violation"] is True and a["taintward.redacted"] is True
        _assert_no_raw_in_spans(exporter)

    def test_responses_api_request_is_redacted(self, ward, otel):
        _, exporter = otel
        bodies = []
        client = ward.protect_openai(self._client(bodies))
        client.responses.create(model="gpt-test", instructions=f"key {AWS}",
                                input=f"my ssn is {SSN}")
        sent = json.dumps(bodies[0])
        for raw in RAW:
            assert raw not in sent
        assert _spans(exporter, "chat gpt-test")[0].attributes["taintward.destination"] == "llm"

    def test_clean_request_is_not_flagged(self, ward, otel):
        _, exporter = otel
        bodies = []
        client = ward.protect_openai(self._client(bodies))
        with ward.run("clean.run"):  # clean taint slate
            client.chat.completions.create(
                model="gpt-test", messages=[{"role": "user", "content": "hello there"}])
        assert bodies[0]["messages"][0]["content"] == "hello there"
        a = _spans(exporter, "chat gpt-test")[0].attributes
        assert "taintward.violation" not in a
        assert a["taintward.redacted"] is False


@needs_anthropic
class TestAnthropicClient:
    def test_messages_request_is_redacted(self, ward, otel):
        import anthropic
        try:  # newer anthropic SDKs ship their own httpx fork
            import httpx2 as httpx
        except ImportError:
            import httpx
        _, exporter = otel
        bodies = []

        def handler(request):
            bodies.append(json.loads(request.content))
            return httpx.Response(200, json={
                "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-test",
                "content": [{"type": "text", "text": "noted"}], "stop_reason": "end_turn",
                "stop_sequence": None, "usage": {"input_tokens": 9, "output_tokens": 2}})

        client = anthropic.Anthropic(api_key="test", base_url="http://fake.local",
                                     http_client=httpx.Client(transport=httpx.MockTransport(handler)))
        ward.protect_anthropic(client)
        client.messages.create(model="claude-test", max_tokens=50, system=f"key {AWS}", messages=[
            {"role": "user", "content": [{"type": "text", "text": f"ssn {SSN}"}]},
            {"role": "assistant", "content": [{"type": "tool_use", "id": "tu_1",
                                               "name": "lookup", "input": {"q": SSN}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "tu_1",
                                          "content": RECORD}]},
        ])
        sent = json.dumps(bodies[0])
        for raw in RAW:
            assert raw not in sent
        assert bodies[0]["messages"][2]["content"][0]["tool_use_id"] == "tu_1"
        a = _spans(exporter, "chat claude-test")[0].attributes
        assert a["gen_ai.provider.name"] == "anthropic"
        assert a["taintward.destination"] == "llm"
        assert a["gen_ai.usage.output_tokens"] == 2
        _assert_no_raw_in_spans(exporter)


# ---------------------------------------------------------------------------
# OpenAI Agents SDK
# ---------------------------------------------------------------------------


@needs_agents
@needs_openai
class TestOpenAIAgents:
    def _tools(self, seen):
        from agents import function_tool

        @function_tool
        def lookup(employee: str) -> str:
            """Look up an employee record."""
            return RECORD

        @function_tool
        def send_email(to: str, body: str) -> str:
            """Send an email to an external address."""
            seen["send_email"] = body
            return "sent"

        @function_tool
        async def store(record: str) -> str:
            """Store a record in the internal cache."""
            seen["store"] = record
            return "stored"

        return [lookup, send_email, store]

    def test_wrapped_function_tool_keeps_schema(self, ward):
        from agents import FunctionTool
        originals = self._tools({})
        wrapped = ward.wrap_function_tools(originals)
        for o, w in zip(originals, wrapped):
            assert isinstance(w, FunctionTool)
            assert (w.name, w.description, w.params_json_schema, w.strict_json_schema) == \
                   (o.name, o.description, o.params_json_schema, o.strict_json_schema)
            assert w.on_invoke_tool is not o.on_invoke_tool
        assert ward.wrap_function_tools(wrapped)[0].on_invoke_tool is wrapped[0].on_invoke_tool

    def test_agent_run_with_protected_client(self, ward, otel):
        import httpx
        import openai
        from agents import (
            Agent,
            OpenAIChatCompletionsModel,
            Runner,
            set_tracing_disabled,
        )
        set_tracing_disabled(True)
        _, exporter = otel
        seen, bodies = {}, []
        script = [
            [("lookup", {"employee": "alice"})],
            [("send_email", {"to": "auditor@example.com", "body": f"ssn {SSN} key {AWS}"}),
             ("store", {"record": f"ssn {SSN} key {AWS}"})],
            None,
        ]
        client = openai.AsyncOpenAI(
            api_key="test", base_url="http://fake.local/v1",
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(
                _openai_handler(bodies, script))))
        ward.protect_openai(client)
        agent = Agent(name="hr", instructions="You are an HR bot.",
                      model=OpenAIChatCompletionsModel(model="gpt-test", openai_client=client),
                      tools=ward.wrap_function_tools(self._tools(seen)))

        async def go():
            with ward.run("agents.run"):
                return await Runner.run(agent, f"my ssn is {SSN}")

        result = asyncio.run(go())
        assert result.final_output == "done"
        assert len(bodies) == 3
        for b in bodies:
            for raw in RAW:
                assert raw not in json.dumps(b)
        assert SSN not in seen["send_email"] and AWS not in seen["send_email"]
        assert "[PII]" in seen["send_email"]
        _assert_internal_token(seen["store"])

        email = _spans(exporter, "send_email")[0].attributes
        assert email["taintward.destination"] == "external"
        assert email["gen_ai.tool.name"] == "send_email"
        assert email["taintward.framework"] == "openai-agents"
        assert email["taintward.violation"] is True
        chat = _spans(exporter, "chat gpt-test")
        assert len(chat) == 3 and all(s.attributes["taintward.destination"] == "llm" for s in chat)
        _assert_no_raw_in_spans(exporter)
