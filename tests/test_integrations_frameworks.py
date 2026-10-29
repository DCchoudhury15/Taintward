"""Offline tests for the CrewAI, LlamaIndex, Pydantic AI, Google ADK and
LiteLLM adapters (no API keys, no network).

Each framework runs for real with a scripted fake model, so the tests check
the framework's own call path, not only the wrapper. Each class is skipped
when its framework is not installed (pip install "taintward[crewai]" etc.).
They check that:

  * no raw value reaches the model request,
  * the model's answer and tool calls come back with real values,
  * an internal tool gets the reversible token, an external tool the mask,
    an ``allow`` argument the real value,
  * spans carry the destination and the violation flag and hold no raw value.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os

import pytest
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from taintward.sdk.integrations import Ward

SSN = "234-12-1234"
EMAIL = "alice.lee@example.com"
ASK = f"Look up SSN {SSN} and email {EMAIL} about it"
RAW = (SSN, EMAIL)

os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")
os.environ.setdefault("PYDANTIC_AI_NO_BANNER", "1")


def _has(mod: str) -> bool:
    try:
        return importlib.util.find_spec(mod) is not None
    except ModuleNotFoundError:
        return False


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
    return Ward({"lookup": "internal",
                 "send_email": {"destination": "external", "allow": ["to"]}},
                tracer=tracer, llm_jurisdiction="us")


def no_raw(blob) -> bool:
    text = blob if isinstance(blob, str) else json.dumps(blob, default=str)
    return not any(r in text for r in RAW)


def spans(exporter, framework=None):
    out = []
    for s in exporter.get_finished_spans():
        a = dict(s.attributes or {})
        assert no_raw(a), f"raw value on span {s.name}"
        if framework is None or a.get("taintward.framework") == framework:
            out.append((s.name, a))
    return out


def check_spans(exporter, framework):
    got = spans(exporter, framework)
    llm = [a for n, a in got if a.get("taintward.destination") == "llm"]
    assert llm and all(a["gen_ai.operation.name"] == "chat" for a in llm)
    assert any(a.get("taintward.violation") for a in llm)
    by_tool = {a.get("gen_ai.tool.name"): a for _, a in got if a.get("gen_ai.tool.name")}
    assert by_tool["lookup"]["taintward.destination"] == "internal"
    assert not by_tool["lookup"].get("taintward.violation")
    assert by_tool["send_email"]["taintward.destination"] == "external"
    assert by_tool["send_email"]["taintward.violation"] is True


class Tools:
    """The two tools every framework test uses, recording what they got."""

    def __init__(self):
        self.got: dict = {}

    def lookup(self, ssn: str) -> str:
        """Look up a customer by SSN."""
        self.got["lookup"] = ssn
        return "customer 7 found"

    def send_email(self, to: str, body: str) -> str:
        """Send an email."""
        self.got["send_email"] = (to, body)
        return "sent"

    def check(self):
        token = self.got["lookup"]
        assert token != SSN and len(token) == len(SSN) and token[3] == "-"  # FF1 token
        to, body = self.got["send_email"]
        assert to == EMAIL                     # allow-listed
        assert SSN not in body and "[PII]" in body


# ---------------------------------------------------------------------------
# CrewAI
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _has("crewai"), reason="crewai not installed")
class TestCrewAI:
    def _crew(self, ward, tools, script, sent):
        from crewai import Agent, Crew, Task
        from crewai.llms.base_llm import BaseLLM
        from crewai.tools import tool

        from taintward.sdk.integrations.crewai import protect_llm, wrap_tools

        class Scripted(BaseLLM):
            def call(self, messages, *a, **kw):
                sent.append(json.dumps(messages, default=str))
                return script[min(len(sent), len(script)) - 1]

            def supports_function_calling(self):
                return False

        lookup = tool("lookup")(tools.lookup)
        send_email = tool("send_email")(tools.send_email)
        agent = Agent(role="support", goal="help", backstory="b",
                      llm=protect_llm(Scripted(model="scripted"), ward=ward),
                      tools=wrap_tools([lookup, send_email], ward=ward))
        task = Task(description=ASK, expected_output="a short answer", agent=agent)
        return Crew(agents=[agent], tasks=[task])

    def test_crew_run(self, ward, otel):
        tools, sent = Tools(), []
        script = [
            'Thought: look up\nAction: lookup\nAction Input: {"ssn": "<SSN_1>"}',
            'Thought: email\nAction: send_email\nAction Input: '
            '{"to": "<EMAIL_1>", "body": "About SSN <SSN_1>"}',
            "Thought: done\nFinal Answer: emailed <EMAIL_1>",
        ]
        with ward.run():
            out = self._crew(ward, tools, script, sent).kickoff()
        assert all(no_raw(s) for s in sent)
        assert "<SSN_1>" in sent[0] and "placeholders" in sent[0]
        assert out.raw == f"emailed {EMAIL}"
        tools.check()
        check_spans(otel[1], "crewai")

    def test_wrap_keeps_tool_shape(self, ward):
        from crewai.tools import BaseTool, tool

        from taintward.sdk.integrations.crewai import wrap_tool
        t = tool("lookup")(Tools().lookup)
        w = wrap_tool(t, ward=ward)
        assert isinstance(w, BaseTool) and isinstance(w, type(t))
        assert w.name == t.name and w.description == t.description
        assert wrap_tool(w, ward=ward) is w
        assert type(t).__name__ != type(w).__name__  # the original is unchanged


# ---------------------------------------------------------------------------
# LlamaIndex
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _has("llama_index.core"), reason="llama-index-core not installed")
class TestLlamaIndex:
    def _llm(self, script, sent):
        from llama_index.core.llms import (
            ChatMessage,
            ChatResponse,
            CompletionResponse,
            CustomLLM,
            LLMMetadata,
        )
        from llama_index.core.llms.callbacks import (
            llm_chat_callback,
            llm_completion_callback,
        )

        class Scripted(CustomLLM):
            @property
            def metadata(self):
                return LLMMetadata(model_name="scripted")

            @llm_chat_callback()
            def chat(self, messages, **kw):
                sent.append(json.dumps([m.model_dump(mode="json") for m in messages]))
                return ChatResponse(message=ChatMessage(role="assistant", content=script()))

            @llm_completion_callback()
            def complete(self, prompt, formatted=False, **kw):
                sent.append(prompt)
                return CompletionResponse(text=script())

            @llm_completion_callback()
            def stream_complete(self, prompt, formatted=False, **kw):
                sent.append(prompt)

                def gen():
                    text = ""
                    for piece in ("Mail <EMA", "IL_1> now"):
                        text += piece
                        yield CompletionResponse(text=text, delta=piece)
                return gen()

        return Scripted()

    def test_react_agent_run(self, ward, otel):
        from llama_index.core.agent.workflow import ReActAgent
        from llama_index.core.tools import FunctionTool

        from taintward.sdk.integrations.llamaindex import protect_llm, wrap_tools
        tools, sent = Tools(), []
        steps = iter([
            'Thought: look up.\nAction: lookup\nAction Input: {"ssn": "<SSN_1>"}',
            'Thought: email.\nAction: send_email\nAction Input: '
            '{"to": "<EMAIL_1>", "body": "About SSN <SSN_1>"}',
            "Thought: I can answer without using any more tools.\nAnswer: emailed <EMAIL_1>",
        ])
        llm = protect_llm(self._llm(lambda: next(steps), sent), ward=ward)
        agent = ReActAgent(tools=wrap_tools([FunctionTool.from_defaults(tools.lookup),
                                             FunctionTool.from_defaults(tools.send_email)],
                                            ward=ward), llm=llm, streaming=False)

        async def go():
            with ward.run():
                return await agent.run(user_msg=ASK)
        out = asyncio.run(go())
        assert all(no_raw(s) for s in sent)
        assert str(out) == f"emailed {EMAIL}"
        tools.check()
        check_spans(otel[1], "llamaindex")

    def test_chat_and_stream_are_restored_once(self, ward, otel):
        from llama_index.core.llms import ChatMessage

        from taintward.sdk.integrations.llamaindex import protect_llm
        sent = []
        llm = protect_llm(self._llm(lambda: "To <EMAIL_1> re <SSN_1>", sent), ward=ward)
        with ward.run():
            r = llm.chat([ChatMessage(role="user", content=ASK)])
            last = list(llm.stream_complete(f"to {EMAIL}"))[-1]
        assert r.message.content == f"To {EMAIL} re {SSN}"
        assert last.text == f"Mail {EMAIL} now"
        assert all(no_raw(s) for s in sent)
        # CustomLLM.chat calls complete: still one llm span per request
        assert len([n for n, a in spans(otel[1], "llamaindex")]) == 2

    def test_context_param_passes_through(self, ward):
        from llama_index.core.tools import FunctionTool

        from taintward.sdk.integrations.llamaindex import wrap_tool
        marker = object()
        seen = {}

        def lookup(ctx, ssn: str) -> str:
            """Look up."""
            seen["ctx"], seen["ssn"] = ctx, ssn
            return "ok"
        t = FunctionTool.from_defaults(lookup)
        t.ctx_param_name = "ctx"
        with ward.run():
            wrap_tool(t, ward=ward).call(ctx=marker, ssn=SSN)
        assert seen["ctx"] is marker and seen["ssn"] != SSN


# ---------------------------------------------------------------------------
# Pydantic AI
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _has("pydantic_ai"), reason="pydantic-ai not installed")
class TestPydanticAI:
    def _model(self, sent):
        from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart
        from pydantic_ai.models.function import FunctionModel

        def fn(messages, info):
            sent.append(repr(messages))
            if len(sent) == 1:
                return ModelResponse(parts=[
                    ToolCallPart("lookup", {"ssn": "<SSN_1>"}),
                    ToolCallPart("send_email",
                                 '{"to": "<EMAIL_1>", "body": "About SSN <SSN_1>"}'),
                ])
            return ModelResponse(parts=[TextPart("Emailed <EMAIL_1>.")])
        return FunctionModel(fn)

    def test_agent_run(self, ward, otel):
        from pydantic_ai import Agent

        from taintward.sdk.integrations.pydanticai import protect_model, wrap_tools
        tools, sent = Tools(), []
        agent = Agent(protect_model(self._model(sent), ward=ward),
                      toolsets=[wrap_tools([tools.lookup, tools.send_email], ward=ward)])
        with ward.run():
            r = agent.run_sync(ASK, instructions="Be brief.")
        assert all(no_raw(s) for s in sent)
        assert "placeholders" in sent[0] and "Be brief." in sent[0]
        assert r.output == f"Emailed {EMAIL}."
        tools.check()
        check_spans(otel[1], "pydantic-ai")
        # the history keeps real values; the next request redacts them again
        assert EMAIL in repr(r.all_messages())

    def test_placeholders_off_sends_masks(self, otel):
        from pydantic_ai import Agent

        from taintward.sdk.integrations.pydanticai import protect_model
        sent = []
        ward = Ward(tracer=otel[0], placeholders=False)
        with ward.run():
            Agent(protect_model(self._model(sent), ward=ward)).run_sync(ASK)
        assert no_raw(sent[0]) and "[PII]" in sent[0] and "<SSN_1>" not in sent[0]


# ---------------------------------------------------------------------------
# Google ADK
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _has("google.adk"), reason="google-adk not installed")
class TestGoogleADK:
    def _run(self, agent, ward, text):
        from google.adk.runners import InMemoryRunner
        from google.genai import types

        async def go():
            runner = InMemoryRunner(agent=agent, app_name="t")
            s = await runner.session_service.create_session(app_name="t", user_id="u")
            out = []
            with ward.run():
                async for ev in runner.run_async(
                        user_id="u", session_id=s.id,
                        new_message=types.Content(role="user", parts=[types.Part(text=text)])):
                    if ev.content and ev.content.parts:
                        out += [p.text for p in ev.content.parts if p.text]
            return out
        return asyncio.run(go())

    def _model(self, sent):
        from google.adk.models.base_llm import BaseLlm
        from google.adk.models.llm_response import LlmResponse
        from google.genai import types

        def call(name, args):
            return types.Part(function_call=types.FunctionCall(name=name, args=args))

        class Scripted(BaseLlm):
            model: str = "scripted"

            async def generate_content_async(self, llm_request, stream=False):
                sent.append(llm_request.model_dump_json(exclude={"tools_dict"}))
                if len(sent) == 1:
                    parts = [call("lookup", {"ssn": "<SSN_1>"}),
                             call("send_email", {"to": "<EMAIL_1>", "body": "About SSN <SSN_1>"})]
                else:
                    parts = [types.Part(text="Emailed <EMAIL_1>.")]
                yield LlmResponse(content=types.Content(role="model", parts=parts))
        return Scripted()

    def test_runner(self, ward, otel):
        from google.adk.agents import LlmAgent

        from taintward.sdk.integrations.google_adk import protect_model, wrap_tools
        tools, sent = Tools(), []
        agent = LlmAgent(name="support", model=protect_model(self._model(sent), ward=ward),
                         instruction="Be brief.",
                         tools=wrap_tools([tools.lookup, tools.send_email], ward=ward))
        out = self._run(agent, ward, ASK)
        assert all(no_raw(s) for s in sent)
        assert "placeholders" in sent[0] and "Be brief." in sent[0]
        assert out[-1] == f"Emailed {EMAIL}."
        tools.check()
        check_spans(otel[1], "google-adk")

    def test_toolset_tools_are_wrapped(self, ward):
        from google.adk.tools import FunctionTool
        from google.adk.tools.base_toolset import BaseToolset

        from taintward.sdk.integrations._common import is_protected
        from taintward.sdk.integrations.google_adk import wrap_tools

        class Set(BaseToolset):
            async def get_tools(self, readonly_context=None):
                return [FunctionTool(Tools().lookup)]

            async def close(self):
                pass
        (wrapped,) = wrap_tools([Set()], ward=ward)
        assert isinstance(wrapped, Set)
        assert all(is_protected(t) for t in asyncio.run(wrapped.get_tools()))


# ---------------------------------------------------------------------------
# LiteLLM
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _has("litellm"), reason="litellm not installed")
class TestLiteLLM:
    @pytest.fixture
    def fake_litellm(self, monkeypatch):
        """The real litellm.completion with a fixed mock answer, recording the
        messages it was called with. The patch is undone after the test."""
        import litellm
        sent = []
        real = litellm.completion
        real_async = litellm.acompletion

        def completion(*args, **kwargs):
            sent.append(json.dumps(kwargs.get("messages"), default=str))
            return real(*args, **kwargs, mock_response="Sent to <EMAIL_1> re <SSN_1>.")

        async def acompletion(*args, **kwargs):
            sent.append(json.dumps(kwargs.get("messages"), default=str))
            return await real_async(*args, **kwargs, mock_response="ok <SSN_1>")
        monkeypatch.setattr(litellm, "completion", completion)
        monkeypatch.setattr(litellm, "acompletion", acompletion)
        return litellm, sent

    def test_sdk_completion(self, ward, otel, fake_litellm):
        from taintward.sdk.integrations.litellm import protect_litellm
        litellm, sent = fake_litellm
        protect_litellm(ward=ward)
        protect_litellm(ward=ward)  # twice is fine
        with ward.run():
            r = litellm.completion("gpt-4o-mini", [{"role": "user", "content": ASK}])
            a = asyncio.run(litellm.acompletion(model="gpt-4o-mini",
                                                messages=[{"role": "user", "content": ASK}]))
        assert all(no_raw(s) for s in sent) and "<SSN_1>" in sent[0]
        assert r.choices[0].message.content == f"Sent to {EMAIL} re {SSN}."
        assert a.choices[0].message.content == f"ok {SSN}"
        llm = [a for _, a in spans(otel[1], "litellm")]
        assert len(llm) == 2 and all(a["taintward.violation"] for a in llm)

    def test_proxy_guardrail_round_trip(self, ward, otel):
        import litellm

        from taintward.sdk.integrations.litellm import TaintwardGuardrail
        g = TaintwardGuardrail(ward=ward, guardrail_name="taintward")
        data = {"model": "m", "messages": [{"role": "user", "content": ASK}]}
        data = asyncio.run(g.async_pre_call_hook(None, None, data, "acompletion"))
        assert no_raw(data["messages"]) and data["messages"][0]["role"] == "system"
        assert no_raw(data["metadata"])  # only an opaque request id
        resp = litellm.ModelResponse(choices=[{"message": {
            "role": "assistant", "content": "Done: <EMAIL_1>",
            "tool_calls": [{"id": "c1", "type": "function", "function": {
                "name": "send_email", "arguments": '{"to": "<EMAIL_1>"}'}}]}}])
        out = asyncio.run(g.async_post_call_success_hook(data, None, resp))
        msg = out.choices[0].message
        assert msg.content == f"Done: {EMAIL}"
        assert json.loads(msg.tool_calls[0].function.arguments) == {"to": EMAIL}
        assert g._pending == {}  # the map is dropped after the answer
        assert spans(otel[1], "litellm-proxy")

    def test_proxy_stream_gets_masks(self, ward):
        from taintward.sdk.integrations.litellm import TaintwardGuardrail
        g = TaintwardGuardrail(ward=ward, guardrail_name="taintward")
        data = {"model": "m", "stream": True, "messages": [{"role": "user", "content": ASK}]}
        data = asyncio.run(g.async_pre_call_hook(None, None, data, "acompletion"))
        assert "[PII]" in json.dumps(data["messages"]) and "<SSN_1>" not in json.dumps(data)
        assert "taintward_request" not in data.get("metadata", {})

    def test_pending_maps_are_bounded(self, ward):
        from taintward.sdk.integrations.litellm import TaintwardGuardrail
        g = TaintwardGuardrail(ward=ward, guardrail_name="taintward", max_pending=2)
        for _ in range(5):
            asyncio.run(g.async_pre_call_hook(
                None, None, {"messages": [{"role": "user", "content": ASK}]}, "acompletion"))
        assert len(g._pending) == 2
