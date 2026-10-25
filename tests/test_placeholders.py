"""Consistent placeholders for the LLM, and restore on the way back.

Offline: fake LangChain models and httpx.MockTransport for the OpenAI and
Anthropic SDKs. The checks:

  * the request to the provider never holds the raw values, it holds
    <PERSON_1>, <SSN_1>, <AWS_KEY_1>, ...
  * the model's answer is returned to the caller with the real values,
  * an internal tool called with <SSN_1> gets the reversible token of the real
    SSN, an external tool gets a mask (or the real value for an allow-listed
    argument), never the raw value otherwise,
  * placeholders are stable across turns of one run, and runs do not share
    maps.
"""

from __future__ import annotations

import asyncio
import contextvars
import importlib.util
import json
import threading

import pytest
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from taintward.core.doe import Sensitivity
from taintward.sdk import placeholders as ph
from taintward.sdk.destinations import DEST_EXTERNAL, DEST_INTERNAL, DEST_LLM, DEST_LOG
from taintward.sdk.integrations import Ward
from taintward.sdk.placeholders import PlaceholderMap
from taintward.sdk.redact import get_redactor, redact_payload
from taintward.sdk.vault import MemoryVault

SSN = "234-12-1234"
AWS = "AKIAIOSFODNN7EXAMPLE"
NAME = "Alice Lee"
EMAIL = "alice.lee@example.com"
RAW = (SSN, AWS, NAME, EMAIL)
PROMPT = f"Write to {NAME} ({EMAIL}) about her tax form. Her ssn is {SSN}, key {AWS}."


def _has(mod: str) -> bool:
    return importlib.util.find_spec(mod) is not None


needs_langchain = pytest.mark.skipif(
    not (_has("langchain_core") and _has("langgraph")), reason="langchain not installed")
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
    return Ward({
        "lookup": "internal",
        "store": "internal",
        "send_email": {"destination": "external", "allow": ["to"]},
        "audit_log": "log",
    }, tracer=tracer)


def _no_raw(blob, raws=RAW):
    text = blob if isinstance(blob, str) else json.dumps(blob, default=str)
    for raw in raws:
        assert raw not in text, f"raw value {raw!r} leaked"


def _no_raw_in_spans(exporter, raws=RAW):
    for s in exporter.get_finished_spans():
        _no_raw(json.dumps(dict(s.attributes or {}), default=str), raws)


def _reverse(token: str) -> str | None:
    return get_redactor().reverse(token)


# ---------------------------------------------------------------------------
# The map itself
# ---------------------------------------------------------------------------


class TestPlaceholderMap:
    def test_stable_typed_numbered(self):
        m = PlaceholderMap()
        assert m.placeholder_for(NAME, "PERSON") == "<PERSON_1>"
        assert m.placeholder_for(SSN, "US_SSN") == "<SSN_1>"
        assert m.placeholder_for("Bob Stone", "PERSON") == "<PERSON_2>"
        assert m.placeholder_for(NAME, "PERSON") == "<PERSON_1>"  # same value, same placeholder
        assert m.placeholder_for(AWS, "AWS_ACCESS_KEY", Sensitivity.SECRET) == "<AWS_KEY_1>"
        assert m.placeholder_for("a@b.org", "EMAIL_ADDRESS") == "<EMAIL_1>"
        assert m.placeholder_for("x", "SOME NEW-TYPE") == "<SOME_NEW_TYPE_1>"
        assert m.placeholder_for("y", None, Sensitivity.SECRET) == "<SECRET_1>"
        assert len(m) == 7
        assert NAME not in repr(m)

    def test_restore_text_variants(self):
        m = PlaceholderMap()
        m.placeholder_for(NAME, "PERSON")
        m.placeholder_for(SSN, "US_SSN")
        out = m.restore_text("Dear <PERSON_1>, < SSN_1 > / <person_1> / &lt;SSN_1&gt;")
        assert out == f"Dear {NAME}, {SSN} / {NAME} / {SSN}"

    def test_invented_placeholders_are_left_alone(self):
        m = PlaceholderMap()
        m.placeholder_for(NAME, "PERSON")
        text = "<PERSON_2> and <SSN_1> and <b>bold</b> and a < b > c"
        assert m.restore_text(text) == text
        assert m.lookup("<PERSON_9>") is None
        assert "<PERSON_1>" in m and "<PERSON_2>" not in m

    def test_restore_inside_json_keeps_it_valid(self):
        m = PlaceholderMap()
        tricky = 'O"Brien \\ Sr'
        m.placeholder_for(tricky, "PERSON")
        args = json.dumps({"name": "<PERSON_1>", "n": 3, "tags": ["<PERSON_1>", "<X_1>"]})
        out = json.loads(m.restore_text(args))
        assert out == {"name": tricky, "n": 3, "tags": [tricky, "<X_1>"]}

    def test_restore_structures_and_inplace(self):
        m = PlaceholderMap()
        m.placeholder_for(SSN, "US_SSN")
        assert m.restore({"a": ["<SSN_1>", ("<SSN_1>",)], "b": 1}) == \
            {"a": [SSN, (SSN,)], "b": 1}
        obj = {"choices": [{"message": {"content": "ssn <SSN_1>"}}]}
        assert m.restore_inplace(obj) is obj
        assert obj["choices"][0]["message"]["content"] == f"ssn {SSN}"

    def test_find_known_matches_whole_values(self):
        m = PlaceholderMap()
        m.placeholder_for("Zork Quux", "PERSON")
        spans = m.find_known("hi Zork Quux, not Zork Quuxes")
        assert [(s.start, s.end, s.entity_type) for s in spans] == [(3, 12, "PERSON")]

    def test_clear(self):
        m = PlaceholderMap()
        m.placeholder_for(SSN, "US_SSN")
        m.clear()
        assert len(m) == 0 and m.restore_text("<SSN_1>") == "<SSN_1>"


class TestRedactWithPlaceholders:
    def test_llm_gets_placeholders_other_sinks_unchanged(self):
        m = PlaceholderMap()
        text = f"ssn {SSN} key {AWS}"
        to_llm = redact_payload(text, DEST_LLM, placeholders=m)
        assert to_llm == "ssn <SSN_1> key <AWS_KEY_1>"
        assert redact_payload(text, DEST_EXTERNAL, placeholders=m) == "ssn [PII] key [SECRET]"
        assert redact_payload(text, DEST_LOG, placeholders=m) == "ssn [PII] key [SECRET]"
        token = redact_payload(SSN, DEST_INTERNAL, placeholders=m)
        assert token != SSN and _reverse(token) == SSN
        # without a map: the old masks
        assert redact_payload(text, DEST_LLM) == "ssn [PII] key [SECRET]"

    def test_known_values_are_redacted_even_when_not_detected(self):
        m = PlaceholderMap()
        m.placeholder_for("zork quux", "PERSON")  # lowercase: NER does not find it
        assert redact_payload("call zork quux", DEST_EXTERNAL) == "call zork quux"
        assert redact_payload("call zork quux", DEST_EXTERNAL, placeholders=m) == "call [PII]"
        assert redact_payload("call zork quux", DEST_LLM, placeholders=m) == "call <PERSON_1>"

    def test_overlap_prefers_secret(self):
        m = PlaceholderMap()  # the AWS key is also tagged ORGANIZATION by NER
        assert redact_payload(f"key {AWS}", DEST_LLM, placeholders=m) == "key <AWS_KEY_1>"


class TestScope:
    def test_scope_is_per_run_and_cleared(self):
        with ph.scope() as a:
            a.placeholder_for(NAME, "PERSON")
            assert ph.current() is a
            with ph.scope() as b:
                assert ph.current() is b and len(b) == 0
            assert ph.current() is a
        assert ph.current() is None
        assert len(a) == 0  # cleared at the end of the run

    def test_copied_context_and_threads_share_the_run_map(self):
        with ph.scope() as m:
            seen = []

            def work():
                seen.append(ph.current())
                ph.current().placeholder_for(SSN, "US_SSN")

            contextvars.copy_context().run(work)
            ctx = contextvars.copy_context()
            t = threading.Thread(target=ctx.run, args=(work,))
            t.start()
            t.join()
            assert seen == [m, m]
            assert m.lookup("<SSN_1>") == SSN and len(m) == 1

    def test_ward_run_installs_and_clears_a_map(self, ward):
        assert ward.placeholder_map() is None
        with ward.run("r"):
            m = ward.placeholder_map()
            assert m is not None and ward.llm_placeholder_map() is m
        assert ward.placeholder_map() is None
        # outside a run every LLM call gets its own fresh map
        assert ward.llm_placeholder_map() is not ward.llm_placeholder_map()
        off = Ward(placeholders=False)
        with off.run("r"):
            assert off.placeholder_map() is None and off.llm_placeholder_map() is None


class TestVaultBacked:
    def test_conversation_survives_runs_and_can_be_forgotten(self):
        vault = MemoryVault()
        a = PlaceholderMap(vault=vault, conversation_id="conv-1")
        assert a.placeholder_for(NAME, "PERSON") == "<PERSON_1>"
        assert a.placeholder_for(SSN, "US_SSN") == "<SSN_1>"
        # nothing in the vault keys reveals the value or the conversation id
        keys = " ".join(vault._rows)
        assert NAME not in keys and SSN not in keys and "conv-1" not in keys

        b = PlaceholderMap(vault=vault, conversation_id="conv-1")  # a later run
        assert b.restore_text("<PERSON_1> <SSN_1>") == f"{NAME} {SSN}"
        assert b.placeholder_for(SSN, "US_SSN") == "<SSN_1>"
        assert b.placeholder_for("Bob Stone", "PERSON") == "<PERSON_2>"  # counter kept

        other = PlaceholderMap(vault=vault, conversation_id="conv-2")
        assert other.restore_text("<PERSON_1>") == "<PERSON_1>"

        assert b.forget_conversation() > 0
        c = PlaceholderMap(vault=vault, conversation_id="conv-1")
        assert c.restore_text("<PERSON_1>") == "<PERSON_1>"

    def test_vault_needs_conversation_id(self):
        with pytest.raises(ValueError):
            PlaceholderMap(vault=MemoryVault())

    def test_ward_run_with_conversation_id(self, otel):
        tracer, _ = otel
        vault = MemoryVault()
        w = Ward(tracer=tracer, placeholder_vault=vault)
        with w.run("turn1", conversation_id="c"):
            w.placeholder_map().placeholder_for(SSN, "US_SSN")
        with w.run("turn2", conversation_id="c"):
            assert w.placeholder_map().restore_text("<SSN_1>") == SSN
        with w.run("other"):  # no conversation id: plain in-memory map
            assert w.placeholder_map().restore_text("<SSN_1>") == "<SSN_1>"


# ---------------------------------------------------------------------------
# OpenAI client (mocked HTTP)
# ---------------------------------------------------------------------------


def _completion(n, content=None, tool_calls=None):
    msg = {"role": "assistant", "content": content}
    if tool_calls:
        msg["tool_calls"] = [
            {"id": f"call_{n}_{i}", "type": "function",
             "function": {"name": name, "arguments": json.dumps(args)}}
            for i, (name, args) in enumerate(tool_calls)]
    return {"id": f"cc_{n}", "object": "chat.completion", "created": 0, "model": "gpt-test",
            "choices": [{"index": 0, "message": msg,
                         "finish_reason": "tool_calls" if tool_calls else "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}


def _openai(bodies, replies, async_=False):
    import httpx
    import openai

    def handler(request):
        bodies.append(json.loads(request.content))
        return httpx.Response(200, json=replies[len(bodies) - 1])

    transport = httpx.MockTransport(handler)
    if async_:
        return openai.AsyncOpenAI(api_key="t", base_url="http://fake.local/v1",
                                  http_client=httpx.AsyncClient(transport=transport))
    return openai.OpenAI(api_key="t", base_url="http://fake.local/v1",
                         http_client=httpx.Client(transport=transport))


@needs_openai
class TestOpenAIPlaceholders:
    def test_request_has_placeholders_answer_is_restored(self, ward, otel):
        _, exporter = otel
        bodies = []
        client = ward.protect_openai(_openai(bodies, [_completion(
            1, content="Drafted a letter to <PERSON_1> about the form for SSN < SSN_1 >.",
            tool_calls=[("lookup", {"name": "<PERSON_1>", "ssn": "<SSN_1>"})])]))
        with ward.run("r"):
            resp = client.chat.completions.create(model="gpt-test", messages=[
                {"role": "user", "content": PROMPT}])
        sent = json.dumps(bodies[0])
        _no_raw(sent)
        content = bodies[0]["messages"][0]["content"]
        for p in ("<PERSON_1>", "<EMAIL_1>", "<SSN_1>", "<AWS_KEY_1>"):
            assert p in content
        msg = resp.choices[0].message
        assert msg.content == f"Drafted a letter to {NAME} about the form for SSN {SSN}."
        assert json.loads(msg.tool_calls[0].function.arguments) == {"name": NAME, "ssn": SSN}
        # the span keeps the placeholder version, never the real values
        _no_raw_in_spans(exporter)
        out = _spans(exporter, "chat gpt-test")[0].attributes["gen_ai.output.messages"]
        assert "PERSON_1" in out

    def test_consistent_across_turns_in_one_run(self, ward):
        bodies = []
        client = ward.protect_openai(_openai(bodies, [
            _completion(1, content="Hello <PERSON_1>."),
            _completion(2, content="<PERSON_1> and <PERSON_2> both have forms."),
        ]))
        with ward.run("r"):
            history = [{"role": "user", "content": f"I am {NAME}, ssn {SSN}."}]
            r1 = client.chat.completions.create(model="gpt-test", messages=history)
            assert r1.choices[0].message.content == f"Hello {NAME}."
            history += [r1.choices[0].message,  # the caller keeps the restored message
                        {"role": "user", "content": "Also add Bob Stone please."}]
            r2 = client.chat.completions.create(model="gpt-test", messages=history)
        second = json.dumps(bodies[1])
        _no_raw(second, RAW + ("Bob Stone",))
        assert bodies[1]["messages"][0]["content"] == "I am <PERSON_1>, ssn <SSN_1>."
        assert bodies[1]["messages"][1]["content"] == "Hello <PERSON_1>."
        assert "<PERSON_2>" in bodies[1]["messages"][2]["content"]
        assert r2.choices[0].message.content == f"{NAME} and Bob Stone both have forms."

    def test_runs_do_not_share_maps(self, ward):
        bodies = []
        client = ward.protect_openai(_openai(bodies, [
            _completion(1, content="ok <PERSON_1>"),
            _completion(2, content="ok <PERSON_1>"),
            _completion(3, content="ok <PERSON_1>"),
        ]))
        with ward.run("alice"):
            a = client.chat.completions.create(
                model="gpt-test", messages=[{"role": "user", "content": f"I am {NAME}."}])
        with ward.run("bob"):
            b = client.chat.completions.create(
                model="gpt-test", messages=[{"role": "user", "content": "I am Bob Stone."}])
        # no run: a fresh map for this call only, nothing to restore from
        c = client.chat.completions.create(
            model="gpt-test", messages=[{"role": "user", "content": "hello"}])
        assert a.choices[0].message.content == f"ok {NAME}"
        assert b.choices[0].message.content == "ok Bob Stone"
        assert c.choices[0].message.content == "ok <PERSON_1>"

    def test_async_client(self, ward):
        bodies = []
        client = ward.protect_openai(_openai(bodies, [_completion(1, content="hi <PERSON_1>")],
                                             async_=True))

        async def go():
            with ward.run("r"):
                return await client.chat.completions.create(
                    model="gpt-test", messages=[{"role": "user", "content": PROMPT}])

        resp = asyncio.run(go())
        _no_raw(bodies[0])
        assert resp.choices[0].message.content == f"hi {NAME}"

    def test_placeholders_off_sends_masks(self, otel):
        tracer, _ = otel
        w = Ward(tracer=tracer, placeholders=False)
        bodies = []
        client = w.protect_openai(_openai(bodies, [_completion(1, content="ok <PERSON_1>")]))
        with w.run("r"):
            resp = client.chat.completions.create(
                model="gpt-test", messages=[{"role": "user", "content": PROMPT}])
        content = bodies[0]["messages"][0]["content"]
        _no_raw(content)
        assert "[PII]" in content and "<PERSON_1>" not in content
        assert resp.choices[0].message.content == "ok <PERSON_1>"  # nothing restored


def _spans(exporter, name=None):
    return [s for s in exporter.get_finished_spans() if name is None or s.name == name]


@needs_anthropic
class TestAnthropicPlaceholders:
    def test_text_and_tool_use_are_restored(self, ward, otel):
        import anthropic
        try:
            import httpx2 as httpx
        except ImportError:
            import httpx
        _, exporter = otel
        bodies = []

        def handler(request):
            bodies.append(json.loads(request.content))
            return httpx.Response(200, json={
                "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-test",
                "content": [
                    {"type": "text", "text": "Writing to <PERSON_1> now."},
                    {"type": "tool_use", "id": "tu_1", "name": "send_email",
                     "input": {"to": "<EMAIL_1>", "body": "Dear <PERSON_1>"}}],
                "stop_reason": "tool_use", "stop_sequence": None,
                "usage": {"input_tokens": 1, "output_tokens": 1}})

        client = anthropic.Anthropic(api_key="t", base_url="http://fake.local",
                                     http_client=httpx.Client(transport=httpx.MockTransport(handler)))
        ward.protect_anthropic(client)
        with ward.run("r"):
            resp = client.messages.create(model="claude-test", max_tokens=50,
                                          system=f"key {AWS}",
                                          messages=[{"role": "user", "content": PROMPT}])
        _no_raw(bodies[0])
        assert "<AWS_KEY_1>" in bodies[0]["system"] and "<PERSON_1>" in json.dumps(bodies[0])
        assert resp.content[0].text == f"Writing to {NAME} now."
        assert resp.content[1].input == {"to": EMAIL, "body": f"Dear {NAME}"}
        _no_raw_in_spans(exporter)


# ---------------------------------------------------------------------------
# LangChain / LangGraph agent loop
# ---------------------------------------------------------------------------


def _lc_tools(seen):
    from langchain_core.tools import tool

    @tool
    def lookup(employee: str) -> str:
        """Look up an employee record (internal)."""
        seen["lookup"] = employee
        return f"{NAME}: ssn {SSN}, tax form missing"

    @tool
    def send_email(to: str, body: str) -> str:
        """Send an email (external)."""
        seen["send_email"] = {"to": to, "body": body}
        return "sent"

    @tool
    def store(record: str) -> str:
        """Save a note in the internal cache."""
        seen["store"] = record
        return "stored"

    @tool
    def audit_log(line: str) -> str:
        """Write a line to the audit log."""
        seen["audit_log"] = line
        return "logged"

    return [lookup, send_email, store, audit_log]


def _scripted(responses, requests):
    from langchain_core.language_models.fake_chat_models import (
        FakeMessagesListChatModel,
    )

    class FakeToolModel(FakeMessagesListChatModel):
        def bind_tools(self, tools, **kwargs):
            return self

        def _generate(self, messages, stop=None, run_manager=None, **kwargs):
            requests.append(list(messages))
            return super()._generate(messages, stop=stop, run_manager=run_manager, **kwargs)

    return FakeToolModel(responses=responses)


def _lc_script():
    from langchain_core.messages import AIMessage

    def call(i, name, args):
        return AIMessage("", tool_calls=[{"name": name, "args": args, "id": f"c{i}"}])

    # What a real model would write: it only ever saw the placeholders.
    return [
        call(1, "lookup", {"employee": "<PERSON_1>"}),
        call(2, "send_email", {"to": "<EMAIL_1>",
                               "body": "Hi <PERSON_1>, your tax form is missing (ssn <SSN_1>)."}),
        call(3, "store", {"record": "<PERSON_1> reminded, ssn <SSN_1>"}),
        call(4, "audit_log", {"line": "reminded <PERSON_1>"}),
        AIMessage("Done: emailed <PERSON_1> at <EMAIL_1> about the tax form. "
                  "<PERSON_7> is unknown."),
    ]


def _request_text(requests) -> str:
    return json.dumps([[(m.type, m.content, getattr(m, "tool_calls", None)) for m in r]
                       for r in requests], default=str)


@needs_langchain
class TestLangChainPlaceholders:
    def _run(self, ward, *, ainvoke=False):
        import warnings

        from langgraph.prebuilt import create_react_agent
        seen, requests = {}, []
        model = ward.protect_langchain_model(_scripted(_lc_script(), requests))
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            agent = create_react_agent(model, ward.wrap_langchain_tools(_lc_tools(seen)))
        inp = {"messages": [("user", PROMPT)]}

        async def go():
            with ward.run("lg"):
                return await agent.ainvoke(inp)

        if ainvoke:
            out = asyncio.run(go())
        else:
            with ward.run("lg"):
                out = agent.invoke(inp)
        return out, seen, requests

    @pytest.mark.parametrize("ainvoke", [False, True])
    def test_agent_completes_task_without_leaking(self, ward, otel, ainvoke):
        _, exporter = otel
        out, seen, requests = self._run(ward, ainvoke=ainvoke)

        # 1. the provider only ever saw placeholders, stable over 5 turns
        text = _request_text(requests)
        assert len(requests) == 5
        _no_raw(text)
        for p in ("<PERSON_1>", "<EMAIL_1>", "<SSN_1>", "<AWS_KEY_1>"):
            assert p in text
        assert "<PERSON_2>" not in text and "<SSN_2>" not in text

        # 2. the caller gets the real values back (invented ones stay as they are)
        assert out["messages"][-1].content == (
            f"Done: emailed {NAME} at {EMAIL} about the tax form. <PERSON_7> is unknown.")

        # 3. internal tools: reversible token of the real value
        assert seen["lookup"] != NAME and _reverse(seen["lookup"]) == NAME
        _no_raw(seen["store"])
        ssn_token = seen["store"].rsplit("ssn ", 1)[1]
        assert _reverse(ssn_token) == SSN

        # 4. external tool: allow-listed "to" is real, the body is masked
        assert seen["send_email"]["to"] == EMAIL
        _no_raw(seen["send_email"]["body"])
        assert "[PII]" in seen["send_email"]["body"] and "<" not in seen["send_email"]["body"]

        # 5. log sink: masked, even for a bare known name
        assert seen["audit_log"] == "reminded [PII]"
        _no_raw_in_spans(exporter)

    def test_wrapped_tool_restores_per_destination(self, ward):
        """A tool called directly with placeholders (for example from a
        streamed answer that was not restored)."""
        seen = {}
        lookup, send_email, store, audit_log = ward.wrap_langchain_tools(_lc_tools(seen))
        with ward.run("r"):
            m = ward.placeholder_map()
            m.placeholder_for(SSN, "US_SSN")
            m.placeholder_for(EMAIL, "EMAIL_ADDRESS")
            store.invoke({"record": "ssn <SSN_1>"})
            send_email.invoke({"to": "<EMAIL_1>", "body": "ssn <SSN_1> <SSN_5>"})
            audit_log.invoke({"line": "ssn <SSN_1>"})
        assert _reverse(seen["store"].split()[1]) == SSN
        assert seen["send_email"] == {"to": EMAIL, "body": "ssn [PII] <SSN_5>"}
        assert seen["audit_log"] == "ssn [PII]"

    def test_redact_and_restore_message_roundtrip(self):
        from langchain_core.messages import AIMessage

        from taintward.sdk.integrations.langchain import redact_message, restore_message
        m = PlaceholderMap()
        msg = AIMessage(f"to {NAME}", tool_calls=[
            {"name": "t", "args": {"ssn": SSN}, "id": "1"}])
        red = redact_message(msg, DEST_LLM, placeholders=m)
        assert red.content == "to <PERSON_1>" and red.tool_calls[0]["args"] == {"ssn": "<SSN_1>"}
        back = restore_message(red, m)
        assert back.content == msg.content and back.tool_calls[0]["args"] == {"ssn": SSN}


# ---------------------------------------------------------------------------
# OpenAI Agents SDK
# ---------------------------------------------------------------------------


@needs_agents
@needs_openai
class TestOpenAIAgentsPlaceholders:
    def test_agent_tool_calls_with_placeholders(self, ward, otel):
        from agents import (
            Agent,
            OpenAIChatCompletionsModel,
            Runner,
            function_tool,
            set_tracing_disabled,
        )
        set_tracing_disabled(True)
        _, exporter = otel
        seen, bodies = {}, []

        @function_tool
        def send_email(to: str, body: str) -> str:
            """Send an email (external)."""
            seen["send_email"] = {"to": to, "body": body}
            return "sent"

        @function_tool
        def store(record: str) -> str:
            """Save a note (internal)."""
            seen["store"] = record
            return "stored"

        client = ward.protect_openai(_openai(bodies, [
            _completion(1, tool_calls=[
                ("send_email", {"to": "<EMAIL_1>", "body": "Hi <PERSON_1>, ssn <SSN_1>"}),
                ("store", {"record": "ssn <SSN_1>"})]),
            _completion(2, content="Emailed <PERSON_1>."),
        ], async_=True))
        agent = Agent(name="hr", instructions="HR bot",
                      model=OpenAIChatCompletionsModel(model="gpt-test", openai_client=client),
                      tools=ward.wrap_function_tools([send_email, store]))

        async def go():
            with ward.run("agents"):
                return await Runner.run(agent, PROMPT)

        result = asyncio.run(go())
        assert result.final_output == f"Emailed {NAME}."
        for b in bodies:
            _no_raw(b)
        assert "<SSN_1>" in json.dumps(bodies[0])
        assert seen["send_email"]["to"] == EMAIL
        _no_raw(seen["send_email"]["body"])
        assert _reverse(seen["store"].split()[1]) == SSN
        _no_raw_in_spans(exporter)
