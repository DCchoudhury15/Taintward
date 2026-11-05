"""The ``parse()`` helpers of the OpenAI and Anthropic SDKs send their own
request (they do not call ``create``). On a protected client the request
must be redacted and the parsed answer restored (mocked HTTP, no API keys).
"""

from __future__ import annotations

import asyncio
import importlib
import importlib.util
import json

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from taintward.sdk import instrumentation as instr
from taintward.sdk.integrations import Ward

pydantic = pytest.importorskip("pydantic")

SSN = "234-12-1234"
ASK = f"my ssn is {SSN}"
ANSWER = '{"ssn": "<SSN_1>"}'


class Out(pydantic.BaseModel):
    ssn: str


def _has(mod: str) -> bool:
    return importlib.util.find_spec(mod) is not None


@pytest.fixture(autouse=True)
def _no_leftover_taint():
    """These calls run outside a run: their taint stays in the test
    thread's context. Drop it so later tests start clean."""
    yield
    instr._LOOSE_TAINT.set(None)


@pytest.fixture
def otel():
    provider = TracerProvider()
    exporter = InMemorySpanExporter()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    yield provider.get_tracer("taintward"), exporter
    provider.shutdown()


@pytest.fixture
def ward(otel):
    return Ward({}, tracer=otel[0], llm_jurisdiction="us")


def _httpx(sdk: str):
    base = importlib.import_module(f"{sdk}._base_client")
    return getattr(base, "httpx2", None) or base.httpx


def _client(sdk: str, bodies: list, answer: dict, *, is_async: bool = False):
    mod = importlib.import_module(sdk)
    httpx = _httpx(sdk)

    def handler(request):
        bodies.append(request.content.decode())
        return httpx.Response(200, json=answer)
    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(transport=transport) if is_async else httpx.Client(transport=transport)
    name = {"openai": "OpenAI", "anthropic": "Anthropic"}[sdk]
    cls = getattr(mod, f"Async{name}" if is_async else name)
    base = "http://fake.local/v1" if sdk == "openai" else "http://fake.local"
    return cls(api_key="test", base_url=base, http_client=http, max_retries=0)


def _llm_span(exporter) -> dict:
    spans = [dict(s.attributes or {}) for s in exporter.get_finished_spans()]
    assert SSN not in json.dumps(spans, default=str)
    (a,) = [a for a in spans if a.get("taintward.destination") == "llm"]
    return a


CHAT = {"id": "c", "object": "chat.completion", "created": 0, "model": "gpt-test",
        "choices": [{"index": 0, "finish_reason": "stop",
                     "message": {"role": "assistant", "content": ANSWER}}]}
RESPONSE = {"id": "r", "object": "response", "created_at": 0, "model": "gpt-test",
            "status": "completed", "parallel_tool_calls": False, "tool_choice": "auto",
            "tools": [], "output": [{"type": "message", "id": "m", "role": "assistant",
                                     "status": "completed", "content": [
                                         {"type": "output_text", "text": ANSWER,
                                          "annotations": []}]}]}
MESSAGE = {"id": "m", "type": "message", "role": "assistant", "model": "claude-test",
           "content": [{"type": "text", "text": ANSWER}], "stop_reason": "end_turn",
           "stop_sequence": None, "usage": {"input_tokens": 3, "output_tokens": 4}}


@pytest.mark.skipif(not _has("openai"), reason="openai not installed")
class TestOpenAIParse:
    def test_chat_parse(self, ward, otel):
        bodies = []
        client = ward.protect_openai(_client("openai", bodies, CHAT))
        r = client.chat.completions.parse(model="gpt-test", response_format=Out,
                                          messages=[{"role": "user", "content": ASK}])
        assert SSN not in bodies[0] and "<SSN_1>" in bodies[0]
        assert r.choices[0].message.parsed == Out(ssn=SSN)
        assert "<SSN_1>" in _llm_span(otel[1])["gen_ai.output.messages"]

    def test_async_chat_parse(self, ward, otel):
        bodies = []
        client = ward.protect_openai(_client("openai", bodies, CHAT, is_async=True))
        r = asyncio.run(client.chat.completions.parse(
            model="gpt-test", response_format=Out, messages=[{"role": "user", "content": ASK}]))
        assert SSN not in bodies[0]
        assert r.choices[0].message.parsed == Out(ssn=SSN)
        _llm_span(otel[1])

    def test_responses_parse(self, ward, otel):
        bodies = []
        client = ward.protect_openai(_client("openai", bodies, RESPONSE))
        r = client.responses.parse(model="gpt-test", input=ASK, text_format=Out)
        assert SSN not in bodies[0] and "<SSN_1>" in bodies[0]
        assert r.output_parsed == Out(ssn=SSN)
        _llm_span(otel[1])


@pytest.mark.skipif(not _has("anthropic"), reason="anthropic not installed")
class TestAnthropicParse:
    def test_messages_parse(self, ward, otel):
        bodies = []
        client = ward.protect_anthropic(_client("anthropic", bodies, MESSAGE))
        r = client.messages.parse(model="claude-test", max_tokens=50, output_format=Out,
                                  messages=[{"role": "user", "content": ASK}])
        assert SSN not in bodies[0] and "<SSN_1>" in bodies[0]
        assert r.parsed_output == Out(ssn=SSN)
        a = _llm_span(otel[1])
        assert a["gen_ai.usage.output_tokens"] == 4

    def test_async_messages_parse(self, ward, otel):
        bodies = []
        client = ward.protect_anthropic(_client("anthropic", bodies, MESSAGE, is_async=True))
        r = asyncio.run(client.messages.parse(
            model="claude-test", max_tokens=50, output_format=Out,
            messages=[{"role": "user", "content": ASK}]))
        assert SSN not in bodies[0]
        assert r.parsed_output == Out(ssn=SSN)
