"""Every way a request leaves a protected OpenAI / Anthropic client.

``protect_openai`` / ``protect_anthropic`` patched ``create`` on one client
object. These paths went around it and sent everything raw (mocked HTTP, no
API keys):

* a copy made with ``client.with_options(...)`` or ``client.copy()``,
* Anthropic's ``client.beta.messages`` (create, stream, count_tokens),
* ``client.messages.count_tokens``,
* request fields outside the conversation: ``prediction``, ``metadata``,
  ``user``, the variables of a stored ``prompt``.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import logging

import pytest
from opentelemetry.sdk.trace import TracerProvider

from taintward.sdk import instrumentation as instr
from taintward.sdk.integrations import Ward
from taintward.sdk.integrations.llm_clients import protect_anthropic, protect_openai

SSN = "234-12-1234"
EMAIL = "jo.fox@example.com"
ASK = [{"role": "user", "content": f"my ssn is {SSN}"}]

CHAT = {"id": "c", "object": "chat.completion", "created": 1, "model": "m",
        "choices": [{"index": 0, "finish_reason": "stop",
                     "message": {"role": "assistant", "content": "got <SSN_1>"}}]}
MESSAGE = {"id": "m", "type": "message", "role": "assistant", "model": "m",
           "content": [{"type": "text", "text": "got <SSN_1>"}], "stop_reason": "end_turn",
           "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 1}}
RESPONSE = {"id": "r", "object": "response", "created_at": 1, "model": "m", "status": "completed",
            "output": [{"id": "o", "type": "message", "role": "assistant", "status": "completed",
                        "content": [{"type": "output_text", "text": "ok", "annotations": []}]}],
            "parallel_tool_calls": True, "tool_choice": "auto", "tools": []}


def _has(mod: str) -> bool:
    return importlib.util.find_spec(mod) is not None


needs_openai = pytest.mark.skipif(not _has("openai"), reason="openai not installed")
needs_anthropic = pytest.mark.skipif(not _has("anthropic"), reason="anthropic not installed")


@pytest.fixture(autouse=True)
def _no_leftover_taint():
    yield
    instr._LOOSE_TAINT.set(None)


@pytest.fixture
def ward():
    provider = TracerProvider()
    yield Ward({}, tracer=provider.get_tracer("taintward"), llm_jurisdiction="us")
    provider.shutdown()


def _client(sdk: str, sent: list, ward):
    """A protected client whose requests land in ``sent`` as (path, body)."""
    mod = importlib.import_module(sdk)
    base = importlib.import_module(f"{sdk}._base_client")
    httpx = getattr(base, "httpx2", None) or base.httpx

    def handler(request):
        path = request.url.path
        sent.append((path, request.content.decode()))
        if path.endswith("count_tokens"):
            return httpx.Response(200, json={"input_tokens": 7})
        if path.endswith("/responses"):
            return httpx.Response(200, json=RESPONSE)
        return httpx.Response(200, json=CHAT if sdk == "openai" else MESSAGE)

    if sdk == "openai":
        client = mod.OpenAI(api_key="test", base_url="http://fake.local/v1", max_retries=0,
                            http_client=httpx.Client(transport=httpx.MockTransport(handler)))
        return protect_openai(client, ward=ward)
    client = mod.Anthropic(api_key="test", base_url="http://fake.local", max_retries=0,
                           http_client=httpx.Client(transport=httpx.MockTransport(handler)))
    return protect_anthropic(client, ward=ward)


def _last(sent) -> str:
    return sent[-1][1]


# --- copies of the client ------------------------------------------------------

@needs_openai
def test_openai_with_options_copy_is_protected(ward):
    sent: list = []
    client = _client("openai", sent, ward)
    for derived in (client.with_options(timeout=5), client.copy(), client.copy().with_options(max_retries=0)):
        out = derived.chat.completions.create(model="m", messages=ASK)
        assert SSN not in _last(sent) and "<SSN_1>" in _last(sent)
        assert out.choices[0].message.content == f"got {SSN}"      # and restored


@needs_anthropic
def test_anthropic_with_options_copy_is_protected(ward):
    sent: list = []
    client = _client("anthropic", sent, ward)
    for derived in (client.with_options(timeout=5), client.copy()):
        out = derived.messages.create(model="m", max_tokens=8, messages=ASK)
        assert SSN not in _last(sent) and "<SSN_1>" in _last(sent)
        assert out.content[0].text == f"got {SSN}"


# --- Anthropic: the beta namespace and token counting ------------------------------

@needs_anthropic
def test_anthropic_beta_messages_create_is_protected(ward):
    sent: list = []
    client = _client("anthropic", sent, ward)
    out = client.beta.messages.create(model="m", max_tokens=8, messages=ASK)
    assert SSN not in _last(sent) and "<SSN_1>" in _last(sent)
    assert out.content[0].text == f"got {SSN}"
    # a copy of the client: its beta namespace too
    client.with_options(timeout=5).beta.messages.create(model="m", max_tokens=8, messages=ASK)
    assert SSN not in _last(sent)


@needs_anthropic
def test_anthropic_beta_stream_request_is_redacted(ward):
    sent: list = []
    client = _client("anthropic", sent, ward)
    try:
        with client.beta.messages.stream(model="m", max_tokens=8, messages=ASK):
            pass
    except Exception:  # noqa: BLE001 - the fake answer is not a stream; the request is what counts
        pass
    assert sent and SSN not in _last(sent) and "<SSN_1>" in _last(sent)


@needs_anthropic
@pytest.mark.parametrize("beta", [False, True])
def test_anthropic_count_tokens_is_redacted(ward, beta):
    sent: list = []
    client = _client("anthropic", sent, ward)
    messages = client.beta.messages if beta else client.messages
    out = messages.count_tokens(model="m", messages=ASK, system=f"the user's mail is {EMAIL}")
    assert out.input_tokens == 7
    path, body = sent[-1]
    assert path.endswith("count_tokens")
    assert SSN not in body and EMAIL not in body and "<SSN_1>" in body
    # no placeholder instruction is added to a count
    assert "replaced by placeholders" not in body


@needs_anthropic
def test_anthropic_batch_is_sent_with_masks_and_warns_once(ward, caplog):
    """A batch answer comes back in another call, so placeholders could not
    be put back: the requests get one-way masks. They used to go out raw."""
    sent: list = []
    client = _client("anthropic", sent, ward)
    requests = [
        {"custom_id": "a1", "params": {"model": "m", "max_tokens": 8, "messages": ASK,
                                       "system": f"mail {EMAIL}", "metadata": {"user_id": EMAIL}}},
        {"custom_id": "a2", "params": {"model": "m", "max_tokens": 8,
                                       "messages": [{"role": "user", "content": "hello"}]}},
    ]
    with caplog.at_level(logging.WARNING, logger="taintward.sdk"):
        for _ in range(2):
            try:
                client.messages.batches.create(requests=requests)
            except Exception:  # noqa: BLE001 - the fake answer is not a batch
                pass
    path, text = sent[-1]
    assert path.endswith("/batches")
    assert SSN not in text and EMAIL not in text
    body = json.loads(text)["requests"]
    assert body[0]["custom_id"] == "a1"
    assert body[0]["params"]["messages"][0]["content"] == "my ssn is [PII]"
    assert body[0]["params"]["system"] == "mail [PII]"
    assert body[0]["params"]["metadata"] == {"user_id": "[PII]"}
    assert body[1]["params"]["messages"][0]["content"] == "hello"
    assert caplog.text.count("messages.batches requests are sent with one-way masks") == 1
    # the caller's own list is not changed
    assert requests[0]["params"]["messages"][0]["content"] == f"my ssn is {SSN}"


# --- request fields outside the conversation ------------------------------------------

@needs_openai
def test_openai_chat_prediction_user_and_metadata_are_redacted(ward):
    sent: list = []
    client = _client("openai", sent, ward)
    client.chat.completions.create(
        model="m", messages=[{"role": "user", "content": "hi"}],
        prediction={"type": "content", "content": f"ssn {SSN}"},
        user=EMAIL, metadata={"name": "Alice Lee", "id": SSN, "plan": "pro"})
    body = json.loads(_last(sent))
    assert body["prediction"] == {"type": "content", "content": "ssn <SSN_1>"}
    assert body["user"] == "<EMAIL_1>"
    # "name" and "id" are fields of the application's record here, not protocol
    assert body["metadata"] == {"name": "<PERSON_1>", "id": "<SSN_1>", "plan": "pro"}
    assert SSN not in _last(sent) and EMAIL not in _last(sent) and "Alice Lee" not in _last(sent)


@needs_openai
def test_an_opaque_user_id_is_left_alone(ward):
    sent: list = []
    client = _client("openai", sent, ward)
    client.chat.completions.create(model="m", messages=[{"role": "user", "content": "hi"}],
                                   user="u_8841", safety_identifier="acct-77")
    body = json.loads(_last(sent))
    assert body["user"] == "u_8841" and body["safety_identifier"] == "acct-77"


@needs_openai
def test_openai_responses_prompt_variables_are_redacted(ward):
    sent: list = []
    client = _client("openai", sent, ward)
    client.responses.create(model="m", input="hi", user=EMAIL, prompt={
        "id": "pmpt_1", "version": "2", "variables": {"name": "Alice Lee", "id": SSN}})
    body = json.loads(_last(sent))
    assert body["prompt"]["id"] == "pmpt_1" and body["prompt"]["version"] == "2"
    assert body["prompt"]["variables"] == {"name": "<PERSON_1>", "id": "<SSN_1>"}
    assert body["user"] == "<EMAIL_1>"


@needs_anthropic
def test_anthropic_metadata_user_id_is_redacted(ward):
    sent: list = []
    client = _client("anthropic", sent, ward)
    client.messages.create(model="m", max_tokens=8, messages=[{"role": "user", "content": "hi"}],
                           metadata={"user_id": EMAIL})
    assert json.loads(_last(sent))["metadata"] == {"user_id": "<EMAIL_1>"}
    client.messages.create(model="m", max_tokens=8, messages=[{"role": "user", "content": "hi"}],
                           metadata={"user_id": "u_8841"})
    assert json.loads(_last(sent))["metadata"] == {"user_id": "u_8841"}


# --- a tool result given as a list of records ---------------------------------------

def test_list_of_records_is_data_and_protocol_parts_stay_valid():
    """In [{"name": ..., "id": ...}] under "content" the keys are the
    application's, not protocol: both values were sent raw."""
    from taintward.sdk.destinations import DEST_LLM
    from taintward.sdk.integrations._payload import redact_structure
    from taintward.sdk.placeholders import PlaceholderMap

    pmap = PlaceholderMap()
    msg = {"role": "tool", "tool_call_id": "t1",
           "content": [{"name": "Alice Lee", "id": SSN, "status": "active"}]}
    out = redact_structure(msg, DEST_LLM, pmap)
    assert out["tool_call_id"] == "t1" and out["role"] == "tool"
    assert out["content"] == [{"name": "<PERSON_1>", "id": "<SSN_1>", "status": "active"}]

    # protocol parts in the same place are left valid: type, ids and image data stay
    parts = {"role": "user", "content": [
        {"type": "text", "text": f"ssn {SSN}"},
        {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}},
        # a protocol id is never rewritten, whatever it looks like: the
        # request would no longer match its tool call
        {"type": "tool_result", "tool_use_id": SSN, "content": "ok"}]}
    out = redact_structure(parts, DEST_LLM, pmap)
    assert out["content"][0] == {"type": "text", "text": "ssn <SSN_1>"}
    assert out["content"][1] == parts["content"][1]
    assert out["content"][2] == parts["content"][2]
    # a list of messages (role, no type) is protocol too
    items = {"input": [{"role": "user", "content": f"ssn {SSN}", "name": "alice"}]}
    assert redact_structure(items, DEST_LLM, pmap) == {
        "input": [{"role": "user", "content": "ssn <SSN_1>", "name": "alice"}]}


@needs_openai
def test_openai_tool_message_with_a_list_of_records(ward):
    sent: list = []
    client = _client("openai", sent, ward)
    client.chat.completions.create(model="m", messages=[
        {"role": "user", "content": "look it up"},
        {"role": "tool", "tool_call_id": "t1", "content": [{"name": "Alice Lee", "id": SSN}]}])
    assert SSN not in _last(sent) and "Alice Lee" not in _last(sent)
