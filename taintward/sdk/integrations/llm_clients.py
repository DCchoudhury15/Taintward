"""Redaction for raw LLM provider clients (OpenAI and Anthropic SDKs).

The LLM provider is an egress sink: everything in the request (system
prompt, user text, earlier tool results, earlier tool call arguments) leaves
the process. ``protect_openai(client)`` and ``protect_anthropic(client)``
patch the client *instance* so each request is redacted for the ``llm``
destination before it is sent, and a ``chat <model>`` span is recorded with
``taintward.destination=llm``.

Patched methods (sync and async clients):

* OpenAI: ``client.chat.completions.create`` and ``client.responses.create``
* Anthropic: ``client.messages.create``

Use the protected OpenAI client with the OpenAI Agents SDK too
(``agents.set_default_openai_client(client)`` or
``OpenAIChatCompletionsModel(openai_client=client)``) so the agent's own model
calls are redacted.

With placeholders on (the default), the request carries stable placeholders
(``<PERSON_1>``, ``<SSN_1>``) instead of masks, and the response object is
restored in place before it is returned: message text, tool call arguments
(OpenAI JSON strings, Anthropic ``tool_use.input``) and Responses API output
items get the real values back. The span keeps the placeholder version.

With ``stream=True`` the same stream object is returned, and each chunk it
hands out is a restored copy: text deltas, tool call argument deltas
(JSON-escaped), and the full texts of the "done" events. A placeholder split
across two chunks is restored whole (the start is held back for a moment).
The span stays open until the stream ends and then records the answer. The
OpenAI ``chat.completions.stream()`` and ``responses.stream()`` helpers call
``create``, so they are covered too.

The patch is applied to one client object only. Other clients, Anthropic's
``messages.stream()`` helper, and the ``with_raw_response`` /
``with_streaming_response`` helpers are not covered.
"""

from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, Mapping

from opentelemetry import trace

from taintward.sdk import placeholders as ph
from taintward.sdk.destinations import DEST_LLM
from taintward.sdk.instrumentation import GuardedCall
from taintward.sdk.integrations import Ward, _resolve
from taintward.sdk.integrations._payload import structure_redactor, to_plain
from taintward.sdk.integrations._stream import (
    ChatChunks,
    Pieces,
    StreamCall,
    clone,
    get,
    guard_stream,
    is_stream,
    json_format,
    set_usage,
)

_PATCHED_MARK = "__taintward_patched__"

# Request fields that carry content, per API. Everything else (model,
# temperature, tool schemas, ...) is passed through unchanged.
_OPENAI_CHAT_FIELDS = ("messages",)
_OPENAI_RESPONSES_FIELDS = ("input", "instructions")
_ANTHROPIC_FIELDS = ("messages", "system")


def _output_view(provider: str, resp: Any) -> Any:
    """Small, JSON-able view of a provider response for taint detection."""
    if provider == "openai.chat":
        choices = getattr(resp, "choices", None)
        if choices is not None:
            return [to_plain(getattr(c, "message", c)) for c in choices]
    if provider == "openai.responses":
        out = getattr(resp, "output", None)
        if out is not None:
            return [to_plain(o) for o in out]
    if provider == "anthropic":
        content = getattr(resp, "content", None)
        if content is not None:
            return [to_plain(b) for b in content]
    plain = to_plain(resp)
    return plain if isinstance(plain, (dict, list, str)) else str(plain)


def _usage_attrs(span, resp: Any) -> None:
    set_usage(span, getattr(resp, "usage", None))


# --- streams ---------------------------------------------------------------

_RESPONSE_END = ("response.completed", "response.incomplete", "response.failed")


class _ResponseEvents:
    """Handler for OpenAI Responses API stream events.

    Every ``*.delta`` event with a text ``delta`` (not base64 audio) is
    restored piece by piece
    (``*arguments*`` ones as JSON), keyed by its item and part. Its
    ``*.done`` event gets the held end as one extra delta event first, and
    its full text restored. ``response.completed`` carries the whole
    response: it is recorded (placeholder version) and restored."""

    def __init__(self, pmap, *, json_text: bool = False) -> None:
        self.p = Pieces(pmap)
        self.json_text = json_text
        self.last: dict = {}
        self.final: Any = None
        self.usage: Any = None

    @staticmethod
    def _key(ev: Any, prefix: str) -> tuple:
        return (prefix, get(ev, "item_id"), get(ev, "output_index"),
                get(ev, "content_index"), get(ev, "summary_index"))

    def _extra(self, key: tuple, rest: str) -> list:
        if not rest or key not in self.last:
            return []
        ev = clone(self.last[key])
        ev.delta = rest
        return [ev]

    def item(self, ev: Any) -> list:
        t = get(ev, "type") or ""
        delta = get(ev, "delta")
        if t.endswith(".delta") and isinstance(delta, str) and t != "response.audio.delta":
            prefix = t[:-len(".delta")]
            key = self._key(ev, prefix)
            json_mode = "arguments" in prefix or (
                self.json_text and prefix == "response.output_text")
            ev = clone(ev)
            ev.delta = self.p.push(key, delta, "json" if json_mode else "text")
            self.last[key] = ev
            return [ev]
        out = []
        if t.endswith(".done"):
            key = self._key(ev, t[:-len(".done")])
            out += self._extra(key, self.p.flush(key))
        if t in _RESPONSE_END and get(ev, "response") is not None:
            self.final = _output_view("openai.responses", ev.response)
            self.usage = get(ev.response, "usage")
        if t.endswith(".done") or t in _RESPONSE_END:
            ev = clone(ev)
            self.p.restore_full(ev)
        out.append(ev)
        return out

    def end(self) -> list:
        out = []
        for key in self.p.holding():
            out += self._extra(key, self.p.flush(key))
        return out

    def view(self) -> Any:
        if self.final is not None:
            return self.final
        return [{"type": k[0], "text": self.p.raw(k) or ""} for k in self.p.keys()]

    def annotate(self, span) -> None:
        set_usage(span, self.usage)


# content_block_delta type -> (field, mode)
_ANTHROPIC_DELTAS = {
    "text_delta": ("text", "text"),
    "input_json_delta": ("partial_json", "json"),
    "thinking_delta": ("thinking", "text"),
}


class _AnthropicEvents:
    """Handler for Anthropic Messages stream events: text, tool input JSON
    and thinking deltas are restored piece by piece per content block; the
    held end goes out as one extra delta event before ``content_block_stop``."""

    def __init__(self, pmap) -> None:
        self.p = Pieces(pmap)
        self.last: dict = {}
        self.blocks: dict = {}
        self.usage: dict = {}

    def _usage(self, usage: Any) -> None:
        for f in ("input_tokens", "output_tokens"):
            v = get(usage, f)
            if isinstance(v, int):
                self.usage[f] = v

    def _extra(self, key: tuple, rest: str) -> list:
        if not rest or key not in self.last:
            return []
        ev = clone(self.last[key])
        setattr(ev.delta, key[1], rest)
        return [ev]

    def item(self, ev: Any) -> list:
        t = get(ev, "type")
        if t == "message_start":
            msg = get(ev, "message")
            self._usage(get(msg, "usage"))
            if get(msg, "content"):
                ev = clone(ev)
                self.p.restore_full(ev.message.content)
        elif t == "content_block_start":
            block = get(ev, "content_block")
            self.blocks[ev.index] = (get(block, "type"), get(block, "name"))
            if isinstance(get(block, "text"), str) and block.text:
                ev = clone(ev)
                ev.content_block.text = self.p.push((ev.index, "text"), block.text)
            elif get(block, "input"):
                ev = clone(ev)
                self.p.restore_full(ev.content_block.input)
        elif t == "content_block_delta":
            field, mode = _ANTHROPIC_DELTAS.get(get(ev.delta, "type"), (None, None))
            value = get(ev.delta, field) if field else None
            if isinstance(value, str) and value:
                key = (ev.index, field)
                ev = clone(ev)
                setattr(ev.delta, field, self.p.push(key, value, mode))
                self.last[key] = ev
        elif t == "content_block_stop":
            out = []
            for key in self.p.holding(lambda k: k[0] == ev.index):
                out += self._extra(key, self.p.flush(key))
            return [*out, ev]
        elif t == "message_delta":
            self._usage(get(ev, "usage"))
        return [ev]

    def end(self) -> list:
        out = []
        for key in self.p.holding():
            out += self._extra(key, self.p.flush(key))
        return out

    def view(self) -> list:
        out = []
        for idx in sorted(set(self.blocks) | {k[0] for k in self.p.keys()}):
            kind, name = self.blocks.get(idx, (None, None))
            for field in ("text", "thinking", "partial_json"):
                text = self.p.raw((idx, field))
                if text is None:
                    continue
                if field == "partial_json":
                    out.append({"type": kind or "tool_use", "name": name, "input": text})
                else:
                    out.append({"type": field, field: text})
        return out

    def annotate(self, span) -> None:
        set_usage(span, self.usage)


def _stream_handler(provider: str, kwargs: dict, pmap):
    if provider == "openai.chat":
        return ChatChunks(pmap, json_content=json_format(kwargs.get("response_format")))
    if provider == "openai.responses":
        return _ResponseEvents(pmap, json_text=json_format(kwargs.get("text")))
    return _AnthropicEvents(pmap)


def _guard_request(provider: str, system: str, fields: tuple[str, ...],
                   kwargs: dict, ward: Ward, pmap=None) -> GuardedCall:
    model = str(kwargs.get("model", ""))
    content = {k: kwargs[k] for k in fields if k in kwargs}
    return GuardedCall(
        f"chat {model}".strip(),
        destination=DEST_LLM,
        jurisdiction=ward.llm_jurisdiction,
        tracer=ward.tracer,
        kwargs=content,
        redact=structure_redactor(pmap),
        input_attr="gen_ai.input.messages",
        output_attr="gen_ai.output.messages",
        input_view=lambda _a, kw: kw,
        kind=trace.SpanKind.CLIENT,
        attributes={
            "gen_ai.operation.name": "chat",
            "gen_ai.provider.name": system,
            "gen_ai.request.model": model,
            "taintward.framework": provider,
        },
    )


def with_instruction(provider: str, content: dict, pmap, ward: Ward) -> dict:
    """The redacted request fields plus one system line that asks the model to
    copy the placeholders exactly (``ward.placeholder_instruction``). Returns
    ``content`` itself when nothing is added (no placeholders, or turned off)."""
    if pmap is None or not len(pmap) or not getattr(ward, "placeholder_instruction", True):
        return content
    names = ph.placeholders_in(content)
    if not names:
        return content
    line = ph.instruction_for(names)
    if provider == "openai.chat":
        msgs = list(content.get("messages") or [])
        first = msgs[0] if msgs else None
        if (isinstance(first, Mapping) and first.get("role") in ("system", "developer")
                and isinstance(first.get("content"), str)):
            msgs[0] = {**first, "content": f"{first['content']}\n\n{line}"}
        else:
            msgs.insert(0, {"role": "system", "content": line})
        return {**content, "messages": msgs}
    if provider == "openai.responses":
        prev = content.get("instructions")
        return {**content, "instructions": f"{prev}\n\n{line}" if prev else line}
    if provider == "anthropic":
        prev = content.get("system")
        if isinstance(prev, str) and prev:
            new: Any = f"{prev}\n\n{line}"
        elif isinstance(prev, list):
            new = [*prev, {"type": "text", "text": line}]
        else:
            new = line
        return {**content, "system": new}
    return content


def _wrap_create(original: Callable, provider: str, system: str,
                 fields: tuple[str, ...], ward: Ward) -> Callable:
    is_async = inspect.iscoroutinefunction(inspect.unwrap(original))

    def finish(call: GuardedCall, kwargs: dict, resp: Any, pmap) -> Any:
        # Record first: the span keeps the placeholder version of the answer.
        view = _output_view(provider, resp)
        call.record_result(resp, view=view)
        _usage_attrs(call.span, resp)
        if pmap is not None and len(pmap):
            ph.check_output(pmap, view, span=call.span,
                            strict=getattr(ward, "placeholder_strict", False))
            resp = pmap.restore_inplace(resp)
        return resp

    def request(call: GuardedCall, pmap) -> dict:
        send = with_instruction(provider, call.kwargs, pmap, ward)
        if send is not call.kwargs:
            call.span.set_attribute("taintward.placeholders.instruction", True)
        return send

    def open_stream(kwargs: dict, pmap) -> tuple[StreamCall, dict]:
        sc = StreamCall(_guard_request(provider, system, fields, kwargs, ward, pmap), ward, pmap)
        call = sc.enter()
        try:
            return sc, request(call, pmap)
        except BaseException as e:
            sc.end(None, exc=e, check=False)
            raise

    def stream(sc: StreamCall, kwargs: dict, resp: Any, pmap) -> Any:
        if not is_stream(resp):  # a full answer after all
            try:
                resp = sc.run(finish, sc.call, {**kwargs, "stream": False}, resp, pmap)
            except BaseException as e:
                sc.end(None, exc=e, check=False)
                raise
            sc.end(None, check=False)
            return resp
        return guard_stream(resp, sc, _stream_handler(provider, kwargs, pmap))

    if is_async:
        @functools.wraps(original)
        async def acreate(*args, **kwargs):
            pmap = ward.llm_placeholder_map()
            if kwargs.get("stream"):
                sc, send = open_stream(kwargs, pmap)
                try:
                    resp = await sc.arun(original(*args, **{**kwargs, **send}))
                except BaseException as e:
                    sc.end(None, exc=e, check=False)
                    raise
                return stream(sc, kwargs, resp, pmap)
            with _guard_request(provider, system, fields, kwargs, ward, pmap) as call:
                resp = await original(*args, **{**kwargs, **request(call, pmap)})
                resp = finish(call, kwargs, resp, pmap)
            return resp
        setattr(acreate, _PATCHED_MARK, True)
        return acreate

    @functools.wraps(original)
    def create(*args, **kwargs):
        pmap = ward.llm_placeholder_map()
        if kwargs.get("stream"):
            sc, send = open_stream(kwargs, pmap)
            try:
                resp = sc.run(original, *args, **{**kwargs, **send})
            except BaseException as e:
                sc.end(None, exc=e, check=False)
                raise
            return stream(sc, kwargs, resp, pmap)
        with _guard_request(provider, system, fields, kwargs, ward, pmap) as call:
            resp = original(*args, **{**kwargs, **request(call, pmap)})
            resp = finish(call, kwargs, resp, pmap)
        return resp
    setattr(create, _PATCHED_MARK, True)
    return create


def _patch(resource: Any, provider: str, system: str, fields: tuple[str, ...],
           ward: Ward) -> bool:
    if resource is None:
        return False
    original = getattr(resource, "create", None)
    if original is None or getattr(original, _PATCHED_MARK, False):
        return False
    resource.create = _wrap_create(original, provider, system, fields, ward)
    return True


def protect_openai(client: Any, *, ward: Ward | None = None) -> Any:
    """Patch an ``openai.OpenAI`` / ``openai.AsyncOpenAI`` instance in place
    and return it. Safe to call twice (the second call does nothing)."""
    w = ward or _resolve(None, None)
    chat = getattr(client, "chat", None)
    patched = _patch(getattr(chat, "completions", None), "openai.chat", "openai",
                     _OPENAI_CHAT_FIELDS, w)
    patched |= _patch(getattr(client, "responses", None), "openai.responses", "openai",
                      _OPENAI_RESPONSES_FIELDS, w)
    if not patched and not _already(client, "openai"):
        raise TypeError("client has no chat.completions.create or responses.create")
    return client


def protect_anthropic(client: Any, *, ward: Ward | None = None) -> Any:
    """Patch an ``anthropic.Anthropic`` / ``anthropic.AsyncAnthropic``
    instance in place and return it."""
    w = ward or _resolve(None, None)
    patched = _patch(getattr(client, "messages", None), "anthropic", "anthropic",
                     _ANTHROPIC_FIELDS, w)
    if not patched and not _already(client, "anthropic"):
        raise TypeError("client has no messages.create")
    return client


def _already(client: Any, kind: str) -> bool:
    if kind == "openai":
        res = [getattr(getattr(client, "chat", None), "completions", None),
               getattr(client, "responses", None)]
    else:
        res = [getattr(client, "messages", None)]
    return any(getattr(getattr(r, "create", None), _PATCHED_MARK, False) for r in res)


__all__ = ["protect_openai", "protect_anthropic"]
