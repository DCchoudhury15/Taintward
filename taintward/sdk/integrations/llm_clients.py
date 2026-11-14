"""Redaction for raw LLM provider clients (OpenAI and Anthropic SDKs).

The LLM provider is an egress sink: everything in the request (system
prompt, user text, earlier tool results, earlier tool call arguments) leaves
the process. ``protect_openai(client)`` and ``protect_anthropic(client)``
patch the client *instance* so each request is redacted for the ``llm``
destination before it is sent, and a ``chat <model>`` span is recorded with
``taintward.destination=llm``.

Patched methods (sync and async clients):

* OpenAI: ``client.chat.completions.create`` / ``.parse`` and
  ``client.responses.create`` / ``.parse``
* Anthropic: ``client.messages.create`` / ``.parse`` / ``.count_tokens``
  and the ``client.messages.stream()`` helper, and the same four on
  ``client.beta.messages``
* ``client.with_options(...)`` and ``client.copy(...)``: the client they
  return is protected too
* OpenAI embeddings: ``client.embeddings.create``. The input is masked for
  the ``rag`` destination (an embedding can be turned back into text), see
  ``_embed.py``.

The ``parse()`` helpers send their own request (they do not call
``create``), so they are patched the same way as ``create``: the request is
redacted and the parsed answer (``.parsed``, ``parsed_output``) is restored
with the rest of the response.

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

Anthropic's ``messages.stream()`` helper does not call ``create``: it builds
the request itself and sends it when its ``with`` block starts. The patched
helper redacts the request at that moment (the span opens then too) and
hands the redacted fields to the SDK's own helper, so the SDK still builds
the request (headers, ``output_format``). The event stream inside the SDK's
``MessageStream`` gets the same restore as ``create(stream=True)``, so its
events, ``text_stream``, snapshots and ``get_final_message()`` carry the
real values. The SDK's own tracing reads that snapshot for its span when its
``content_mode`` is ``"content"``; the snapshot is kept from it, so that span
gets no answer text, as for ``create(stream=True)``.

Besides the conversation itself (``messages``, ``system``, ``input``,
``instructions``) these request fields are redacted: ``prediction``, the
``variables`` of a stored ``prompt``, ``metadata``, and the end user
identifiers ``user`` and ``safety_identifier`` (an identifier that is an
email address is personal data too; an opaque id is left as it is).

The patch is applied to one client object and the copies made from it.
Anthropic batch requests (``messages.batches.create``) are sent with one-way
masks instead of placeholders: a batch answer comes back in another call,
so it could not be restored. The first one logs a warning. OpenAI batches
are built from an uploaded file and are not covered, like other clients.
The answers of the ``with_raw_response`` / ``with_streaming_response``
helpers are not restored.
"""

from __future__ import annotations

import functools
import inspect
import logging
from typing import Any, Callable, Mapping

from opentelemetry import trace

from taintward.sdk import placeholders as ph
from taintward.sdk.destinations import DEST_LLM
from taintward.sdk.instrumentation import GuardedCall
from taintward.sdk.integrations import Ward, _resolve
from taintward.sdk.integrations._payload import (
    payload_redactor,
    structure_redactor,
    to_plain,
)
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

log = logging.getLogger("taintward.sdk")

_PATCHED_MARK = "__taintward_patched__"

# Request fields that carry content, per API. Everything else (model,
# temperature, tool schemas, ...) is passed through unchanged.
# Everything in a request that can hold the user's data. The identifiers at
# the end go to the provider too.
_OPENAI_CHAT_FIELDS = ("messages", "prediction", "metadata", "user", "safety_identifier")
_OPENAI_RESPONSES_FIELDS = ("input", "instructions", "prompt", "metadata", "user",
                            "safety_identifier")
_ANTHROPIC_FIELDS = ("messages", "system", "metadata")


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

    def __init__(self, pmap, *, json_text: bool = False) -> None:
        self.p = Pieces(pmap)
        self.text_mode = "json" if json_text else "text"
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
                ev.content_block.text = self.p.push((ev.index, "text"), block.text,
                                                    self.text_mode)
            elif get(block, "input"):
                ev = clone(ev)
                self.p.restore_full(ev.content_block.input)
        elif t == "content_block_delta":
            field, mode = _ANTHROPIC_DELTAS.get(get(ev.delta, "type"), (None, None))
            if field == "text":
                mode = self.text_mode
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
    return _AnthropicEvents(pmap, json_text=_anthropic_json(kwargs))


def _anthropic_json(kwargs: dict) -> bool:
    """Does an Anthropic request ask for a JSON answer (``output_format`` or
    ``output_config.format``)? Its text is then restored JSON-escaped."""
    return json_format(kwargs.get("output_format")) or json_format(kwargs.get("output_config"))


# Request fields that are the application's own data as a whole: no key in
# them is a protocol key ({"name": ..., "id": ...} is a customer record).
_DATA_FIELDS = frozenset({"metadata"})


def _request_redactor(content: dict, pmap) -> Callable:
    """The redactor for the fields of one request. GuardedCall hands it one
    field value at a time, so the fields in _DATA_FIELDS are told apart by
    the object they are."""
    data = {id(v) for k, v in content.items() if k in _DATA_FIELDS and isinstance(v, Mapping)}
    structure, payload = structure_redactor(pmap), payload_redactor(pmap)

    def redact(value: Any, destination: str) -> Any:
        return (payload if id(value) in data else structure)(value, destination)
    return redact


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
        redact=_request_redactor(content, pmap),
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


def _send_fields(provider: str, call: GuardedCall, pmap, ward: Ward) -> dict:
    """The redacted request fields to send (with the placeholder line)."""
    send = with_instruction(provider, call.kwargs, pmap, ward)
    if send is not call.kwargs:
        call.span.set_attribute("taintward.placeholders.instruction", True)
    return send


def _open_stream(provider: str, system: str, fields: tuple[str, ...], kwargs: dict,
                 ward: Ward, pmap) -> tuple[StreamCall, dict]:
    """Open the span of a streamed request and redact it."""
    sc = StreamCall(_guard_request(provider, system, fields, kwargs, ward, pmap), ward, pmap)
    call = sc.enter()
    try:
        return sc, _send_fields(provider, call, pmap, ward)
    except BaseException as e:
        sc.end(None, exc=e, check=False)
        raise


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
        return _send_fields(provider, call, pmap, ward)

    def open_stream(kwargs: dict, pmap) -> tuple[StreamCall, dict]:
        return _open_stream(provider, system, fields, kwargs, ward, pmap)

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


# --- Anthropic messages.stream() ---------------------------------------------


class _MessageStreamManager:
    """What a protected client's ``messages.stream()`` returns. ``with`` sends
    the redacted request and gives the SDK's own ``MessageStream``."""

    def __init__(self, start: Callable[[], Any]) -> None:
        self._start = start
        self._stream: Any = None

    def __enter__(self) -> Any:
        self._stream = self._start()
        return self._stream

    def __exit__(self, *exc: Any) -> None:
        if self._stream is not None:
            self._stream.close()


class _AsyncMessageStreamManager:
    """The async client's version: ``async with``."""

    def __init__(self, start: Callable[[], Any]) -> None:
        self._start = start
        self._stream: Any = None

    async def __aenter__(self) -> Any:
        self._stream = await self._start()
        return self._stream

    async def __aexit__(self, *exc: Any) -> None:
        if self._stream is not None:
            await self._stream.close()


def _guard_message_stream(sc: StreamCall, ms: Any, kwargs: dict, pmap) -> Any:
    """Restore the events the SDK's ``MessageStream`` reads, and keep its
    snapshot (real values) out of the SDK's own span."""
    raw = getattr(ms, "_raw_stream", None)
    if raw is None or not is_stream(raw):
        # Not the SDK layout this was written for: the request was redacted,
        # but the answer keeps its placeholders.
        log.warning("taintward: cannot restore Anthropic messages.stream() answers "
                    "with this SDK version; they keep their placeholders")
        sc.end(None, check=False)
        return ms
    guarded = guard_stream(raw, sc, _AnthropicEvents(pmap, json_text=_anthropic_json(kwargs)))
    if guarded is not raw:
        ms._raw_stream = guarded
    try:
        from anthropic.lib._tracing import withhold_message_snapshot
    except ImportError:  # an SDK without tracing of its own
        return ms
    withhold_message_snapshot(raw)
    return ms


def _wrap_message_stream(original: Callable, ward: Ward, is_async: bool) -> Callable:
    provider = system = "anthropic"

    def open_(args: tuple, kwargs: dict) -> tuple[StreamCall, Any, Any]:
        pmap = ward.llm_placeholder_map()
        sc, send = _open_stream(provider, system, _ANTHROPIC_FIELDS, kwargs, ward, pmap)
        try:
            manager = sc.run(original, *args, **{**kwargs, **send})
        except BaseException as e:
            sc.end(None, exc=e, check=False)
            raise
        return sc, manager, pmap

    if is_async:
        @functools.wraps(original)
        def astream(*args, **kwargs):
            async def start():
                sc, manager, pmap = open_(args, kwargs)
                try:
                    ms = await sc.arun(manager.__aenter__())
                except BaseException as e:
                    sc.end(None, exc=e, check=False)
                    raise
                return _guard_message_stream(sc, ms, kwargs, pmap)
            return _AsyncMessageStreamManager(start)
        setattr(astream, _PATCHED_MARK, True)
        return astream

    @functools.wraps(original)
    def stream(*args, **kwargs):
        def start():
            sc, manager, pmap = open_(args, kwargs)
            try:
                ms = sc.run(manager.__enter__)
            except BaseException as e:
                sc.end(None, exc=e, check=False)
                raise
            return _guard_message_stream(sc, ms, kwargs, pmap)
        return _MessageStreamManager(start)
    setattr(stream, _PATCHED_MARK, True)
    return stream


def _patch_message_stream(resource: Any, ward: Ward) -> bool:
    original = getattr(resource, "stream", None) if resource is not None else None
    if original is None or getattr(original, _PATCHED_MARK, False):
        return False
    is_async = inspect.iscoroutinefunction(inspect.unwrap(resource.create))
    resource.stream = _wrap_message_stream(original, ward, is_async)
    return True


def _wrap_embeddings(original: Callable, ward: Ward) -> Callable:
    from taintward.sdk.integrations._embed import embed_async, embed_sync

    if inspect.iscoroutinefunction(inspect.unwrap(original)):
        @functools.wraps(original)
        async def acreate(*args, **kwargs):
            return await embed_async(
                ward, "openai", "openai", str(kwargs.get("model", "")), kwargs.get("input"),
                lambda texts: original(*args, **{**kwargs, "input": texts}))
        setattr(acreate, _PATCHED_MARK, True)
        return acreate

    @functools.wraps(original)
    def create(*args, **kwargs):
        return embed_sync(
            ward, "openai", "openai", str(kwargs.get("model", "")), kwargs.get("input"),
            lambda texts: original(*args, **{**kwargs, "input": texts}))
    setattr(create, _PATCHED_MARK, True)
    return create


def _patch_embeddings(resource: Any, ward: Ward) -> bool:
    original = getattr(resource, "create", None) if resource is not None else None
    if original is None or getattr(original, _PATCHED_MARK, False):
        return False
    resource.create = _wrap_embeddings(original, ward)
    return True


def _wrap_count_tokens(original: Callable, provider: str, system: str,
                       fields: tuple[str, ...], ward: Ward) -> Callable:
    """Token counting sends the whole prompt to the provider: redact it the
    same way. The answer is a number, so nothing is restored."""
    if inspect.iscoroutinefunction(inspect.unwrap(original)):
        @functools.wraps(original)
        async def acount(*args, **kwargs):
            with _guard_request(provider, system, fields, kwargs, ward,
                                ward.llm_placeholder_map()) as call:
                return await original(*args, **{**kwargs, **call.kwargs})
        setattr(acount, _PATCHED_MARK, True)
        return acount

    @functools.wraps(original)
    def count(*args, **kwargs):
        with _guard_request(provider, system, fields, kwargs, ward,
                            ward.llm_placeholder_map()) as call:
            return original(*args, **{**kwargs, **call.kwargs})
    setattr(count, _PATCHED_MARK, True)
    return count


def _patch_count_tokens(resource: Any, provider: str, system: str,
                        fields: tuple[str, ...], ward: Ward) -> bool:
    original = getattr(resource, "count_tokens", None) if resource is not None else None
    if original is None or getattr(original, _PATCHED_MARK, False):
        return False
    resource.count_tokens = _wrap_count_tokens(original, provider, system, fields, ward)
    return True


def _wrap_batches_create(original: Callable, provider: str, system: str,
                         fields: tuple[str, ...], ward: Ward, what: str) -> Callable:
    """A batch answer comes back later, in another call, so it could not be
    restored: placeholders would stay in it. The requests are sent with
    one-way masks instead, and the first call says so."""
    warned: list[bool] = []

    def guard(kwargs: dict) -> tuple[GuardedCall, list]:
        if not warned:
            warned.append(True)
            log.warning("taintward: %s requests are sent with one-way masks ([PII], "
                        "[SECRET]), not placeholders: a batch answer cannot be restored", what)
        requests = [to_plain(r) for r in (kwargs.get("requests") or [])]
        content = [{k: p[k] for k in fields if k in p}
                   for p in ((r.get("params") or {}) if isinstance(r, Mapping) else {}
                             for r in requests)]
        structure, payload = structure_redactor(None), payload_redactor(None)

        def redact(value: Any, destination: str) -> Any:
            return [{k: (payload if k in _DATA_FIELDS and isinstance(v, Mapping)
                         else structure)(v, destination) for k, v in item.items()}
                    for item in value]
        call = GuardedCall(
            f"batch {what}", destination=DEST_LLM, jurisdiction=ward.llm_jurisdiction,
            tracer=ward.tracer, kwargs={"requests": content}, redact=redact,
            input_attr="gen_ai.input.messages", output_attr="gen_ai.output.messages",
            input_view=lambda _a, kw: kw, kind=trace.SpanKind.CLIENT,
            attributes={"gen_ai.operation.name": "batch", "gen_ai.provider.name": system,
                        "taintward.framework": provider})
        return call, requests

    def send(call: GuardedCall, requests: list) -> list:
        out = []
        for r, redacted in zip(requests, call.kwargs["requests"]):
            if isinstance(r, Mapping) and isinstance(r.get("params"), Mapping):
                r = {**r, "params": {**r["params"], **redacted}}
            out.append(r)
        return out

    if inspect.iscoroutinefunction(inspect.unwrap(original)):
        @functools.wraps(original)
        async def acreate(*args, **kwargs):
            call, requests = guard(kwargs)
            with call:
                return await original(*args, **{**kwargs, "requests": send(call, requests)})
        setattr(acreate, _PATCHED_MARK, True)
        return acreate

    @functools.wraps(original)
    def create(*args, **kwargs):
        call, requests = guard(kwargs)
        with call:
            return original(*args, **{**kwargs, "requests": send(call, requests)})
    setattr(create, _PATCHED_MARK, True)
    return create


def _patch_batches(resource: Any, provider: str, system: str, fields: tuple[str, ...],
                   ward: Ward, what: str) -> None:
    batches = getattr(resource, "batches", None) if resource is not None else None
    original = getattr(batches, "create", None)
    if original is None or getattr(original, _PATCHED_MARK, False):
        return
    try:
        batches.create = _wrap_batches_create(original, provider, system, fields, ward, what)
    except Exception:  # noqa: BLE001 - a resource that cannot be patched
        log.warning("taintward: could not patch %s.create; batch requests are not "
                    "redacted", what)


def _patch_copies(client: Any, protect: Callable, ward: Ward) -> None:
    """``client.with_options(...)`` and ``client.copy(...)`` build a new
    client object. Protect that one too: it was sending everything raw."""
    for name in ("copy", "with_options"):
        original = getattr(client, name, None)
        if original is None or getattr(original, _PATCHED_MARK, False):
            continue

        @functools.wraps(original)
        def derived(*args, _original=original, **kwargs):
            return protect(_original(*args, **kwargs), ward=ward)
        setattr(derived, _PATCHED_MARK, True)
        try:
            setattr(client, name, derived)
        except Exception:  # noqa: BLE001 - a client that cannot be patched
            log.warning("taintward: could not patch %s() on %s; a client made with it "
                        "is not protected", name, type(client).__name__)


def _patch(resource: Any, provider: str, system: str, fields: tuple[str, ...],
           ward: Ward) -> bool:
    """Patch ``create`` and ``parse`` (which sends its own request)."""
    if resource is None:
        return False
    patched = False
    for name in ("create", "parse"):
        original = getattr(resource, name, None)
        if original is None or getattr(original, _PATCHED_MARK, False):
            continue
        setattr(resource, name, _wrap_create(original, provider, system, fields, ward))
        patched = True
    return patched


def protect_openai(client: Any, *, ward: Ward | None = None) -> Any:
    """Patch an ``openai.OpenAI`` / ``openai.AsyncOpenAI`` instance in place
    and return it. Safe to call twice (the second call does nothing)."""
    w = ward or _resolve(None, None)
    chat = getattr(client, "chat", None)
    patched = _patch(getattr(chat, "completions", None), "openai.chat", "openai",
                     _OPENAI_CHAT_FIELDS, w)
    patched |= _patch(getattr(client, "responses", None), "openai.responses", "openai",
                      _OPENAI_RESPONSES_FIELDS, w)
    patched |= _patch_embeddings(getattr(client, "embeddings", None), w)
    if not patched and not _already(client, "openai"):
        raise TypeError("client has no chat.completions.create or responses.create")
    _patch_copies(client, protect_openai, w)
    return client


def protect_anthropic(client: Any, *, ward: Ward | None = None) -> Any:
    """Patch an ``anthropic.Anthropic`` / ``anthropic.AsyncAnthropic``
    instance in place and return it: ``create``, ``parse``, ``stream`` and
    ``count_tokens`` of ``client.messages`` and of ``client.beta.messages``."""
    w = ward or _resolve(None, None)
    messages = getattr(client, "messages", None)
    patched = _patch(messages, "anthropic", "anthropic", _ANTHROPIC_FIELDS, w)
    if patched or _already(client, "anthropic"):
        patched |= _patch_message_stream(messages, w)
    if not patched and not _already(client, "anthropic"):
        raise TypeError("client has no messages.create")
    _patch_count_tokens(messages, "anthropic", "anthropic", _ANTHROPIC_FIELDS, w)
    _patch_batches(messages, "anthropic", "anthropic", _ANTHROPIC_FIELDS, w, "messages.batches")
    # The beta namespace is a second set of the same endpoints.
    try:
        beta = getattr(getattr(client, "beta", None), "messages", None)
    except Exception:  # noqa: BLE001 - an SDK without it
        beta = None
    if beta is not None:
        if _patch(beta, "anthropic", "anthropic", _ANTHROPIC_FIELDS, w):
            _patch_message_stream(beta, w)
        _patch_count_tokens(beta, "anthropic", "anthropic", _ANTHROPIC_FIELDS, w)
        _patch_batches(beta, "anthropic", "anthropic", _ANTHROPIC_FIELDS, w,
                       "beta.messages.batches")
    _patch_copies(client, protect_anthropic, w)
    return client


def _already(client: Any, kind: str) -> bool:
    if kind == "openai":
        res = [getattr(getattr(client, "chat", None), "completions", None),
               getattr(client, "responses", None)]
    else:
        res = [getattr(client, "messages", None)]
    return any(getattr(getattr(r, "create", None), _PATCHED_MARK, False) for r in res)


__all__ = ["protect_openai", "protect_anthropic"]
