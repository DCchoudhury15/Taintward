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
Streamed responses are not restored (see docs/integrations.md).

The patch is applied to one client object only. Other clients, and the
``with_raw_response`` / ``with_streaming_response`` helpers, are not covered.
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
    usage = getattr(resp, "usage", None)
    if usage is None:
        return
    for src, dst in (
        ("prompt_tokens", "gen_ai.usage.input_tokens"),
        ("input_tokens", "gen_ai.usage.input_tokens"),
        ("completion_tokens", "gen_ai.usage.output_tokens"),
        ("output_tokens", "gen_ai.usage.output_tokens"),
    ):
        v = getattr(usage, src, None)
        if isinstance(v, int):
            span.set_attribute(dst, v)


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
        if kwargs.get("stream"):
            return resp  # streamed output is not inspected; the request still was
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

    if is_async:
        @functools.wraps(original)
        async def acreate(*args, **kwargs):
            pmap = ward.llm_placeholder_map()
            with _guard_request(provider, system, fields, kwargs, ward, pmap) as call:
                resp = await original(*args, **{**kwargs, **request(call, pmap)})
                resp = finish(call, kwargs, resp, pmap)
            return resp
        setattr(acreate, _PATCHED_MARK, True)
        return acreate

    @functools.wraps(original)
    def create(*args, **kwargs):
        pmap = ward.llm_placeholder_map()
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
