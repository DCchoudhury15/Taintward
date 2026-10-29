"""LlamaIndex adapter.

``wrap_tools(tools, mapping)`` returns protected copies of LlamaIndex tools
(``FunctionTool``, ``QueryEngineTool`` or any ``AsyncBaseTool``). ``call`` /
``acall`` (what agents use) run through the destination gate for the tool's
name. A workflow ``Context`` argument is passed through untouched. The
returned ``ToolOutput`` is recorded masked on the span.

``protect_llm(llm)`` returns a protected copy of a LlamaIndex LLM. ``chat``,
``achat``, ``complete`` and ``acomplete`` and their ``stream_*`` versions
send the request redacted for the ``llm`` destination: message text blocks,
tool call blocks and ``additional_kwargs`` (where OpenAI style tool calls
live). ``chat_with_tools`` and agents go through these methods too. With
placeholders on, the answer is restored: the message text, tool call
arguments and ``additional_kwargs``. In a stream each chunk's message (the
text so far) is restored, so the last chunk is complete; a placeholder split
across two ``delta`` strings stays in the deltas.

``response.raw`` (the provider's own response) is left as the provider sent
it, with placeholders.
"""

from __future__ import annotations

import contextvars
import functools
from typing import Any, Iterable, Mapping

from llama_index.core.base.llms.types import (
    ChatMessage,
    ChatResponse,
    CompletionResponse,
    TextBlock,
    ToolCallBlock,
)
from llama_index.core.tools.types import BaseTool

from taintward.sdk.integrations import Ward, _resolve
from taintward.sdk.integrations._common import (
    finish_llm,
    instruction,
    is_protected,
    isolated_aiter,
    isolated_iter,
    llm_call,
    protected_copy,
    tool_call,
    ward_of,
)
from taintward.sdk.integrations._payload import redact_structure

FRAMEWORK = "llamaindex"

# Set while a protected LLM method runs: LLM classes often call one method
# from another (CustomLLM.chat calls complete), and the request is already
# redacted by then.
_INSIDE: contextvars.ContextVar[bool] = contextvars.ContextVar("taintward_li_llm", default=False)


# ---------------------------------------------------------------------------
# tools
# ---------------------------------------------------------------------------

def _split(tool, kwargs: dict) -> tuple[dict, dict]:
    ctx = getattr(tool, "ctx_param_name", None)
    keep = {k: v for k, v in kwargs.items() if k == ctx}
    return {k: v for k, v in kwargs.items() if k != ctx}, keep


def _out_view(out: Any) -> Any:
    content = getattr(out, "content", None)
    return content if isinstance(content, str) else str(out)


def _tool_class(base: type) -> type:
    class Protected(base):  # type: ignore[misc, valid-type]
        def call(self, *args, **kwargs):
            data, keep = _split(self, kwargs)
            with tool_call(ward_of(self), self.metadata.name, FRAMEWORK,
                           args=args, kwargs=data) as call:
                out = super().call(*call.args, **call.kwargs, **keep)
                call.record_result(out, view=_out_view(out))
            return out

        async def acall(self, *args, **kwargs):
            data, keep = _split(self, kwargs)
            with tool_call(ward_of(self), self.metadata.name, FRAMEWORK,
                           args=args, kwargs=data) as call:
                out = await super().acall(*call.args, **call.kwargs, **keep)
                call.record_result(out, view=_out_view(out))
            return out

    return Protected


def wrap_tool(tool: BaseTool, mapping: Mapping[str, Any] | None = None, *,
              ward: Ward | None = None) -> BaseTool:
    if is_protected(tool):
        return tool
    return protected_copy(tool, _tool_class, _resolve(ward, mapping))


def wrap_tools(tools: Iterable[BaseTool], mapping: Mapping[str, Any] | None = None, *,
               ward: Ward | None = None) -> list[BaseTool]:
    w = _resolve(ward, mapping)
    return [wrap_tool(t, ward=w) for t in tools]


# ---------------------------------------------------------------------------
# messages
# ---------------------------------------------------------------------------

def _map_message(m: ChatMessage, fn) -> ChatMessage:
    blocks = []
    for b in m.blocks:
        if isinstance(b, TextBlock):
            b = b.model_copy(update={"text": fn(b.text)})
        elif isinstance(b, ToolCallBlock):
            b = b.model_copy(update={"tool_kwargs": fn(b.tool_kwargs)})
        blocks.append(b)
    return m.model_copy(update={"blocks": blocks,
                                "additional_kwargs": fn(dict(m.additional_kwargs))})


def _dump(messages: list[ChatMessage]) -> list[dict]:
    return [m.model_dump(mode="json", exclude={"additional_kwargs": {"raw"}}) for m in messages]


def _messages_redactor(pmap):
    def redact(messages, destination):
        return [_map_message(m, lambda v: redact_structure(v, destination, pmap))
                for m in messages]
    return redact


def _restore_response(resp: Any, pmap) -> Any:
    if isinstance(resp, ChatResponse):
        resp.message = _map_message(resp.message, pmap.restore_inplace)
        if isinstance(resp.delta, str):
            resp.delta = pmap.restore_text(resp.delta)
        resp.additional_kwargs = pmap.restore_inplace(resp.additional_kwargs)
    elif isinstance(resp, CompletionResponse):
        resp.text = pmap.restore_text(resp.text)
        if isinstance(resp.delta, str):
            resp.delta = pmap.restore_text(resp.delta)
        resp.additional_kwargs = pmap.restore_inplace(resp.additional_kwargs)
    return resp


def _view(resp: Any) -> Any:
    if isinstance(resp, ChatResponse):
        return _dump([resp.message])
    return getattr(resp, "text", str(resp))


def _model(llm) -> str:
    meta = getattr(llm, "metadata", None)
    return str(getattr(meta, "model_name", "") or getattr(llm, "model", ""))


class _Request:
    """Redacts one request and restores what comes back."""

    def __init__(self, llm, field: str, value: Any):
        self.ward = ward_of(llm)
        self.pmap = self.ward.llm_placeholder_map()
        self.field = field
        msgs = field == "messages"
        self.call = llm_call(
            self.ward, _model(llm), FRAMEWORK, "llamaindex", {field: value}, self.pmap,
            redact=_messages_redactor(self.pmap) if msgs else None,
            view=(lambda kw: {"messages": _dump(kw["messages"])}) if msgs else None)

    def __enter__(self):
        self.call.__enter__()
        value = self.call.kwargs[self.field]
        line = instruction(self.pmap, self.ward,
                           _dump(value) if self.field == "messages" else value)
        if line:
            self.call.span.set_attribute("taintward.placeholders.instruction", True)
            if self.field == "messages":
                value = [ChatMessage(role="system", content=line), *value]
            else:
                value = f"{line}\n\n{value}"
        self.value = value
        return self

    def __exit__(self, *exc):
        return self.call.__exit__(*exc)

    def done(self, resp: Any) -> Any:
        if finish_llm(self.call, self.ward, self.pmap, _view(resp)):
            resp = _restore_response(resp, self.pmap)
        return resp

    def chunk(self, resp: Any) -> Any:
        return _restore_response(resp, self.pmap) if self.pmap is not None and len(self.pmap) \
            else resp


def _llm_class(base: type) -> type:
    def plain(name: str, field: str):
        original = getattr(base, name)

        @functools.wraps(original)
        def method(self, value, *args, **kwargs):
            if _INSIDE.get():
                return original(self, value, *args, **kwargs)
            tok = _INSIDE.set(True)
            try:
                with _Request(self, field, value) as req:
                    return req.done(original(self, req.value, *args, **kwargs))
            finally:
                _INSIDE.reset(tok)
        return method

    def aplain(name: str, field: str):
        original = getattr(base, name)

        @functools.wraps(original)
        async def method(self, value, *args, **kwargs):
            if _INSIDE.get():
                return await original(self, value, *args, **kwargs)
            tok = _INSIDE.set(True)
            try:
                with _Request(self, field, value) as req:
                    return req.done(await original(self, req.value, *args, **kwargs))
            finally:
                _INSIDE.reset(tok)
        return method

    def stream(name: str, field: str):
        original = getattr(base, name)

        @functools.wraps(original)
        def method(self, value, *args, **kwargs):
            if _INSIDE.get():
                return original(self, value, *args, **kwargs)
            req = _Request(self, field, value)

            def gen():
                with req:
                    last = None
                    tok = _INSIDE.set(True)
                    try:
                        inner = original(self, req.value, *args, **kwargs)
                    finally:
                        _INSIDE.reset(tok)
                    for r in inner:
                        last = req.chunk(r)
                        yield last
                    if last is not None:
                        req.call.record_result(_view(last), view=_view(last))
            return isolated_iter(gen())
        return method

    def astream(name: str, field: str):
        original = getattr(base, name)

        @functools.wraps(original)
        async def method(self, value, *args, **kwargs):
            if _INSIDE.get():
                return await original(self, value, *args, **kwargs)
            req = _Request(self, field, value)

            async def gen():
                with req:
                    last = None
                    tok = _INSIDE.set(True)
                    try:
                        inner = await original(self, req.value, *args, **kwargs)
                    finally:
                        _INSIDE.reset(tok)
                    async for r in inner:
                        last = req.chunk(r)
                        yield last
                    if last is not None:
                        req.call.record_result(_view(last), view=_view(last))
            return isolated_aiter(gen())
        return method

    ns = {
        "chat": plain("chat", "messages"),
        "complete": plain("complete", "prompt"),
        "achat": aplain("achat", "messages"),
        "acomplete": aplain("acomplete", "prompt"),
        "stream_chat": stream("stream_chat", "messages"),
        "stream_complete": stream("stream_complete", "prompt"),
        "astream_chat": astream("astream_chat", "messages"),
        "astream_complete": astream("astream_complete", "prompt"),
    }
    return type("Protected", (base,), ns)


def protect_llm(llm: Any, *, ward: Ward | None = None) -> Any:
    if is_protected(llm):
        return llm
    return protected_copy(llm, _llm_class, _resolve(ward, None))


__all__ = ["wrap_tool", "wrap_tools", "protect_llm"]
