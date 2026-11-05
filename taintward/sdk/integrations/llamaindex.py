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
arguments and ``additional_kwargs``. A stream hands out restored copies of
its chunks: each chunk's message (the text so far) is restored, and the
``delta`` strings are restored piece by piece, so a placeholder split across
two deltas is restored whole (text held back for that comes in one extra
chunk at the end).

``response.raw`` (the provider's own response) is left as the provider sent
it, with placeholders.

Embeddings and ingestion (destination ``rag``, masks, see ``_embed.py``):
``protect_embedding(embed_model)`` returns a protected copy of an embedding
model; the text of documents and queries is masked before it is sent.
``redact_nodes()`` is a transformation for an ``IngestionPipeline`` (or
``VectorStoreIndex.from_documents(..., transformations=[...])``): it masks
the text and metadata of each node, so what the vector store and docstore
keep is masked too. Put it after the splitter and before the embedding
model.
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
from taintward.sdk.integrations._stream import Pieces

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
        resp.additional_kwargs = pmap.restore_inplace(resp.additional_kwargs)
    elif isinstance(resp, CompletionResponse):
        resp.text = pmap.restore_text(resp.text)
        resp.additional_kwargs = pmap.restore_inplace(resp.additional_kwargs)
    return resp


class _Chunks:
    """Restored copies of streamed responses (the stream's own chunks keep
    the placeholders). The full text of each chunk is restored as a whole;
    ``delta`` goes through a ``StreamRestorer``."""

    def __init__(self, pmap) -> None:
        self.p = Pieces(pmap)
        self.pmap = self.p.pmap
        self.last: Any = None

    def chunk(self, resp: Any) -> Any:
        if self.pmap is None or not isinstance(resp, (ChatResponse, CompletionResponse)):
            return resp
        new = resp.model_copy()
        if isinstance(resp, ChatResponse):
            new.message = _map_message(resp.message, self.pmap.restore_inplace)
        else:
            new.text = self.pmap.restore_text(resp.text, spaced=False)
        new.additional_kwargs = self.pmap.restore_inplace(dict(resp.additional_kwargs))
        if isinstance(resp.delta, str):
            new.delta = self.p.push("delta", resp.delta)
        self.last = new
        return new

    def end(self) -> Any:
        """One extra chunk with the held end of the deltas, or None."""
        rest = self.p.flush("delta")
        if not rest or self.last is None:
            return None
        extra = self.last.model_copy()
        extra.delta = rest
        return extra


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

    def finish_stream(self, last: Any) -> None:
        """Record the streamed answer (placeholder version) and check it."""
        if last is not None:
            finish_llm(self.call, self.ward, self.pmap, _view(last), spaced=False)


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
                    last, chunks = None, _Chunks(req.pmap)
                    tok = _INSIDE.set(True)
                    try:
                        inner = original(self, req.value, *args, **kwargs)
                    finally:
                        _INSIDE.reset(tok)
                    for r in inner:
                        last = r
                        yield chunks.chunk(r)
                    extra = chunks.end()
                    if extra is not None:
                        yield extra
                    req.finish_stream(last)
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
                    last, chunks = None, _Chunks(req.pmap)
                    tok = _INSIDE.set(True)
                    try:
                        inner = await original(self, req.value, *args, **kwargs)
                    finally:
                        _INSIDE.reset(tok)
                    async for r in inner:
                        last = r
                        yield chunks.chunk(r)
                    extra = chunks.end()
                    if extra is not None:
                        yield extra
                    req.finish_stream(last)
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


# ---------------------------------------------------------------------------
# embeddings and ingestion (destination rag)
# ---------------------------------------------------------------------------


def _embedding_class(base: type) -> type:
    from taintward.sdk.integrations._embed import embed_async, embed_sync

    def name(self) -> str:
        return str(getattr(self, "model_name", "") or type(self).__name__)

    class Protected(base):  # type: ignore[misc, valid-type]
        def get_query_embedding(self, query, *a, **kw):
            return embed_sync(ward_of(self), FRAMEWORK, FRAMEWORK, name(self), query,
                              lambda t: super(Protected, self).get_query_embedding(t, *a, **kw))

        async def aget_query_embedding(self, query, *a, **kw):
            return await embed_async(
                ward_of(self), FRAMEWORK, FRAMEWORK, name(self), query,
                lambda t: super(Protected, self).aget_query_embedding(t, *a, **kw))

        def get_text_embedding(self, text, *a, **kw):
            return embed_sync(ward_of(self), FRAMEWORK, FRAMEWORK, name(self), text,
                              lambda t: super(Protected, self).get_text_embedding(t, *a, **kw))

        async def aget_text_embedding(self, text, *a, **kw):
            return await embed_async(
                ward_of(self), FRAMEWORK, FRAMEWORK, name(self), text,
                lambda t: super(Protected, self).aget_text_embedding(t, *a, **kw))

        def get_text_embedding_batch(self, texts, *a, **kw):
            return embed_sync(
                ward_of(self), FRAMEWORK, FRAMEWORK, name(self), list(texts),
                lambda t: super(Protected, self).get_text_embedding_batch(t, *a, **kw))

        async def aget_text_embedding_batch(self, texts, *a, **kw):
            return await embed_async(
                ward_of(self), FRAMEWORK, FRAMEWORK, name(self), list(texts),
                lambda t: super(Protected, self).aget_text_embedding_batch(t, *a, **kw))
    return Protected


def protect_embedding(embed_model: Any, *, ward: Ward | None = None) -> Any:
    """Return a protected copy of a LlamaIndex embedding model: document and
    query text is masked for the ``rag`` destination before it is sent, and
    an ``embeddings <model>`` span is recorded."""
    if is_protected(embed_model):
        return embed_model
    return protected_copy(embed_model, _embedding_class, _resolve(ward, None))


def _redact_class():
    from llama_index.core.schema import TransformComponent
    from pydantic import PrivateAttr

    from taintward.sdk.integrations._embed import store_sync

    class TaintwardRedactNodes(TransformComponent):
        """Masks the text and metadata of each node for the ``rag``
        destination (returns masked copies; the input nodes are not
        changed)."""

        _ward: Any = PrivateAttr(default=None)

        def __call__(self, nodes, **kwargs):
            nodes = list(nodes)
            content = {"nodes": [{"text": n.get_content(), "metadata": dict(n.metadata)}
                                 for n in nodes]}

            def send(masked: dict) -> list:
                out = []
                for node, m in zip(nodes, masked["nodes"]):
                    new = node.model_copy(deep=True)
                    new.set_content(m["text"])
                    new.metadata = m["metadata"]
                    out.append(new)
                return out
            return store_sync(self._ward or _resolve(None, None), FRAMEWORK, "ingestion",
                              content, send)
    return TaintwardRedactNodes


_REDACT_CLS: type | None = None


def redact_nodes(*, ward: Ward | None = None) -> Any:
    """A transformation that masks node text and metadata for the ``rag``
    destination (``IngestionPipeline(transformations=[splitter,
    redact_nodes(), embed_model])``)."""
    global _REDACT_CLS
    if _REDACT_CLS is None:
        _REDACT_CLS = _redact_class()
    t = _REDACT_CLS()
    t._ward = ward
    return t


__all__ = ["wrap_tool", "wrap_tools", "protect_llm", "protect_embedding", "redact_nodes"]
