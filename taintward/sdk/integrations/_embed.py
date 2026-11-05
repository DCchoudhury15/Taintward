"""Embedding requests and vector store writes (destination ``rag``).

An embedding can be turned back into text close to the original (OWASP
LLM08:2025), and a vector store keeps the text and metadata next to each
vector. So the text sent to an embedding model, and what a vector store
keeps, are masked for the ``rag`` destination (``[PII]`` / ``[SECRET]``).
Masks, not placeholders: a placeholder number is only stable within one
request, so the same person would get a different number in each document,
while a mask is the same everywhere. A query is masked the same way, so it
still lands near the documents it was written for.

``embed_sync`` / ``embed_async`` run one embedding request through the gate,
``store_sync`` / ``store_async`` one vector store write. Each records a span
with ``taintward.destination=rag``; the vectors themselves are never
recorded, only how many there are and their size. A framework method that
calls another protected one (``aembed_documents`` running
``embed_documents`` in a thread) is gated once.
"""

from __future__ import annotations

import contextvars
from typing import Any, Awaitable, Callable

from opentelemetry import trace

from taintward.sdk.destinations import DEST_RAG
from taintward.sdk.instrumentation import GuardedCall
from taintward.sdk.integrations import Ward
from taintward.sdk.integrations._stream import get, set_usage

_IN_EMBED: contextvars.ContextVar[bool] = contextvars.ContextVar("taintward_embed", default=False)
_IN_STORE: contextvars.ContextVar[bool] = contextvars.ContextVar("taintward_store", default=False)


def is_text_input(value: Any) -> bool:
    """A string or a list of strings. Token id lists cannot be scanned and are
    sent as they are."""
    if isinstance(value, str):
        return True
    return isinstance(value, (list, tuple)) and all(isinstance(v, str) for v in value)


def _embed_call(ward: Ward, model: str, framework: str, system: str, texts: Any) -> GuardedCall:
    return GuardedCall(
        f"embeddings {model}".strip(), destination=DEST_RAG,
        jurisdiction=ward.llm_jurisdiction, tracer=ward.tracer, kwargs={"input": texts},
        input_attr="taintward.rag.input", output_attr="taintward.rag.output",
        input_view=lambda _a, kw: kw["input"], kind=trace.SpanKind.CLIENT,
        attributes={"gen_ai.operation.name": "embeddings", "gen_ai.provider.name": system,
                    "gen_ai.request.model": model, "taintward.framework": framework})


def _shape(out: Any) -> dict:
    """How many vectors and their size, from a provider response or a plain
    list of vectors. Never the vectors."""
    data = get(out, "data")
    vectors = [get(d, "embedding") for d in data] if isinstance(data, list) else out
    if isinstance(vectors, list) and vectors and isinstance(vectors[0], (int, float)):
        vectors = [vectors]  # one query vector
    if not isinstance(vectors, list):
        return {}
    first = vectors[0] if vectors else None
    return {"vectors": len(vectors),
            "dimensions": len(first) if isinstance(first, (list, tuple)) else 0}


def _end_embed(call: GuardedCall, out: Any) -> None:
    call.record_result(_shape(out))
    set_usage(call.span, get(out, "usage"))


def embed_sync(ward: Ward, framework: str, system: str, model: str, texts: Any,
               send: Callable[[Any], Any]) -> Any:
    """``send(masked_texts)`` under the gate; returns its result."""
    if _IN_EMBED.get() or not is_text_input(texts):
        return send(texts)
    token = _IN_EMBED.set(True)
    try:
        with _embed_call(ward, model, framework, system, texts) as call:
            out = send(call.kwargs["input"])
            _end_embed(call, out)
            return out
    finally:
        _IN_EMBED.reset(token)


async def embed_async(ward: Ward, framework: str, system: str, model: str, texts: Any,
                      send: Callable[[Any], Awaitable[Any]]) -> Any:
    if _IN_EMBED.get() or not is_text_input(texts):
        return await send(texts)
    token = _IN_EMBED.set(True)
    try:
        with _embed_call(ward, model, framework, system, texts) as call:
            out = await send(call.kwargs["input"])
            _end_embed(call, out)
            return out
    finally:
        _IN_EMBED.reset(token)


def _store_call(ward: Ward, name: str, framework: str, content: dict) -> GuardedCall:
    return GuardedCall(
        f"vectorstore.add {name}".strip(), destination=DEST_RAG, tracer=ward.tracer,
        kwargs=content, input_attr="taintward.rag.input", output_attr="taintward.rag.output",
        attributes={"taintward.rag.operation": "add", "taintward.framework": framework})


def _added(out: Any) -> dict:
    return {"added": len(out)} if isinstance(out, (list, tuple)) else {}


def store_sync(ward: Ward, framework: str, name: str, content: dict,
               send: Callable[[dict], Any]) -> Any:
    """``send(masked_content)`` under the gate for one vector store write."""
    if _IN_STORE.get():
        return send(content)
    token = _IN_STORE.set(True)
    try:
        with _store_call(ward, name, framework, content) as call:
            out = send(call.kwargs)
            call.record_result(_added(out))
            return out
    finally:
        _IN_STORE.reset(token)


async def store_async(ward: Ward, framework: str, name: str, content: dict,
                      send: Callable[[dict], Awaitable[Any]]) -> Any:
    if _IN_STORE.get():
        return await send(content)
    token = _IN_STORE.set(True)
    try:
        with _store_call(ward, name, framework, content) as call:
            out = await send(call.kwargs)
            call.record_result(_added(out))
            return out
    finally:
        _IN_STORE.reset(token)
