"""Pieces shared by the CrewAI, LlamaIndex, Pydantic AI, Google ADK and
LiteLLM adapters.

``tool_call`` builds the destination gate for one tool run, the same way the
OpenAI Agents adapter does: placeholders still in the input are swapped for
the real values first, then the tool's destination decides what it gets.
``llm_call`` builds the gate for one model request (destination ``llm``) and
``finish_llm`` checks and restores the answer. ``protected_copy`` makes the
"copy with a small subclass" objects the adapters return, so ``isinstance``
checks keep working and the original object is not changed.
"""

from __future__ import annotations

import asyncio
import contextvars
import copy
from typing import Any, AsyncIterator, Callable, Iterator

from opentelemetry import trace

from taintward.sdk import placeholders as ph
from taintward.sdk.destinations import DEST_LLM
from taintward.sdk.instrumentation import GuardedCall
from taintward.sdk.integrations import Ward
from taintward.sdk.integrations._payload import (
    allow_masked_view,
    payload_redactor,
    structure_redactor,
)

PATCHED = "__taintward_ward__"


def tool_call(ward: Ward, name: str, framework: str, *, args: Any = (),
              kwargs: dict | None = None) -> GuardedCall:
    policy = ward.policy_for(name)
    pmap = ward.placeholder_map()
    args, kwargs = list(args), dict(kwargs or {})
    if pmap is not None:
        args, kwargs = pmap.restore(args), pmap.restore(kwargs)
    return GuardedCall(
        name, destination=policy.destination, jurisdiction=policy.jurisdiction,
        tracer=ward.tracer, args=args, kwargs=kwargs, passthrough=policy.allow,
        redact=payload_redactor(pmap), input_view=allow_masked_view(policy.allow, pmap),
        attributes={"gen_ai.tool.name": name, "gen_ai.operation.name": "execute_tool",
                    "taintward.framework": framework},
    )


def llm_call(ward: Ward, model: str, framework: str, system: str, content: dict,
             pmap, *, redact: Callable[[Any, str], Any] | None = None,
             view: Callable[[dict], Any] | None = None) -> GuardedCall:
    """Gate for one model request. ``content`` holds only the fields that carry
    user data; ``call.kwargs`` then holds them redacted."""
    return GuardedCall(
        f"chat {model}".strip(), destination=DEST_LLM, jurisdiction=ward.llm_jurisdiction,
        tracer=ward.tracer, kwargs=content, redact=redact or structure_redactor(pmap),
        input_attr="gen_ai.input.messages", output_attr="gen_ai.output.messages",
        input_view=(lambda _a, kw: view(kw)) if view else (lambda _a, kw: kw),
        kind=trace.SpanKind.CLIENT,
        attributes={"gen_ai.operation.name": "chat", "gen_ai.provider.name": system,
                    "gen_ai.request.model": model, "taintward.framework": framework},
    )


def finish_llm(call: GuardedCall, ward: Ward, pmap, view: Any) -> bool:
    """Record the answer (placeholder version) and check it. Returns True when
    the caller should restore it."""
    call.record_result(view, view=view)
    if pmap is None or not len(pmap):
        return False
    ph.check_output(pmap, view, span=call.span,
                    strict=getattr(ward, "placeholder_strict", False))
    return True


def instruction(pmap, ward: Ward, content: Any) -> str | None:
    """The system line asking the model to copy placeholders, or None."""
    if pmap is None or not len(pmap) or not getattr(ward, "placeholder_instruction", True):
        return None
    names = ph.placeholders_in(content)
    return ph.instruction_for(names) if names else None


_CLASSES: dict[tuple, type] = {}


def protected_copy(obj: Any, make_class: Callable[[type], type], ward: Ward) -> Any:
    """A shallow copy of ``obj`` whose class is ``make_class(type(obj))``.

    The class is made once per (class, ward) and holds the ward as a class
    attribute, so nothing is added to the instance (pydantic models dump and
    copy their fields only)."""
    base = type(obj)
    k = (base, id(ward))
    if k not in _CLASSES:
        cls = make_class(base)
        cls.__name__ = cls.__qualname__ = f"Taintward{base.__name__}"
        setattr(cls, PATCHED, ward)
        _CLASSES[k] = cls
    copier = getattr(obj, "model_copy", None)
    new = copier() if callable(copier) else copy.copy(obj)
    object.__setattr__(new, "__class__", _CLASSES[k])
    return new


def ward_of(obj: Any) -> Ward:
    return getattr(type(obj), PATCHED)


def is_protected(obj: Any) -> bool:
    return getattr(type(obj), PATCHED, None) is not None


# A generator that yields while a GuardedCall is open would leave the call's
# span (and taint) as the *current* context in the caller's code between two
# chunks: the framework's own tracing then writes onto our span, and nested
# work looks like it runs inside the LLM call. These helpers step the
# generator in a private copy of the context instead, so nothing it attaches
# reaches the caller. Taint still flows on: inside a run it goes to the run's
# shared box.

def isolated_iter(gen: Iterator[Any]) -> Iterator[Any]:
    ctx = contextvars.copy_context()
    try:
        while True:
            try:
                item = ctx.run(next, gen)
            except StopIteration:
                return
            yield item
    finally:
        ctx.run(gen.close)


async def isolated_aiter(agen: AsyncIterator[Any]) -> AsyncIterator[Any]:
    ctx = contextvars.copy_context()
    try:
        while True:
            try:
                item = await asyncio.create_task(agen.__anext__(), context=ctx)
            except StopAsyncIteration:
                return
            yield item
    finally:
        await asyncio.create_task(agen.aclose(), context=ctx)
