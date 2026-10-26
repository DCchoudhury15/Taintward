"""LangChain / LangGraph adapter.

``wrap_tools(tools, mapping)`` returns protected copies of LangChain tools
(``BaseTool``, ``StructuredTool``, ``@tool`` functions). ``protect_chat_model``
returns a protected copy of a chat model so every request it sends to the LLM
provider is redacted for the ``llm`` destination.

Why wrapping and not a callback handler: LangChain callbacks
(``on_tool_start``, ``on_chat_model_start``) only *observe* the input; they
cannot change what the tool or the provider receives. To redact before the
call we must sit in the call path.

How: the copy keeps every field of the original (name, description, args
schema, ``return_direct``, ``response_format``, callbacks, ...) and its class
becomes a small subclass of the original class that overrides only the entry
points (``run`` / ``arun`` for tools, ``invoke`` / ``ainvoke`` and
``_convert_input`` for chat models). So ``isinstance`` checks, LangGraph's
``ToolNode`` and ``bind_tools`` keep working, and the original object is not
modified.

Placeholders (on by default): the model gets ``<PERSON_1>`` style
placeholders instead of masks, and the ``AIMessage`` it returns from
``invoke`` / ``ainvoke`` (text, ``tool_calls`` args, ``additional_kwargs``) is
restored to the real values. A wrapped tool restores any placeholder still in
its input from the run's map, then the normal destination gate runs on the
real values (internal: reversible token, external/log/rag: mask, ``allow``
arguments: real value).
"""

from __future__ import annotations

import contextvars
from typing import Any, ClassVar, Iterable, Mapping

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import BaseMessage, SystemMessage
from langchain_core.prompt_values import ChatPromptValue
from langchain_core.tools import BaseTool
from opentelemetry import trace

from taintward.sdk import placeholders as ph
from taintward.sdk.destinations import DEST_LLM
from taintward.sdk.instrumentation import GuardedCall
from taintward.sdk.integrations import ToolPolicy, Ward, _resolve
from taintward.sdk.integrations._payload import (
    allow_masked_view,
    payload_redactor,
    redact_structure,
)
from taintward.sdk.integrations._payload import plain_view as _plain_view
from taintward.sdk.redact import redact_payload

_POLICY_ATTR = "__taintward_policy__"


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


def _split_input(tool: BaseTool, tool_input: dict) -> tuple[dict, dict]:
    """Split a dict input into model-visible args and injected args (state,
    runtime, tool call id, callbacks). Only the visible args are user data;
    injected ones are framework objects and are passed through untouched."""
    try:
        visible = tool._filter_injected_args(tool_input)
    except Exception:
        visible = dict(tool_input)
    injected = {k: v for k, v in tool_input.items() if k not in visible}
    return visible, injected


def _guard(tool: BaseTool, tool_input: Any, ward: Ward):
    """Build the GuardedCall for one tool run plus a function that rebuilds the
    tool input from the redacted values.

    With a run placeholder map, placeholders in the input are first swapped
    for the real values, so the gate (taint label, redaction, ``allow``) sees
    exactly what the tool would get without placeholders. The gate also
    redacts every value the map knows, even where the detector misses it."""
    policy: ToolPolicy = getattr(type(tool), _POLICY_ATTR)
    pmap = ward.placeholder_map()
    restore = pmap.restore if pmap is not None else (lambda v: v)
    common = dict(
        destination=policy.destination,
        jurisdiction=policy.jurisdiction,
        tracer=ward.tracer,
        passthrough=policy.allow,
        redact=payload_redactor(pmap),
        input_view=allow_masked_view(policy.allow, pmap),
        attributes={
            "gen_ai.tool.name": tool.name,
            "gen_ai.operation.name": "execute_tool",
            "taintward.framework": "langchain",
        },
    )
    # A raw ToolCall dict passed straight to run(): redact its "args".
    if isinstance(tool_input, dict) and tool_input.get("type") == "tool_call":
        visible, injected = _split_input(tool, dict(tool_input.get("args") or {}))
        call = GuardedCall(tool.name, kwargs=restore(visible), **common)
        return call, lambda c: {**tool_input, "args": {**injected, **c.kwargs}}
    if isinstance(tool_input, dict):
        visible, injected = _split_input(tool, tool_input)
        call = GuardedCall(tool.name, kwargs=restore(visible), **common)
        return call, lambda c: {**injected, **c.kwargs}
    call = GuardedCall(tool.name, args=[restore(tool_input)], **common)
    return call, lambda c: c.args[0]


_TOOL_CLASSES: dict[tuple[type, ToolPolicy, int], type] = {}


def _protected_tool_class(base: type, policy: ToolPolicy, ward: Ward) -> type:
    key = (base, policy, id(ward))
    if key in _TOOL_CLASSES:
        return _TOOL_CLASSES[key]

    class Protected(base):  # type: ignore[misc, valid-type]
        __taintward_policy__: ClassVar[ToolPolicy] = policy

        def run(self, tool_input, *args, **kwargs):
            call, rebuild = _guard(self, tool_input, ward)
            with call:
                out = super().run(rebuild(call), *args, **kwargs)
                call.record_result(out, view=_plain_view(out))
            return out

        async def arun(self, tool_input, *args, **kwargs):
            call, rebuild = _guard(self, tool_input, ward)
            with call:
                out = await super().arun(rebuild(call), *args, **kwargs)
                call.record_result(out, view=_plain_view(out))
            return out

    Protected.__name__ = f"Protected{base.__name__}"
    Protected.__qualname__ = Protected.__name__
    _TOOL_CLASSES[key] = Protected
    return Protected


def wrap_tool(tool: BaseTool, mapping: Mapping[str, Any] | None = None, *,
              ward: Ward | None = None) -> BaseTool:
    """Return a protected copy of one LangChain tool (the original is unchanged)."""
    if not isinstance(tool, BaseTool):
        raise TypeError(f"expected a langchain BaseTool, got {type(tool).__name__}")
    w = _resolve(ward, mapping)
    base = type(tool)
    if getattr(base, _POLICY_ATTR, None) is not None:
        base = base.__mro__[1]  # already protected: re-wrap from the original class
    cls = _protected_tool_class(base, w.policy_for(tool.name), w)
    copy = tool.model_copy()
    copy.__class__ = cls
    return copy


def wrap_tools(tools: Iterable[BaseTool], mapping: Mapping[str, Any] | None = None, *,
               ward: Ward | None = None) -> list[BaseTool]:
    """Protect a list of LangChain tools.

    ``mapping`` (tool name -> destination) is merged over the map given to
    ``init()``; tools in neither get the default destination (external).
    """
    w = _resolve(ward, mapping)
    return [wrap_tool(t, ward=w) for t in tools]


# ---------------------------------------------------------------------------
# Chat models (the LLM is an egress sink)
# ---------------------------------------------------------------------------


def redact_message(msg: BaseMessage, destination: str = DEST_LLM, *,
                   placeholders=None) -> BaseMessage:
    """A copy of ``msg`` with user content, tool call args and extra kwargs
    redacted for ``destination`` (``placeholders``: see ``taintward.sdk.placeholders``)."""
    update: dict[str, Any] = {}
    content = msg.content
    if isinstance(content, str):
        new = redact_payload(content, destination, placeholders=placeholders)
    else:
        new = redact_structure(content, destination, placeholders)
    if new != content:
        update["content"] = new
    tool_calls = getattr(msg, "tool_calls", None)
    if tool_calls:
        update["tool_calls"] = [
            {**tc, "args": redact_payload(tc.get("args", {}), destination,
                                          placeholders=placeholders)}
            for tc in tool_calls
        ]
    invalid = getattr(msg, "invalid_tool_calls", None)
    if invalid:
        update["invalid_tool_calls"] = [redact_structure(tc, destination, placeholders)
                                        for tc in invalid]
    if msg.additional_kwargs:
        update["additional_kwargs"] = redact_structure(msg.additional_kwargs, destination,
                                                       placeholders)
    return msg.model_copy(update=update) if update else msg


def restore_message(msg: Any, placeholders) -> Any:
    """A copy of a model's message with placeholders swapped back to the real
    values (text, tool call args, invalid tool calls, extra kwargs)."""
    if placeholders is None or not len(placeholders) or not isinstance(msg, BaseMessage):
        return msg
    update: dict[str, Any] = {}
    content = placeholders.restore(msg.content)
    if content != msg.content:
        update["content"] = content
    for field in ("tool_calls", "invalid_tool_calls", "tool_call_chunks"):
        value = getattr(msg, field, None)
        if value:
            new = placeholders.restore(value)
            if new != value:
                update[field] = new
    if msg.additional_kwargs:
        new = placeholders.restore(msg.additional_kwargs)
        if new != msg.additional_kwargs:
            update["additional_kwargs"] = new
    return msg.model_copy(update=update) if update else msg


def _message_view(msg: BaseMessage) -> dict:
    view: dict[str, Any] = {"role": msg.type, "content": msg.content}
    if getattr(msg, "tool_calls", None):
        view["tool_calls"] = msg.tool_calls
    return view


def _messages_redactor(placeholders):
    def redact(messages: list[BaseMessage], destination: str) -> list[BaseMessage]:
        return [redact_message(m, destination, placeholders=placeholders) for m in messages]
    return redact


def _model_name(model: BaseChatModel) -> str:
    for attr in ("model_name", "model", "model_id"):
        v = getattr(model, attr, None)
        if isinstance(v, str) and v:
            return v
    try:
        return model._llm_type
    except Exception:
        return type(model).__name__


# Set while our invoke() is running, so the inner _convert_input() call does
# not redact (and open a span) a second time.
_IN_GUARDED_INVOKE: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "taintward_lc_guarded_invoke", default=False
)


def _llm_call(model: BaseChatModel, messages: list[BaseMessage], ward: Ward,
              placeholders=None) -> GuardedCall:
    name = _model_name(model)
    return GuardedCall(
        f"chat {name}",
        destination=DEST_LLM,
        jurisdiction=ward.llm_jurisdiction,
        tracer=ward.tracer,
        kwargs={"messages": messages},
        redact=_messages_redactor(placeholders),
        input_attr="gen_ai.input.messages",
        output_attr="gen_ai.output.messages",
        input_view=lambda _a, kw: [_message_view(m) for m in kw["messages"]],
        attributes={
            "gen_ai.operation.name": "chat",
            "gen_ai.request.model": name,
            "taintward.framework": "langchain",
        },
        kind=trace.SpanKind.CLIENT,
    )


def with_instruction(messages: list[BaseMessage], pmap, ward: Ward) -> list[BaseMessage]:
    """The redacted messages plus one system line that asks the model to copy
    the placeholders exactly (``ward.placeholder_instruction``)."""
    if pmap is None or not len(pmap) or not getattr(ward, "placeholder_instruction", True):
        return messages
    names = ph.placeholders_in(messages)
    if not names:
        return messages
    line = ph.instruction_for(names)
    first = messages[0] if messages else None
    if isinstance(first, SystemMessage) and isinstance(first.content, str):
        return [first.model_copy(update={"content": f"{first.content}\n\n{line}"}),
                *messages[1:]]
    return [SystemMessage(line), *messages]


def _send(call: GuardedCall, pmap, ward: Ward) -> list[BaseMessage]:
    messages = call.kwargs["messages"]
    send = with_instruction(messages, pmap, ward)
    if send is not messages:
        call.span.set_attribute("taintward.placeholders.instruction", True)
    return send


def _finish(call: GuardedCall, out: Any, pmap, ward: Ward) -> None:
    view = _message_view(out) if isinstance(out, BaseMessage) else out
    call.record_result(out, view=view)  # placeholder version
    if pmap is not None and len(pmap):
        ph.check_output(pmap, view, span=call.span,
                        strict=getattr(ward, "placeholder_strict", False))


_MODEL_CLASSES: dict[tuple[type, int], type] = {}


def _protected_model_class(base: type, ward: Ward) -> type:
    key = (base, id(ward))
    if key in _MODEL_CLASSES:
        return _MODEL_CLASSES[key]

    class Protected(base):  # type: ignore[misc, valid-type]
        __taintward_ward__: ClassVar[Ward] = ward

        def _convert_input(self, input):  # every entry point passes here
            pv = super()._convert_input(input)
            if _IN_GUARDED_INVOKE.get():
                return pv
            # stream / astream / direct generate: redact, record a request span.
            # The streamed output is not restored (see docs/integrations.md).
            pmap = ward.llm_placeholder_map()
            with _llm_call(self, pv.to_messages(), ward, pmap) as call:
                messages = _send(call, pmap, ward)
            return ChatPromptValue(messages=messages)

        def invoke(self, input, config=None, **kwargs):
            messages = super()._convert_input(input).to_messages()
            pmap = ward.llm_placeholder_map()
            with _llm_call(self, messages, ward, pmap) as call:
                tok = _IN_GUARDED_INVOKE.set(True)
                try:
                    out = super().invoke(
                        ChatPromptValue(messages=_send(call, pmap, ward)), config, **kwargs
                    )
                finally:
                    _IN_GUARDED_INVOKE.reset(tok)
                _finish(call, out, pmap, ward)
            return restore_message(out, pmap)

        async def ainvoke(self, input, config=None, **kwargs):
            messages = super()._convert_input(input).to_messages()
            pmap = ward.llm_placeholder_map()
            with _llm_call(self, messages, ward, pmap) as call:
                tok = _IN_GUARDED_INVOKE.set(True)
                try:
                    out = await super().ainvoke(
                        ChatPromptValue(messages=_send(call, pmap, ward)), config, **kwargs
                    )
                finally:
                    _IN_GUARDED_INVOKE.reset(tok)
                _finish(call, out, pmap, ward)
            return restore_message(out, pmap)

    Protected.__name__ = f"Protected{base.__name__}"
    Protected.__qualname__ = Protected.__name__
    _MODEL_CLASSES[key] = Protected
    return Protected


def protect_chat_model(model: BaseChatModel, *, ward: Ward | None = None) -> BaseChatModel:
    """Return a protected copy of a LangChain chat model.

    Every request (user text, tool results, earlier tool call args) is
    redacted for the ``llm`` destination before it reaches the provider, and
    a ``chat <model>`` span with ``taintward.destination=llm`` is recorded.
    ``bind_tools`` / ``with_config`` on the copy keep the protection.
    """
    if not isinstance(model, BaseChatModel):
        raise TypeError(f"expected a langchain BaseChatModel, got {type(model).__name__}")
    w = ward or _resolve(None, None)
    base = type(model)
    if getattr(base, "__taintward_ward__", None) is not None:
        base = base.__mro__[1]
    copy = model.model_copy()
    copy.__class__ = _protected_model_class(base, w)
    return copy


__all__ = ["wrap_tool", "wrap_tools", "protect_chat_model", "redact_message",
           "restore_message"]
