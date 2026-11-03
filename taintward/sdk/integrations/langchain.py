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
restored to the real values. ``stream`` / ``astream`` hand out restored
copies of the chunks: text (also content blocks), tool call chunk arguments
and ``additional_kwargs`` tool calls. A placeholder split across chunks is
restored whole; text held back for that is added to the last chunk. A wrapped tool restores any placeholder still in
its input from the run's map, then the normal destination gate runs on the
real values (internal: reversible token, external/log/rag: mask, ``allow``
arguments: real value).
"""

from __future__ import annotations

import contextvars
from typing import Any, ClassVar, Iterable, Mapping

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessageChunk, BaseMessage, SystemMessage
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
from taintward.sdk.integrations._stream import (
    Guard,
    Pieces,
    StreamCall,
    async_items,
    sync_items,
)
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


# Fields of a content block that hold streamed text, and how to restore them.
_BLOCK_FIELDS = {"text": "text", "thinking": "text", "reasoning": "text",
                 "partial_json": "json", "args": "json"}


class _Chunks:
    """Stream handler for ``AIMessageChunk`` objects."""

    def __init__(self, pmap) -> None:
        self.p = Pieces(pmap)
        self.pmap = self.p.pmap
        self.block_types: dict = {}
        self.names: dict = {}
        self.whole: list = []  # full messages (a model that cannot stream)
        self.closed = False

    # -- one chunk ------------------------------------------------------------
    def _content(self, content: Any) -> Any:
        if isinstance(content, str):
            return self.p.push(("text",), content)
        if not isinstance(content, list):
            return content
        out, changed = [], False
        for pos, block in enumerate(content):
            new = block
            if isinstance(block, str):
                new = self.p.push(("text",), block)
            elif isinstance(block, dict):
                idx = block.get("index", pos)
                self.block_types.setdefault(idx, block.get("type"))
                for field, mode in _BLOCK_FIELDS.items():
                    v = block.get(field)
                    if isinstance(v, str) and v:
                        r = self.p.push(("block", idx, field), v, mode)
                        if r != v:
                            new = {**new, field: r}
            changed |= new is not block
            out.append(new)
        return out if changed else content

    def _tool_chunks(self, chunks: list) -> list:
        out, changed = [], False
        for pos, tc in enumerate(chunks):
            idx = tc.get("index")
            idx = pos if idx is None else idx
            if tc.get("name"):
                self.names[idx] = tc["name"]
            args = tc.get("args")
            new = tc
            if isinstance(args, str) and args:
                r = self.p.push(("tool", idx), args, "json")
                if r != args:
                    new = {**tc, "args": r}
            else:
                self.p.touch(("tool", idx))
            changed |= new is not tc
            out.append(new)
        return out if changed else chunks

    def _kwargs(self, ak: dict) -> dict:
        if not ak:
            return ak
        new = dict(ak)
        changed = False
        calls = ak.get("tool_calls")
        if isinstance(calls, list):
            fixed = []
            for pos, tc in enumerate(calls):
                fn = tc.get("function") if isinstance(tc, dict) else None
                args = fn.get("arguments") if isinstance(fn, dict) else None
                if isinstance(args, str) and args:
                    idx = tc.get("index", pos)
                    r = self.p.push(("ak_tool", idx), args, "json")
                    if r != args:
                        tc = {**tc, "function": {**fn, "arguments": r}}
                        changed = True
                fixed.append(tc)
            new["tool_calls"] = fixed
        fc = ak.get("function_call")
        if isinstance(fc, dict) and isinstance(fc.get("arguments"), str) and fc["arguments"]:
            r = self.p.push(("ak_fc",), fc["arguments"], "json")
            if r != fc["arguments"]:
                new["function_call"] = {**fc, "arguments": r}
                changed = True
        rc = ak.get("reasoning_content")
        if isinstance(rc, str) and rc:
            r = self.p.push(("ak_reasoning",), rc)
            if r != rc:
                new["reasoning_content"] = r
                changed = True
        return new if changed else ak

    # -- held text --------------------------------------------------------------
    def _add_held(self, content: Any, tool_chunks: list, ak: dict) -> tuple:
        """Add every held end to one chunk's fields."""
        for key in self.p.holding():
            rest = self.p.flush(key)
            if not rest:
                continue
            kind = key[0]
            if kind == "text":
                content = content + rest if isinstance(content, str) else [*content, rest]
            elif kind == "block":
                block = {"type": self.block_types.get(key[1]) or "text", key[2]: rest,
                         "index": key[1]}
                content = [*_as_list(content), block]
            elif kind == "tool":
                tool_chunks = [*tool_chunks, {"name": None, "args": rest, "id": None,
                                              "index": key[1], "type": "tool_call_chunk"}]
            elif kind == "ak_tool":
                ak = {**ak, "tool_calls": [*(ak.get("tool_calls") or []),
                                           {"index": key[1], "function": {"arguments": rest}}]}
            elif kind == "ak_fc":
                ak = {**ak, "function_call": {"arguments": rest}}
            elif kind == "ak_reasoning":
                ak = {**ak, "reasoning_content": rest}
        return content, tool_chunks, ak

    def item(self, chunk: Any) -> list:
        if not isinstance(chunk, AIMessageChunk):
            if isinstance(chunk, BaseMessage):
                self.whole.append(chunk)
                return [restore_message(chunk, self.pmap)]
            return [chunk]
        content = self._content(chunk.content)
        tool_chunks = self._tool_chunks(chunk.tool_call_chunks)
        ak = self._kwargs(chunk.additional_kwargs)
        if chunk.chunk_position == "last":
            content, tool_chunks, ak = self._add_held(content, tool_chunks, ak)
            self.closed = True
        if (content is chunk.content and tool_chunks is chunk.tool_call_chunks
                and ak is chunk.additional_kwargs):
            return [chunk]
        return [_rebuild_chunk(chunk, content, tool_chunks, ak)]

    def end(self) -> list:
        if not self.p.holding():
            return []
        content, tool_chunks, ak = self._add_held("", [], {})
        return [AIMessageChunk(content=content, tool_call_chunks=tool_chunks,
                               additional_kwargs=ak)]

    def view(self) -> Any:
        """The answer as the model wrote it."""
        if self.whole:
            return [_message_view(m) for m in self.whole]
        keys = self.p.keys()
        text = self.p.raw(("text",)) or ""
        blocks = [{"type": self.block_types.get(k[1]) or "text", k[2]: self.p.raw(k)}
                  for k in keys if k[0] == "block"]
        view: dict[str, Any] = {"role": "ai", "content": blocks if blocks and not text else text}
        if blocks and text:
            view["blocks"] = blocks
        tools = sorted((k[1] for k in keys if k[0] == "tool"), key=str)
        if tools:
            view["tool_calls"] = [{"name": self.names.get(i), "args": self.p.raw(("tool", i))}
                                  for i in tools]
        extra = {k[0]: self.p.raw(k) for k in keys if k[0].startswith("ak_")}
        if extra:
            view["additional_kwargs"] = extra
        return view


def _as_list(content: Any) -> list:
    if isinstance(content, str):
        return [content] if content else []
    return list(content)


def _rebuild_chunk(chunk: AIMessageChunk, content: Any, tool_chunks: list,
                   ak: dict) -> AIMessageChunk:
    """A new chunk with these fields; its parsed ``tool_calls`` are made
    again from ``tool_chunks`` (the constructor does that)."""
    data = {name: getattr(chunk, name) for name in type(chunk).model_fields}
    data.pop("tool_calls", None)
    data.pop("invalid_tool_calls", None)
    data.update(content=content, tool_call_chunks=tool_chunks, additional_kwargs=ak)
    return type(chunk)(**data)


def _open_stream(model, messages: list[BaseMessage], ward: Ward):
    """Start one streamed request: the span, the redacted messages, and a
    context in which the inner stream must run (so the inner
    ``_convert_input`` / ``invoke`` do not redact a second time)."""
    pmap = ward.llm_placeholder_map()
    sc = StreamCall(_llm_call(model, messages, ward, pmap), ward, pmap)
    call = sc.enter()
    try:
        send = _send(call, pmap, ward)
        sc.run(_IN_GUARDED_INVOKE.set, True)
    except BaseException as e:
        sc.end(None, exc=e, check=False)
        raise
    return sc, ChatPromptValue(messages=send), pmap


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
            # batch / direct generate and other paths that do not go through
            # invoke or stream: redact, record a request span.
            pmap = ward.llm_placeholder_map()
            with _llm_call(self, pv.to_messages(), ward, pmap) as call:
                messages = _send(call, pmap, ward)
            return ChatPromptValue(messages=messages)

        def stream(self, input, config=None, *, stop=None, **kwargs):
            messages = super()._convert_input(input).to_messages()
            sc, prompt, pmap = _open_stream(self, messages, ward)
            try:
                inner = super().stream(prompt, config, stop=stop, **kwargs)
            except BaseException as e:
                sc.end(None, exc=e, check=False)
                raise
            guard = Guard(sc, _Chunks(pmap))
            return sync_items(guard, lambda: sc.run(next, inner),
                              on_close=lambda: sc.run(inner.close))

        def astream(self, input, config=None, *, stop=None, **kwargs):
            messages = super()._convert_input(input).to_messages()
            sc, prompt, pmap = _open_stream(self, messages, ward)
            try:
                inner = super().astream(prompt, config, stop=stop, **kwargs)
            except BaseException as e:
                sc.end(None, exc=e, check=False)
                raise
            guard = Guard(sc, _Chunks(pmap))
            return async_items(guard, lambda: sc.arun(inner.__anext__()),
                               on_close=lambda: sc.arun(inner.aclose()))

        def invoke(self, input, config=None, **kwargs):
            if _IN_GUARDED_INVOKE.get():  # a stream fell back to invoke
                return super().invoke(input, config, **kwargs)
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
            if _IN_GUARDED_INVOKE.get():  # a stream fell back to ainvoke
                return await super().ainvoke(input, config, **kwargs)
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
