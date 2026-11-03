"""Pydantic AI adapter.

``TaintwardModel(model)`` wraps any Pydantic AI model (an object or a name
such as ``"openai:gpt-4.1"``). Every request is redacted for the ``llm``
destination: system and user prompts, instructions, tool results, retry
prompts and earlier model responses (text, thinking, tool call arguments).
With placeholders on, the response from ``request`` is restored (text,
thinking and tool call arguments). ``request_stream`` (``run_stream``,
``iter``) redacts the request too, and the stream hands out restored events:
text, thinking and tool call argument deltas (a placeholder split across
deltas is restored whole), and ``get()`` returns the restored response, so
the output and the message history hold real values.

``TaintwardToolset(toolset)`` wraps any toolset (``FunctionToolset``, an MCP
server, ...); ``wrap_tools([fn, Tool(...)])`` builds a ``FunctionToolset``
and wraps it. Every tool call goes through the destination gate for the
tool's name, after Pydantic AI has validated the arguments.

    agent = Agent(tw.protect_pydantic_ai_model("openai:gpt-4.1"),
                  toolsets=[tw.wrap_pydantic_ai_tools([lookup, send_email])])

Tools registered with ``@agent.tool`` live in the agent's own toolset and
are not covered; pass them through ``wrap_tools`` instead.
"""

from __future__ import annotations

import dataclasses
import json
import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Iterable, Mapping

from pydantic_ai.messages import (
    ModelMessage,
    ModelRequest,
    ModelResponse,
    PartDeltaEvent,
    PartEndEvent,
    PartStartEvent,
    RetryPromptPart,
    SystemPromptPart,
    TextPart,
    TextPartDelta,
    ThinkingPart,
    ThinkingPartDelta,
    ToolCallPart,
    ToolCallPartDelta,
    ToolReturnPart,
    UserPromptPart,
)
from pydantic_ai.models.wrapper import WrapperModel
from pydantic_ai.toolsets import AbstractToolset, FunctionToolset
from pydantic_ai.toolsets.wrapper import WrapperToolset

from taintward.sdk.integrations import Ward, _resolve
from taintward.sdk.integrations._common import (
    finish_llm,
    instruction,
    llm_call,
    tool_call,
)
from taintward.sdk.integrations._payload import plain_view
from taintward.sdk.integrations._stream import Pieces, StreamCall

log = logging.getLogger("taintward.sdk")

FRAMEWORK = "pydantic-ai"

# Part type -> the field that holds user data.
_FIELDS = {
    SystemPromptPart: "content", UserPromptPart: "content", ToolReturnPart: "content",
    RetryPromptPart: "content", TextPart: "content", ThinkingPart: "content",
    ToolCallPart: "args",
}


def _text_only(value: Any) -> bool:
    """User prompt content can hold images or files; only strings are sent
    through redaction, other items are kept as they are."""
    return isinstance(value, (str, dict, list)) and not (
        isinstance(value, list) and any(not isinstance(v, str) for v in value))


def _slots(messages: list[ModelMessage]) -> list[tuple[int, int | None, str]]:
    out = []
    for i, msg in enumerate(messages):
        if isinstance(msg, ModelRequest) and isinstance(msg.instructions, str):
            out.append((i, None, "instructions"))
        for j, part in enumerate(msg.parts):
            field = _FIELDS.get(type(part))
            if field and _text_only(getattr(part, field)):
                out.append((i, j, field))
    return out


def _get(messages, slot):
    i, j, field = slot
    return getattr(messages[i] if j is None else messages[i].parts[j], field)


def _rebuild(messages: list[ModelMessage], slots, values) -> list[ModelMessage]:
    new = [dataclasses.replace(m, parts=list(m.parts)) for m in messages]
    for (i, j, field), v in zip(slots, values):
        if j is None:
            new[i] = dataclasses.replace(new[i], **{field: v})
        else:
            new[i].parts[j] = dataclasses.replace(new[i].parts[j], **{field: v})
    return new


def _add_instruction(messages: list[ModelMessage], line: str | None) -> list[ModelMessage]:
    if not line:
        return messages
    for i in range(len(messages) - 1, -1, -1):
        m = messages[i]
        if isinstance(m, ModelRequest):
            ins = f"{m.instructions}\n\n{line}" if m.instructions else line
            return [*messages[:i], dataclasses.replace(m, instructions=ins), *messages[i + 1:]]
    return messages


def _restore(resp: ModelResponse, pmap) -> ModelResponse:
    parts = []
    for p in resp.parts:
        field = _FIELDS.get(type(p))
        if field and isinstance(getattr(p, field), (str, dict)):
            p = dataclasses.replace(p, **{field: pmap.restore(getattr(p, field))})
        parts.append(p)
    resp.parts = parts
    return resp


def _resp_view(resp: ModelResponse) -> list:
    return [getattr(p, _FIELDS[type(p)]) for p in resp.parts if type(p) in _FIELDS]


# --- streams ---------------------------------------------------------------

# Delta type -> (the field with streamed text, restore mode)
_DELTAS = {TextPartDelta: ("content_delta", "text"),
           ThinkingPartDelta: ("content_delta", "text"),
           ToolCallPartDelta: ("args_delta", "json")}
_PART_DELTA = {TextPart: TextPartDelta, ThinkingPart: ThinkingPartDelta,
               ToolCallPart: ToolCallPartDelta}


def _restore_args(pmap, args: Any) -> Any:
    """Tool call arguments of a streamed part: a dict, complete JSON, or JSON
    that is not complete yet (``get()`` in the middle of a stream)."""
    if isinstance(args, dict):
        return pmap.restore(args)
    if not isinstance(args, str):
        return args
    try:
        json.loads(args)
    except ValueError:
        return pmap.restore_json_fragment(args)
    return pmap.restore_text(args)


def _restore_part(part: Any, pmap) -> Any:
    """A restored copy of one part (the stream's own part is not changed)."""
    field = _FIELDS.get(type(part))
    if field is None or pmap is None:
        return part
    value = getattr(part, field)
    if field == "args":
        new = _restore_args(pmap, value)
    elif isinstance(value, str):
        new = pmap.restore_text(value, spaced=False)
    else:
        return part
    return part if new == value else dataclasses.replace(part, **{field: new})


class _Events:
    """Stream handler for Pydantic AI response events, keyed by part index.

    It also remembers the restored text it handed out per part, because
    ``get()`` in the middle of a stream must agree with it: Pydantic AI
    starts ``stream_text`` from ``get()`` and goes on with the events, so a
    snapshot that already restored the held tail would repeat it."""

    def __init__(self, pmap) -> None:
        self.p = Pieces(pmap)
        self.pmap = self.p.pmap
        self.kinds: dict[int, type] = {}
        self.sent: dict[int, str] = {}
        self.ended: set[int] = set()

    def _push(self, index: int, value: Any, mode: str) -> Any:
        if isinstance(value, dict):
            return self.pmap.restore(value) if self.pmap is not None else value
        out = self.p.push(index, value, mode)
        if isinstance(out, str):
            self.sent[index] = self.sent.get(index, "") + out
        return out

    def _held(self, index: int) -> list:
        self.ended.add(index)
        rest = self.p.flush(index)
        delta = _PART_DELTA.get(self.kinds.get(index))
        if not rest or delta is None:
            return []
        self.sent[index] = self.sent.get(index, "") + rest
        field = _DELTAS[delta][0]
        return [PartDeltaEvent(index=index, delta=delta(**{field: rest}))]

    def part(self, index: int, part: Any) -> Any:
        """The restored copy of part ``index`` of a ``get()`` snapshot."""
        field = _FIELDS.get(type(part))
        value = getattr(part, field) if field else None
        if (index in self.sent and index not in self.ended and isinstance(value, str)
                and self.p.raw(index) == value):  # still streaming: what was sent
            return dataclasses.replace(part, **{field: self.sent[index]})
        return _restore_part(part, self.pmap)

    def item(self, ev: Any) -> list:
        if isinstance(ev, PartStartEvent):
            part = ev.part
            field = _FIELDS.get(type(part))
            if field is not None and type(part) in _PART_DELTA:
                self.kinds[ev.index] = type(part)
                value = getattr(part, field)
                new = self._push(ev.index, value, "json" if field == "args" else "text")
                if new != value:
                    ev = dataclasses.replace(
                        ev, part=dataclasses.replace(part, **{field: new}))
            return [ev]
        if isinstance(ev, PartDeltaEvent):
            spec = _DELTAS.get(type(ev.delta))
            if spec is not None:
                field, mode = spec
                value = getattr(ev.delta, field)
                new = self._push(ev.index, value, mode)
                if new != value:
                    ev = dataclasses.replace(
                        ev, delta=dataclasses.replace(ev.delta, **{field: new}))
            return [ev]
        if isinstance(ev, PartEndEvent):
            return [*self._held(ev.index),
                    dataclasses.replace(ev, part=_restore_part(ev.part, self.pmap))]
        return [ev]

    def end(self) -> list:
        out = []
        for index in self.p.holding():
            out += self._held(index)
        return out


async def _restored_events(events: AsyncIterator[Any], handler: _Events) -> AsyncIterator[Any]:
    async for ev in events:
        for out in handler.item(ev):
            yield out
    for out in handler.end():
        yield out


_STATE = "_taintward_stream"
_STREAM_CLASSES: dict[type, type] = {}


def _stream_class(base: type) -> type:
    cls = _STREAM_CLASSES.get(base)
    if cls is not None:
        return cls

    class Restoring(base):  # type: ignore[misc, valid-type]
        def __aiter__(self):
            state = self.__dict__[_STATE]
            if state["events"] is None:
                state["events"] = _restored_events(super().__aiter__(), state["handler"])
            return state["events"]

        def get(self):
            resp = super().get()
            handler = self.__dict__[_STATE]["handler"]
            return dataclasses.replace(
                resp, parts=[handler.part(i, p) for i, p in enumerate(resp.parts)])

    Restoring.__name__ = Restoring.__qualname__ = f"Taintward{base.__name__}"
    _STREAM_CLASSES[base] = Restoring
    return Restoring


def _restore_stream(stream: Any, pmap) -> None:
    """Make ``stream`` (a ``StreamedResponse``) hand out restored events and a
    restored ``get()``. Its own parts keep the placeholders."""
    try:
        stream.__dict__[_STATE] = {"handler": _Events(pmap), "events": None}
        stream.__class__ = _stream_class(type(stream))
    except (TypeError, AttributeError):  # pragma: no cover - a slotted stream class
        log.warning("taintward: cannot restore a %s stream; its text keeps placeholders",
                    type(stream).__name__)


@dataclasses.dataclass(init=False)
class TaintwardModel(WrapperModel):
    """A model whose requests go through the ``llm`` destination gate."""

    ward: Ward | None = None

    def __init__(self, wrapped: Any, *, ward: Ward | None = None):
        super().__init__(wrapped)
        self.ward = ward

    def _gate(self, messages: list[ModelMessage]):
        ward = _resolve(self.ward, None)
        pmap = ward.llm_placeholder_map()
        slots = _slots(messages)
        call = llm_call(ward, self.model_name, FRAMEWORK, self.system,
                        {"parts": [_get(messages, s) for s in slots]}, pmap)
        return ward, pmap, slots, call

    def _send(self, messages, ward, pmap, slots, call):
        sent = call.kwargs["parts"]
        line = instruction(pmap, ward, sent)
        if line:
            call.span.set_attribute("taintward.placeholders.instruction", True)
        return _add_instruction(_rebuild(messages, slots, sent), line)

    async def request(self, messages, model_settings, model_request_parameters):
        ward, pmap, slots, call = self._gate(messages)
        with call:
            resp = await super().request(self._send(messages, ward, pmap, slots, call),
                                         model_settings, model_request_parameters)
            if finish_llm(call, ward, pmap, _resp_view(resp)):
                resp = _restore(resp, pmap)
        return resp

    @asynccontextmanager
    async def request_stream(self, messages, model_settings, model_request_parameters,
                             run_context=None) -> AsyncIterator[Any]:
        ward, pmap, slots, call = self._gate(messages)
        # The span is entered and ended in a private context: Pydantic AI may
        # leave this context manager in another task than it entered it.
        sc = StreamCall(call, ward, pmap)
        sc.enter()
        view = None
        try:
            send = self._send(messages, ward, pmap, slots, call)
            async with super().request_stream(send, model_settings, model_request_parameters,
                                              run_context) as stream:
                raw_get = type(stream).get  # the placeholder version, for the span
                if pmap is not None and len(pmap):
                    _restore_stream(stream, pmap)
                try:
                    yield stream
                finally:
                    view = _resp_view(raw_get(stream))
        except BaseException as e:
            sc.end(view, exc=e, check=False)
            raise
        error = sc.end(view)
        if error is not None:
            raise error


def protect_model(model: Any, *, ward: Ward | None = None) -> TaintwardModel:
    if isinstance(model, TaintwardModel):
        return model
    return TaintwardModel(model, ward=ward)


@dataclasses.dataclass
class TaintwardToolset(WrapperToolset):
    """A toolset whose tool calls go through the destination gate."""

    ward: Ward | None = None

    async def call_tool(self, name, tool_args, ctx, tool):
        ward = _resolve(self.ward, None)
        with tool_call(ward, name, FRAMEWORK, kwargs=tool_args) as call:
            out = await super().call_tool(name, call.kwargs, ctx, tool)
            call.record_result(out, view=plain_view(out))
        return out


def wrap_toolset(toolset: AbstractToolset, mapping: Mapping[str, Any] | None = None, *,
                 ward: Ward | None = None) -> TaintwardToolset:
    if isinstance(toolset, TaintwardToolset):
        return toolset
    return TaintwardToolset(toolset, ward=_resolve(ward, mapping))


def wrap_tools(tools: Iterable[Any], mapping: Mapping[str, Any] | None = None, *,
               ward: Ward | None = None) -> TaintwardToolset:
    """Functions or ``Tool`` objects -> one protected ``FunctionToolset``."""
    return wrap_toolset(FunctionToolset(list(tools)), mapping, ward=ward)


__all__ = ["TaintwardModel", "TaintwardToolset", "protect_model", "wrap_toolset", "wrap_tools"]
