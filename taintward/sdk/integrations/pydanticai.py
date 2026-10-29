"""Pydantic AI adapter.

``TaintwardModel(model)`` wraps any Pydantic AI model (an object or a name
such as ``"openai:gpt-4.1"``). Every request is redacted for the ``llm``
destination: system and user prompts, instructions, tool results, retry
prompts and earlier model responses (text, thinking, tool call arguments).
With placeholders on, the response from ``request`` is restored (text,
thinking and tool call arguments). ``request_stream`` redacts the request
too, but the streamed response keeps its placeholders; tools still get real
values because the toolset below restores them from the run's map.

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
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Iterable, Mapping

from pydantic_ai.messages import (
    ModelMessage,
    ModelRequest,
    ModelResponse,
    RetryPromptPart,
    SystemPromptPart,
    TextPart,
    ThinkingPart,
    ToolCallPart,
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
        with call:
            async with super().request_stream(
                    self._send(messages, ward, pmap, slots, call), model_settings,
                    model_request_parameters, run_context) as stream:
                yield stream


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
