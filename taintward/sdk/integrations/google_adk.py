"""Google Agent Development Kit (ADK) adapter.

``wrap_tools(tools, mapping)`` takes what ``LlmAgent(tools=...)`` takes:
plain functions (made into ``FunctionTool``), ``BaseTool`` objects and
toolsets (``McpToolset`` and others). Tools come back as protected copies
whose ``run_async`` goes through the destination gate for the tool's name; a
toolset comes back as a copy whose ``get_tools`` returns protected tools.
The ``ToolContext`` is passed through untouched.

``protect_model(model)`` takes a ``BaseLlm`` (``Gemini``, ``LiteLlm``, ...)
or a model name (resolved with ADK's model registry) and returns a
protected copy. Each ``generate_content_async`` request is redacted for the
``llm`` destination: text parts, function call arguments, function responses
and the system instruction. With placeholders on, every response is
restored (text and function call arguments), including the chunks of a
streamed response; a placeholder split across two partial chunks is
restored in the final, complete response.

    agent = LlmAgent(name="support", model=tw.protect_adk_model("gemini-2.5-flash"),
                     tools=tw.wrap_adk_tools([lookup, send_email]))
"""

from __future__ import annotations

import inspect
from typing import Any, Iterable, Mapping

from google.adk.models.base_llm import BaseLlm
from google.adk.models.registry import LLMRegistry
from google.adk.tools import FunctionTool
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.base_toolset import BaseToolset
from google.genai import types

from taintward.sdk.integrations import Ward, _resolve
from taintward.sdk.integrations._common import (
    finish_llm,
    instruction,
    is_protected,
    isolated_aiter,
    llm_call,
    protected_copy,
    tool_call,
    ward_of,
)
from taintward.sdk.integrations._payload import plain_view, to_plain

FRAMEWORK = "google-adk"


# ---------------------------------------------------------------------------
# tools
# ---------------------------------------------------------------------------

def _tool_class(base: type) -> type:
    class Protected(base):  # type: ignore[misc, valid-type]
        async def run_async(self, *, args, tool_context):
            with tool_call(ward_of(self), self.name, FRAMEWORK, kwargs=args) as call:
                out = await super().run_async(args=call.kwargs, tool_context=tool_context)
                call.record_result(out, view=plain_view(out))
            return out

    return Protected


def _toolset_class(base: type) -> type:
    class Protected(base):  # type: ignore[misc, valid-type]
        async def get_tools(self, readonly_context=None):
            tools = super().get_tools(readonly_context)
            if inspect.isawaitable(tools):
                tools = await tools
            return [_wrap_one(t, ward_of(self)) for t in tools]

    return Protected


def _wrap_one(tool: Any, ward: Ward) -> Any:
    if is_protected(tool):
        return tool
    if isinstance(tool, BaseToolset):
        return protected_copy(tool, _toolset_class, ward)
    if not isinstance(tool, BaseTool):
        if not callable(tool):
            return tool
        tool = FunctionTool(tool)
    return protected_copy(tool, _tool_class, ward)


def wrap_tools(tools: Iterable[Any], mapping: Mapping[str, Any] | None = None, *,
               ward: Ward | None = None) -> list[Any]:
    w = _resolve(ward, mapping)
    return [_wrap_one(t, w) for t in tools]


# ---------------------------------------------------------------------------
# model
# ---------------------------------------------------------------------------

def _slots(contents: list[types.Content]) -> list[tuple[int, int, str]]:
    out = []
    for i, c in enumerate(contents):
        for j, p in enumerate(c.parts or []):
            if p.text is not None:
                out.append((i, j, "text"))
            if p.function_call is not None and p.function_call.args:
                out.append((i, j, "function_call"))
            if p.function_response is not None and p.function_response.response:
                out.append((i, j, "function_response"))
    return out


def _value(part: types.Part, kind: str) -> Any:
    if kind == "text":
        return part.text
    if kind == "function_call":
        return part.function_call.args
    return part.function_response.response


def _with_value(part: types.Part, kind: str, v: Any) -> types.Part:
    if kind == "text":
        return part.model_copy(update={"text": v})
    if kind == "function_call":
        return part.model_copy(update={"function_call": part.function_call.model_copy(
            update={"args": v})})
    return part.model_copy(update={"function_response": part.function_response.model_copy(
        update={"response": v})})


def _system_text(config) -> Any:
    si = getattr(config, "system_instruction", None) if config is not None else None
    return si if isinstance(si, str) else None


def _rebuild(request, slots, values, system: Any, line: str | None):
    contents = [c.model_copy(update={"parts": list(c.parts or [])}) for c in request.contents]
    for (i, j, kind), v in zip(slots, values):
        contents[i].parts[j] = _with_value(contents[i].parts[j], kind, v)
    config = request.config
    if config is not None and (system is not None or line):
        si = config.system_instruction
        if isinstance(si, str) or si is None:
            text = system if system is not None else si
            si = f"{text}\n\n{line}" if text and line else (line or text)
        elif line and isinstance(si, types.Content):
            si = si.model_copy(update={"parts": [*(si.parts or []), types.Part(text=line)]})
        config = config.model_copy(update={"system_instruction": si})
    return request.model_copy(update={"contents": contents, "config": config})


def _view(resp) -> Any:
    content = getattr(resp, "content", None)
    return to_plain(content) if content is not None else None


def _restore_partial(pmap, content, seen: str) -> str:
    """Restore one streamed chunk in place. ``seen`` is the text of the
    earlier chunks, so a link address that started there still blocks
    restore (gap G1). Returns the new ``seen``."""
    for part in content.parts or []:
        if part.text:
            raw = part.text
            part.text = pmap.restore_text(raw, before=seen)
            seen += raw
        elif part.function_call is not None:
            pmap.restore_inplace(part.function_call)
    return seen


def _model_class(base: type) -> type:
    class Protected(base):  # type: ignore[misc, valid-type]
        def generate_content_async(self, llm_request, stream: bool = False):
            return isolated_aiter(self._taintward_generate(llm_request, stream))

        async def _taintward_generate(self, llm_request, stream):
            ward = ward_of(self)
            pmap = ward.llm_placeholder_map()
            slots = _slots(llm_request.contents or [])
            content = {"parts": [_value(llm_request.contents[i].parts[j], k)
                                 for i, j, k in slots]}
            system = _system_text(llm_request.config)
            if system is not None:
                content["system"] = system
            with llm_call(ward, str(llm_request.model or self.model), FRAMEWORK, "gemini",
                          content, pmap) as call:
                line = instruction(pmap, ward, call.kwargs)
                if line:
                    call.span.set_attribute("taintward.placeholders.instruction", True)
                request = _rebuild(llm_request, slots, call.kwargs["parts"],
                                   call.kwargs.get("system"), line)
                last = None
                seen = ""
                restore = pmap is not None and len(pmap) > 0
                async for resp in super().generate_content_async(request, stream):
                    if not getattr(resp, "partial", False):
                        last = _view(resp)
                        if finish_llm(call, ward, pmap, last) and resp.content is not None:
                            resp.content = pmap.restore_inplace(resp.content)
                    elif restore and resp.content is not None:
                        seen = _restore_partial(pmap, resp.content, seen)
                    yield resp

    return Protected


def protect_model(model: Any, *, ward: Ward | None = None) -> BaseLlm:
    if isinstance(model, str):
        model = LLMRegistry.new_llm(model)
    if is_protected(model):
        return model
    return protected_copy(model, _model_class, _resolve(ward, None))


__all__ = ["wrap_tools", "protect_model"]
