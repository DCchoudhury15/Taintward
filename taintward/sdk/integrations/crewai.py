"""CrewAI adapter.

``wrap_tools(tools, mapping)`` returns protected copies of CrewAI tools
(``BaseTool`` subclasses and ``@tool`` functions). Only ``_run`` / ``_arun``
are overridden, which is what CrewAI calls for every tool use (also through
``to_structured_tool``), so name, description, args schema, caching, usage
limits and ``result_as_answer`` are unchanged. Each run goes through the
destination gate for the tool's name.

``protect_llm(llm)`` returns a protected copy of a CrewAI LLM (``crewai.LLM``
or any ``BaseLLM``). ``call`` / ``acall`` send the messages redacted for the
``llm`` destination and restore placeholders in the answer before CrewAI
parses it, so a tool call written by the model reaches the wrapped tool with
real values. When CrewAI runs native tool calls inside ``call``, those tools
see the same placeholder map.

Use both::

    agent = Agent(role=..., goal=..., backstory=...,
                  llm=tw.protect_crewai_llm(LLM(model="gpt-4.1")),
                  tools=tw.wrap_crewai_tools([lookup, send_email]))
"""

from __future__ import annotations

import contextlib
from typing import Any, Iterable, Mapping

from crewai.llms.base_llm import BaseLLM
from crewai.tools import BaseTool

from taintward.sdk import placeholders as ph
from taintward.sdk.integrations import Ward, _resolve
from taintward.sdk.integrations._common import (
    finish_llm,
    instruction,
    is_protected,
    llm_call,
    protected_copy,
    tool_call,
    ward_of,
)
from taintward.sdk.integrations._payload import plain_view

FRAMEWORK = "crewai"


def _tool_class(base: type) -> type:
    class Protected(base):  # type: ignore[misc, valid-type]
        def _run(self, *args, **kwargs):
            with tool_call(ward_of(self), self.name, FRAMEWORK, args=args, kwargs=kwargs) as call:
                out = super()._run(*call.args, **call.kwargs)
                call.record_result(out, view=plain_view(out))
            return out

        async def _arun(self, *args, **kwargs):
            with tool_call(ward_of(self), self.name, FRAMEWORK, args=args, kwargs=kwargs) as call:
                out = await super()._arun(*call.args, **call.kwargs)
                call.record_result(out, view=plain_view(out))
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


def _messages(messages: Any, line: str | None) -> Any:
    if not line:
        return messages
    if isinstance(messages, str):
        return [{"role": "system", "content": line}, {"role": "user", "content": messages}]
    msgs = list(messages)
    if msgs and isinstance(msgs[0], dict) and msgs[0].get("role") == "system" \
            and isinstance(msgs[0].get("content"), str):
        msgs[0] = {**msgs[0], "content": f"{msgs[0]['content']}\n\n{line}"}
    else:
        msgs.insert(0, {"role": "system", "content": line})
    return msgs


@contextlib.contextmanager
def _llm_scope(llm: BaseLLM, messages: Any):
    ward = ward_of(llm)
    pmap = ward.llm_placeholder_map()
    own = pmap is not None and ph.current() is not pmap
    tok = ph.activate(pmap) if own else None  # tools run inside call() see it
    try:
        with llm_call(ward, str(getattr(llm, "model", "")), FRAMEWORK, "crewai",
                      {"messages": messages}, pmap) as call:
            sent = call.kwargs["messages"]
            line = instruction(pmap, ward, sent)
            if line:
                call.span.set_attribute("taintward.placeholders.instruction", True)
            box: dict = {"messages": _messages(sent, line)}
            yield box
            out = box.get("out")
            if finish_llm(call, ward, pmap, out if isinstance(out, (str, dict, list)) else str(out)):
                box["out"] = pmap.restore(out) if isinstance(out, (str, dict, list)) \
                    else pmap.restore_inplace(out)
    finally:
        if tok is not None:
            ph.deactivate(tok)


def _llm_class(base: type) -> type:
    class Protected(base):  # type: ignore[misc, valid-type]
        def call(self, messages, *args, **kwargs):
            with _llm_scope(self, messages) as box:
                box["out"] = super().call(box["messages"], *args, **kwargs)
            return box["out"]

        async def acall(self, messages, *args, **kwargs):
            with _llm_scope(self, messages) as box:
                box["out"] = await super().acall(box["messages"], *args, **kwargs)
            return box["out"]

    return Protected


def protect_llm(llm: BaseLLM, *, ward: Ward | None = None) -> BaseLLM:
    if is_protected(llm):
        return llm
    return protected_copy(llm, _llm_class, _resolve(ward, None))


__all__ = ["wrap_tool", "wrap_tools", "protect_llm"]
