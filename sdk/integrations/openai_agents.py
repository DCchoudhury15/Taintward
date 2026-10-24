"""OpenAI Agents SDK (``openai-agents``) adapter.

``wrap_function_tools(tools, mapping)`` returns protected copies of
``FunctionTool`` objects (what ``@function_tool`` produces). The copy keeps
the name, description, JSON schema, strict mode, guardrails, approval and
timeout settings. Only ``on_invoke_tool`` is wrapped: the JSON arguments the
model produced are parsed, redacted for the tool's destination, and the
original invoker runs with the redacted JSON inside an AgentWard span.

Non-function tools (hosted tools such as web search, MCP servers, computer
tools) are returned unchanged: they do not run in this process, so there is
no argument to redact here. Their data still goes through the LLM request,
which ``protect_openai`` covers.
"""

from __future__ import annotations

import copy
import json
from typing import Any, Iterable, Mapping

from agents import FunctionTool

from sdk.instrumentation import GuardedCall
from sdk.integrations import Ward, _resolve
from sdk.integrations._payload import plain_view as _plain_view

_PATCHED_MARK = "__agentward_patched__"


def _make_invoker(original, name: str, policy, ward: Ward):
    destination, jurisdiction = policy.destination, policy.jurisdiction

    async def on_invoke_tool(ctx, input: str):
        try:
            parsed = json.loads(input) if input else {}
        except (TypeError, ValueError):
            parsed = None
        if isinstance(parsed, dict):
            call = GuardedCall(name, destination=destination, jurisdiction=jurisdiction,
                               tracer=ward.tracer, kwargs=parsed, attributes=_attrs(name),
                               passthrough=policy.allow)
        else:  # not a JSON object: redact the raw text
            call = GuardedCall(name, destination=destination, jurisdiction=jurisdiction,
                               tracer=ward.tracer, args=[input], attributes=_attrs(name))
        with call:
            if isinstance(parsed, dict):
                redacted = json.dumps(call.kwargs, ensure_ascii=False)
            else:
                redacted = call.args[0]
            run_ctx = _redacted_context(ctx, input, redacted)
            out = await original(run_ctx, redacted)
            call.record_result(out, view=_plain_view(out))
        return out

    setattr(on_invoke_tool, _PATCHED_MARK, True)
    return on_invoke_tool


def _attrs(name: str) -> dict:
    return {
        "gen_ai.tool.name": name,
        "gen_ai.operation.name": "execute_tool",
        "agentward.framework": "openai-agents",
    }


def _redacted_context(ctx, raw: str, redacted: str):
    """A shallow copy of the ToolContext that carries the redacted arguments.

    The runner may have pre-parsed the raw arguments (for approval checks)
    and stored them on the context; those would bypass redaction and would
    also fail the SDK's own "prepared arguments match" check, so they are
    dropped and the tool parses the redacted JSON itself.
    """
    if redacted == raw:
        return ctx
    try:
        new = copy.copy(ctx)
        if hasattr(new, "tool_arguments"):
            new.tool_arguments = redacted
        if hasattr(new, "_function_tool_arguments"):
            new._function_tool_arguments = None
        return new
    except Exception:
        if hasattr(ctx, "_function_tool_arguments"):
            ctx._function_tool_arguments = None
        return ctx


def wrap_function_tool(tool: Any, mapping: Mapping[str, Any] | None = None, *,
                       ward: Ward | None = None) -> Any:
    """Protect one ``FunctionTool``; other tool types are returned unchanged."""
    if not isinstance(tool, FunctionTool):
        return tool
    if getattr(tool.on_invoke_tool, _PATCHED_MARK, False):
        return tool
    w = _resolve(ward, mapping)
    policy = w.policy_for(tool.name)
    new = copy.copy(tool)
    new.on_invoke_tool = _make_invoker(tool.on_invoke_tool, tool.name, policy, w)
    return new


def wrap_function_tools(tools: Iterable[Any], mapping: Mapping[str, Any] | None = None,
                        *, ward: Ward | None = None) -> list[Any]:
    """Protect a list of agent tools (pass the result to ``Agent(tools=...)``)."""
    w = _resolve(ward, mapping)
    return [wrap_function_tool(t, ward=w) for t in tools]


__all__ = ["wrap_function_tool", "wrap_function_tools"]
