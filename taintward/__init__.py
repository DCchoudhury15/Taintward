"""Taintward: runtime data-exposure control for AI agents.

The integrations API is available at the top level::

    import taintward as tw

    tw.init("hr-agent", destinations={"search_db": "internal",
                                      "send_email": ("external", "us")})
    tools = tw.wrap_langchain_tools(tools)
    with tw.run("agent.run"):
        ...

Subpackages: ``taintward.sdk`` (detection, redaction, taint, tracing),
``taintward.core`` (the data over-exposure model), ``taintward.evidence``
(signed evidence log and compliance report), ``taintward.gateway`` (MCP
gateway) and ``taintward.fix_suggester``.

The names below are loaded on first use, so ``import taintward.core.doe``
does not load the SDK and its dependencies.
"""

from __future__ import annotations

import importlib

__version__ = "0.3.0"

_EXPORTS = {
    "init": "taintward.sdk.integrations",
    "run": "taintward.sdk.integrations",
    "restore": "taintward.sdk.integrations",
    "wrap_langchain_tools": "taintward.sdk.integrations",
    "protect_langchain_model": "taintward.sdk.integrations",
    "wrap_function_tools": "taintward.sdk.integrations",
    "protect_openai": "taintward.sdk.integrations",
    "protect_anthropic": "taintward.sdk.integrations",
    "wrap_crewai_tools": "taintward.sdk.integrations",
    "protect_crewai_llm": "taintward.sdk.integrations",
    "wrap_llamaindex_tools": "taintward.sdk.integrations",
    "protect_llamaindex_llm": "taintward.sdk.integrations",
    "wrap_pydantic_ai_tools": "taintward.sdk.integrations",
    "wrap_pydantic_ai_toolset": "taintward.sdk.integrations",
    "protect_pydantic_ai_model": "taintward.sdk.integrations",
    "wrap_adk_tools": "taintward.sdk.integrations",
    "protect_adk_model": "taintward.sdk.integrations",
    "protect_litellm": "taintward.sdk.integrations",
    "get_ward": "taintward.sdk.integrations",
    "Ward": "taintward.sdk.integrations",
    "health": "taintward.sdk.detect",
}

__all__ = sorted(_EXPORTS)


def __getattr__(name: str):
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module 'taintward' has no attribute {name!r}")
    value = getattr(importlib.import_module(module), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
