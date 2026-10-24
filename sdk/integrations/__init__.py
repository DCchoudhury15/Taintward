"""Low-code AgentWard integration for agent frameworks.

Instead of putting ``@instrument_tool(...)`` on every tool by hand, call
``init()`` once with a tool-name -> destination map, then hand your framework
objects to an adapter::

    from sdk import integrations as ward

    ward.init("hr-agent", destinations={
        "search_db": "internal",
        "send_email": ("external", "us"),   # (destination, jurisdiction)
    })
    tools = ward.wrap_langchain_tools(tools)      # LangChain / LangGraph
    model = ward.protect_langchain_model(model)   # LLM requests are redacted
    client = ward.protect_openai(OpenAI())        # plain OpenAI client
    agent_tools = ward.wrap_function_tools(tools) # OpenAI Agents SDK

Unmapped tools default to ``external``. That is the safe choice: an unknown
tool may send data anywhere, so it gets the non-reversible mask and its span
is flagged when a tainted chain reaches it. Marking a tool ``internal`` is an
explicit, reviewable decision to trust it with reversible tokens. A tool that
was wrongly left external only loses some usefulness (it sees ``[PII]``); a
tool wrongly treated as internal would receive data it should not.

All redaction and detection is done by the existing SDK (``sdk.detect``,
``sdk.redact.redact_payload``, ``sdk.instrumentation.GuardedCall``). The
adapters only translate each framework's call shape into that one gate.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from typing import Any, Iterator, Mapping

from opentelemetry import trace

from sdk import instrumentation as instr
from sdk.destinations import (
    DEST_EXTERNAL, DEST_INTERNAL, DEST_LLM, DEST_LOG, DEST_RAG,
)

VALID_DESTINATIONS = frozenset({DEST_INTERNAL, DEST_EXTERNAL, DEST_LLM, DEST_LOG, DEST_RAG})

# Safe default for tools that are not in the map. See module docstring.
DEFAULT_DESTINATION = DEST_EXTERNAL


@dataclass(frozen=True)
class ToolPolicy:
    """Where one tool sends its input."""

    destination: str = DEFAULT_DESTINATION
    jurisdiction: str = ""
    # Argument names passed to the tool unredacted, e.g. the recipient address
    # of an email tool. An explicit, reviewed exception: the values are still
    # scanned, so the taint label and the violation flag stay correct.
    allow: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        object.__setattr__(self, "allow", frozenset(self.allow))
        if self.destination not in VALID_DESTINATIONS:
            raise ValueError(
                f"unknown destination {self.destination!r}; "
                f"use one of {sorted(VALID_DESTINATIONS)}"
            )


def _to_policy(value: Any) -> ToolPolicy:
    """Accept "external", ("external", "eu"), {"destination": .., "jurisdiction":
    .., "allow": [..]}, or a ToolPolicy."""
    if isinstance(value, ToolPolicy):
        return value
    if isinstance(value, str):
        return ToolPolicy(value)
    if isinstance(value, (tuple, list)) and 1 <= len(value) <= 2:
        return ToolPolicy(*value)
    if isinstance(value, Mapping):
        return ToolPolicy(
            destination=value.get("destination", DEFAULT_DESTINATION),
            jurisdiction=value.get("jurisdiction", ""),
            allow=frozenset(value.get("allow", ())),
        )
    raise TypeError(f"cannot read a tool policy from {value!r}")


class Ward:
    """Holds the tool map, the LLM policy and the tracer used by adapters."""

    def __init__(
        self,
        destinations: Mapping[str, Any] | None = None,
        *,
        default_destination: str = DEFAULT_DESTINATION,
        default_jurisdiction: str = "",
        llm_jurisdiction: str = "",
        tracer: trace.Tracer | None = None,
    ) -> None:
        self.default = ToolPolicy(default_destination, default_jurisdiction)
        self.policies: dict[str, ToolPolicy] = {
            name: _to_policy(v) for name, v in (destinations or {}).items()
        }
        self.llm_jurisdiction = llm_jurisdiction
        self.tracer = tracer

    def policy_for(self, tool_name: str) -> ToolPolicy:
        return self.policies.get(tool_name, self.default)

    def is_mapped(self, tool_name: str) -> bool:
        return tool_name in self.policies

    def with_overrides(self, mapping: Mapping[str, Any] | None) -> "Ward":
        """A copy with extra/overriding tool entries (used by ``wrap_*(mapping=)``)."""
        if not mapping:
            return self
        w = Ward(default_destination=self.default.destination,
                 default_jurisdiction=self.default.jurisdiction,
                 llm_jurisdiction=self.llm_jurisdiction, tracer=self.tracer)
        w.policies = {**self.policies, **{k: _to_policy(v) for k, v in mapping.items()}}
        return w

    @contextlib.contextmanager
    def run(self, name: str = "agent.run") -> Iterator[object]:
        """One agent run: one trace, a clean taint slate, and taint that
        follows the run across framework threads and asyncio tasks."""
        root = instr.begin_run(name, tracer=self.tracer)
        try:
            yield root
        finally:
            instr.end_run()

    # Adapter shortcuts (imported lazily so the frameworks stay optional).
    def wrap_langchain_tools(self, tools, mapping=None):
        from sdk.integrations.langchain import wrap_tools
        return wrap_tools(tools, mapping, ward=self)

    def protect_langchain_model(self, model):
        from sdk.integrations.langchain import protect_chat_model
        return protect_chat_model(model, ward=self)

    def wrap_function_tools(self, tools, mapping=None):
        from sdk.integrations.openai_agents import wrap_function_tools
        return wrap_function_tools(tools, mapping, ward=self)

    def protect_openai(self, client):
        from sdk.integrations.llm_clients import protect_openai
        return protect_openai(client, ward=self)

    def protect_anthropic(self, client):
        from sdk.integrations.llm_clients import protect_anthropic
        return protect_anthropic(client, ward=self)


_GLOBAL: Ward | None = None


def init(
    service_name: str,
    endpoint: str | None = None,
    destinations: Mapping[str, Any] | None = None,
    *,
    default_destination: str = DEFAULT_DESTINATION,
    default_jurisdiction: str = "",
    llm_jurisdiction: str = "",
    console: bool = False,
    tracer: trace.Tracer | None = None,
) -> Ward:
    """Configure AgentWard once per process and return the global ``Ward``.

    * ``service_name`` / ``endpoint`` / ``console`` go to
      ``instrumentation.configure_tracing`` (OTLP/HTTP to SigNoz).
    * ``destinations`` maps tool names to a destination, e.g.
      ``{"send_email": "external", "search_db": "internal"}``. A value can also
      be ``("external", "eu")`` or ``{"destination": .., "jurisdiction": ..}``.
    * ``default_destination`` is used for tools not in the map (default
      ``external``, the safe choice).
    * ``llm_jurisdiction`` tags LLM request spans (e.g. ``"us"``).
    * ``tracer``: pass your own tracer to skip global tracing setup (tests, or
      an app that already configured OpenTelemetry).
    """
    global _GLOBAL
    if tracer is None:
        tracer = instr.configure_tracing(
            service_name, endpoint=endpoint or instr.DEFAULT_OTLP_HTTP, console=console,
        )
    _GLOBAL = Ward(
        destinations,
        default_destination=default_destination,
        default_jurisdiction=default_jurisdiction,
        llm_jurisdiction=llm_jurisdiction,
        tracer=tracer,
    )
    return _GLOBAL


def get_ward() -> Ward:
    """The ``Ward`` from ``init()``, or a safe default (every tool external)."""
    global _GLOBAL
    if _GLOBAL is None:
        _GLOBAL = Ward()
    return _GLOBAL


def _resolve(ward: Ward | None, mapping: Mapping[str, Any] | None) -> Ward:
    return (ward or get_ward()).with_overrides(mapping)


def run(name: str = "agent.run"):
    """Context manager for one agent run on the global ``Ward``."""
    return get_ward().run(name)


# Module-level shortcuts on the global Ward.
def wrap_langchain_tools(tools, mapping=None):
    return get_ward().wrap_langchain_tools(tools, mapping)


def protect_langchain_model(model):
    return get_ward().protect_langchain_model(model)


def wrap_function_tools(tools, mapping=None):
    return get_ward().wrap_function_tools(tools, mapping)


def protect_openai(client):
    return get_ward().protect_openai(client)


def protect_anthropic(client):
    return get_ward().protect_anthropic(client)


__all__ = [
    "DEFAULT_DESTINATION", "ToolPolicy", "Ward", "init", "get_ward", "run",
    "wrap_langchain_tools", "protect_langchain_model", "wrap_function_tools",
    "protect_openai", "protect_anthropic",
]
