"""Low-code Taintward integration for agent frameworks.

Instead of putting ``@instrument_tool(...)`` on every tool by hand, call
``init()`` once with a tool-name -> destination map, then hand your framework
objects to an adapter::

    from taintward.sdk import integrations as ward

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

Placeholders (on by default): the LLM does not get ``[PII]`` masks, it gets
stable typed placeholders such as ``<PERSON_1>`` and ``<SSN_1>``, so it can
still do the task. The model's answer and tool calls are restored to the real
values before they reach your code, and each tool then gets what its
destination allows (see ``taintward.sdk.placeholders`` and docs/integrations.md). Turn
it off with ``init(..., placeholders=False)`` to go back to masks.

All redaction and detection is done by the existing SDK (``taintward.sdk.detect``,
``taintward.sdk.redact.redact_payload``, ``taintward.sdk.instrumentation.GuardedCall``). The
adapters only translate each framework's call shape into that one gate.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from typing import Any, Iterator, Mapping

from opentelemetry import trace

from taintward.sdk import instrumentation as instr
from taintward.sdk import placeholders as ph
from taintward.sdk.destinations import (
    DEST_EXTERNAL,
    DEST_INTERNAL,
    DEST_LLM,
    DEST_LOG,
    DEST_RAG,
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
        placeholders: bool = True,
        placeholder_vault: Any = None,
        placeholder_ttl: float | None = None,
    ) -> None:
        self.default = ToolPolicy(default_destination, default_jurisdiction)
        self.policies: dict[str, ToolPolicy] = {
            name: _to_policy(v) for name, v in (destinations or {}).items()
        }
        self.llm_jurisdiction = llm_jurisdiction
        self.tracer = tracer
        self.placeholders = placeholders
        self.placeholder_vault = placeholder_vault
        self.placeholder_ttl = placeholder_ttl

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
                 llm_jurisdiction=self.llm_jurisdiction, tracer=self.tracer,
                 placeholders=self.placeholders,
                 placeholder_vault=self.placeholder_vault,
                 placeholder_ttl=self.placeholder_ttl)
        w.policies = {**self.policies, **{k: _to_policy(v) for k, v in mapping.items()}}
        return w

    @contextlib.contextmanager
    def run(self, name: str = "agent.run", *,
            conversation_id: str | None = None) -> Iterator[object]:
        """One agent run: one trace, a clean taint slate, taint that follows
        the run across framework threads and asyncio tasks, and one
        placeholder map shared by every LLM call and tool in the run.

        ``conversation_id`` with a ``placeholder_vault`` keeps the
        placeholders of a long-lived conversation in the vault, so later runs
        of the same conversation reuse them. Without a vault the map lives in
        memory and is cleared when the run ends.
        """
        root = instr.begin_run(name, tracer=self.tracer)
        tok = None
        if self.placeholders:
            if conversation_id and self.placeholder_vault is not None:
                pmap = ph.PlaceholderMap(vault=self.placeholder_vault,
                                         conversation_id=conversation_id,
                                         ttl=self.placeholder_ttl)
            else:
                pmap = ph.PlaceholderMap()
            tok = ph.activate(pmap)
        try:
            yield root
        finally:
            if tok is not None:
                ph.deactivate(tok)
            instr.end_run()

    def placeholder_map(self) -> "ph.PlaceholderMap | None":
        """The run's placeholder map for tool calls (None when placeholders
        are off or no run is active)."""
        return ph.current() if self.placeholders else None

    def llm_placeholder_map(self) -> "ph.PlaceholderMap | None":
        """The map for one LLM request: the run's map, or a fresh map for this
        one call when no run is active (never shared between callers)."""
        if not self.placeholders:
            return None
        pmap = ph.current()
        return pmap if pmap is not None else ph.PlaceholderMap()

    def restore(self, value: Any) -> Any:
        """Swap placeholders back to real values with the current run's map
        (for output the adapters do not restore, e.g. collected stream text)."""
        return ph.restore(value) if self.placeholders else value

    # Adapter shortcuts (imported lazily so the frameworks stay optional).
    def wrap_langchain_tools(self, tools, mapping=None):
        from taintward.sdk.integrations.langchain import wrap_tools
        return wrap_tools(tools, mapping, ward=self)

    def protect_langchain_model(self, model):
        from taintward.sdk.integrations.langchain import protect_chat_model
        return protect_chat_model(model, ward=self)

    def wrap_function_tools(self, tools, mapping=None):
        from taintward.sdk.integrations.openai_agents import wrap_function_tools
        return wrap_function_tools(tools, mapping, ward=self)

    def protect_openai(self, client):
        from taintward.sdk.integrations.llm_clients import protect_openai
        return protect_openai(client, ward=self)

    def protect_anthropic(self, client):
        from taintward.sdk.integrations.llm_clients import protect_anthropic
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
    placeholders: bool = True,
    placeholder_vault: Any = None,
    placeholder_ttl: float | None = None,
) -> Ward:
    """Configure Taintward once per process and return the global ``Ward``.

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
    * ``placeholders`` (default True): the LLM gets stable placeholders such
      as ``<PERSON_1>`` instead of ``[PII]``, and the model's output is
      restored. False goes back to plain masks.
    * ``placeholder_vault`` / ``placeholder_ttl``: optional ``taintward.sdk.vault``
      backend (and entry lifetime) for placeholders of long-lived
      conversations, used by ``run(conversation_id=...)``.
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
        placeholders=placeholders,
        placeholder_vault=placeholder_vault,
        placeholder_ttl=placeholder_ttl,
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


def run(name: str = "agent.run", *, conversation_id: str | None = None):
    """Context manager for one agent run on the global ``Ward``."""
    return get_ward().run(name, conversation_id=conversation_id)


def restore(value):
    """Restore placeholders with the current run's map (global ``Ward``)."""
    return get_ward().restore(value)


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
    "DEFAULT_DESTINATION", "ToolPolicy", "Ward", "init", "get_ward", "run", "restore",
    "wrap_langchain_tools", "protect_langchain_model", "wrap_function_tools",
    "protect_openai", "protect_anthropic",
]
