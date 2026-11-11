"""Sink-destination classes shared across the SDK and collector policy.

Kept in a leaf module to avoid circular imports between ``taintward.sdk.redact`` and
``taintward.sdk.instrumentation``, and so tools that only read a destination
map (the control plane, the audit) do not load the detectors.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

DEST_INTERNAL = "internal"
DEST_EXTERNAL = "external"
DEST_LLM = "llm"
DEST_LOG = "log"
DEST_RAG = "rag"

VALID_DESTINATIONS = frozenset({DEST_INTERNAL, DEST_EXTERNAL, DEST_LLM, DEST_LOG, DEST_RAG})

# Safe default for tools that are not in the map (see taintward.sdk.integrations).
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
        allow = value.get("allow") or ()
        if isinstance(allow, str):
            # allow: to   (one name, not a list): not the letters "t" and "o"
            allow = (allow,)
        return ToolPolicy(
            destination=value.get("destination", DEFAULT_DESTINATION),
            jurisdiction=value.get("jurisdiction", ""),
            allow=frozenset(allow),
        )
    raise TypeError(f"cannot read a tool policy from {value!r}")
