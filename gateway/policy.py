"""Policy decision for the gateway: the rules of collector/policy/pii_egress.rego
written in Python.

The Rego file stays the source of truth. The gateway does not embed an OPA
engine (no ``opa`` binary is required to run it), so this module mirrors the
Rego rules one to one, and ``tests/test_gateway.py`` keeps the two in sync:
it parses the Rego file's sets and rule names and fails if they drift, and,
when an ``opa`` binary is on PATH, it also evaluates both on the same inputs
and compares the decisions.

Rego rules mirrored here:

* ``violation``: ``sensitive == true`` and ``destination`` in
  ``sensitive_sinks`` -> ``{"rule": "pii_egress", "sink": destination}``
* ``transfer_violation``: ``classes`` contains ``pii`` and ``jurisdiction``
  in ``non_adequate_jurisdictions`` ->
  ``{"rule": "transfer", "jurisdiction": jurisdiction}``
* ``redact``: ``sensitive == true``
* ``decision``: ``{"redact": redact, "violations": violation | transfer_violation}``
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Keep these equal to the sets in pii_egress.rego (enforced by a test).
SENSITIVE_SINKS = frozenset({"external", "llm", "log"})
NON_ADEQUATE_JURISDICTIONS = frozenset({"us"})

RULE_PII_EGRESS = "pii_egress"
RULE_TRANSFER = "transfer"
RULE_NAMES = frozenset({RULE_PII_EGRESS, RULE_TRANSFER})


@dataclass(frozen=True)
class PolicyInput:
    """Same shape as the Rego ``input`` document."""

    sensitive: bool
    classes: str  # comma-joined, e.g. "pii,secret"
    destination: str
    jurisdiction: str = ""
    tool: str = ""

    def as_dict(self) -> dict:
        return {
            "sensitive": self.sensitive,
            "classes": self.classes,
            "destination": self.destination,
            "jurisdiction": self.jurisdiction,
            "tool": self.tool,
        }


@dataclass(frozen=True)
class Decision:
    redact: bool
    violations: list[dict] = field(default_factory=list)

    @property
    def is_violation(self) -> bool:
        return bool(self.violations)

    def rules(self) -> list[str]:
        return sorted({v["rule"] for v in self.violations})


def _has_class(classes: str, cls: str) -> bool:
    return cls in classes.split(",")


def evaluate(inp: PolicyInput) -> Decision:
    """Evaluate ``data.agentward.decision`` for one input."""
    violations: list[dict] = []
    if inp.sensitive is True and inp.destination in SENSITIVE_SINKS:
        violations.append({"rule": RULE_PII_EGRESS, "sink": inp.destination})
    if _has_class(inp.classes, "pii") and inp.jurisdiction in NON_ADEQUATE_JURISDICTIONS:
        violations.append({"rule": RULE_TRANSFER, "jurisdiction": inp.jurisdiction})
    return Decision(redact=inp.sensitive is True, violations=violations)
