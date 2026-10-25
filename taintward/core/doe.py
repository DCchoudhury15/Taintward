"""Formal Data Over-Exposure (DOE) model: the mathematical anchor for Taintward.

Implements the definition from AgentRaft (arXiv:2603.07557, Lin et al., 2026)::

    D_OE = (D_trans \\ (D_nec ∪ D_int)) ∩ D_total

where

    D_total : all data retrieved at the source
    D_trans : the data payload actually delivered to the sink
    D_int   : data the user intended to transmit
    D_nec   : data strictly necessary for the sink to perform its function
    D_OE    : over-exposed data, fields that reached a sink although neither
              intended by the user nor required by the sink

AgentRaft computes these sets offline from a custom agent-trace format and
judges ``D_nec`` with a multi-LLM voting committee. Taintward computes the
*same* sets at runtime from OpenTelemetry spans and judges ``D_nec`` with a
deterministic Rego policy (see ``collector/policy/``). The formal model is
identical; this module is the shared anchor and is unit-tested against the
paper's worked examples.

This module is pure: no I/O, no OTel, no SigNoz. It operates on sets of
:class:`Field` identifiers so the same logical field is equal across the source
payload, the transmitted payload, and the policy tables.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Iterator


class Sensitivity(str, Enum):
    """Sensitivity class of a data element.

    ``CLEAN`` fields are never the target of enforcement; ``PII`` and
    ``SECRET`` are. The enum derives from ``str`` so labels serialize
    cleanly into OTel baggage / span attributes.
    """

    CLEAN = "clean"
    PII = "pii"
    SECRET = "secret"

    @property
    def is_sensitive(self) -> bool:
        return self is not Sensitivity.CLEAN


@dataclass(frozen=True, eq=False)
class Field:
    """A single data element within a payload.

    Equality and hashing are by ``name`` only so that the same logical field
    compares equal across the source payload, the transmitted payload, and the
    policy tables. ``value`` is carried for redaction/diagnostics and is
    deliberately excluded from identity: two ``Field`` objects with the same
    name but different values are the *same field* for DOE purposes.
    """

    name: str
    value: object = None
    sensitivity: Sensitivity = Sensitivity.CLEAN

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Field):
            return NotImplemented
        return self.name == other.name

    def __hash__(self) -> int:
        return hash(self.name)

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"Field({self.name!r}, {self.sensitivity.value})"


def _frozen(fields: Iterable[Field]) -> frozenset[Field]:
    return frozenset(fields)


@dataclass(frozen=True)
class DOESets:
    """The four input sets that define a single source→sink observation.

    All sets are :class:`Field`-keyed. Fields may appear in ``D_nec`` or
    ``D_int`` that are not in ``D_total`` (e.g. a sink-internal field the
    user never saw); those simply never contribute to ``D_OE`` because of
    the intersection with ``D_total``.
    """

    d_total: frozenset[Field]  # all data retrieved at the source
    d_trans: frozenset[Field]  # data payload delivered to the sink
    d_int: frozenset[Field]  # data the user intended to transmit
    d_nec: frozenset[Field]  # data strictly necessary for the sink

    @classmethod
    def of(
        cls,
        d_total: Iterable[Field],
        d_trans: Iterable[Field],
        d_int: Iterable[Field],
        d_nec: Iterable[Field],
    ) -> "DOESets":
        return cls(
            d_total=_frozen(d_total),
            d_trans=_frozen(d_trans),
            d_int=_frozen(d_int),
            d_nec=_frozen(d_nec),
        )


@dataclass(frozen=True)
class DOEResult:
    """Output of :func:`classify`: the four input sets plus the computed ``D_OE``."""

    d_total: frozenset[Field]
    d_trans: frozenset[Field]
    d_int: frozenset[Field]
    d_nec: frozenset[Field]
    d_oe: frozenset[Field]  # over-exposed fields

    @property
    def is_violation(self) -> bool:
        """True iff at least one field was over-exposed on this observation."""
        return bool(self.d_oe)

    @property
    def over_exposed_names(self) -> tuple[str, ...]:
        """Over-exposed field names, sorted, for assertions and dashboards."""
        return tuple(sorted(f.name for f in self.d_oe))

    def sensitive_over_exposure(self) -> frozenset[Field]:
        """The subset of ``D_OE`` that is sensitive (PII or SECRET).

        The DOE formula itself is sensitivity-agnostic: a clean field can be
        over-exposed. Enforcement, however, only fires on sensitive
        over-exposure. This helper is the bridge from the formal model to the
        Rego policy's ``PII + external/llm ⇒ VIOLATION`` rule.
        """
        return frozenset(f for f in self.d_oe if f.sensitivity.is_sensitive)

    def __iter__(self) -> Iterator[Field]:  # convenience: iterate D_OE
        return iter(self.d_oe)


def classify(sets: DOESets) -> DOEResult:
    """Compute ``D_OE = (D_trans \\ (D_nec ∪ D_int)) ∩ D_total``.

    A field is over-exposed iff **all** of:

    * it was delivered to the sink (in ``D_trans``), and
    * it originated at the source (in ``D_total``), and
    * it was **not** strictly necessary for the sink (not in ``D_nec``), and
    * it was **not** intended by the user (not in ``D_int``).

    The intersection with ``D_total`` is what scopes the violation to data the
    agent actually retrieved; sink-internal fields the user never saw are
    excluded even if they appear in ``D_trans``.
    """
    allowed = sets.d_nec | sets.d_int
    excess = sets.d_trans - allowed
    d_oe = excess & sets.d_total
    return DOEResult(
        d_total=sets.d_total,
        d_trans=sets.d_trans,
        d_int=sets.d_int,
        d_nec=sets.d_nec,
        d_oe=_frozen(d_oe),
    )


def sensitive_fields(fields: Iterable[Field]) -> frozenset[Field]:
    """Filter to the sensitive members of an iterable of fields."""
    return _frozen(f for f in fields if f.sensitivity.is_sensitive)