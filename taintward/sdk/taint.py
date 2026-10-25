"""Taint label + OpenTelemetry baggage propagation.

The taint tag is a compact, **non-sensitive** descriptor that rides with data
through the OTel pipeline. It NEVER carries the secret value, only:

    taint.id      a uuid identifying the taint origin
    taint.classes comma-joined sensitivity classes (e.g. ``pii,secret``)
    taint.level   coarse severity (``low`` | ``medium`` | ``high``)
    taint.source  span id (16 hex chars) of the span that first found the data

Two propagation layers (see docs/agentraft-mapping.md section D, the core novelty):

1. **Call-chain taint (baggage).** A value-independent flag: "this execution
   chain has touched sensitive data." Because it isn't tied to the secret's
   surface form, it survives any LLM transformation by construction, even if
   the LLM reformats, abbreviates, or paraphrases the value, the chain is
   still flagged.

2. **Field-level taint (detection re-fire).** Every tool input/output is
   re-scanned by ``taintward.sdk.detect``; specific fields carrying detectable PII get
   labeled. This survives reformatting *iff* the PII stays detectable.

The chain-level tag is a **safe over-approximation**: a PII-touched chain
reaching an external/LLM sink is a violation even when the specific field
can't be pinpointed after the transformation. The residual gap is PII
transformed into a non-detectable form that nonetheless "leaks" semantically,
and that's exactly where AgentRaft's Φ (LLM-judged semantic dependency) would
be needed as a Phase 6 fall-back. The LLM-hop spike (``spike/llm_hop.py``)
demonstrates this.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Mapping

from opentelemetry import baggage

from taintward.core.doe import Sensitivity

logger = logging.getLogger("taintward.sdk")

# Baggage keys (W3C baggage is a flat string→string map; keep keys short).
KEY_ID = "taint.id"
KEY_CLASSES = "taint.classes"
KEY_LEVEL = "taint.level"
KEY_SOURCE = "taint.source"
BAGGAGE_KEYS = (KEY_ID, KEY_CLASSES, KEY_LEVEL, KEY_SOURCE)

# Span attribute prefixes (materialized on spans for SigNoz filtering).
ATTR_ID = "taintward.taint.id"
ATTR_CLASSES = "taintward.taint.classes"
ATTR_LEVEL = "taintward.taint.level"
ATTR_SENSITIVE = "taintward.sensitive"  # boolean, for cheap SigNoz filters


class TaintLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @classmethod
    def from_classes(cls, classes: Iterable[Sensitivity]) -> "TaintLevel":
        """Derive a coarse level from the set of sensitivity classes.

        SECRET ⇒ high; PII ⇒ medium; otherwise low.
        """
        s = set(classes)
        if Sensitivity.SECRET in s:
            return cls.HIGH
        if Sensitivity.PII in s:
            return cls.MEDIUM
        return cls.LOW


@dataclass(frozen=True)
class TaintLabel:
    """The non-sensitive taint descriptor that propagates through OTel.

    ``source_span_id`` is the span that first found the sensitive data, for
    lineage. It rides in baggage so the span that reaches a sink can name
    where the data came from. ``value_fingerprint``
    is an optional short hash of the secret for correlation only, never the
    secret itself.
    """

    id: str
    classes: frozenset[Sensitivity]
    level: TaintLevel
    source_span_id: str | None = None
    value_fingerprint: str | None = None

    @classmethod
    def of(
        cls,
        classes: Iterable[Sensitivity],
        *,
        source_span_id: str | None = None,
        value_fingerprint: str | None = None,
        id: str | None = None,
    ) -> "TaintLabel":
        classes_f = frozenset(c for c in classes if c.is_sensitive)
        return cls(
            id=id or uuid.uuid4().hex,
            classes=classes_f,
            level=TaintLevel.from_classes(classes_f),
            source_span_id=source_span_id,
            value_fingerprint=value_fingerprint,
        )

    @property
    def is_tainted(self) -> bool:
        return bool(self.classes)

    def merge(self, other: "TaintLabel | None") -> "TaintLabel":
        """Merge two labels: union the classes, keep the higher level, keep
        the earliest id (origin) for lineage."""
        if other is None or not other.is_tainted:
            return self
        if not self.is_tainted:
            return other
        merged_classes = self.classes | other.classes
        return TaintLabel(
            id=self.id,  # keep origin
            classes=merged_classes,
            level=TaintLevel.from_classes(merged_classes),
            source_span_id=self.source_span_id or other.source_span_id,
            value_fingerprint=self.value_fingerprint or other.value_fingerprint,
        )

    # --- baggage (de)serialization ---

    def to_baggage(self) -> Mapping[str, str]:
        """Encode as W3C baggage entries. Never includes the secret."""
        if not self.is_tainted:
            return {}
        bag = {
            KEY_ID: self.id,
            KEY_CLASSES: ",".join(sorted(c.value for c in self.classes)),
            KEY_LEVEL: self.level.value,
        }
        if self.source_span_id:
            bag[KEY_SOURCE] = self.source_span_id
        return bag

    @classmethod
    def from_baggage(
        cls, bag: Mapping[str, str] | None
    ) -> "TaintLabel | None":
        """Decode a taint label from a baggage map, or ``None`` if absent.

        Resilient to malformed baggage (a version-skewed peer, a hand-edited
        header, transport corruption): an unrecognized class token is
        dropped individually rather than invalidating the whole label, and
        an unrecognized/missing level falls back to the level derived from
        the (validated) classes instead of raising. This module's "safe
        over-approximation" policy (see module docstring) means corrupt
        input must never silently erase real taint or crash the caller --
        either would defeat the enforcement this label exists for.
        """
        if not bag:
            return None
        if KEY_CLASSES not in bag:
            return None
        classes_seen: set[Sensitivity] = set()
        for c in str(bag[KEY_CLASSES]).split(","):
            if not c:
                continue
            try:
                classes_seen.add(Sensitivity(c))
            except ValueError:
                logger.warning(
                    "taint.from_baggage: dropping unrecognized taint class %r", c
                )
        classes = frozenset(classes_seen)
        if not classes:
            return None
        try:
            level = TaintLevel(bag[KEY_LEVEL])
        except (KeyError, ValueError):
            level = TaintLevel.from_classes(classes)
        return cls(
            id=bag.get(KEY_ID, uuid.uuid4().hex),
            classes=classes,
            level=level,
            source_span_id=_span_id(bag.get(KEY_SOURCE)),
        )

    # --- span attributes ---

    def to_span_attrs(self) -> Mapping[str, str | bool]:
        """Materialize the taint as span attributes for SigNoz filtering."""
        if not self.is_tainted:
            return {ATTR_SENSITIVE: False}
        return {
            ATTR_SENSITIVE: True,
            ATTR_ID: self.id,
            ATTR_CLASSES: ",".join(sorted(c.value for c in self.classes)),
            ATTR_LEVEL: self.level.value,
        }


def _span_id(value) -> str | None:
    """A 16-hex-char span id from baggage, or None (baggage is not trusted)."""
    if isinstance(value, str) and len(value) == 16:
        try:
            int(value, 16)
            return value.lower()
        except ValueError:
            pass
    return None


def attach(label: TaintLabel, context=None):
    """Attach a taint label to the OTel context as baggage.

    Returns the new context. Use ``context_api.attach(ctx)`` to make it
    current, or pass it to ``start_as_current_span(context=...)``.
    """
    from opentelemetry import context as context_api

    ctx = context if context is not None else context_api.get_current()
    for k, v in label.to_baggage().items():
        ctx = baggage.set_baggage(k, v, context=ctx)
    return ctx


def current(context=None) -> TaintLabel | None:
    """Read the taint label from the current (or given) OTel context."""
    from opentelemetry import context as context_api

    ctx = context if context is not None else context_api.get_current()
    return TaintLabel.from_baggage(baggage.get_all(ctx))