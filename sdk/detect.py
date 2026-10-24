"""Sensitive-data detection for the AgentWard SDK.

Two detection families:

* **PII** via `presidio-analyzer` (regex + spaCy NER): SSN, email, phone,
  credit card, person names, etc.
* **Secrets** via custom recognizers: AWS access keys, GitHub tokens, and a
  generic high-entropy API-key heuristic, so the demo breach-simulator can
  inject a credential, not just an SSN.

Output is a :class:`TaintLabel` carrying only sensitivity *classes* and a
short non-reversible **fingerprint** of the matched value, never the value
itself. The fingerprint lets the lineage map correlate the same secret across
spans without re-storing it.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from typing import Iterable, Mapping

from core.doe import Sensitivity
from sdk.recognizers_extra import EXTRA_SECRET_TYPES, build_extra_recognizers
from sdk.taint import TaintLabel

# ---------------------------------------------------------------------------
# Secret recognizers (Presidio PatternRecognizer instances).
# ---------------------------------------------------------------------------

try:
    from presidio_analyzer import Pattern, PatternRecognizer
except ImportError:  # presidio optional for unit testing of detect's pure helpers
    Pattern = None  # type: ignore[assignment]
    PatternRecognizer = None  # type: ignore[assignment]

# Sensitivity mapping for Presidio built-in entity types.
_PII_TYPES = {
    "USA_SSN", "EMAIL_ADDRESS", "PHONE_NUMBER", "US_BANK_NUMBER",
    "CREDIT_CARD", "IBAN_CODE", "IP_ADDRESS", "US_DRIVER_LICENSE",
    "LOCATION", "PERSON", "DATE_TIME", "URL", "IN_AADHAAR", "IN_PAN",
}


def fingerprint(value: str) -> str:
    """Short, non-reversible sha256 fingerprint of a matched value."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]


def _build_secret_recognizers():
    if PatternRecognizer is None:
        return []
    return [
        PatternRecognizer(
            name="AWS_ACCESS_KEY",
            patterns=[Pattern("aws_akia", r"AKIA[0-9A-Z]{16}", 0.95)],
            supported_entity="AWS_ACCESS_KEY",
        ),
        PatternRecognizer(
            name="GITHUB_TOKEN",
            patterns=[Pattern(
                "ghp", r"gh[pousr]_[A-Za-z0-9]{36}", 0.95
            )],
            supported_entity="GITHUB_TOKEN",
        ),
        PatternRecognizer(
            name="GENERIC_API_KEY",
            patterns=[Pattern(
                "generic", r"(?i)(api[_-]?key|secret|token)[\"' :=]{1,4}[A-Za-z0-9_\-]{20,}", 0.5
            )],
            supported_entity="GENERIC_API_KEY",
        ),
    ]


_analyzer = None  # lazily built; expensive (loads spaCy model)


def _get_analyzer():
    """Build (once) and return the Presidio AnalyzerEngine with secrets added.

    Pins the NLP engine to ``en_core_web_sm`` so Presidio does not auto-download
    the 400MB ``en_core_web_lg`` model on first use. The small model is enough
    for our regex + light-NER detection needs; callers wanting stronger NER
    can swap the model here.
    """
    global _analyzer
    if _analyzer is not None:
        return _analyzer
    from presidio_analyzer import AnalyzerEngine  # local import: heavy
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    config = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
    }
    engine = NlpEngineProvider(nlp_configuration=config).create_engine()
    _analyzer = AnalyzerEngine(nlp_engine=engine)
    for rec in _build_secret_recognizers() + build_extra_recognizers():
        _analyzer.registry.add_recognizer(rec)
    return _analyzer


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class Detection:
    """A single detected sensitive span."""

    __slots__ = ("entity_type", "start", "end", "score", "sensitivity", "fingerprint")

    def __init__(self, entity_type: str, start: int, end: int, score: float,
                 sensitivity: Sensitivity, fingerprint: str):
        self.entity_type = entity_type
        self.start = start
        self.end = end
        self.score = score
        self.sensitivity = sensitivity
        self.fingerprint = fingerprint

    @property
    def is_sensitive(self) -> bool:
        return self.sensitivity.is_sensitive

    def __repr__(self) -> str:  # pragma: no cover
        return (f"Detection({self.entity_type}, {self.sensitivity.value}, "
                f"fp={self.fingerprint}, score={self.score:.2f})")


def _classify(entity_type: str) -> Sensitivity:
    """Map a Presidio entity type to a Sensitivity class."""
    if entity_type in {"AWS_ACCESS_KEY", "GITHUB_TOKEN", "GENERIC_API_KEY"} | EXTRA_SECRET_TYPES:
        return Sensitivity.SECRET
    if entity_type in _PII_TYPES:
        return Sensitivity.PII
    # Unknown PII-ish entity from presidio defaults to PII.
    return Sensitivity.PII


# Zero-width / invisible characters someone could slip between the digits of
# an SSN etc. to dodge a plain regex without changing how the text looks when
# rendered.
_ZERO_WIDTH_CHARS = "\u200b\u200c\u200d\u2060\ufeff"

# Characters that are never part of a sensitive value but can end up on the
# edge of a detected span.
_SPAN_EDGE_TRIM = "'\"` \t\r\n"


def _normalize_for_detection(text: str) -> tuple[str, list[int]]:
    """NFKC-fold the text (fullwidth Unicode digits, etc. collapse to plain
    ASCII) and strip zero-width characters, so a homoglyph or an invisible
    character doesn't let sensitive data slip past the regex/NER recognizers.

    Returns the normalized text plus a map from each of its character
    positions back to the matching position in the original text, so
    detection offsets can still be spliced against the original string by
    ``mask_text``/``redact_text`` (NFKC-folding a fullwidth digit is 1:1 on
    length; dropping zero-width characters is what the map is actually for).
    """
    text = unicodedata.normalize("NFKC", text)
    kept_chars: list[str] = []
    position_map: list[int] = []
    for i, ch in enumerate(text):
        if ch in _ZERO_WIDTH_CHARS:
            continue
        kept_chars.append(ch)
        position_map.append(i)
    return "".join(kept_chars), position_map


def detect_text(text: str, *, threshold: float = 0.5) -> list[Detection]:
    """Detect sensitive spans in ``text``. Returns [] if none / on error.

    Presidio is loaded lazily; if the spaCy model is unavailable, returns []
    rather than crashing, so callers (the spike) can still observe chain-level
    taint propagation via baggage even when field detection degrades.
    """
    if not text:
        return []
    normalized, position_map = _normalize_for_detection(text)
    try:
        analyzer = _get_analyzer()
    except Exception:  # spaCy model missing, etc.
        return []
    try:
        results = analyzer.analyze(
            text=normalized,
            language="en",
            score_threshold=threshold,
            return_decision_process=False,
        )
    except Exception:
        return []
    out: list[Detection] = []
    for r in results:
        sens = _classify(r.entity_type)
        if not sens.is_sensitive:
            continue
        # Map normalized-text offsets back to the original text's offsets.
        start = position_map[r.start] if r.start < len(position_map) else len(text)
        if r.end > r.start and r.end - 1 < len(position_map):
            end = position_map[r.end - 1] + 1
        else:
            end = start
        # spaCy NER can pull a neighbouring quote or space into the span
        # ("Alice Lee'" inside a repr), and masking it would eat the quote
        # and break the surrounding JSON. Trim those from both edges.
        while start < end and text[start] in _SPAN_EDGE_TRIM:
            start += 1
        while end > start and text[end - 1] in _SPAN_EDGE_TRIM:
            end -= 1
        if start == end:
            continue
        out.append(Detection(
            entity_type=r.entity_type,
            start=start,
            end=end,
            score=r.score,
            sensitivity=sens,
            fingerprint=fingerprint(text[start:end]),
        ))
    return out


def detect_value(value: object) -> list[Detection]:
    """Detect in a single value (coerced to str)."""
    if value is None or isinstance(value, bool):
        return []
    return detect_text(str(value))


def detect_mapping(payload: Mapping[str, object] | Iterable) -> list[Detection]:
    """Detect across a JSON-like payload (dict / list / scalar)."""
    found: list[Detection] = []
    if isinstance(payload, Mapping):
        for v in payload.values():
            found.extend(detect_mapping(v))
    elif isinstance(payload, (list, tuple)):
        for v in payload:
            found.extend(detect_mapping(v))
    else:
        found.extend(detect_value(payload))
    return found


def taint_for(detections: Iterable[Detection], *, source_span_id: str | None = None) -> TaintLabel:
    """Build a TaintLabel from a set of detections. Empty if nothing sensitive."""
    classes = {d.sensitivity for d in detections if d.is_sensitive}
    # Use the first secret/PII fingerprint for correlation; never the value.
    fp = next((d.fingerprint for d in detections if d.is_sensitive), None)
    return TaintLabel.of(classes, source_span_id=source_span_id, value_fingerprint=fp)


_MASK_TOKEN = {
    Sensitivity.PII: "[PII]",
    Sensitivity.SECRET: "[SECRET]",
}


def mask_text(text: str, detections: Iterable[Detection]) -> str:
    """Replace detected sensitive spans with ``[PII]`` / ``[SECRET]`` tokens.

    Non-reversible masking used when serializing tool I/O onto span attributes,
    so SigNoz never stores raw PII. Phase 4's ``sdk/redact.py`` replaces this
    with destination-aware reversible (FF1) redaction for internal sinks.
    """
    if not text:
        return text
    # Presidio recognizers can overlap (e.g. EMAIL_ADDRESS and URL both firing
    # on "alice@example.com"). Splicing every raw span independently corrupts
    # the output, since a later splice's offsets go stale once an earlier one
    # has already changed the string's length. Dedup first: keep the longest
    # detection per region, same as sdk/redact.py's redact_text.
    sens_dets = sorted(
        (d for d in detections if d.is_sensitive),
        key=lambda d: (d.start, -(d.end - d.start)),
    )
    kept: list = []
    for d in sens_dets:
        if kept and d.start < kept[-1].end:
            continue  # overlaps the previous (longer, same-start) kept span
        kept.append(d)
    out = text
    for d in sorted(kept, key=lambda d: d.start, reverse=True):
        out = out[:d.start] + _MASK_TOKEN.get(d.sensitivity, "[REDACTED]") + out[d.end:]
    return out


def mask_value(value: object) -> object:
    """Mask a single scalar value; leaves structure (dict/list) intact, masking
    leaf strings."""
    if isinstance(value, str):
        return mask_text(value, detect_text(value))
    if isinstance(value, Mapping):
        return {k: mask_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        t = type(value)
        return t(mask_value(v) for v in value)  # type: ignore[call-arg]
    return value