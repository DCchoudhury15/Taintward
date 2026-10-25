"""Plain-regex recognizers for when Presidio cannot be used at all.

``taintward.sdk.detect`` normally gets its pattern recognizers from Presidio. If
Presidio (or the spaCy it imports) fails to load, detection must not fall to
nothing, so these small standard-library recognizers take over: SSN, email,
credit card (Luhn), phone, IBAN (mod 97), IPv4, plus every secret pattern
the SDK knows. They are less exact than Presidio's, but they keep masking,
redaction and taint working.

Each object has the parts of a Presidio recognizer that ``taintward.sdk.detect``
uses: ``supported_entities``, ``context``, ``is_loaded``, ``load()`` and
``analyze(text, entities, nlp_artifacts)``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable

from taintward.sdk.recognizers_extra import _luhn_ok, _phone_ok, _valid_ssn


@dataclass(frozen=True)
class _Result:
    entity_type: str
    start: int
    end: int
    score: float


class RegexRecognizer:
    """One entity type found with one or more regexes and an optional check."""

    def __init__(self, entity: str, patterns: Iterable[tuple[str, float]], *,
                 context: Iterable[str] = (), check: Callable[[str], bool] | None = None):
        self.name = f"fallback_{entity.lower()}"
        self.supported_entities = [entity]
        self.context = list(context)
        self.is_loaded = True
        self._patterns = [(re.compile(rx), score) for rx, score in patterns]
        self._check = check

    def load(self) -> None:
        return None

    def analyze(self, text: str, entities=None, nlp_artifacts=None) -> list[_Result]:
        out = []
        ent = self.supported_entities[0]
        for rx, score in self._patterns:
            for m in rx.finditer(text):
                if m.start() == m.end():
                    continue
                if self._check is not None and not self._check(m.group(0)):
                    continue
                out.append(_Result(ent, m.start(), m.end(), score))
        return out


def _ssn_ok(s: str) -> bool:
    d = re.sub(r"\D", "", s)
    return len(d) == 9 and _valid_ssn(d[:3], d[3:5], d[5:])


def _card_ok(s: str) -> bool:
    d = re.sub(r"\D", "", s)
    return 13 <= len(d) <= 19 and _luhn_ok(d)


def _iban_ok(s: str) -> bool:
    v = s.replace(" ", "").upper()
    if len(v) < 15:
        return False
    v = v[4:] + v[:4]
    try:
        n = int("".join(str(int(c, 36)) for c in v))
    except ValueError:
        return False
    return n % 97 == 1


def _phone_check(s: str) -> bool:
    try:
        import phonenumbers  # noqa: F401
    except Exception:  # noqa: BLE001 - no phonenumbers: accept the shape
        return True
    return _phone_ok(s)


def build_fallback_recognizers(secret_patterns: Iterable[tuple[str, str, str, float]]) -> list:
    """The regex-only recognizer set. ``secret_patterns`` are the
    ``(entity, name, regex, score)`` tuples from ``taintward.sdk.detect`` and
    ``taintward.sdk.recognizers_extra``."""
    recs = [
        RegexRecognizer("US_SSN", [(r"(?<![\w-])\d{3}[- .]\d{2}[- .]\d{4}(?![\w-])", 0.85)],
                        context=["ssn", "social", "security"], check=_ssn_ok),
        RegexRecognizer("EMAIL_ADDRESS",
                        [(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b",
                          1.0)]),
        RegexRecognizer("CREDIT_CARD", [(r"(?<![\w-])\d(?:[ -]?\d){12,18}(?![\w-])", 1.0)],
                        check=_card_ok),
        RegexRecognizer("PHONE_NUMBER", [
            (r"(?<![\w+])(?:\+?1[ .-]?)?(?:\(\d{3}\)|\d{3})[ .-]?\d{3}[ .-]\d{4}(?!\w)", 0.6),
            (r"(?<!\w)\+\d{1,3}(?:[ .-]?\d{2,5}){2,4}(?!\w)", 0.6),
        ], context=["phone", "tel", "mobile", "cell"], check=_phone_check),
        RegexRecognizer("IBAN_CODE",
                        [(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b", 1.0)],
                        check=_iban_ok),
        RegexRecognizer("IP_ADDRESS", [(
            r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])",
            0.6)]),
    ]
    by_type: dict[str, list[tuple[str, float]]] = {}
    for etype, _name, rx, score in secret_patterns:
        by_type.setdefault(etype, []).append((rx, score))
    recs += [RegexRecognizer(etype, pats) for etype, pats in by_type.items()]
    return recs
