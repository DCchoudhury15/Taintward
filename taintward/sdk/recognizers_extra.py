"""Extra recognizers used by taintward.sdk.detect.

Two kinds live here:

* Presidio ``PatternRecognizer`` objects for secret types with a fixed,
  self-describing shape (JSON Web Tokens, PEM / OpenSSH private keys). A
  plain pattern is enough and false alarms are very unlikely.
* Small plain-Python "context" recognizers that Presidio cannot express on
  its own, because they need the JSON key of a value or a cleaned-up copy of
  the text: a 9-digit SSN without dashes next to an ``ssn`` key or word,
  digits spaced out one by one (``5 3 6 - 2 2 - 8 4 9 1``), US street
  addresses, and credential-looking values under a key like ``api_key``.

Each context recognizer takes the (normalized) text of one value plus the
words of its JSON key and returns ``(entity_type, start, end, score)``
tuples. They only use the standard library (and ``phonenumbers``, which
Presidio already needs), so they cost microseconds per value.
"""

from __future__ import annotations

import re

try:
    from presidio_analyzer import Pattern, PatternRecognizer
except Exception:  # noqa: BLE001 - presidio missing or broken: regex-only fallback
    Pattern = None  # type: ignore[assignment]
    PatternRecognizer = None  # type: ignore[assignment]

# Secret entity types added here; taintward.sdk.detect classifies them as SECRET.
EXTRA_SECRET_TYPES = frozenset({"JWT", "PRIVATE_KEY"})

# header.payload.signature, base64url. A JWT header and payload are JSON
# objects, so both segments start with "eyJ" (base64 of '{"').
_JWT = r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"

# The BEGIN line, plus the body and END line when they are present. The body
# group is optional so a truncated key (only the header made it into a log
# line) is still caught.
_PEM = (r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"
        r"(?:[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----)?")


# (entity type, pattern name, regex, score), shared with the regex-only
# fallback in taintward.sdk.detect.
EXTRA_PATTERNS: tuple[tuple[str, str, str, float], ...] = (
    ("JWT", "jwt", _JWT, 0.9),
    ("PRIVATE_KEY", "pem_private_key", _PEM, 0.95),
)


def build_extra_recognizers() -> list:
    if PatternRecognizer is None:
        return []
    return [
        PatternRecognizer(
            name="JWT",
            patterns=[Pattern("jwt", _JWT, 0.9)],
            supported_entity="JWT",
        ),
        PatternRecognizer(
            name="PRIVATE_KEY",
            patterns=[Pattern("pem_private_key", _PEM, 0.95)],
            supported_entity="PRIVATE_KEY",
        ),
    ]


# ---------------------------------------------------------------------------
# Context recognizers (plain Python)
# ---------------------------------------------------------------------------

# Words (in the JSON key, or just before the value) that say "this is an SSN".
_SSN_CONTEXT = re.compile(
    r"(?i)(?<![a-z])(?:ssn|ssns|ss#|social[\s_-]*security|tax[\s_-]*id|taxpayer[\s_-]*id)(?![a-z])"
)
_PLAIN_NINE = re.compile(r"(?<![\w-])(\d{3})(\d{2})(\d{4})(?![\w-])")

# How far back (in characters) we look for a context word inside the value.
_CONTEXT_WINDOW = 48


def _valid_ssn(area: str, group: str, serial: str) -> bool:
    return not (area in ("000", "666") or area[0] == "9" or group == "00" or serial == "0000")


def plain_ssn(text: str, key_words: str) -> list[tuple]:
    """A 9-digit number with no dashes, only when the key or nearby text says SSN.

    Without that context a bare 9-digit number is far more likely to be a
    tracking number or an order ID, so it is never flagged on its own.
    """
    out = []
    key_says_ssn = bool(key_words) and _SSN_CONTEXT.search(key_words) is not None
    for m in _PLAIN_NINE.finditer(text):
        if not _valid_ssn(*m.groups()):
            continue
        if key_says_ssn or _SSN_CONTEXT.search(text, max(0, m.start() - _CONTEXT_WINDOW), m.start()):
            out.append(("US_SSN", m.start(), m.end(), 0.6))
    return out


# Digits written one by one with spaces (and maybe " - ") between them.
_SPACED_HINT = re.compile(r"\d {1,3}\d")
_SPACED_RUN = re.compile(r"(?<![\w+])(?:\+ ?)?\d(?:(?: {1,3}- {1,3}| {1,3})\d){8,18}(?![\w])")
_SPACED_SSN = re.compile(r"(\d{3})-(\d{2})-(\d{4})")
_SPACED_PHONE = re.compile(r"\+\d{1,3}(?: \d{1,5}){1,4}|\d{3}-\d{3}-\d{4}")


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _collapse_spaced(run: str) -> str:
    run = re.sub(r" {1,3}- {1,3}", "-", run)
    run = re.sub(r" {2,}", "\x00", run)  # a wide gap stays a (single) space
    return run.replace(" ", "").replace("\x00", " ")


def _phone_ok(candidate: str) -> bool:
    try:
        import phonenumbers
    except ImportError:  # pragma: no cover - presidio depends on it
        return False
    try:
        num = phonenumbers.parse(candidate, "US")
    except phonenumbers.NumberParseException:
        return False
    return phonenumbers.is_valid_number(num)


def spaced_digits(text: str, key_words: str) -> list[tuple]:
    """Catch an SSN, card or phone number typed with a space between every digit.

    The run is collapsed back to its normal form and only accepted when that
    form passes a real check: SSN area/group/serial rules, a Luhn checksum for
    cards, a valid number for phones. So a plain list like "1 2 3 4 5 6 7 8 9"
    is not flagged.
    """
    if not _SPACED_HINT.search(text):
        return []
    out = []
    for m in _SPACED_RUN.finditer(text):
        flat = _collapse_spaced(m.group(0))
        ssn = _SPACED_SSN.fullmatch(flat)
        digits = re.sub(r"\D", "", flat)
        if ssn and _valid_ssn(*ssn.groups()):
            out.append(("US_SSN", m.start(), m.end(), 0.6))
        elif flat.isdigit() and 13 <= len(flat) <= 19 and _luhn_ok(flat):
            out.append(("CREDIT_CARD", m.start(), m.end(), 0.6))
        elif _SPACED_PHONE.fullmatch(flat) and _phone_ok(flat):
            out.append(("PHONE_NUMBER", m.start(), m.end(), 0.6))
        elif len(digits) == 9 and plain_ssn(digits, key_words or text[:m.start()][-_CONTEXT_WINDOW:]):
            out.append(("US_SSN", m.start(), m.end(), 0.6))
    return out


_STREET_SUFFIX = (r"(?:St|Street|Ave|Avenue|Rd|Road|Blvd|Boulevard|Dr|Drive|Ln|Lane|Way|Ct|"
                  r"Court|Pl|Place|Ter|Terrace|Pkwy|Parkway|Hwy|Highway|Cir|Circle|Sq|Square)")
_STREET = re.compile(
    r"\b\d{1,6}(?: [A-Z][a-zA-Z]+){1,4} " + _STREET_SUFFIX + r"\b\.?"
    r"(?:,? (?:Apt|Suite|Unit|Ste)\.? ?#?\w+)?"
    r"(?:, [A-Z][a-zA-Z]+(?: [A-Z][a-zA-Z]+){0,2})?"
    r"(?:, [A-Z]{2})?"
    r"(?: \d{5}(?:-\d{4})?)?"
)


_STREET_HINT = re.compile(r"\d [A-Z]")


def street_address(text: str, key_words: str) -> list[tuple]:
    """US-style street address: number, capitalized street name, street type,
    then optional unit, city, state and ZIP. Case-sensitive on purpose, so
    "3 main st" in a log line is left alone."""
    if not _STREET_HINT.search(text):
        return []
    return [("STREET_ADDRESS", m.start(), m.end(), 0.7) for m in _STREET.finditer(text)]


# A key whose value is a credential no matter what it looks like.
_SECRET_KEY = re.compile(
    r"(?i)(?:api[\s_-]?key|apikey|secret|passwd|password|pwd|private[\s_-]?key|"
    r"credential|access[\s_-]?key|auth[\s_-]?token|access[\s_-]?token|refresh[\s_-]?token|"
    r"bearer|(?<![a-z])token(?![a-z]))"
)
_CREDENTIAL_SHAPE = re.compile(r"[A-Za-z0-9_\-+/=.~:]{16,}")
_PASSWORD_KEY = re.compile(r"(?i)passw(?:or)?d|(?<![a-z])pwd(?![a-z])")


def keyed_secret(text: str, key_words: str) -> list[tuple]:
    """A value stored under a key such as ``api_key``, ``client_secret``,
    ``password`` or ``gh_token``. The key is the evidence; the value only has
    to look like a credential (16+ token characters with both letters and
    digits). Passwords are flagged whatever their shape, as long as they are
    a single word."""
    if not key_words or _SECRET_KEY.search(key_words) is None:
        return []
    value = text.strip()
    if not value:
        return []
    start = text.index(value)
    end = start + len(value)
    if (_PASSWORD_KEY.search(key_words) and " " not in value and len(value) >= 4
            and len(set(value)) > 2):
        return [("GENERIC_API_KEY", start, end, 0.6)]
    if (_CREDENTIAL_SHAPE.fullmatch(value) and any(c.isdigit() for c in value)
            and any(c.isalpha() for c in value)):
        return [("GENERIC_API_KEY", start, end, 0.6)]
    return []


# Keys that the context recognizers above react to.
KEY_PATTERNS = (_SSN_CONTEXT, _SECRET_KEY)

# Run for every value (key_words may be "").
CONTEXT_RECOGNIZERS = (plain_ssn, spaced_digits, street_address, keyed_secret)

# Entity types the context recognizers can produce, with their Sensitivity
# class as a string ("pii" / "secret"); detect.py maps them.
CONTEXT_TYPES = {"US_SSN": "pii", "CREDIT_CARD": "pii", "PHONE_NUMBER": "pii",
                 "STREET_ADDRESS": "pii", "GENERIC_API_KEY": "secret"}

# Extra context words for Presidio's built-in recognizers, by entity type.
# Presidio matches a context word as a substring of a nearby word, so "tel"
# here also covers "tel:" and "tel_no".
EXTRA_CONTEXT = {
    "PHONE_NUMBER": ["tel", "contact", "whatsapp", "fax", "sms"],
}
