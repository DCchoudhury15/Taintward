"""Extra secret recognizers registered by sdk.detect.

Small, high-precision regexes for two secret types the base set missed
completely in the benchmark (bench/run_detection.py): JSON Web Tokens and
PEM / OpenSSH private keys. Both have a fixed, self-describing shape, so a
plain pattern is enough and false alarms are very unlikely.
"""

from __future__ import annotations

try:
    from presidio_analyzer import Pattern, PatternRecognizer
except ImportError:  # presidio optional for unit testing of detect's pure helpers
    Pattern = None  # type: ignore[assignment]
    PatternRecognizer = None  # type: ignore[assignment]

# Secret entity types added here; sdk.detect classifies them as SECRET.
EXTRA_SECRET_TYPES = frozenset({"JWT", "PRIVATE_KEY"})

# header.payload.signature, base64url. A JWT header and payload are JSON
# objects, so both segments start with "eyJ" (base64 of '{"').
_JWT = r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"

# The BEGIN line, plus the body and END line when they are present. The body
# group is optional so a truncated key (only the header made it into a log
# line) is still caught.
_PEM = (r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"
        r"(?:[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----)?")


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
