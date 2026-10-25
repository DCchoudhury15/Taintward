"""Destination-aware redaction: the Phase 4 standout feature.

The real "context-aware" redaction: the *same* sensitive value is treated
differently depending on where it is going, because Phase 2/3 taint tracking
followed where the data actually travels (not a static field-name mask).

    internal sink        -> format-preserving REVERSIBLE token
                            (the internal store can still use/correlate a value
                            of the same shape/length without holding raw PII;
                            the token reverses back to the original)
    external / llm / log -> non-reversible [PII] / [SECRET] mask
                            (the value must not leave, and cannot be recovered
                            from what is stored)
    rag                  -> mask (embeddings are invertible, OWASP LLM08:2025)

Placeholder mode (``placeholders=`` a ``taintward.sdk.placeholders.PlaceholderMap``):
the ``llm`` destination gets a typed, numbered placeholder such as
``<PERSON_1>`` instead of the mask, stable within the map, so the model can
still tell values apart. Every other destination is unchanged, but values the
map already knows are redacted even where the detector misses them.

Implementation: FF1 format-preserving encryption (NIST SP 800-38G, see
taintward/sdk/ff1.py) makes the token (same length, digits stay digits, separators kept
in place). A pluggable vault (taintward/sdk/vault.py) maps token -> exact original so
reversal is exact even where FPE alone cannot be (letter case is not kept in a
radix-36 token). Values too short for FF1's minimum domain size
(radix**len >= 1,000,000, so fewer than 6 digits or 4 letters/digits) are
masked instead of tokenized.

Keys (details in docs/redaction-crypto.md):
    TAINTWARD_FPE_KEY        hex AES key (32/48/64 hex chars). Keep it secret.
    TAINTWARD_FPE_KEY_ID     optional label stored with each token in the vault
    TAINTWARD_ALLOW_DEMO_KEY =1 to use the built-in demo key (demos only)
If no key is set and the demo key is not allowed, a random key is generated
once per process and a warning is logged: tokens then differ after a restart.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import string
import warnings
from typing import Mapping

from taintward.core.doe import Sensitivity
from taintward.sdk import _walk
from taintward.sdk.destinations import DEST_INTERNAL, DEST_LLM
from taintward.sdk.ff1 import FF1
from taintward.sdk.vault import MemoryVault, Vault, get_vault

log = logging.getLogger("taintward.redact")

# Reversible redaction is only for trusted internal sinks. Everything else
# (external/llm/log/rag) gets a non-reversible mask.
_REVERSIBLE_SINKS = {DEST_INTERNAL}

_MASK_TOKEN = {
    Sensitivity.PII: "[PII]",
    Sensitivity.SECRET: "[SECRET]",
}

# Public demo key. Only used when TAINTWARD_ALLOW_DEMO_KEY=1. Never in production.
_DEMO_KEY = "EF4359D8D580AA4F7F036D6F04FB771B"
_TWEAK_DOMAIN = b"taintward-ff1-v1"

_ALPHA_RE = re.compile(r"[0-9A-Za-z]")

_PROCESS_KEY: str | None = None  # random fallback key, generated once per process


def _resolve_key(key_hex: str | None) -> str:
    """Explicit key > TAINTWARD_FPE_KEY > demo key (opt-in) > random per process."""
    global _PROCESS_KEY
    key = key_hex or os.environ.get("TAINTWARD_FPE_KEY")
    if key:
        return key.strip()
    if os.environ.get("TAINTWARD_ALLOW_DEMO_KEY") == "1":
        log.warning("taintward: using the PUBLIC demo FPE key (TAINTWARD_ALLOW_DEMO_KEY=1). "
                    "Do not use this outside demos.")
        return _DEMO_KEY
    if _PROCESS_KEY is None:
        _PROCESS_KEY = os.urandom(32).hex()
        msg = ("taintward: TAINTWARD_FPE_KEY is not set; generated a random per-process "
               "FPE key. Tokens will NOT be stable across restarts or between processes. "
               "Set TAINTWARD_FPE_KEY for real use.")
        log.warning(msg)
        warnings.warn(msg, RuntimeWarning, stacklevel=3)
    return _PROCESS_KEY


def _radix_for(s: str) -> int | None:
    """Pick the FF1 radix for the alphabet chars in s, or None if there are none."""
    alpha = _ALPHA_RE.findall(s)
    if not alpha:
        return None
    if all(c in string.digits for c in alpha):
        return 10
    return 36  # _ALPHA_RE only matches 0-9A-Za-z


def _layout(s: str) -> str:
    """Shape of s: d=digit, a=lowercase, A=uppercase, other chars kept as is.

    It goes into the FF1 tweak, so values that differ only in letter case or
    digit/letter layout get different tokens instead of colliding (the cipher
    sees letters lowercased). For digit-only values the layout can be rebuilt
    from the token itself, which keeps the vault-miss fallback working.
    """
    out = []
    for c in s:
        if c in string.digits:
            out.append("d")
        elif "a" <= c <= "z":
            out.append("a")
        elif "A" <= c <= "Z":
            out.append("A")
        else:
            out.append(c)
    return "".join(out)


class Redactor:
    """Destination-aware redactor: reversible FPE token for internal, mask elsewhere.

    vault: where token -> original is kept. Default comes from TAINTWARD_VAULT
        (MemoryVault when unset).
    structural_fallback: when the vault has no entry, try to decrypt a
        digit-only token with the key. Default: on for MemoryVault (tokens
        from another process can still be reversed), off for persistent
        vaults, so that deleting a vault entry (GDPR erasure) really makes the
        token unreversible through this API.
    ttl: optional lifetime in seconds for vault entries.
    """

    def __init__(self, key_hex: str | None = None, tweak_hex: str | None = None, *,
                 vault: Vault | None = None, structural_fallback: bool | None = None,
                 ttl: float | None = None, key_id: str | None = None):
        self.key = _resolve_key(key_hex)
        try:
            key = bytes.fromhex(self.key)
        except ValueError:
            raise ValueError("TAINTWARD_FPE_KEY must be hex") from None
        if len(key) not in (16, 24, 32):
            raise ValueError("TAINTWARD_FPE_KEY must be 32, 48 or 64 hex chars")
        self.key_id = (key_id or os.environ.get("TAINTWARD_FPE_KEY_ID")
                       or "k" + hashlib.sha256(b"taintward-key-id" + key).hexdigest()[:8])
        self.tweak = bytes.fromhex(tweak_hex) if tweak_hex else b""
        self._ciphers = {10: FF1(key, 10), 36: FF1(key, 36)}
        self._vault: Vault = vault if vault is not None else get_vault()
        if structural_fallback is None:
            structural_fallback = isinstance(self._vault, MemoryVault)
        self.structural_fallback = structural_fallback
        self.ttl = ttl

    @property
    def vault(self) -> Vault:
        return self._vault

    def _tweak_for(self, radix: int, layout: str) -> bytes:
        return b"|".join([_TWEAK_DOMAIN, self.tweak, str(radix).encode(), layout.encode()])

    def _fpe_encrypt(self, s: str) -> str | None:
        """Format-preserving encrypt: alphabet chars -> same-length token chars,
        separators kept in place. Output letters are lowercase (radix 36 uses
        0-9a-z). Returns None if s can't be FPE'd (no alphabet chars, or fewer
        than FF1's minimum length for the radix: 6 digits / 4 alnum)."""
        radix = _radix_for(s)
        if radix is None:
            return None
        cipher = self._ciphers[radix]
        positions = [m.start() for m in _ALPHA_RE.finditer(s)]
        if len(positions) < cipher.min_len:
            return None  # below the FF1 domain-size floor: caller masks it
        alpha = "".join(s[i] for i in positions).lower()
        enc = cipher.encrypt(alpha, self._tweak_for(radix, _layout(s)))
        result = list(s)
        for n, idx in enumerate(positions):
            result[idx] = enc[n]
        return "".join(result)

    def _fpe_decrypt(self, token: str) -> str | None:
        """Reverse _fpe_encrypt structurally, without the vault.

        Only for digit-only (radix 10) tokens: an alnum token's original
        letter case and digit/letter layout are in the tweak and cannot be
        read back from the token, so we refuse rather than guess.

        Not airtight: a radix-36 value can, by chance, encrypt to an all-digit
        token. This fallback would then decrypt it with the radix-10 cipher
        and return a wrong value. The vault is the source of truth; this
        path only exists for tokens from another process with a MemoryVault.
        """
        if _radix_for(token) != 10:
            return None
        positions = [m.start() for m in _ALPHA_RE.finditer(token)]
        cipher = self._ciphers[10]
        if len(positions) < cipher.min_len:
            return None
        alpha = "".join(token[i] for i in positions)
        try:
            dec = cipher.decrypt(alpha, self._tweak_for(10, _layout(token)))
        except ValueError:
            return None
        result = list(token)
        for n, idx in enumerate(positions):
            result[idx] = dec[n]
        return "".join(result)

    # --- public API ---

    def redact_value(self, value: str, sensitivity: Sensitivity,
                     destination: str, *, subject: str | None = None) -> str:
        """Redact one value for a destination.

        internal -> reversible FPE token (vaulted for exact reversal; falls
        back to a mask if FPE can't handle the value, e.g. too short); any
        other sink -> non-reversible mask. ``subject`` (optional, e.g. a user
        id) tags the vault entry so forget_subject() can erase it later.
        """
        if not sensitivity.is_sensitive or not value:
            return value
        if destination in _REVERSIBLE_SINKS:
            token = self._fpe_encrypt(value)
            if token is not None:
                existing = self._vault.get(token)
                if existing is None or existing == value:
                    self._vault.put(token, value, ttl=self.ttl, subject=subject,
                                    key_id=self.key_id)
                    return token
                # Token already maps to a different original (two values with
                # a different layout landed on the same string). Never
                # overwrite: that would make the older token reverse wrongly.
                log.warning("taintward: FPE token collision, masking value instead")
        return _MASK_TOKEN.get(sensitivity, "[REDACTED]")

    def redact_text(self, text: str, detections, destination: str, *,
                    subject: str | None = None, placeholders=None) -> str:
        """Apply redaction to each detected span in text (right-to-left).

        Overlapping detections (e.g. AWS_ACCESS_KEY and GENERIC_API_KEY on the
        same region) are deduped to the longest per region so the output is
        well-formed regardless of how many recognizers match. For spans of the
        same length a SECRET wins over PII, then the higher score.

        ``placeholders`` (a PlaceholderMap): for the ``llm`` destination each
        span becomes its stable placeholder (``<SSN_1>``) instead of a mask.
        """
        if not text:
            return text
        sens = [d for d in detections if d.is_sensitive]
        # Keep the longest detection at any point; drop spans overlapping a
        # longer, already-kept span.
        sens.sort(key=lambda x: (x.start, -(x.end - x.start),
                                 x.sensitivity != Sensitivity.SECRET,
                                 -float(getattr(x, "score", 0.0) or 0.0)))
        kept: list = []
        for d in sens:
            if kept and d.start < kept[-1].end:
                continue  # overlaps the previous (longer, same-start) kept span
            kept.append(d)
        out = text
        for d in sorted(kept, key=lambda x: x.start, reverse=True):
            original = text[d.start:d.end]
            if placeholders is not None and destination == DEST_LLM:
                redacted = placeholders.placeholder_for(
                    original, getattr(d, "entity_type", None), d.sensitivity)
            else:
                redacted = self.redact_value(original, d.sensitivity, destination,
                                             subject=subject)
            out = out[:d.start] + redacted + out[d.end:]
        return out

    def reverse(self, token: str) -> str | None:
        """Reverse an internal-sink FPE token to the exact original.

        Returns None for masks or unknown tokens. Masks are non-reversible by
        construction, that's the whole point of the external/llm/log path.
        """
        if token in _MASK_TOKEN.values():
            return None
        original = self._vault.get(token)
        if original is not None:
            return original
        if self.structural_fallback:
            return self._fpe_decrypt(token)  # digit-only tokens only
        return None

    def forget(self, token: str) -> bool:
        """Erase one token mapping from the vault."""
        return self._vault.delete(token)

    def forget_subject(self, subject: str) -> int:
        """GDPR erasure: delete every vault mapping tagged with this subject.

        With structural_fallback on (the MemoryVault default), digit-only
        tokens can still be decrypted by anyone holding the FPE key, so
        erasure is only complete with structural_fallback off (the default for
        persistent vaults).
        """
        return self._vault.forget_subject(subject)

    def is_reversible(self, destination: str) -> bool:
        return destination in _REVERSIBLE_SINKS


# Module-level singleton used by the SDK egress gate.
_DEFAULT: Redactor | None = None


def get_redactor() -> Redactor:
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = Redactor()
    return _DEFAULT


def redact_value(value, sensitivity, destination, *, subject=None) -> str:
    return get_redactor().redact_value(value, sensitivity, destination, subject=subject)


def redact_text(text, detections, destination, *, subject=None, placeholders=None) -> str:
    return get_redactor().redact_text(text, detections, destination, subject=subject,
                                      placeholders=placeholders)


def _is_key_to_scan(k) -> bool:
    return isinstance(k, (str, int, float)) and not isinstance(k, bool)


def _redact_walk(value, destination: str, r: "Redactor", subject, placeholders):
    from taintward.sdk.detect import detect_text, safe_str

    if isinstance(value, str):
        ds = detect_text(value)
        if placeholders is not None:
            ds = list(ds) + list(placeholders.find_known(value))
        if any(d.is_sensitive for d in ds):
            return r.redact_text(value, ds, destination, subject=subject,
                                 placeholders=placeholders)
        return value
    if isinstance(value, Mapping):
        def key(k):
            if not _is_key_to_scan(k):
                return k
            return _redact_walk(k, destination, r, subject, placeholders)
        return _walk.rebuild_mapping(value, _walk.unique_keys(
            (k, key(k), _redact_walk(v, destination, r, subject, placeholders))
            for k, v in value.items()))
    if _walk.is_collection(value):
        return _walk.rebuild_collection(
            value, [_redact_walk(v, destination, r, subject, placeholders) for v in value])
    if _walk.is_scalar_leaf(value):
        return value
    # int, float, Decimal, bytes, any object: check its str form. A sensitive
    # value is replaced by the redacted string, never passed on unchanged.
    text = safe_str(value)
    if text is None:
        return "[REDACTED]"  # cannot be checked, so it cannot be passed on
    redacted = _redact_walk(text, destination, r, subject, placeholders)
    return value if redacted == text else redacted


def redact_payload(value, destination: str, redactor: "Redactor | None" = None, *,
                   subject: str | None = None, placeholders=None):
    """Recursively redact sensitive values in a structured payload for the
    given destination. Non-sensitive values and structure are preserved. Used
    by the SDK egress gate on tool input args.

    * Containers: dict (and dict subclasses such as OrderedDict), list,
      tuple, namedtuple, set and frozenset keep their type; other Mapping /
      Sequence types become a dict / list.
    * Dict keys are redacted like values. When two redacted keys come out the
      same, a numeric suffix keeps them apart (``[PII]``, ``[PII]_2``).
    * Leaves that are not strings (int, float, Decimal, any object) are
      checked in their ``str`` form; a sensitive one is replaced by the
      redacted string (a mask, or a token for ``internal``). None and
      booleans are kept.
    * Outside a ``detection_scope`` the whole payload is detected first in
      one pass, so JSON keys count as context (``{"ssn": 234121234}``).

    ``placeholders`` (a ``taintward.sdk.placeholders.PlaceholderMap``, optional): the
    ``llm`` destination gets stable placeholders instead of masks, and for
    every destination the values the map already knows are redacted even
    where the detector does not find them.
    """
    from taintward.sdk import detect as _detect

    r = redactor or get_redactor()
    if ((isinstance(value, Mapping) or _walk.is_collection(value))
            and not _detect.in_detection_scope()):
        with _detect.detection_scope():
            _detect.detect_leaves(value)
            return _redact_walk(value, destination, r, subject, placeholders)
    return _redact_walk(value, destination, r, subject, placeholders)
