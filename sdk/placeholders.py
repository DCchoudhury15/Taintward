"""Consistent placeholders for the LLM, and restore on the way back.

The problem with masks: when the model gets ``[PII]`` it cannot do its job.
"Write to [PII] about her tax form" has lost who the letter is for, and two
different people both become ``[PII]``.

Placeholders fix that. Every sensitive value sent to the LLM is replaced by a
typed, numbered, stable placeholder::

    "Alice Lee"            -> <PERSON_1>
    "234-12-1234"          -> <SSN_1>
    "AKIAIOSFODNN7EXAMPLE" -> <AWS_KEY_1>
    "bob@example.com"      -> <EMAIL_1>

Within one run (one conversation) the same value always gets the same
placeholder and different values get different numbers, so the model can
still reason about "who is who". The model writes its answer and its tool
calls with the placeholders, and AgentWard swaps them back:

    model answer -> caller (end user)     real values
    model tool call -> any tool           real values first, then the tool's
                                          normal destination gate runs
                                          (internal: reversible token,
                                          external/log/rag: mask, unless the
                                          argument is in the tool's allow list)

The map (placeholder -> real value) is kept in memory for the run only. It is
never sent anywhere and it is cleared when the run ends. For long-lived
conversations it can be backed by a token vault (``sdk.vault``), keyed by a
conversation id; the vault entries are tagged with a subject so one call to
``forget_conversation()`` erases them.

``PlaceholderMap.find_known`` also lets the redactor redact a value the map
already knows even when the detector misses it in a new context (for example
a bare name in a tool argument), so restoring never lets a known value slip
past the gate.
"""

from __future__ import annotations

import contextlib
import contextvars
import hashlib
import hmac
import json
import re
import threading
from typing import Any, Iterator, Mapping

from core.doe import Sensitivity

# <PERSON_1>, < PERSON_1 >, <person_1>, &lt;PERSON_1&gt; (HTML-escaped)
PLACEHOLDER_RE = re.compile(
    r"(?:<|&lt;)\s*([A-Za-z][A-Za-z0-9_]*?)_(\d{1,6})\s*(?:>|&gt;)"
)

# Detector entity type -> short placeholder label.
_LABELS = {
    "PERSON": "PERSON",
    "US_SSN": "SSN",
    "USA_SSN": "SSN",
    "EMAIL_ADDRESS": "EMAIL",
    "PHONE_NUMBER": "PHONE",
    "AWS_ACCESS_KEY": "AWS_KEY",
    "GITHUB_TOKEN": "GITHUB_TOKEN",
    "GENERIC_API_KEY": "API_KEY",
    "CREDIT_CARD": "CARD",
    "IBAN_CODE": "IBAN",
    "IP_ADDRESS": "IP",
    "US_BANK_NUMBER": "BANK_ACCOUNT",
    "US_DRIVER_LICENSE": "DRIVER_LICENSE",
    "US_PASSPORT": "PASSPORT",
    "LOCATION": "LOCATION",
    "DATE_TIME": "DATE",
    "URL": "URL",
    "ORGANIZATION": "ORG",
    "IN_AADHAAR": "AADHAAR",
    "IN_PAN": "PAN",
}

_LABEL_SAFE = re.compile(r"[^A-Z0-9]+")

# Known values shorter than this are not force-redacted by find_known: a two
# letter value would match inside too many unrelated words.
_MIN_KNOWN_LEN = 3


def label_for(entity_type: str | None, sensitivity: Sensitivity) -> str:
    """Placeholder label for a detector entity type, e.g. US_SSN -> SSN."""
    if entity_type and entity_type in _LABELS:
        return _LABELS[entity_type]
    if entity_type:
        safe = _LABEL_SAFE.sub("_", entity_type.upper()).strip("_")
        if safe:
            return safe
    return "SECRET" if sensitivity == Sensitivity.SECRET else "PII"


class KnownSpan:
    """A detection-shaped span for a value the map already knows."""

    __slots__ = ("entity_type", "start", "end", "score", "sensitivity")

    def __init__(self, entity_type: str, start: int, end: int, sensitivity: Sensitivity):
        self.entity_type = entity_type
        self.start = start
        self.end = end
        self.score = 1.0
        self.sensitivity = sensitivity

    @property
    def is_sensitive(self) -> bool:
        return self.sensitivity.is_sensitive

    def __repr__(self) -> str:  # pragma: no cover
        return f"KnownSpan({self.entity_type}, {self.start}:{self.end})"


class _Entry:
    __slots__ = ("value", "entity_type", "sensitivity")

    def __init__(self, value: str, entity_type: str, sensitivity: Sensitivity):
        self.value = value
        self.entity_type = entity_type
        self.sensitivity = sensitivity


class PlaceholderMap:
    """Placeholder <-> real value map for one run (one conversation).

    vault: optional ``sdk.vault`` backend for long-lived conversations. Only
        the public vault API is used (put/get/delete/forget_subject).
    conversation_id: required with ``vault``; names the conversation whose
        placeholders are stored. It is stored only as a keyed hash.
    ttl: lifetime in seconds of vault entries.
    index_key: secret key for the keyed hashes used in vault keys. Default is
        derived from the FPE key (``sdk.redact.get_redactor().key``), so vault
        keys do not reveal values or conversation ids.

    Thread safe: frameworks run tools in threads that share the run's map.
    """

    def __init__(self, *, vault: Any = None, conversation_id: str | None = None,
                 ttl: float | None = None, index_key: bytes | None = None) -> None:
        if vault is not None and not conversation_id:
            raise ValueError("a vault-backed PlaceholderMap needs a conversation_id")
        self._lock = threading.RLock()
        self._by_value: dict[str, str] = {}
        self._by_placeholder: dict[str, _Entry] = {}
        self._counts: dict[str, int] = {}
        self._known_re: re.Pattern | None = None
        self._vault = vault
        self.conversation_id = conversation_id
        self.ttl = ttl
        if vault is not None:
            if index_key is None:
                from sdk.redact import get_redactor
                index_key = hmac.new(bytes.fromhex(get_redactor().key),
                                     b"agentward-placeholder-index-v1", hashlib.sha256).digest()
            self._index_key = index_key
            conv = self._hash(conversation_id or "")[:24]
            self._prefix = f"agentward-ph:{conv}:"
            self.subject = f"agentward-conversation:{conversation_id}"
        else:
            self._index_key = b""
            self._prefix = ""
            self.subject = None

    # --- vault helpers -----------------------------------------------------

    def _hash(self, s: str) -> str:
        return hmac.new(self._index_key, s.encode(), hashlib.sha256).hexdigest()

    def _vput(self, key: str, value: str) -> None:
        self._vault.put(self._prefix + key, value, ttl=self.ttl, subject=self.subject)

    def _vget(self, key: str) -> str | None:
        return self._vault.get(self._prefix + key)

    def _load(self, placeholder: str) -> _Entry | None:
        """Read one placeholder entry from the vault into memory."""
        raw = self._vget("p:" + placeholder)
        if raw is None:
            return None
        try:
            rec = json.loads(raw)
            entry = _Entry(rec["v"], rec.get("t", ""), Sensitivity(rec.get("s", "pii")))
        except (ValueError, KeyError, TypeError):
            return None
        self._remember(placeholder, entry)
        return entry

    def _remember(self, placeholder: str, entry: _Entry) -> None:
        self._by_placeholder[placeholder] = entry
        self._by_value.setdefault(entry.value, placeholder)
        self._known_re = None

    # --- public API --------------------------------------------------------

    def placeholder_for(self, value: str, entity_type: str | None = None,
                        sensitivity: Sensitivity = Sensitivity.PII) -> str:
        """The stable placeholder for ``value``; a new one if it is unseen."""
        with self._lock:
            ph = self._by_value.get(value)
            if ph is not None:
                return ph
            if self._vault is not None:
                ph = self._vget("i:" + self._hash(value))
                if ph is not None and self._load(ph) is not None:
                    return ph
            label = label_for(entity_type, sensitivity)
            n = self._counts.get(label)
            if n is None and self._vault is not None:
                try:
                    n = int(self._vget("n:" + label) or 0)
                except ValueError:
                    n = 0
            n = (n or 0) + 1
            ph = f"<{label}_{n}>"
            while ph in self._by_placeholder:  # never reuse a number
                n += 1
                ph = f"<{label}_{n}>"
            self._counts[label] = n
            entry = _Entry(value, entity_type or "", sensitivity)
            self._remember(ph, entry)
            if self._vault is not None:
                self._vput("p:" + ph, json.dumps(
                    {"v": value, "t": entity_type or "", "s": sensitivity.value}))
                self._vput("i:" + self._hash(value), ph)
                self._vput("n:" + label, str(n))
            return ph

    def lookup(self, placeholder: str) -> str | None:
        """Real value for a placeholder (any spacing/case variant), or None."""
        m = PLACEHOLDER_RE.fullmatch(placeholder.strip())
        if not m:
            return None
        entry = self._entry(_canonical(m))
        return entry.value if entry else None

    def _entry(self, canonical: str) -> _Entry | None:
        with self._lock:
            entry = self._by_placeholder.get(canonical)
            if entry is None and self._vault is not None:
                entry = self._load(canonical)
            return entry

    def find_known(self, text: str) -> list[KnownSpan]:
        """Spans of values this map already knows, found by exact match.

        Used together with the detector so a known value is redacted even
        where the detector would miss it (for example a bare name)."""
        if not text:
            return []
        with self._lock:
            if self._known_re is None:
                vals = sorted((v for v in self._by_value if len(v) >= _MIN_KNOWN_LEN),
                              key=len, reverse=True)
                if not vals:
                    return []
                alt = "|".join(re.escape(v) for v in vals)
                self._known_re = re.compile(rf"(?<![0-9A-Za-z])(?:{alt})(?![0-9A-Za-z])")
            pattern = self._known_re
            entries = {v: self._by_placeholder[p] for v, p in self._by_value.items()}
        out = []
        for m in pattern.finditer(text):
            e = entries.get(m.group(0))
            if e is not None:
                out.append(KnownSpan(e.entity_type, m.start(), m.end(), e.sensitivity))
        return out

    def restore_text(self, text: str) -> str:
        """Swap every known placeholder in ``text`` for its real value.

        Unknown placeholders (for example ones the model invented) are left as
        they are. A string that is a JSON object or array (tool call
        arguments) is restored inside the parsed JSON, so a real value with a
        quote or backslash stays valid JSON."""
        if not isinstance(text, str) or not PLACEHOLDER_RE.search(text):
            return text
        stripped = text.strip()
        if stripped[:1] in ("{", "["):
            try:
                parsed = json.loads(text)
            except ValueError:
                parsed = None
            if isinstance(parsed, (dict, list)):
                return json.dumps(self.restore(parsed), ensure_ascii=False)

        def sub(m: re.Match) -> str:
            entry = self._entry(_canonical(m))
            return entry.value if entry else m.group(0)

        return PLACEHOLDER_RE.sub(sub, text)

    def restore(self, value: Any) -> Any:
        """Restore placeholders in a str / dict / list / tuple (a new object)."""
        if isinstance(value, str):
            return self.restore_text(value)
        if isinstance(value, Mapping):
            return {k: self.restore(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.restore(v) for v in value]
        if isinstance(value, tuple):
            return tuple(self.restore(v) for v in value)
        return value

    def restore_inplace(self, obj: Any, _depth: int = 0) -> Any:
        """Restore placeholders inside a provider response object.

        Dicts and lists are changed in place, pydantic models (OpenAI and
        Anthropic SDK responses) get their fields set. Returns the object, or
        a new value for str/tuple."""
        if _depth > 64:
            return obj
        if isinstance(obj, str):
            return self.restore_text(obj)
        if isinstance(obj, dict):
            for k, v in list(obj.items()):
                new = self.restore_inplace(v, _depth + 1)
                if new is not v:
                    obj[k] = new
            return obj
        if isinstance(obj, list):
            for i, v in enumerate(obj):
                new = self.restore_inplace(v, _depth + 1)
                if new is not v:
                    obj[i] = new
            return obj
        if isinstance(obj, tuple):
            return tuple(self.restore_inplace(v, _depth + 1) for v in obj)
        if hasattr(type(obj), "model_fields"):  # pydantic v2 model
            fields = dict(getattr(obj, "__dict__", {}))
            extra = getattr(obj, "__pydantic_extra__", None) or {}
            for name, v in list(fields.items()) + list(extra.items()):
                new = self.restore_inplace(v, _depth + 1)
                if new is not v:
                    try:
                        setattr(obj, name, new)
                    except Exception:
                        try:
                            object.__setattr__(obj, name, new)
                        except Exception:
                            pass
        return obj

    def placeholders(self) -> list[str]:
        """The placeholders issued so far (never the values)."""
        with self._lock:
            return list(self._by_placeholder)

    def __len__(self) -> int:
        return len(self._by_placeholder)

    def __contains__(self, placeholder: object) -> bool:
        return isinstance(placeholder, str) and self.lookup(placeholder) is not None

    def clear(self) -> None:
        """Drop the in-memory map (vault entries, if any, are kept)."""
        with self._lock:
            self._by_value.clear()
            self._by_placeholder.clear()
            self._counts.clear()
            self._known_re = None

    def forget_conversation(self) -> int:
        """Erase this conversation's placeholders from memory and the vault."""
        self.clear()
        if self._vault is None or self.subject is None:
            return 0
        return self._vault.forget_subject(self.subject)

    def __repr__(self) -> str:  # never print values
        return f"PlaceholderMap({len(self)} placeholders)"


def _canonical(m: re.Match) -> str:
    return f"<{m.group(1).upper()}_{int(m.group(2))}>"


# ---------------------------------------------------------------------------
# Run scope
# ---------------------------------------------------------------------------

# The map of the current run. A copied context (LangChain tool threads,
# asyncio tasks) still points at the same map object, so every call in the
# run shares it.
_CURRENT: contextvars.ContextVar[PlaceholderMap | None] = contextvars.ContextVar(
    "agentward_placeholders", default=None
)


def current() -> PlaceholderMap | None:
    """The placeholder map of the current run, or None outside a run."""
    return _CURRENT.get()


def activate(pmap: PlaceholderMap) -> contextvars.Token:
    """Make ``pmap`` the current map. Pair with ``deactivate``."""
    return _CURRENT.set(pmap)


def deactivate(token: contextvars.Token) -> None:
    """End the scope started by ``activate``: clear the map and unset it."""
    pmap = _CURRENT.get()
    try:
        _CURRENT.reset(token)
    except ValueError:  # reset from another context
        _CURRENT.set(None)
    if pmap is not None:
        pmap.clear()


@contextlib.contextmanager
def scope(pmap: PlaceholderMap | None = None) -> Iterator[PlaceholderMap]:
    """``with scope() as pmap:`` one placeholder map for the block."""
    pmap = pmap if pmap is not None else PlaceholderMap()
    tok = activate(pmap)
    try:
        yield pmap
    finally:
        deactivate(tok)


def restore(value: Any, pmap: PlaceholderMap | None = None) -> Any:
    """Restore placeholders with ``pmap`` (default: the current run's map).

    Use it for output the adapters do not restore themselves, for example
    text you collected from a stream."""
    pmap = pmap if pmap is not None else current()
    return pmap.restore(value) if pmap is not None else value


__all__ = [
    "PLACEHOLDER_RE", "PlaceholderMap", "KnownSpan", "label_for",
    "current", "activate", "deactivate", "scope", "restore",
]
