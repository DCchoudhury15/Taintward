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
calls with the placeholders, and Taintward swaps them back:

    model answer -> caller (end user)     real values
    model tool call -> any tool           real values first, then the tool's
                                          normal destination gate runs
                                          (internal: reversible token,
                                          external/log/rag: mask, unless the
                                          argument is in the tool's allow list)

The map (placeholder -> real value) is kept in memory for the run only. It is
never sent anywhere and it is cleared when the run ends. For long-lived
conversations it can be backed by a token vault (``taintward.sdk.vault``), keyed by a
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
import logging
import re
import threading
import unicodedata
from typing import Any, Iterator, Mapping

from taintward.core.doe import Sensitivity

# <PERSON_1>, < PERSON_1 >, <person_1>, &lt;PERSON_1&gt; (HTML-escaped)
PLACEHOLDER_RE = re.compile(
    r"(?:<|&lt;)\s*([A-Za-z][A-Za-z0-9_]*?)_(\d{1,6})\s*(?:>|&gt;)"
)

# Tolerant restore: forms real models write instead of <PERSON_1>. Measured
# with bench/placeholders (see docs/placeholders-eval.md). Three shapes:
#
#   bracketed  [PERSON_1] {PERSON_1} {{PERSON_1}} (PERSON_1) <Person 1>
#              <PERSON-1> \<PERSON\_1\> «PERSON_1» ＜PERSON_1＞ 【PERSON_1】
#   bare       PERSON_1, Person_1, PERSON\_1 (markdown escaped)
#   spaced     Person 1, PERSON 1, Person-1 (only when unambiguous, see
#              PlaceholderMap._spaced_ok)
#
# A form is restored only when it names a placeholder that is in this run's
# map, so text like "[Step 1]" or "Table 2" is never touched.
# Any letters, also full-width and CJK: models translate labels ("<名前_1>").
_WORD = r"[^\W\d_][^\W_]*"
_SEP = r"(?:\\?[_＿]|[ \-])"
_OPEN = r"\\?(?:<|&lt;|\{\{|\[\[|\[|\{|\(|«|‹|〈|《|＜|【|「|『)"
_CLOSE = r"\\?(?:>|&gt;|\}\}|\]\]|\]|\}|\)|»|›|〉|》|＞|】|」|』)"
_TOLERANT_RE = re.compile(
    r"(?P<exact>(?:<|&lt;)\s*(?P<elabel>[A-Za-z][A-Za-z0-9_]*?)_(?P<enum>\d{1,6})\s*(?:>|&gt;))"
    rf"|(?P<open>{_OPEN})[ \t]*(?P<blabel>{_WORD}(?:{_SEP}{_WORD})*?){_SEP}?"
    rf"(?P<bnum>\d{{1,6}})[ \t]*{_CLOSE}"
    rf"|(?<![\w\\])(?P<ulabel>{_WORD}(?:\\?[_＿]{_WORD})*?)\\?[_＿](?P<unum>\d{{1,6}})(?!\w)"
    rf"|(?<![\w\\])(?P<slabel>[A-Za-z]+)[ \-](?P<snum>\d{{1,3}})(?![\w])(?![.,]\d)"
)
# <PERSON> with no number: the model dropped the number (never restored).
_NUMBERLESS_RE = re.compile(r"(?:<|&lt;|\[)\s*([A-Za-z][A-Za-z_]*)\s*(?:>|&gt;|\])")

# Other names models use for a label, mostly from translating the
# placeholder. Used only for the bracketed and bare forms, and only when the
# alias is not itself a label in the map.
_ALIASES = {
    "NAME": "PERSON", "PERSONA": "PERSON", "PERSONNE": "PERSON", "PERSONE": "PERSON",
    "PERSOON": "PERSON", "NOMBRE": "PERSON", "NOM": "PERSON",
    "MAIL": "EMAIL", "E_MAIL": "EMAIL", "CORREO": "EMAIL", "COURRIEL": "EMAIL",
    "TELEFONO": "PHONE", "TELEFON": "PHONE", "TELEPHONE": "PHONE", "TEL": "PHONE",
    "SOZIALVERSICHERUNGSNUMMER": "SSN",
    "TARJETA": "CARD", "CARTE": "CARD", "KARTE": "CARD", "CREDIT_CARD": "CARD",
    # Japanese / Chinese
    "名前": "PERSON", "氏名": "PERSON", "姓名": "PERSON", "名字": "PERSON", "人物": "PERSON",
    "メールアドレス": "EMAIL", "メール": "EMAIL", "电子邮件": "EMAIL", "邮箱": "EMAIL",
    "電話番号": "PHONE", "电话": "PHONE", "电话号码": "PHONE",
}

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

# Labels that look like Taintward placeholders even when this map does not
# have them: an unknown <PHONE_1> is worth a warning, an unknown [Step 1] is not.
_VOCAB = frozenset(set(_LABELS.values()) | set(_ALIASES) | {"SECRET", "PII"})

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

    vault: optional ``taintward.sdk.vault`` backend for long-lived conversations. Only
        the public vault API is used (put/get/delete/forget_subject).
    conversation_id: required with ``vault``; names the conversation whose
        placeholders are stored. It is stored only as a keyed hash.
    ttl: lifetime in seconds of vault entries.
    index_key: secret key for the keyed hashes used in vault keys. Default is
        derived from the FPE key (``taintward.sdk.redact.get_redactor().key``), so vault
        keys do not reveal values or conversation ids.

    Thread safe: frameworks run tools in threads that share the run's map.
    """

    def __init__(self, *, vault: Any = None, conversation_id: str | None = None,
                 ttl: float | None = None, index_key: bytes | None = None,
                 tolerant: bool = True) -> None:
        if vault is not None and not conversation_id:
            raise ValueError("a vault-backed PlaceholderMap needs a conversation_id")
        self._lock = threading.RLock()
        self._by_value: dict[str, str] = {}
        self._by_placeholder: dict[str, _Entry] = {}
        self._counts: dict[str, int] = {}
        self._known_re: re.Pattern | None = None
        self._vault = vault
        self.tolerant = tolerant
        self.conversation_id = conversation_id
        self.ttl = ttl
        if vault is not None:
            if index_key is None:
                from taintward.sdk.redact import get_redactor
                index_key = hmac.new(bytes.fromhex(get_redactor().key),
                                     b"taintward-placeholder-index-v1", hashlib.sha256).digest()
            self._index_key = index_key
            conv = self._hash(conversation_id or "")[:24]
            self._prefix = f"taintward-ph:{conv}:"
            self.subject = f"taintward-conversation:{conversation_id}"
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
        if not isinstance(text, str) or not text:
            return text
        # JSON first: tool call arguments from some servers (Ollama) escape
        # "<" as <, so the raw string has no "<PERSON_1>" in it.
        if text.lstrip()[:1] in ("{", "[") and ("\\u003c" in text or self._might_have(text)):
            try:
                parsed = json.loads(text)
            except ValueError:
                parsed = None
            if isinstance(parsed, (dict, list)):
                restored = self.restore(parsed)
                if restored == parsed:
                    return text  # nothing to restore: keep the original string
                return json.dumps(restored, ensure_ascii=False)
        if not self._might_have(text):
            return text

        if not self.tolerant:
            def sub(m: re.Match) -> str:
                entry = self._entry(_canonical(m))
                return entry.value if entry else m.group(0)

            return PLACEHOLDER_RE.sub(sub, text)

        spaced = self._spaced_ok(text)
        return _TOLERANT_RE.sub(lambda m: self._classify(m, spaced)[0] or m.group(0), text)

    def _might_have(self, text: str) -> bool:
        pattern = _TOLERANT_RE if self.tolerant else PLACEHOLDER_RE
        return pattern.search(text) is not None

    # --- tolerant restore --------------------------------------------------

    def _labels(self) -> set[str]:
        with self._lock:
            return {p[1:-1].rsplit("_", 1)[0] for p in self._by_placeholder}

    def _resolve(self, label: str, num: str, *, alias: bool) -> _Entry | None:
        try:
            n = int(num)
        except ValueError:
            return None
        entry = self._entry(f"<{label}_{n}>")
        if entry is None and alias and label in _ALIASES and label not in self._labels():
            entry = self._entry(f"<{_ALIASES[label]}_{n}>")
        return entry

    def _spaced_ok(self, text: str) -> dict[str, bool]:
        """Per label: may "Person 1" style forms be restored in this text?

        Only when the model never wrote that label as a real placeholder in
        the same text (then "Person 1" is more likely a list number) and every
        "Person N" it wrote is a placeholder of this map."""
        seen: dict[str, bool] = {}
        proper: set[str] = set()
        for m in _TOLERANT_RE.finditer(text):
            if m.group("slabel"):
                label = m.group("slabel").upper()
                known = self._entry(f"<{label}_{int(m.group('snum'))}>") is not None
                seen[label] = seen.get(label, True) and known
            else:
                raw = m.group("elabel") or m.group("blabel") or m.group("ulabel")
                proper.add(_norm_label(raw))
        return {k: ok and k not in proper for k, ok in seen.items()}

    def _classify(self, m: re.Match, spaced: dict[str, bool]) -> tuple[str | None, str]:
        """(real value or None, kind) for one match of _TOLERANT_RE.

        kind: exact, repaired (a rewritten form that was restored), lost (a
        known placeholder in a form that is not safe to restore), unknown (a
        placeholder that is not in the map), or ignore (ordinary text)."""
        if m.group("exact"):
            label, num = m.group("elabel").upper(), m.group("enum")
            entry = self._entry(f"<{label}_{int(num)}>")
            if entry is not None:
                return entry.value, "exact"
            entry = self._resolve(_norm_label(label), num, alias=True)
            if entry is not None:
                return entry.value, "repaired"
            return None, self._unknown_kind(_norm_label(label))
        if m.group("blabel"):
            label = _norm_label(m.group("blabel"))
            entry = self._resolve(label, m.group("bnum"), alias=True)
            if entry is not None:
                return entry.value, "repaired"
            return None, self._unknown_kind(label)
        if m.group("ulabel"):
            raw = m.group("ulabel").replace("\\", "")
            label = _norm_label(raw)
            entry = self._resolve(label, m.group("unum"), alias=True)
            letters = re.sub(r"[^A-Za-z]", "", raw)
            if letters.isupper() or raw.replace("_", " ").istitle():
                if entry is not None:
                    return entry.value, "repaired"
                return None, self._unknown_kind(label)
            # person_1: could be a variable name in code; never restored.
            return None, "lost" if entry is not None else "ignore"
        raw = m.group("slabel")
        label = raw.upper()
        if not (raw.isupper() or raw.istitle()):
            return None, "ignore"
        entry = self._entry(f"<{label}_{int(m.group('snum'))}>")
        if entry is None:
            return None, "ignore"  # "Step 1", "Person 3" in a numbered list
        if spaced.get(label):
            return entry.value, "repaired"
        return None, "lost"

    def _unknown_kind(self, label: str) -> str:
        if label in self._labels() or label in _VOCAB:
            return "unknown"
        return "ignore"

    def diagnose(self, text: str) -> dict[str, list[str]]:
        """What restoring ``text`` (a model answer, before restore) will do.

        Returns lists of placeholder forms (never values):

        * ``repaired``: rewritten forms that tolerant restore fixes,
          for example ``[PERSON_1]`` or ``Person 1``.
        * ``lost``: forms that point at a known placeholder but are not safe
          to restore (``<PERSON>`` with no number, ``person_1`` in lower case,
          ``Person 1`` next to a real ``<PERSON_2>``). The caller gets this
          text as the model wrote it.
        * ``unknown``: placeholders that are not in the map, for example an
          invented ``<PERSON_3>``.
        """
        out: dict[str, list[str]] = {"repaired": [], "lost": [], "unknown": []}
        if not isinstance(text, str) or not text:
            return out
        if not self.tolerant:
            for m in PLACEHOLDER_RE.finditer(text):
                if self._entry(_canonical(m)) is None:
                    label = _norm_label(m.group(1))
                    if self._unknown_kind(label) == "unknown":
                        out["unknown"].append(m.group(0))
        else:
            spaced = self._spaced_ok(text)
            for m in _TOLERANT_RE.finditer(text):
                _, kind = self._classify(m, spaced)
                if kind in out:
                    out[kind].append(m.group(0).strip())
        labels = self._labels()
        for m in _NUMBERLESS_RE.finditer(text):
            if _norm_label(m.group(1)) in labels:
                out["lost"].append(m.group(0))
        return out

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


def _norm_label(raw: str) -> str:
    """'Aws key', 'AWS\\_KEY', full-width 'ＰＥＲＳＯＮ' -> 'AWS_KEY' / 'PERSON'."""
    label = unicodedata.normalize("NFKC", raw).upper()
    return re.sub(r"[\s\-\\_]+", "_", label).strip("_")


# ---------------------------------------------------------------------------
# Run scope
# ---------------------------------------------------------------------------

# The map of the current run. A copied context (LangChain tool threads,
# asyncio tasks) still points at the same map object, so every call in the
# run shares it.
_CURRENT: contextvars.ContextVar[PlaceholderMap | None] = contextvars.ContextVar(
    "taintward_placeholders", default=None
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


# ---------------------------------------------------------------------------
# Helping the model, and checking its answer
# ---------------------------------------------------------------------------

log = logging.getLogger("taintward.sdk")

# Short on purpose: it is added to every request that has placeholders.
INSTRUCTION = (
    "Some values in this conversation were replaced by placeholders: {names}. "
    "Each one stands for a real value the user already gave, so it is not a blank "
    "to fill in and it is safe to repeat. Copy each placeholder exactly as written, "
    "with the angle brackets, wherever you need that value: in text, lists, JSON, "
    "code and tool call arguments. Keep placeholders unchanged when you translate. "
    "Do not invent new placeholders and do not ask for the real values."
)
_INSTRUCTION_MAX = 20  # placeholders named in the instruction


class PlaceholderRestoreError(RuntimeError):
    """Strict mode: the model's answer has placeholders that could not be
    restored. ``lost`` and ``unknown`` hold the placeholder forms (never
    values)."""

    def __init__(self, lost: list[str], unknown: list[str]):
        self.lost, self.unknown = lost, unknown
        super().__init__(
            "model answer has placeholders that could not be restored: "
            + ", ".join((lost + unknown)[:10]))


def placeholders_in(value: Any) -> list[str]:
    """Canonical placeholders found in a request payload, in order of first
    appearance (exact forms only: this is what Taintward itself wrote)."""
    out: dict[str, None] = {}

    def walk(v: Any, depth: int = 0) -> None:
        if depth > 64:
            return
        if isinstance(v, str):
            for m in PLACEHOLDER_RE.finditer(v):
                out.setdefault(_canonical(m), None)
        elif isinstance(v, Mapping):
            for x in v.values():
                walk(x, depth + 1)
        elif isinstance(v, (list, tuple)):
            for x in v:
                walk(x, depth + 1)
        else:
            content = getattr(v, "content", None)  # LangChain messages
            if content is not None:
                walk(content, depth + 1)
            for name in ("tool_calls", "additional_kwargs"):
                if getattr(v, name, None):
                    walk(getattr(v, name), depth + 1)

    walk(value)
    return list(out)


def instruction_for(names: list[str]) -> str:
    """The system line that asks the model to copy ``names`` exactly."""
    shown = names[:_INSTRUCTION_MAX]
    text = ", ".join(shown) + (", ..." if len(names) > len(shown) else "")
    return INSTRUCTION.format(names=text)


def _strings(value: Any, depth: int = 0) -> Iterator[str]:
    if depth > 64:
        return
    if isinstance(value, str):
        if "\\u003c" in value and value.lstrip()[:1] in ("{", "["):
            try:  # JSON tool arguments with an escaped "<" (Ollama)
                yield from _strings(json.loads(value), depth + 1)
                return
            except ValueError:
                pass
        yield value
    elif isinstance(value, Mapping):
        for v in value.values():
            yield from _strings(v, depth + 1)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _strings(v, depth + 1)


def check_output(pmap: PlaceholderMap, raw_output: Any, *, span: Any = None,
                 strict: bool = False) -> dict[str, list[str]]:
    """Check a model answer (the placeholder version, before restore).

    Records ``taintward.placeholders.repaired`` / ``.lost`` / ``.unknown``
    on ``span`` (placeholder forms only, never values), logs a warning when
    something could not be restored, and raises ``PlaceholderRestoreError``
    in strict mode."""
    found: dict[str, list[str]] = {"repaired": [], "lost": [], "unknown": []}
    for s in _strings(raw_output):
        for k, v in pmap.diagnose(s).items():
            found[k].extend(v)
    if span is not None:
        for k, v in found.items():
            if v:
                try:
                    span.set_attribute(f"taintward.placeholders.{k}", list(dict.fromkeys(v))[:20])
                except Exception:  # pragma: no cover - a span that is already ended
                    pass
    if found["lost"] or found["unknown"]:
        log.warning("taintward: model answer has placeholders that could not be restored "
                    "(lost: %s; unknown: %s)", found["lost"][:5], found["unknown"][:5])
        if strict:
            raise PlaceholderRestoreError(found["lost"], found["unknown"])
    return found


__all__ = [
    "PLACEHOLDER_RE", "PlaceholderMap", "KnownSpan", "label_for",
    "current", "activate", "deactivate", "scope", "restore",
    "INSTRUCTION", "PlaceholderRestoreError", "placeholders_in", "instruction_for",
    "check_output",
]
