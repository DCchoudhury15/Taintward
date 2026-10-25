"""Sensitive-data detection for the AgentWard SDK.

Two detection families:

* **PII** via `presidio-analyzer` recognizers (regex + checksums) and spaCy
  NER: SSN, email, phone, credit card, person names, places, etc.
* **Secrets** via custom recognizers: AWS access keys, GitHub tokens, JWTs,
  private keys and a generic API-key heuristic, so the demo breach-simulator
  can inject a credential, not just an SSN.

Output is a :class:`Detection` list carrying only sensitivity *classes* and a
short non-reversible **fingerprint** of the matched value, never the value
itself. The fingerprint lets the lineage map correlate the same secret across
spans without re-storing it.

How it stays fast (numbers in docs/benchmark.md):

* Presidio's ``AnalyzerEngine.analyze`` is not called per value. The pattern
  recognizers run directly, once over all the values of a payload joined
  together, and spaCy runs with only its NER step, only on values that have
  a capitalized word in them (IDs, numbers and lower-case notes skip it).
* Context words ("ssn", "phone", ...) are looked up with a cheap regex in a
  short window before each match and in the JSON key of the value, instead of
  Presidio's lemma-based context step, which is slow on long text.
* Results are cached per value (keyed by a hash, so the cache never holds the
  raw text), and inside one tool call (``detection_scope``) every later
  lookup of the same value reuses the first result.

Entity types that fire on almost everything (``DATE_TIME``, ``ORGANIZATION``,
``URL``, ``NRP``, ``MEDICAL_LICENSE``) are not treated as sensitive by
default. ``AGENTWARD_PII_EXTRA_TYPES=DATE_TIME,URL`` (or
:func:`set_pii_types`) turns any of them back on.
"""

from __future__ import annotations

import bisect
import contextlib
import contextvars
import hashlib
import os
import re
import threading
import unicodedata
from collections import OrderedDict
from typing import Iterable, Iterator, Mapping

from core.doe import Sensitivity
from sdk.recognizers_extra import (
    CONTEXT_RECOGNIZERS,
    EXTRA_CONTEXT,
    EXTRA_SECRET_TYPES,
    KEY_PATTERNS,
    build_extra_recognizers,
)
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
    "USA_SSN", "US_SSN", "EMAIL_ADDRESS", "PHONE_NUMBER", "US_BANK_NUMBER",
    "CREDIT_CARD", "IBAN_CODE", "IP_ADDRESS", "US_DRIVER_LICENSE",
    "LOCATION", "PERSON", "STREET_ADDRESS", "IN_AADHAAR", "IN_PAN",
}

_SECRET_TYPES = frozenset({"AWS_ACCESS_KEY", "GITHUB_TOKEN", "GENERIC_API_KEY"}) | EXTRA_SECRET_TYPES

_EXACT_SECRET_TYPES = frozenset({"AWS_ACCESS_KEY", "GITHUB_TOKEN", "JWT", "PRIVATE_KEY"})

# Types that are NOT counted as sensitive unless turned back on. On the
# benchmark they made up most false alarms: DATE_TIME fired on plain integer
# IDs, zip codes and timestamps, ORGANIZATION on UUIDs and words like "SSN",
# URL on the domain inside every email address, MEDICAL_LICENSE on git SHAs.
NOISE_TYPES_DEFAULT = frozenset({"DATE_TIME", "ORGANIZATION", "URL", "NRP", "MEDICAL_LICENSE"})


def _env_types(name: str) -> frozenset:
    raw = os.environ.get(name, "")
    return frozenset(t.strip().upper() for t in raw.split(",") if t.strip())


_noise_types = NOISE_TYPES_DEFAULT - _env_types("AGENTWARD_PII_EXTRA_TYPES")


def set_pii_types(*, enable: Iterable[str] = (), disable: Iterable[str] = ()) -> frozenset:
    """Choose which noisy entity types count as PII.

    ``enable`` turns types such as ``DATE_TIME`` or ``URL`` back on (they then
    taint like any other PII); ``disable`` stops a type from counting. Returns
    the resulting set of ignored types. Clears the detection cache.
    """
    global _noise_types
    _noise_types = (_noise_types - {t.upper() for t in enable}) | {t.upper() for t in disable}
    clear_cache()
    return _noise_types


def ignored_types() -> frozenset:
    """Entity types currently not treated as sensitive."""
    return _noise_types


def fingerprint(value: str) -> str:
    """Short, non-reversible sha256 fingerprint of a matched value."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]


def _build_secret_recognizers():
    if PatternRecognizer is None:
        return []
    return [
        PatternRecognizer(
            name="AWS_ACCESS_KEY",
            # AKIA = long-lived key, ASIA = temporary (STS) key.
            patterns=[Pattern("aws_akia", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}", 0.95)],
            supported_entity="AWS_ACCESS_KEY",
        ),
        PatternRecognizer(
            name="GITHUB_TOKEN",
            patterns=[
                Pattern("ghp", r"gh[pousr]_[A-Za-z0-9]{36}", 0.95),
                # Fine-grained personal access token: github_pat_<22>_<59>.
                Pattern("github_pat", r"github_pat_[A-Za-z0-9]{20,}_[A-Za-z0-9]{40,}", 0.95),
            ],
            supported_entity="GITHUB_TOKEN",
        ),
        PatternRecognizer(
            name="GENERIC_API_KEY",
            patterns=[
                Pattern("generic",
                        r"(?i)(api[_-]?key|secret|token)[\"' :=]{1,4}[A-Za-z0-9_\-]{20,}", 0.5),
                # Stripe-style and Slack-style prefixed keys.
                Pattern("prefixed", r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}", 0.9),
                Pattern("slack", r"\bxox[abprs]-[A-Za-z0-9-]{10,}", 0.9),
                Pattern("bearer", r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}", 0.6),
            ],
            supported_entity="GENERIC_API_KEY",
        ),
    ]


_analyzer = None  # lazily built; expensive (loads spaCy model)
_analyzer_lock = threading.Lock()


def _get_analyzer():
    """Build (once) and return the Presidio AnalyzerEngine with secrets added.

    Pins the NLP engine to ``en_core_web_sm`` so Presidio does not auto-download
    the 400MB ``en_core_web_lg`` model on first use. The small model is enough
    for our regex + light-NER detection needs; callers wanting stronger NER
    can swap the model here.

    The engine is still the source of the recognizers and of the spaCy model,
    but ``detect_text`` does not call ``analyze`` on it (see the module doc).
    """
    global _analyzer
    if _analyzer is not None:
        return _analyzer
    with _analyzer_lock:
        if _analyzer is not None:
            return _analyzer
        from presidio_analyzer import AnalyzerEngine  # local import: heavy
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        config = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        }
        engine = NlpEngineProvider(nlp_configuration=config).create_engine()
        analyzer = AnalyzerEngine(nlp_engine=engine)
        for rec in _build_secret_recognizers() + build_extra_recognizers():
            analyzer.registry.add_recognizer(rec)
        _analyzer = analyzer
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
    """Map a detector entity type to a Sensitivity class."""
    if entity_type in _SECRET_TYPES:
        return Sensitivity.SECRET
    if entity_type in _noise_types:
        return Sensitivity.CLEAN
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


def _normalize_for_detection(text: str) -> tuple[str, list[int] | None]:
    """NFKC-fold the text (fullwidth Unicode digits, etc. collapse to plain
    ASCII) and strip zero-width characters, so a homoglyph or an invisible
    character doesn't let sensitive data slip past the regex/NER recognizers.

    Returns the normalized text plus a map from each of its character
    positions back to the matching position in the original text, so
    detection offsets can still be spliced against the original string by
    ``mask_text``/``redact_text``. The map is ``None`` when the text is
    plain ASCII (nothing to fold, offsets are the same).

    Each character is folded on its own, so a character that NFKC expands
    (a ligature such as U+FB01 "fi") still maps back to its own position.
    """
    if text.isascii():
        return text, None
    kept_chars: list[str] = []
    position_map: list[int] = []
    for i, ch in enumerate(text):
        if ch in _ZERO_WIDTH_CHARS:
            continue
        folded = unicodedata.normalize("NFKC", ch) if ord(ch) > 127 else ch
        for c in folded:
            kept_chars.append(c)
            position_map.append(i)
    return "".join(kept_chars), position_map


# ---------------------------------------------------------------------------
# The fast engine
# ---------------------------------------------------------------------------

# Values are joined with this separator so each recognizer runs once per
# payload. A NUL is not a word character or whitespace, so regexes do not run
# across it; any match that still crosses a boundary is dropped and the
# recognizer is re-run on the values involved.
_SEP = "\n\x00\n"

# spaCy only runs on text that has at least one capitalized word.
_CAPITALIZED = re.compile(r"[A-Z\u00C0-\u00DE][a-z\u00DF-\u00FF]")

_SPACY_TO_PRESIDIO = {
    "PER": "PERSON", "PERSON": "PERSON", "LOC": "LOCATION", "GPE": "LOCATION",
    "ORG": "ORGANIZATION", "DATE": "DATE_TIME", "TIME": "DATE_TIME", "NORP": "NRP",
}
_NER_SCORE = 0.85

# Long text is fed to spaCy in windows of this many characters, overlapping
# so an entity on a window edge is still seen whole by one of them.
_NER_WINDOW = 4000
_NER_OVERLAP = 200
_NER_SEP = "\n\n"

# Presidio's context step, done cheaply: the last few words before a match.
_CONTEXT_WORD = re.compile(r"[A-Za-z][A-Za-z0-9#]*")
_CONTEXT_CHARS = 64
_CONTEXT_WORDS = 5
_CONTEXT_BOOST = 0.35
_CONTEXT_MIN = 0.4

_PHONE_HINT = re.compile(r"(?:\d\D{0,3}){7}")

try:
    import regex as _presidio_re  # the regex module Presidio compiles patterns with
    from presidio_analyzer import PatternRecognizer as _PatternRecognizer
    from presidio_analyzer.pattern_recognizer import (
        REGEX_TIMEOUT_SECONDS as _REGEX_TIMEOUT,
    )
except ImportError:  # pragma: no cover - presidio missing
    _PatternRecognizer = None  # type: ignore[assignment]
    _REGEX_TIMEOUT = None

_PERSON_BAD = re.compile(r"[\d_=@/\\:<>{}\[\]]")


class _Segment:
    """One string value being analyzed, with its JSON key (may be "")."""

    __slots__ = ("text", "key", "norm", "pmap", "results")

    def __init__(self, text: str, key: str):
        self.text = text
        self.key = key
        self.norm, self.pmap = _normalize_for_detection(text)
        self.results: list[tuple] = []  # (entity_type, start, end, score, context_words)


def _best_score(rec, has_context: bool) -> float:
    """Highest score a recognizer can ever give a match. A plain pattern
    recognizer with only weak patterns (US bank numbers at 0.05, passports
    at 0.1) never reaches 0.5 even after the context boost, so it can be
    skipped. Anything with its own validation (checksums) can reach 1.0."""
    if (_PatternRecognizer is None or type(rec).analyze is not _PatternRecognizer.analyze
            or type(rec).validate_result is not _PatternRecognizer.validate_result
            or not getattr(rec, "patterns", None)):
        return 1.0
    best = max(p.score for p in rec.patterns)
    if has_context:
        best = min(1.0, max(best + _CONTEXT_BOOST, _CONTEXT_MIN))
    return best


class _Engine:
    """Runs Presidio's recognizers without ``AnalyzerEngine.analyze``."""

    def __init__(self, analyzer) -> None:
        from presidio_analyzer.predefined_recognizers import SpacyRecognizer

        self.nlp = analyzer.nlp_engine.nlp["en"]
        keep = {"tok2vec", "ner"}
        self.ner_disable = [p for p in self.nlp.pipe_names if p not in keep]
        recs = analyzer.registry.get_recognizers(language="en", all_fields=True)
        self.pattern_recs = []
        for r in recs:
            if isinstance(r, SpacyRecognizer):
                continue
            if not r.is_loaded:
                r.load()
                r.is_loaded = True
            ctx = [w.lower() for w in (r.context or [])]
            for ent in r.supported_entities:
                ctx += EXTRA_CONTEXT.get(ent, [])
            self.pattern_recs.append((r, list(r.supported_entities), tuple(dict.fromkeys(ctx)),
                                      _best_score(r, bool(ctx))))
        self.all_context = frozenset(c for _, _, ctx, _ in self.pattern_recs for c in ctx)

    # -- pattern recognizers -------------------------------------------------
    @staticmethod
    def _join(segs: list[_Segment]) -> tuple[str, list[int]]:
        starts: list[int] = []
        pos = 0
        for s in segs:
            starts.append(pos)
            pos += len(s.norm) + len(_SEP)
        return _SEP.join(s.norm for s in segs), starts

    @staticmethod
    def _match(rec, text: str) -> list[tuple[str, int, int, float]]:
        """Run one recognizer. Plain PatternRecognizers are run here, with the
        same regexes and validation as Presidio but without its per-call
        remove_duplicates (quadratic in the number of hits on long text)."""
        if _PatternRecognizer is not None and type(rec).analyze is _PatternRecognizer.analyze:
            flags = rec.global_regex_flags
            ent = rec.supported_entities[0]
            out = []
            for pat in rec.patterns:
                if not pat.compiled_regex or pat.compiled_with_flags != flags:
                    pat.compiled_with_flags = flags
                    pat.compiled_regex = _presidio_re.compile(pat.regex, flags=flags)
                try:
                    for m in pat.compiled_regex.finditer(text, timeout=_REGEX_TIMEOUT):
                        start, end = m.span()
                        if start == end:
                            continue
                        cur = text[start:end]
                        score = pat.score
                        valid = rec.validate_result(cur)
                        if valid is not None:
                            score = 1.0 if valid else 0.0
                        if rec.invalidate_result(cur):
                            score = 0.0
                        if score > 0:
                            out.append((ent, start, end, score))
                except TimeoutError:
                    continue
            return out
        found = rec.analyze(text=text, entities=list(rec.supported_entities), nlp_artifacts=None)
        return [(r.entity_type, r.start, r.end, r.score) for r in found or ()]

    def run_patterns(self, segs: list[_Segment], threshold: float = 0.5) -> None:
        if not segs:
            return
        noise = _noise_types
        joined_all = None
        joined_digits = None
        for rec, ents, ctx, best in self.pattern_recs:
            if all(e in noise for e in ents):
                continue  # this recognizer only finds ignored types
            if best < threshold:
                continue  # can never reach the threshold, even with context
            if "PHONE_NUMBER" in ents:
                # The phone matcher is the slowest recognizer; only give it
                # values that have 7+ digits close together.
                if joined_digits is None:
                    dsegs = [s for s in segs if _PHONE_HINT.search(s.norm)]
                    joined_digits = (dsegs, *self._join(dsegs))
                group, text, starts = joined_digits
            else:
                if joined_all is None:
                    joined_all = (segs, *self._join(segs))
                group, text, starts = joined_all
            if not group:
                continue
            try:
                found = self._match(rec, text)
            except Exception:
                continue
            redo: set[int] = set()
            for etype, a, b, score in found:
                i = bisect.bisect_right(starts, a) - 1
                seg = group[i]
                s0 = starts[i]
                if b - s0 > len(seg.norm):
                    # Crossed into the next value: run this recognizer again
                    # on each value involved, on its own.
                    redo.add(i)
                    redo.update(range(i + 1, min(len(group), bisect.bisect_right(starts, b))))
                    continue
                seg.results.append((etype, a - s0, b - s0, score, ctx))
            for i in sorted(redo):
                seg = group[i]
                try:
                    again = self._match(rec, seg.norm)
                except Exception:
                    continue
                have = {(x[0], x[1], x[2]) for x in seg.results}
                for etype, a, b, score in again:
                    if (etype, a, b) not in have:
                        seg.results.append((etype, a, b, score, ctx))

    # -- spaCy NER -----------------------------------------------------------
    def run_ner(self, segs: list[_Segment]) -> None:
        wanted = {lbl for lbl, ent in _SPACY_TO_PRESIDIO.items() if ent not in _noise_types}
        if not wanted:
            return
        jobs: list[tuple[_Segment, int, str]] = []
        for s in segs:
            if not _CAPITALIZED.search(s.norm):
                continue
            n = len(s.norm)
            if n <= _NER_WINDOW:
                jobs.append((s, 0, s.norm))
                continue
            off = 0
            while off < n:
                end = min(n, off + _NER_WINDOW)
                if end < n:  # cut at whitespace so a word is not split
                    cut = s.norm.rfind(" ", off + _NER_WINDOW // 2, end)
                    end = cut if cut > 0 else end
                jobs.append((s, off, s.norm[off:end]))
                if end >= n:
                    break
                off = max(off + 1, end - _NER_OVERLAP)
        if not jobs:
            return
        # Pack short pieces into shared docs: spaCy has a fixed cost per doc,
        # so 8 names in one doc are much cheaper than 8 docs of one name.
        packs: list[tuple[list[int], list[tuple[_Segment, int]], str]] = []
        cur_starts: list[int] = []
        cur_refs: list[tuple[_Segment, int]] = []
        cur_parts: list[str] = []
        cur_len = 0
        for seg, off, piece in jobs:
            if cur_parts and cur_len + len(_NER_SEP) + len(piece) > _NER_WINDOW:
                packs.append((cur_starts, cur_refs, _NER_SEP.join(cur_parts)))
                cur_starts, cur_refs, cur_parts, cur_len = [], [], [], 0
            if cur_parts:
                cur_len += len(_NER_SEP)
            cur_starts.append(cur_len)
            cur_refs.append((seg, off))
            cur_parts.append(piece)
            cur_len += len(piece)
        if cur_parts:
            packs.append((cur_starts, cur_refs, _NER_SEP.join(cur_parts)))
        docs = self.nlp.pipe((p[2] for p in packs), disable=self.ner_disable, batch_size=32)
        for (starts, refs, packed), doc in zip(packs, docs):
            for ent in doc.ents:
                if ent.label_ not in wanted:
                    continue
                i = bisect.bisect_right(starts, ent.start_char) - 1
                piece_end = starts[i + 1] - len(_NER_SEP) if i + 1 < len(starts) else len(packed)
                if ent.end_char > piece_end:
                    continue  # crosses into the next value
                etype = _SPACY_TO_PRESIDIO[ent.label_]
                a, b = ent.start_char, ent.end_char
                text = ent.text
                if etype == "PERSON" and _PERSON_BAD.search(text):
                    # 'full_name="Lena Chen' in a log line: keep the name part.
                    cut = max(text.rfind(c) for c in "=\"':") + 1
                    a += cut
                    text = text[cut:]
                    if not text or _PERSON_BAD.search(text):
                        continue  # IDs, zip codes
                if etype in ("PERSON", "LOCATION") and not _CAPITALIZED.search(text):
                    continue  # "info svc" in a log line
                seg, off = refs[i]
                base = off - starts[i]
                seg.results.append((etype, base + a, base + b, _NER_SCORE, ()))

    # -- context recognizers (key / window based) -----------------------------
    @staticmethod
    def run_context(segs: list[_Segment]) -> None:
        for s in segs:
            for fn in CONTEXT_RECOGNIZERS:
                for etype, a, b, score in fn(s.norm, s.key):
                    if etype not in _noise_types:
                        s.results.append((etype, a, b, score, ()))


def _context_hit(seg: _Segment, start: int, ctx: tuple) -> bool:
    window = seg.norm[max(0, start - _CONTEXT_CHARS):start]
    words = [w.lower() for w in _CONTEXT_WORD.findall(window)[-_CONTEXT_WORDS:]]
    if seg.key:
        words += [w.lower() for w in re.split(r"[^A-Za-z0-9#]+", seg.key) if w]
        words.append(seg.key.lower())
    if not words:
        return False
    return any(c in w for c in ctx for w in words)


def _dedupe(results: list[tuple]) -> list[tuple]:
    """Drop a hit that sits inside another hit of the same type with an equal
    or higher score (what Presidio's remove_duplicates does), in n log n."""
    by_type: dict[str, list[tuple]] = {}
    for r in results:
        by_type.setdefault(r[0], []).append(r)
    out: list[tuple] = []
    for items in by_type.values():
        items.sort(key=lambda r: (r[1], -r[2], -r[3]))
        best_end, best_score = -1, -1.0
        last = None
        for r in items:
            if last is not None and r[1] == last[1] and r[2] == last[2]:
                continue  # exact duplicate span
            if r[2] <= best_end and r[3] <= best_score:
                continue
            out.append(r)
            last = r
            if r[2] > best_end or (r[2] == best_end and r[3] > best_score):
                best_end, best_score = r[2], r[3]
    return out


def _finish(seg: _Segment, threshold: float) -> list[Detection]:
    """Context boost, threshold, dedupe and map back to original offsets."""
    scored = []
    for etype, a, b, score, ctx in seg.results:
        if score < threshold and ctx and _context_hit(seg, a, ctx):
            score = min(1.0, max(score + _CONTEXT_BOOST, _CONTEXT_MIN))
        if score >= threshold and b > a:
            scored.append((etype, a, b, score))
    kept = _dedupe(scored)
    # A JWT / GitHub / AWS / private-key hit is more exact than the generic
    # "api_key=..." rule firing on the same characters; keep only the exact one.
    exact = [(a, b) for etype, a, b, _ in kept if etype in _EXACT_SECRET_TYPES]
    if exact:
        kept = [r for r in kept if r[0] != "GENERIC_API_KEY"
                or not any(r[1] < b and a < r[2] for a, b in exact)]
    text = seg.text
    out: list[Detection] = []
    for etype, a, b, score in kept:
        sens = _classify(etype)
        if not sens.is_sensitive:
            continue
        if seg.pmap is None:
            start, end = a, b
        else:
            start = seg.pmap[a] if a < len(seg.pmap) else len(text)
            end = seg.pmap[b - 1] + 1 if b - 1 < len(seg.pmap) else start
        # spaCy NER can pull a neighbouring quote or space into the span
        # ("Alice Lee'" inside a repr), and masking it would eat the quote
        # and break the surrounding JSON. Trim those from both edges.
        while start < end and text[start] in _SPAN_EDGE_TRIM:
            start += 1
        while end > start and text[end - 1] in _SPAN_EDGE_TRIM:
            end -= 1
        if start == end:
            continue
        out.append(Detection(entity_type=etype, start=start, end=end, score=score,
                             sensitivity=sens, fingerprint=fingerprint(text[start:end])))
    out.sort(key=lambda d: (d.start, d.end))
    return out


_engine: _Engine | None = None


def _get_engine() -> _Engine:
    global _engine
    if _engine is None:
        analyzer = _get_analyzer()
        with _analyzer_lock:
            if _engine is None:
                _engine = _Engine(analyzer)
    return _engine


# ---------------------------------------------------------------------------
# Cache and per-call scope
# ---------------------------------------------------------------------------

_CACHE_SIZE = int(os.environ.get("AGENTWARD_DETECT_CACHE_SIZE", "4096") or 0)
_cache: "OrderedDict[tuple, tuple]" = OrderedDict()
_cache_lock = threading.Lock()

# Inside a detection_scope: value hash -> detections already found for that
# value in this tool call (with key context), shared by every later lookup.
_SCOPE: contextvars.ContextVar[dict | None] = contextvars.ContextVar(
    "agentward_detect_scope", default=None)


def _vhash(text: str) -> bytes:
    return hashlib.blake2b(text.encode("utf-8", "surrogatepass"), digest_size=16).digest()


def clear_cache() -> None:
    """Forget every cached detection result."""
    with _cache_lock:
        _cache.clear()


def cache_info() -> dict:
    with _cache_lock:
        return {"size": len(_cache), "max_size": _CACHE_SIZE}


def _cache_get(key: tuple):
    if _CACHE_SIZE <= 0:
        return None
    with _cache_lock:
        hit = _cache.get(key)
        if hit is not None:
            _cache.move_to_end(key)
        return hit


def _cache_put(key: tuple, value: tuple) -> None:
    if _CACHE_SIZE <= 0:
        return
    with _cache_lock:
        _cache[key] = value
        _cache.move_to_end(key)
        while len(_cache) > _CACHE_SIZE:
            _cache.popitem(last=False)


@contextlib.contextmanager
def detection_scope() -> Iterator[dict]:
    """Detect each value once for the duration of the block.

    ``detect_mapping`` inside the block records what it found for every
    string value (including hits that only fired because of the JSON key,
    such as a 9-digit ``ssn``). A later ``detect_text`` on the same string,
    for example from redaction or masking, gets that same answer instead of
    detecting again. ``instrument_tool`` opens one around its input and its
    output handling.
    """
    token = _SCOPE.set({})
    try:
        yield _SCOPE.get()
    finally:
        _SCOPE.reset(token)


def _key_context(key: str) -> str:
    """Only keep a key when it can change the result, so most values share one
    cache entry whatever key they sit under."""
    if not key:
        return ""
    hit = _key_memo.get(key)
    if hit is None:
        words = [w.lower() for w in re.split(r"[^A-Za-z0-9#]+", key) if w] + [key.lower()]
        hit = any(c in w for c in _get_engine().all_context for w in words) or any(
            rx.search(key) for rx in KEY_PATTERNS)
        if len(_key_memo) > 4096:
            _key_memo.clear()
        _key_memo[key] = hit
    return key if hit else ""


_key_memo: dict[str, bool] = {}


def _analyze(items: list[tuple[str, str]], threshold: float) -> list[list[Detection]]:
    """Detect in many (text, key) values at once. Uses the cache."""
    out: list[list[Detection] | None] = [None] * len(items)
    todo: list[tuple[int, _Segment, tuple]] = []
    noise_tag = tuple(sorted(_noise_types))
    for i, (text, key) in enumerate(items):
        if not text:
            out[i] = []
            continue
        kctx = _key_context(key)
        ck = (_vhash(text), kctx, threshold, noise_tag)
        hit = _cache_get(ck)
        if hit is not None:
            out[i] = list(hit)
            continue
        todo.append((i, _Segment(text, kctx), ck))
    if todo:
        engine = _get_engine()
        segs = [t[1] for t in todo]
        engine.run_patterns(segs, threshold)
        engine.run_context(segs)
        engine.run_ner(segs)
        for i, seg, ck in todo:
            dets = _finish(seg, threshold)
            _cache_put(ck, tuple(dets))
            out[i] = dets
    return out  # type: ignore[return-value]


def detect_text(text: str, *, threshold: float = 0.5) -> list[Detection]:
    """Detect sensitive spans in ``text``. Returns [] if none / on error.

    Presidio is loaded lazily; if the spaCy model is unavailable, returns []
    rather than crashing, so callers (the spike) can still observe chain-level
    taint propagation via baggage even when field detection degrades.
    """
    if not text:
        return []
    scope = _SCOPE.get()
    if scope is not None and threshold == 0.5:
        hit = scope.get(_vhash(text))
        if hit is not None:
            return list(hit)
    try:
        return _analyze([(text, "")], threshold)[0]
    except Exception:  # spaCy model missing, etc.
        return []


def detect_value(value: object) -> list[Detection]:
    """Detect in a single value (coerced to str)."""
    if value is None or isinstance(value, bool):
        return []
    return detect_text(str(value))


def _leaves(payload: object, key: str, out: list[tuple[str, str]]) -> None:
    if isinstance(payload, Mapping):
        for k, v in payload.items():
            _leaves(v, str(k), out)
    elif isinstance(payload, (list, tuple)):
        for v in payload:
            _leaves(v, key, out)  # list items inherit the list's key
    elif payload is None or isinstance(payload, bool):
        return
    else:
        out.append((payload if isinstance(payload, str) else str(payload), key))


def detect_leaves(payload: object) -> list[tuple[str, list[Detection]]]:
    """Detect in every leaf value of a JSON-like payload in one pass.

    Returns ``(leaf_text, detections)`` per leaf, offsets relative to the
    leaf. The JSON key of each value is used as context, so ``{"ssn":
    "536228491"}`` is caught even without dashes. Inside a
    :func:`detection_scope` the results are remembered for later
    ``detect_text`` calls on the same strings.
    """
    items: list[tuple[str, str]] = []
    _leaves(payload, "", items)
    if not items:
        return []
    try:
        results = _analyze(items, 0.5)
    except Exception:
        return []
    scope = _SCOPE.get()
    if scope is not None:
        for (text, _), dets in zip(items, results):
            h = _vhash(text)
            prev = scope.get(h)
            if prev is None:
                scope[h] = tuple(dets)
            elif dets:
                seen = {(d.entity_type, d.start, d.end) for d in prev}
                scope[h] = tuple(prev) + tuple(
                    d for d in dets if (d.entity_type, d.start, d.end) not in seen)
    return [(text, dets) for (text, _), dets in zip(items, results)]


def detect_mapping(payload: Mapping[str, object] | Iterable) -> list[Detection]:
    """Detect across a JSON-like payload (dict / list / scalar)."""
    found: list[Detection] = []
    for _, dets in detect_leaves(payload):
        found.extend(dets)
    return found


def taint_for(detections: Iterable[Detection], *, source_span_id: str | None = None) -> TaintLabel:
    """Build a TaintLabel from a set of detections. Empty if nothing sensitive."""
    detections = list(detections)
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
    # Recognizers can overlap (e.g. AWS_ACCESS_KEY and GENERIC_API_KEY both
    # firing on the same key). Splicing every raw span independently corrupts
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
