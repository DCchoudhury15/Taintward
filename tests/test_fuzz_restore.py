"""Property tests for detection, placeholder redaction and restore.

Hypothesis builds text from real PII values, unicode noise and pieces that
look like placeholders, then checks that:

1. detect_text never raises and every span fits in the text,
2. redact then restore gives back the exact text, and no detected value
   is left in the redacted text,
3. StreamRestorer gives the same result as restore_text, wherever the
   stream is cut,
4. restoring arbitrary or mangled model output never raises,
5. a redacted JSON document restores to an equal document,
6. mask_text hides every detected value.

Every map uses restore_in_urls=True: not restoring inside a link address
is a policy choice (gap G1), not a round trip bug.

The default run is small so the file stays fast in CI. For a longer run:
TAINTWARD_FUZZ_EXAMPLES=3000 python -m pytest tests/test_fuzz_restore.py
"""

from __future__ import annotations

import json
import os
import warnings

import pytest

pytest.importorskip("hypothesis")

from hypothesis import HealthCheck, example, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from taintward.sdk import detect  # noqa: E402
from taintward.sdk import placeholders as ph  # noqa: E402
from taintward.sdk.redact import redact_text  # noqa: E402


def _analyzer_available() -> bool:
    try:
        detect._get_analyzer()
        return True
    except Exception:
        return False


needs_analyzer = pytest.mark.skipif(not _analyzer_available(),
                                    reason="Presidio / spaCy model not installed")

EXAMPLES = int(os.environ.get("TAINTWARD_FUZZ_EXAMPLES", "200"))
FUZZ = settings(max_examples=EXAMPLES, deadline=None,
                suppress_health_check=list(HealthCheck))


@pytest.fixture(autouse=True, scope="module")
def _fixed_fpe_key():
    # A fixed key so a failing example replays the same way. The old
    # value comes back when the module is done.
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("TAINTWARD_FPE_KEY", "0" * 64)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            yield


VALUES = [
    "536-22-8491", "maria.garcia@example.com", "Maria Garcia", "+1 415 555 0134",
    "4111 1111 1111 1111", "AKIA" + "IOSFODNN7EXAMPLE", "ghp_" + "a1B2" * 9,
    "Jürgen Müller", "José O'Brien", "李小龙", "FR7630006000011234567890189",
    "a\"b@ex.com", "back\\slash@ex.com", "<SSN_1>", "[PERSON_1]", "PERSON_1",
]
NOISE = st.text(st.characters(codec="utf-8", exclude_categories=("Cs",)), max_size=30)
FILLER = st.sampled_from([" ", ", ", " and ", "\n", " my SSN is ", " email: ", " name ",
                          "\"", "<", ">", "{", "}", "[", "]", "_", "​", "&lt;", " call "])
# A bare placeholder form glued to a value ("PERSON_1ghp_..."). It becomes
# a real placeholder form once the value after it is redacted.
GLUED = st.builds(str.__add__, st.sampled_from(["PERSON_1", "SSN_1", "EMAIL_2", "Person_1"]),
                  st.sampled_from(VALUES))
PIECE = st.one_of(st.sampled_from(VALUES), NOISE, FILLER, GLUED)
TEXT = st.lists(PIECE, max_size=12).map("".join)

MANGLE = st.sampled_from(["<{}>", "[{}]", "{{{{{}}}}}", "&lt;{}&gt;", "<{}", "{}>", "«{}»",
                          "\\<{}\\>", "<{} >", "< {}>", "<{}_>", "<{}__1>"])
NAMES = st.sampled_from(["SSN_1", "PERSON_1", "EMAIL_1", "SSN_99", "PERSON_0",
                         "Person 1", "person_1"])


def _new_map() -> ph.PlaceholderMap:
    return ph.PlaceholderMap(restore_in_urls=True)


def _check_spans(text, dets):
    for d in dets:
        assert 0 <= d.start < d.end <= len(text), (text, d)


def _check_no_leak(text, dets, out):
    """A detected value (6+ chars) must not be in the output, unless the same
    string is also somewhere in the text outside every detected span."""
    rest = list(text)
    for d in dets:
        for i in range(d.start, d.end):
            rest[i] = "\0"
    rest = "".join(rest)
    for d in dets:
        v = text[d.start:d.end].strip()
        if len(v) >= 6 and v not in rest:
            assert v not in out, ("leak", text, v, out)


@needs_analyzer
@FUZZ
@given(TEXT)
def test_detect_never_raises_and_spans_fit(text):
    _check_spans(text, detect.detect_text(text))


@needs_analyzer
@FUZZ
@given(TEXT)
# Found by this test: "PERSON_1" glued to a token was not reserved, so the
# name earlier in the text also got <PERSON_1>.
@example("Maria Garcia PERSON_1" + VALUES[6])
def test_placeholder_round_trip(text):
    m = _new_map()
    dets = detect.detect_text(text)
    out = redact_text(text, dets, "llm", placeholders=m)
    _check_no_leak(text, [d for d in dets if d.is_sensitive], out)
    back = m.restore_text(out)
    assert back == text, (text, out, back)


@needs_analyzer
@FUZZ
@given(TEXT, st.lists(st.integers(0, 200), max_size=6))
def test_stream_restore_matches_whole_restore(text, cuts):
    m = _new_map()
    out = redact_text(text, detect.detect_text(text), "llm", placeholders=m)
    want = m.restore_text(out, spaced=False)
    cuts = sorted({c % (len(out) + 1) for c in cuts})
    pieces, prev = [], 0
    for c in cuts + [len(out)]:
        pieces.append(out[prev:c])
        prev = c
    r = ph.StreamRestorer(m)
    got = "".join(r.push(p) for p in pieces) + r.flush()
    assert got == want, (text, out, pieces, got, want)


@needs_analyzer
@FUZZ
@given(TEXT, st.lists(st.tuples(MANGLE, NAMES), max_size=6), NOISE)
def test_restore_of_model_output_never_raises(text, forms, tail):
    m = _new_map()
    redact_text(text, detect.detect_text(text), "llm", placeholders=m)
    model = text + "".join(f.format(n) for f, n in forms) + tail
    m.restore_text(model)
    m.restore_text(model, spaced=False)
    m.restore_json_fragment(json.dumps(model))
    m.restore({"a": [model, {"b": model}]})
    doc = json.dumps({"x": model})
    r = ph.StreamRestorer(m, "json")
    r.push(doc[:7])
    r.push(doc[7:])
    r.flush()


@needs_analyzer
@FUZZ
@given(TEXT)
def test_json_args_restore_to_equal_doc(text):
    m = _new_map()
    doc = json.dumps({"q": text, "list": [text]})
    out = redact_text(doc, detect.detect_text(doc), "llm", placeholders=m)
    try:
        json.loads(out)
    except ValueError:
        return  # redacting a JSON string does not promise to keep it JSON
    back = m.restore_text(out)
    assert json.loads(back) == json.loads(doc), (doc, out, back)


@needs_analyzer
@FUZZ
@given(TEXT)
def test_mask_text_hides_values(text):
    dets = [d for d in detect.detect_text(text) if d.is_sensitive]
    out = detect.mask_text(text, dets)
    _check_no_leak(text, dets, out)
