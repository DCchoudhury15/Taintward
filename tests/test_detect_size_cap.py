"""Gap G10: values over TAINTWARD_DETECT_MAX_CHARS are masked whole, not scanned."""

from __future__ import annotations

import time

from taintward.core.doe import Sensitivity
from taintward.sdk import detect
from taintward.sdk import placeholders as ph
from taintward.sdk.destinations import DEST_EXTERNAL, DEST_INTERNAL, DEST_LLM
from taintward.sdk.integrations._payload import redact_structure


def test_default_limit():
    assert detect.max_chars() == 500_000


def test_over_the_limit_is_one_secret(monkeypatch):
    monkeypatch.setenv("TAINTWARD_DETECT_MAX_CHARS", "1000")
    text = "Alice Lee " * 200
    dets = detect.detect_text(text)
    assert [(d.entity_type, d.start, d.end, d.sensitivity) for d in dets] \
        == [(detect.OVERSIZE, 0, len(text), Sensitivity.SECRET)]
    assert detect.mask_value({"doc": text}) == {"doc": "[SECRET]"}


def test_under_the_limit_is_scanned(monkeypatch):
    monkeypatch.setenv("TAINTWARD_DETECT_MAX_CHARS", "1000")
    dets = detect.detect_text("ssn 234-12-1234")
    assert dets and all(d.entity_type != detect.OVERSIZE for d in dets)


def test_zero_turns_it_off(monkeypatch):
    monkeypatch.setenv("TAINTWARD_DETECT_MAX_CHARS", "0")
    assert detect.max_chars() == 0
    assert all(d.entity_type != detect.OVERSIZE
               for d in detect.detect_text("x " * 600_000 + "ssn 234-12-1234"))


def test_bad_value_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("TAINTWARD_DETECT_MAX_CHARS", "lots")
    assert detect.max_chars() == 500_000


def test_redaction_per_destination(monkeypatch):
    monkeypatch.setenv("TAINTWARD_DETECT_MAX_CHARS", "100")
    big = "a" * 101
    assert redact_structure({"doc": big}, DEST_EXTERNAL) == {"doc": "[SECRET]"}
    # internal: masked too, never an FF1 token over the whole value
    assert redact_structure({"doc": big}, DEST_INTERNAL) == {"doc": "[SECRET]"}
    pmap = ph.PlaceholderMap()
    assert redact_structure({"doc": big}, DEST_LLM, placeholders=pmap) == {"doc": "<TOO_LARGE_1>"}


def test_large_value_is_fast(monkeypatch):
    monkeypatch.setenv("TAINTWARD_DETECT_MAX_CHARS", "10000")
    text = "Capitalized Words Everywhere " * 200_000  # about 6 MB
    t = time.perf_counter()
    detect.detect_text(text)
    assert time.perf_counter() - t < 0.5
