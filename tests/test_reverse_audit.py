"""Gap G11: reading real values back is recorded (span event + audit log)."""

from __future__ import annotations

import logging

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from taintward.core.doe import Sensitivity
from taintward.sdk.destinations import DEST_INTERNAL
from taintward.sdk.integrations import Ward
from taintward.sdk.redact import Redactor



def _tracer():
    exp = InMemorySpanExporter()
    tp = TracerProvider()
    tp.add_span_processor(SimpleSpanProcessor(exp))
    return tp.get_tracer("t"), exp


def _events(exp):
    return [e for s in exp.get_finished_spans() for e in s.events if e.name == "taintward.reverse"]


def test_reverse_adds_event_to_current_span(caplog):
    tracer, exp = _tracer()
    r = Redactor()
    token = r.redact_value("234-12-1234", Sensitivity.PII, DEST_INTERNAL)
    with caplog.at_level(logging.INFO, logger="taintward.audit"):
        with tracer.start_as_current_span("app"):
            assert r.reverse(token) == "234-12-1234"
            assert r.reverse("999-99-9999x") is None
    ev = _events(exp)
    assert [e.attributes["taintward.reverse.found"] for e in ev] == [1, 0]
    a = ev[0].attributes
    assert a["taintward.reverse.kind"] == "token"
    assert a["taintward.key_id"] == r.key_id
    assert a["taintward.reverse.caller"].startswith(__name__ + ":test_reverse_adds_event")
    # never the value or the token
    assert "234-12-1234" not in str(dict(a)) and token not in str(dict(a))
    assert "234-12-1234" not in caplog.text and token not in caplog.text
    assert "kind=token found=1" in caplog.text


def test_reverse_without_a_span_still_records(caplog):
    with caplog.at_level(logging.INFO, logger="taintward.audit"):
        Redactor().reverse("nothing")
    assert "kind=token found=0" in caplog.text


def test_masks_are_not_reversed_or_recorded(caplog):
    with caplog.at_level(logging.INFO, logger="taintward.audit"):
        assert Redactor().reverse("[PII]") is None
    assert "taintward reverse" not in caplog.text


def test_ward_restore_is_recorded(caplog):
    tracer, exp = _tracer()
    ward = Ward(tracer=tracer)
    with caplog.at_level(logging.INFO, logger="taintward.audit"):
        with ward.run():
            pmap = ward.placeholder_map()
            ph_ = pmap.placeholder_for("Alice Lee", "PERSON", Sensitivity.PII)
            assert ward.restore(f"hi {ph_}") == "hi Alice Lee"
    ev = _events(exp)
    assert ev and ev[0].attributes["taintward.reverse.kind"] == "placeholder"
    assert ev[0].attributes["taintward.reverse.found"] == 1
    assert "Alice Lee" not in caplog.text
