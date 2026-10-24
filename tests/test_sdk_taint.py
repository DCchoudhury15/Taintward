"""Unit tests for the AgentWard SDK propagation, no SigNoz required.

Builds a TracerProvider with an in-memory exporter and drives a two-tool flow
to assert, offline, that:
  * the chain-level taint (baggage) propagates from a tool whose output carries
    PII to the next sibling tool;
  * a tainted chain reaching an external/llm/log sink sets agentward.violation;
  * raw PII is masked in the stored span attributes (never reaches storage).
"""

from __future__ import annotations

import unittest

from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

try:
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )
except ImportError:  # pragma: no cover
    InMemorySpanExporter = None  # type: ignore[assignment]

from core.doe import Sensitivity
from sdk import instrumentation as instr
from sdk import taint as tnt


def _build_tracer():
    provider = TracerProvider(resource=Resource.create({"service.name": "test"}))
    exporter = InMemorySpanExporter()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("agentward")
    return provider, exporter, tracer


def _attrs(span: ReadableSpan, key: str):
    for k, v in (span.attributes or {}).items():
        if k == key:
            return v
    return None


class TestPropagation(unittest.TestCase):
    def setUp(self):
        if InMemorySpanExporter is None:
            self.skipTest("InMemorySpanExporter unavailable")
        self.provider, self.exporter, self.tracer = _build_tracer()

    def tearDown(self):
        try:
            self.provider.shutdown()
        except Exception:
            pass

    def _make_tools(self):
        @instr.instrument_tool("source", destination=instr.DEST_INTERNAL,
                               tracer=self.tracer)
        def source() -> dict:
            return {"ssn": "234-12-1234"}

        @instr.instrument_tool("sink", destination=instr.DEST_EXTERNAL,
                               tracer=self.tracer)
        def sink(payload) -> str:
            return f"sent {payload!r}"

        return source, sink

    def test_chain_taint_propagates_to_next_tool(self):
        source, sink = self._make_tools()
        instr.begin_run("test.run")
        try:
            record = source()
            # The source tool's output carried PII; the chain taint must now be
            # visible to the next tool via the ambient context.
            self.assertIsNotNone(instr.current_taint())
            self.assertIn(Sensitivity.PII, instr.current_taint().classes)
            sink(record)
        finally:
            instr.end_run()

    def test_external_sink_records_violation(self):
        source, sink = self._make_tools()
        instr.begin_run("test.run")
        try:
            sink(source())
        finally:
            instr.end_run()

        spans = self.exporter.get_finished_spans()
        sink_span = next(s for s in spans if s.name == "sink")
        self.assertTrue(_attrs(sink_span, "agentward.violation"))
        classes = _attrs(sink_span, "agentward.taint.classes")
        self.assertIn("pii", classes)

    def test_internal_sink_not_flagged_as_violation(self):
        @instr.instrument_tool("internal_tool", destination=instr.DEST_INTERNAL,
                               tracer=self.tracer)
        def tool() -> dict:
            return {"ssn": "234-12-1234"}

        instr.begin_run("test.run")
        try:
            tool()
        finally:
            instr.end_run()

        spans = self.exporter.get_finished_spans()
        tool_span = next(s for s in spans if s.name == "internal_tool")
        self.assertIsNone(_attrs(tool_span, "agentward.violation"))
        # but the taint is still recorded (it touched PII)
        self.assertIn("pii", _attrs(tool_span, "agentward.taint.classes"))

    def test_raw_pii_is_masked_in_stored_result(self):
        @instr.instrument_tool("leak", destination=instr.DEST_EXTERNAL,
                               tracer=self.tracer)
        def leak() -> str:
            return "record SSN 234-12-1234"

        instr.begin_run("test.run")
        try:
            leak()
        finally:
            instr.end_run()

        spans = self.exporter.get_finished_spans()
        span = next(s for s in spans if s.name == "leak")
        result = _attrs(span, "gen_ai.tool.call.result")
        self.assertNotIn("234-12-1234", result)  # raw SSN never stored
        self.assertIn("[PII]", result)            # masked form is stored

    def test_clean_run_has_no_taint(self):
        @instr.instrument_tool("clean", destination=instr.DEST_INTERNAL,
                               tracer=self.tracer)
        def clean() -> str:
            return "nothing sensitive here"

        instr.begin_run("test.run")
        try:
            clean()
            self.assertIsNone(instr.current_taint())
        finally:
            instr.end_run()

        spans = self.exporter.get_finished_spans()
        span = next(s for s in spans if s.name == "clean")
        self.assertFalse(_attrs(span, "agentward.sensitive"))


class TestTaintLabel(unittest.TestCase):
    def test_empty_label_is_not_tainted(self):
        self.assertFalse(tnt.TaintLabel.of(set()).is_tainted)

    def test_merge_unions_classes(self):
        a = tnt.TaintLabel.of([Sensitivity.PII])
        b = tnt.TaintLabel.of([Sensitivity.SECRET])
        merged = a.merge(b)
        self.assertEqual(merged.classes, {Sensitivity.PII, Sensitivity.SECRET})
        self.assertEqual(merged.level, tnt.TaintLevel.HIGH)

    def test_baggage_roundtrip(self):
        label = tnt.TaintLabel.of([Sensitivity.PII, Sensitivity.SECRET])
        decoded = tnt.TaintLabel.from_baggage(label.to_baggage())
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded.classes, label.classes)
        self.assertEqual(decoded.level, label.level)

    def test_untainted_label_roundtrips_to_none(self):
        # An untainted label serializes to empty baggage; decoding empty
        # baggage must yield None (equivalent to "no taint"), not raise.
        label = tnt.TaintLabel.of(set())
        self.assertEqual(label.to_baggage(), {})
        self.assertIsNone(tnt.TaintLabel.from_baggage(label.to_baggage()))
        self.assertIsNone(tnt.TaintLabel.from_baggage({}))
        self.assertIsNone(tnt.TaintLabel.from_baggage(None))

    def test_unicode_taint_id_roundtrips(self):
        label = tnt.TaintLabel.of([Sensitivity.PII], id="taint-é中文-id")
        decoded = tnt.TaintLabel.from_baggage(label.to_baggage())
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded.id, label.id)

    def test_merge_order_independent_with_untainted_side(self):
        tainted = tnt.TaintLabel.of([Sensitivity.PII])
        untainted = tnt.TaintLabel.of(set())
        # Either merge order must yield the same effective (tainted) result.
        a = tainted.merge(untainted)
        b = untainted.merge(tainted)
        self.assertEqual(a.classes, tainted.classes)
        self.assertEqual(b.classes, tainted.classes)
        self.assertTrue(a.is_tainted)
        self.assertTrue(b.is_tainted)

    def test_merge_with_none_is_identity(self):
        label = tnt.TaintLabel.of([Sensitivity.SECRET])
        self.assertEqual(label.merge(None).classes, label.classes)

    def test_from_baggage_malformed_level_does_not_crash(self):
        # A corrupted/version-skewed baggage.level must never raise -- it
        # should degrade to the level derived from the (valid) classes.
        bag = {
            tnt.KEY_ID: "abc",
            tnt.KEY_CLASSES: "pii",
            tnt.KEY_LEVEL: "not-a-real-level",
        }
        decoded = tnt.TaintLabel.from_baggage(bag)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded.level, tnt.TaintLevel.MEDIUM)

    def test_from_baggage_drops_only_unrecognized_class_tokens(self):
        # One bad token in taint.classes must not erase the valid ones.
        bag = {
            tnt.KEY_ID: "abc",
            tnt.KEY_CLASSES: "pii,not-a-real-class",
            tnt.KEY_LEVEL: "high",
        }
        decoded = tnt.TaintLabel.from_baggage(bag)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded.classes, frozenset({Sensitivity.PII}))

    def test_from_baggage_all_unrecognized_classes_is_none(self):
        bag = {tnt.KEY_ID: "abc", tnt.KEY_CLASSES: "bogus1,bogus2"}
        self.assertIsNone(tnt.TaintLabel.from_baggage(bag))


if __name__ == "__main__":
    unittest.main()