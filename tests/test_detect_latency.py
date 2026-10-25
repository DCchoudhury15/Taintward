"""Wrapped-tool behaviour and a latency regression guard for detection.

The latency test uses a 1 KB payload like bench/run_latency.py and fails if
the median wrapped call is slower than a generous bound (50 ms; the
benchmark machine measures about 5 ms). The cache is cleared before every
call, so this is the cost for a payload the SDK has not seen before. Set
TAINTWARD_SKIP_LATENCY_TEST=1 to skip it on very slow machines.
"""

from __future__ import annotations

import os
import statistics
import sys
import time
import unittest
from pathlib import Path

from taintward.sdk import detect

try:
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )
except ImportError:  # pragma: no cover
    InMemorySpanExporter = None  # type: ignore[assignment]

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "bench"))

LATENCY_BOUND_MS = float(os.environ.get("TAINTWARD_LATENCY_BOUND_MS", "50"))


def _analyzer_available() -> bool:
    try:
        detect._get_analyzer()
        return True
    except Exception:
        return False


def _wrapped_echo(destination: str):
    from taintward.sdk import instrumentation as instr

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("test")

    def echo(*args, **kwargs):
        return {"args": list(args), "kwargs": kwargs}

    return instr.instrument_tool("echo", destination=destination, tracer=tracer)(echo), exporter


@unittest.skipUnless(_analyzer_available() and InMemorySpanExporter is not None,
                     "Presidio / spaCy model or OTel SDK not installed")
class TestWrappedCall(unittest.TestCase):
    def tearDown(self):
        from taintward.sdk import instrumentation as instr
        instr.end_run()

    def test_kwarg_name_is_context_for_redaction(self):
        from taintward.sdk import instrumentation as instr

        detect.clear_cache()
        wrapped, exporter = _wrapped_echo(instr.DEST_EXTERNAL)
        out = wrapped(note="hello", ssn="536228491")
        self.assertEqual(out["kwargs"]["ssn"], "[PII]")
        self.assertEqual(out["kwargs"]["note"], "hello")
        span = exporter.get_finished_spans()[-1]
        self.assertTrue(span.attributes.get("taintward.violation"))
        self.assertNotIn("536228491", str(span.attributes))

    def test_clean_payload_is_not_tainted(self):
        from taintward.sdk import instrumentation as instr

        detect.clear_cache()
        wrapped, exporter = _wrapped_echo(instr.DEST_EXTERNAL)
        wrapped({"id": 96930, "created": "2026-02-07T11:42:43Z", "status": "active"})
        span = exporter.get_finished_spans()[-1]
        self.assertFalse(span.attributes.get("taintward.violation", False))


@unittest.skipIf(os.environ.get("TAINTWARD_SKIP_LATENCY_TEST"), "TAINTWARD_SKIP_LATENCY_TEST is set")
@unittest.skipUnless(_analyzer_available() and InMemorySpanExporter is not None,
                     "Presidio / spaCy model or OTel SDK not installed")
class TestLatency(unittest.TestCase):
    def test_1kb_wrapped_call_median(self):
        from run_latency import make_payload

        from taintward.sdk import instrumentation as instr

        wrapped, exporter = _wrapped_echo(instr.DEST_EXTERNAL)
        payload = make_payload(1_000)
        wrapped(payload)  # warm up
        times = []
        for _ in range(15):
            detect.clear_cache()
            t0 = time.perf_counter()
            wrapped(payload)
            times.append((time.perf_counter() - t0) * 1e3)
            exporter.clear()
            instr.end_run()
        median = statistics.median(times)
        self.assertLess(median, LATENCY_BOUND_MS,
                        f"1 KB wrapped call median {median:.1f} ms >= {LATENCY_BOUND_MS} ms")


if __name__ == "__main__":
    unittest.main()
