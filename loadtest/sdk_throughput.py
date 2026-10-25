"""SDK throughput: wrapped tool calls per second with N threads or processes.

Each worker calls two ``@instrument_tool`` tools in a loop for a fixed time:

* ``clean``: an internal tool with a small payload and no sensitive data
* ``leak``:  an external tool whose payload carries an SSN, an email and an
             AWS key (detect + taint + mask on every call)

Spans go to an in memory exporter through a BatchSpanProcessor, so no
network time is counted (point --otlp-endpoint at a collector to include it).

Usage (from the repo root):

    .venv/bin/python loadtest/sdk_throughput.py                       # threads 1 2 4 8
    .venv/bin/python loadtest/sdk_throughput.py --threads 1 4 --processes 4
    .venv/bin/python loadtest/sdk_throughput.py --label after-fast-detect

It prints a markdown table and writes loadtest/results/sdk-<label>.json and
.md, so runs before and after a change can be compared.
"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import platform
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
# Fixed public demo key so the redactor works without a real key. Benchmark only.
os.environ.setdefault("TAINTWARD_ALLOW_DEMO_KEY", "1")

CLEAN = {"employee_id": "e-1042", "fields": ["team", "manager"], "note": "weekly sync moved"}
LEAK = {
    "employee": "Alice Lee",
    "ssn": "234-12-1234",
    "email": "alice.lee@example.com",
    "deploy_key": "AKIAIOSFODNN7EXAMPLE",
    "note": "send the full record to the auditor",
}


def _setup(otlp_endpoint: str | None):
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    from taintward.sdk import instrumentation as instr

    provider = TracerProvider()
    if otlp_endpoint:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
        exporter = OTLPSpanExporter(endpoint=otlp_endpoint)
    else:
        from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

        class _Drop(SpanExporter):
            """Accepts and drops spans, so memory stays flat during long runs."""

            def export(self, spans):
                return SpanExportResult.SUCCESS
        exporter = _Drop()
    provider.add_span_processor(BatchSpanProcessor(exporter, max_queue_size=65536))
    trace.set_tracer_provider(provider)
    tracer = provider.get_tracer("loadtest")

    @instr.instrument_tool("lookup_employee", destination=instr.DEST_INTERNAL, tracer=tracer)
    def clean_tool(payload: dict) -> dict:
        return {"ok": True, "team": "payroll"}

    @instr.instrument_tool("send_to_auditor", destination=instr.DEST_EXTERNAL,
                           jurisdiction="us", tracer=tracer)
    def leak_tool(payload: dict) -> dict:
        return {"ack": True, "echo": payload["note"]}

    # Warm up Presidio and spaCy (the first call builds the analyzer).
    clean_tool(CLEAN)
    leak_tool(LEAK)
    return provider, {"clean": lambda: clean_tool(CLEAN), "leak": lambda: leak_tool(LEAK)}


def _loop(fn, seconds: float) -> int:
    n = 0
    end = time.perf_counter() + seconds
    while time.perf_counter() < end:
        fn()
        n += 1
    return n


def run_threads(calls, kind: str, threads: int, seconds: float) -> float:
    counts = [0] * threads

    def work(i: int) -> None:
        counts[i] = _loop(calls[kind], seconds)

    ts = [threading.Thread(target=work, args=(i,)) for i in range(threads)]
    t0 = time.perf_counter()
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return sum(counts) / (time.perf_counter() - t0)


def _proc_worker(kind: str, seconds: float, otlp: str | None, ready, start, q) -> None:
    provider, calls = _setup(otlp)
    ready.put(1)
    start.wait()
    q.put(_loop(calls[kind], seconds))
    provider.shutdown()


def run_processes(kind: str, procs: int, seconds: float, otlp: str | None) -> float:
    ctx = mp.get_context("spawn")
    ready, start, q = ctx.Queue(), ctx.Event(), ctx.Queue()
    ps = [ctx.Process(target=_proc_worker, args=(kind, seconds, otlp, ready, start, q))
          for _ in range(procs)]
    for p in ps:
        p.start()
    for _ in ps:  # every process loads Presidio and warms up before the clock starts
        ready.get()
    start.set()
    total = sum(q.get() for _ in ps)
    for p in ps:
        p.join()
    return total / seconds


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--threads", type=int, nargs="*", default=[1, 2, 4, 8])
    ap.add_argument("--processes", type=int, nargs="*", default=[])
    ap.add_argument("--seconds", type=float, default=10.0)
    ap.add_argument("--otlp-endpoint", default=None)
    ap.add_argument("--label", default="current")
    args = ap.parse_args()

    provider, calls = _setup(args.otlp_endpoint)
    rows = []
    for kind in ("clean", "leak"):
        for n in args.threads:
            rate = run_threads(calls, kind, n, args.seconds)
            rows.append({"payload": kind, "mode": "threads", "workers": n, "calls_per_s": round(rate, 1)})
            print(f"{kind:5s} threads={n:<3d} {rate:9.1f} calls/s", flush=True)
        for n in args.processes:
            rate = run_processes(kind, n, args.seconds, args.otlp_endpoint)
            rows.append({"payload": kind, "mode": "processes", "workers": n, "calls_per_s": round(rate, 1)})
            print(f"{kind:5s} procs={n:<3d}   {rate:9.1f} calls/s", flush=True)
    provider.shutdown()

    meta = {
        "label": args.label,
        "python": platform.python_version(),
        "cpus": os.cpu_count(),
        "seconds_per_point": args.seconds,
        "exporter": args.otlp_endpoint or "in-memory (dropped)",
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    out = ROOT / "loadtest" / "results"
    out.mkdir(parents=True, exist_ok=True)
    (out / f"sdk-{args.label}.json").write_text(json.dumps({"meta": meta, "rows": rows}, indent=2) + "\n")
    lines = [f"# SDK throughput ({args.label})", "",
             f"{meta['time']}, Python {meta['python']}, {meta['cpus']} CPUs, "
             f"{args.seconds:g} s per point, exporter: {meta['exporter']}.", "",
             "| payload | mode | workers | wrapped calls/s |", "|---|---|---|---|"]
    lines += [f"| {r['payload']} | {r['mode']} | {r['workers']} | {r['calls_per_s']:.0f} |" for r in rows]
    (out / f"sdk-{args.label}.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines[4:]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
