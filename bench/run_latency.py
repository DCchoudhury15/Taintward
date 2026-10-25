"""Runtime-overhead benchmark for the Taintward SDK.

Measures, at payload sizes of about 100 B, 1 KB, 10 KB and 100 KB:

* ``detect_mapping``  : detection over a structured tool payload (list of
                        record dicts), the path instrument_tool uses
* ``detect_text``     : detection over one plain string of the same size
* ``redact_payload``  : destination-aware redaction (external sink) of the payload
* ``tool_unwrapped``  : a plain echo tool, no SDK
* ``tool_wrapped``    : the same tool under ``@instrument_tool`` (detect input,
                        redact input, detect output, mask output, set span
                        attributes), exported to an in-memory span exporter so
                        no network time is included
* ``tool_wrapped_cached``: the same wrapped call when the exact same payload
                        was already seen (the detection cache is warm)

The detection cache is cleared before every timed call of the other
operations, so their numbers are for payloads the SDK has never seen.

All warm numbers are taken after Presidio has been built once. The one-time
cold init cost (imports + building the analyzer + first call) is measured in
fresh subprocesses.

Writes ``bench/results/latency.json`` and ``latency.md``.

Usage:  python bench/run_latency.py [--budget 8] [--quick]
"""

from __future__ import annotations

import argparse
import importlib.metadata as md
import json
import os
import platform
import random
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

SIZES = {"100B": 100, "1KB": 1_000, "10KB": 10_000, "100KB": 100_000}

FIRST = ["Maria", "James", "Priya", "Wei", "Fatima", "Lukas", "Sofia", "Daniel"]
LAST = ["Garcia", "Smith", "Sharma", "Chen", "Khan", "Muller", "Rossi", "Johnson"]
NOTES = ["customer asked about the refund", "follow up next week",
         "moved to the premium plan", "no action needed", "escalated to billing"]


def make_record(r: random.Random, i: int) -> dict:
    """One synthetic CRM-style row. Every 4th row carries an SSN, every 7th a key."""
    first, last = r.choice(FIRST), r.choice(LAST)
    rec = {"id": 10_000 + i, "name": f"{first} {last}",
           "email": f"{first.lower()}.{last.lower()}@example.com",
           "plan": r.choice(["free", "pro", "team"]), "note": r.choice(NOTES)}
    if i % 4 == 0:
        rec["ssn"] = f"{r.randint(100, 665)}-{r.randint(10, 99)}-{r.randint(1000, 9999)}"
    if i % 7 == 0:
        rec["api_key"] = "AKIA" + "".join(r.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(16))
    return rec


def make_payload(size: int, seed: int = 7) -> list[dict]:
    """A list of records whose JSON encoding is about ``size`` bytes."""
    r = random.Random(seed)
    if size <= 150:
        rec = make_record(r, 1)
        rec = {"id": rec["id"], "name": rec["name"], "email": rec["email"]}
        return [rec]
    rows: list[dict] = []
    while len(json.dumps(rows)) < size:
        rows.append(make_record(r, len(rows)))
    return rows


def make_text(size: int, seed: int = 7) -> str:
    """A plain prose string of about ``size`` chars with some PII sprinkled in."""
    r = random.Random(seed)
    parts: list[str] = []
    n = 0
    i = 0
    while n < size:
        rec = make_record(r, i)
        s = f"{rec['name']} ({rec['email']}) said: {rec['note']}."
        if "ssn" in rec:
            s += f" SSN on file {rec['ssn']}."
        parts.append(s)
        n += len(s) + 1
        i += 1
    return " ".join(parts)[:max(size, 1)]


def percentile(xs: list[float], q: float) -> float:
    xs = sorted(xs)
    if len(xs) == 1:
        return xs[0]
    k = (len(xs) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def bench(fn, *, budget_s: float, min_iter: int, max_iter: int, after=None) -> list[float]:
    """Run fn repeatedly until the time budget or max_iter; return per-call seconds."""
    times: list[float] = []
    start = time.perf_counter()
    while len(times) < max_iter and (len(times) < min_iter or time.perf_counter() - start < budget_s):
        t0 = time.perf_counter()
        fn()
        times.append(time.perf_counter() - t0)
        if after:
            after()
    return times


def summarize(times: list[float], nbytes: int) -> dict:
    mean = statistics.fmean(times)
    return {"n": len(times),
            "p50_ms": percentile(times, 0.50) * 1e3,
            "p95_ms": percentile(times, 0.95) * 1e3,
            "p99_ms": percentile(times, 0.99) * 1e3,
            "mean_ms": mean * 1e3,
            "calls_per_s": 1 / mean if mean else None,
            "kb_per_s": (nbytes / 1e3) / mean if mean else None}


COLD_SNIPPET = r"""
import json, sys, time
t0 = time.perf_counter()
sys.path.insert(0, sys.argv[1])
import taintward.sdk.detect as d
t1 = time.perf_counter()
d._get_analyzer()
t2 = time.perf_counter()
d.detect_text("My SSN is 536-22-8491")
t3 = time.perf_counter()
print(json.dumps({"import_s": t1 - t0, "analyzer_build_s": t2 - t1, "first_call_s": t3 - t2,
                  "total_s": t3 - t0}))
"""


def cold_init(runs: int) -> dict:
    out = []
    for _ in range(runs):
        p = subprocess.run([sys.executable, "-c", COLD_SNIPPET, str(ROOT)],
                           capture_output=True, text=True, check=True)
        out.append(json.loads(p.stdout.strip().splitlines()[-1]))
    keys = out[0].keys()
    return {"runs": runs, "median": {k: statistics.median(o[k] for o in out) for k in keys},
            "all": out}


def machine_info() -> dict:
    cpu = platform.processor()
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    mem_gb = None
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal"):
                mem_gb = round(int(line.split()[1]) / 1024 / 1024, 1)
    except OSError:
        pass
    vers = {}
    for p in ["presidio-analyzer", "spacy", "en-core-web-sm", "opentelemetry-sdk", "ff3"]:
        try:
            vers[p] = md.version(p)
        except md.PackageNotFoundError:
            vers[p] = None
    return {"cpu": cpu, "logical_cpus": os.cpu_count(), "ram_gb": mem_gb,
            "os": f"{platform.system()} {platform.release()}",
            "python": platform.python_version(), "packages": vers}


def main() -> None:
    ap = argparse.ArgumentParser(description="Runtime-overhead benchmark for the Taintward SDK")
    ap.add_argument("--budget", type=float, default=8.0, help="seconds per (operation, size)")
    ap.add_argument("--cold-runs", type=int, default=3)
    ap.add_argument("--quick", action="store_true", help="small budget for a smoke run")
    ap.add_argument("--out-dir", default=str(ROOT / "bench" / "results"))
    ap.add_argument("--name", default="latency", help="output file name (without extension)")
    args = ap.parse_args()
    budget = 1.0 if args.quick else args.budget

    print("measuring cold init in fresh subprocesses ...", flush=True)
    cold = cold_init(1 if args.quick else args.cold_runs)

    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    from taintward.sdk import detect
    from taintward.sdk import instrumentation as instr
    from taintward.sdk.redact import redact_payload

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("taintward-bench")

    def echo(payload):
        return payload

    wrapped = instr.instrument_tool("bench.echo", destination=instr.DEST_EXTERNAL, tracer=tracer)(echo)

    clear = getattr(detect, "clear_cache", lambda: None)  # older detect.py had no cache

    def reset():
        exporter.clear()
        instr.end_run()  # drop the taint frames the wrapper attaches between calls

    def reset_cold():
        reset()
        clear()

    detect.detect_text("warm up")
    redact_payload({"x": "warm up 536-22-8491"}, instr.DEST_EXTERNAL)
    wrapped({"x": "warm up"})
    reset()

    results: dict = {}
    for label, size in SIZES.items():
        payload = make_payload(size)
        text = make_text(size)
        nbytes = len(json.dumps(payload).encode())
        ops = {
            "detect_mapping": lambda: detect.detect_mapping(payload),
            "detect_text": lambda: detect.detect_text(text),
            "redact_payload": lambda: redact_payload(payload, instr.DEST_EXTERNAL),
            "tool_unwrapped": lambda: echo(payload),
            "tool_wrapped": lambda: wrapped(payload),
            "tool_wrapped_cached": lambda: wrapped(payload),
        }
        results[label] = {"payload_bytes": nbytes, "text_chars": len(text),
                          "leaf_values": sum(len(r) for r in payload)}
        for op, fn in ops.items():
            heavy = op != "tool_unwrapped"
            if op == "tool_wrapped_cached":
                fn()  # see the payload once, so every timed call is a cache hit
                after = reset
            else:
                after = reset_cold if heavy else None
                clear()
            times = bench(fn, budget_s=budget, min_iter=3 if heavy else 1000,
                          max_iter=400 if heavy else 100_000, after=after)
            results[label][op] = summarize(times, len(text) if op == "detect_text" else nbytes)
            print(f"{label:>6} {op:<15} n={len(times):<6} p50={results[label][op]['p50_ms']:.3f}ms "
                  f"p99={results[label][op]['p99_ms']:.3f}ms", flush=True)
        w, u = results[label]["tool_wrapped"], results[label]["tool_unwrapped"]
        results[label]["wrap_overhead_p50_ms"] = w["p50_ms"] - u["p50_ms"]

    res = {"machine": machine_info(), "budget_s": budget, "cold_init": cold, "warm": results}
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{args.name}.json").write_text(json.dumps(res, indent=2) + "\n")
    md_text = to_markdown(res)
    (out / f"{args.name}.md").write_text(md_text)
    print(md_text)


def to_markdown(res: dict) -> str:
    m = res["machine"]
    c = res["cold_init"]["median"]
    L = ["# Latency benchmark", "",
         f"Machine: {m['cpu']}, {m['logical_cpus']} logical CPUs, {m['ram_gb']} GB RAM, "
         f"{m['os']}, Python {m['python']}.", "",
         "Packages: " + ", ".join(f"{k} {v}" for k, v in m["packages"].items()), "",
         f"## Cold init (median of {res['cold_init']['runs']} fresh processes)", "",
         "| step | seconds |", "|---|---:|",
         f"| import taintward.sdk.detect | {c['import_s']:.2f} |",
         f"| build Presidio analyzer (loads spaCy model) | {c['analyzer_build_s']:.2f} |",
         f"| first detect_text call | {c['first_call_s']:.2f} |",
         f"| **total** | **{c['total_s']:.2f}** |", "",
         "## Warm, per call", "",
         "| size | operation | n | p50 ms | p95 ms | p99 ms | calls/s | KB/s |",
         "|---|---|---:|---:|---:|---:|---:|---:|"]
    for label, r in res["warm"].items():
        for op in ["detect_mapping", "detect_text", "redact_payload", "tool_unwrapped", "tool_wrapped",
                   "tool_wrapped_cached"]:
            if op not in r:
                continue
            s = r[op]
            L.append(f"| {label} | {op} | {s['n']} | {s['p50_ms']:.3f} | {s['p95_ms']:.3f} | "
                     f"{s['p99_ms']:.3f} | {s['calls_per_s']:.1f} | {s['kb_per_s']:.1f} |")
    L += ["", "## Overhead of wrapping a tool with instrument_tool (p50)", "",
          "| size | payload bytes | leaf values | wrapped p50 ms | unwrapped p50 ms | overhead ms |",
          "|---|---:|---:|---:|---:|---:|"]
    for label, r in res["warm"].items():
        L.append(f"| {label} | {r['payload_bytes']} | {r['leaf_values']} | "
                 f"{r['tool_wrapped']['p50_ms']:.3f} | {r['tool_unwrapped']['p50_ms']:.4f} | "
                 f"{r['wrap_overhead_p50_ms']:.3f} |")
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    main()
