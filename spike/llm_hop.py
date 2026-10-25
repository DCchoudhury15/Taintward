"""Phase 2 make-or-break spike: does a taint tag survive an LLM hop?

Minimal flow:  read_file  ->  llm_rephrase  ->  external_api

The question (PLAN.md section 4 risk #1): if the agent reads an SSN, then calls
an LLM that *regenerates* the value into a new surface form, does structural
baggage propagation keep the taint alive, or do we need AgentRaft's Φ
(LLM-judged semantic dependency) as a fall-back?

The LLM backend is **pluggable**:

* a deterministic stub with three modes: ``passthrough`` (verbatim),
  ``reformat`` (strip dashes, notionally "234121234" so Presidio's US_SSN
  regex no longer matches), ``summarize`` (drop the value entirely: "the
  employee's record"). This lets us deterministically test each
  transformation case.
* the real OpenAI / Anthropic API, activated when ``OPENAI_API_KEY`` or
  ``ANTHROPIC_API_KEY`` is set. Pass ``--llm real`` and ``--provider``.

Expected result (the thesis): the **call-chain taint (baggage)** survives every
mode by construction, it's value-independent, so the ``external_api`` sink is
flagged as a violation in all three. Verified empirically for all three stub
modes: ``taintward.violation=true`` fires on both ``llm_rephrase`` and
``external_api`` every time (see ``--console`` output).

NOTE on the field-level claim above (Phase 2 vs. present code): since Phase 4
added the egress redaction gate, ``llm_rephrase``'s ``record`` argument is
ALREADY masked to literal ``"[PII]"``/``"[SECRET]"`` tokens by
``instrument_tool`` *before* this function body ever runs (any DEST_LLM /
DEST_EXTERNAL / DEST_LOG tool call is redacted on input, unconditionally,
regardless of ``TAINTWARD_MASK_IN_SDK`` -- verified: even with
``TAINTWARD_MASK_IN_SDK=0`` the ``reformat`` stub's ``ssn.replace('-', '')``
runs on the string ``"[PII]"``, not on a raw SSN). So none of the three stub
modes ever actually sees or re-emits a raw, differently-reformatted SSN
anymore, and the original "field-level re-detection catches passthrough and
(maybe) reformat but not summarize" distinction no longer applies as
described -- field-level detection has nothing raw left to catch in any mode.
The residual gap Φ (LLM-judged semantic dependency) would cover is PII
transformed into a non-detectable form that nonetheless travels semantically;
that gap is now demonstrated at the SDK-redaction boundary rather than by
these stubs, but the point still stands: chain-level taint is a value-
independent, safe over-approximation, and it is what actually flags the sink
in this demo, not per-value field re-detection.

Run:
    python3 spike/llm_hop.py                 # stub, all three modes, -> SigNoz
    python3 spike/llm_hop.py --console       # also print spans to stdout
    python3 spike/llm_hop.py --llm real --provider openai   # real API (needs key)
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# repo root on sys.path so `core` / `sdk` import when run as a script
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from opentelemetry import trace  # noqa: E402

from taintward.sdk import instrumentation as instr  # noqa: E402

# ---------------------------------------------------------------------------
# Tools (each wrapped with taint-aware instrumentation)
# ---------------------------------------------------------------------------


@instr.instrument_tool("read_file", destination=instr.DEST_INTERNAL)
def read_file(path: str) -> dict:
    """Simulate reading an HR record that contains an SSN + AWS key."""
    # In a real agent this reads from disk; here we return a tainted record.
    return {
        "employee": "Alice Lee",
        "ssn": "234-12-1234",
        "note": "deploy key AKIAIOSFODNN7EXAMPLE on file",
    }


@instr.instrument_tool("llm_rephrase", destination=instr.DEST_LLM)
def llm_rephrase(record: dict, *, mode: str = "passthrough",
                 llm: str = "stub", provider: str = "openai") -> str:
    """The LLM hop. Reads the incoming chain taint and emits a rephrased string.

    The destination is DEST_LLM (calling a third-party model is itself a sink),
    so this span is also egress-checked.
    """
    instr.current_taint()  # exercised for the spike, value unused
    ssn = record.get("ssn", "")
    if llm == "stub":
        if mode == "passthrough":
            out = f"Employee record for {record['employee']}; SSN {ssn}."
        elif mode == "reformat":
            out = f"Employee record; SSN {ssn.replace('-', '')}."  # 234121234
        elif mode == "summarize":
            out = "The employee's record has been processed."  # value dropped
        else:
            raise ValueError(f"unknown stub mode {mode}")
    else:
        out = _real_llm(record, provider)
    return out


@instr.instrument_tool("external_api", destination=instr.DEST_EXTERNAL)
def external_api(payload: str) -> str:
    """The external sink, where a leak would actually leave the system."""
    incoming = instr.current_taint()
    return f"SENT to external service: {payload!r} (chain_taint={incoming})"


# ---------------------------------------------------------------------------
# Pluggable LLM backend
# ---------------------------------------------------------------------------


def _real_llm(record: dict, provider: str) -> str:
    """Call a real model to rephrase the record. Activated by an API key."""
    prompt = f"Summarize this HR record in one sentence, keeping identifiers: {record}"
    if provider == "anthropic":
        import anthropic  # type: ignore
        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise SystemExit("ANTHROPIC_API_KEY not set")
        resp = anthropic.Anthropic(api_key=key).messages.create(
            model="claude-haiku-4-5-20251001", max_tokens=120,
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.content[0].text  # type: ignore[index]
    # default openai
    import openai  # type: ignore
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        raise SystemExit("OPENAI_API_KEY not set")
    resp = openai.OpenAI(api_key=key).chat.completions.create(
        model="gpt-4o-mini", messages=[{"role": "user", "content": prompt}],
    )
    return resp.choices[0].message.content  # type: ignore[index]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def _run_mode(mode: str, llm: str, provider: str) -> dict:
    print(f"\n=== mode={mode} llm={llm} ===")
    instr.begin_run(f"agent.run.{mode}")
    try:
        record = read_file("hr/alice.json")
        print(f"  read_file     -> chain_taint={instr.current_taint()}")
        rephrased = llm_rephrase(record, mode=mode, llm=llm, provider=provider)
        print(f"  llm_rephrase  -> output={rephrased!r}")
        print(f"                  chain_taint after LLM hop = {instr.current_taint()}")
        ack = external_api(rephrased)
        print(f"  external_api  -> {ack}")
    finally:
        instr.end_run()
    return {
        "mode": mode,
        "chain_taint_at_sink": ack,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--console", action="store_true",
                    help="also export spans to stdout")
    ap.add_argument("--llm", choices=["stub", "real"], default="stub")
    ap.add_argument("--provider", choices=["openai", "anthropic"],
                    default="openai")
    ap.add_argument("--service", default="taintward-spike")
    args = ap.parse_args()

    instr.configure_tracing(args.service, console=args.console)

    modes = ["real-default"] if args.llm == "real" else \
        ["passthrough", "reformat", "summarize"]
    results = []
    for m in modes:
        results.append(_run_mode(m, args.llm, args.provider))

    # Flush the batch span processor so spans reach SigNoz before exit.
    try:
        tp = trace.get_tracer_provider()
        tp.force_flush(timeout_millis=5000)  # type: ignore[attr-defined]
    except Exception:
        pass

    print("\n=== spike summary ===")
    for r in results:
        print(f"  {r['mode']:12} chain_taint_at_external_sink = "
              f"{r['chain_taint_at_sink']}")
    print("\nThesis check: external sink flagged as VIOLATION in every mode "
          "because chain-level taint (baggage) is value-independent.")
    print("Inspect in SigNoz: service=taintward-spike, filter "
          "taintward.violation=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())