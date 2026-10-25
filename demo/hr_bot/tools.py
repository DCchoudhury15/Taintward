"""The HR bot's five tools, each wrapped with taint-aware instrumentation.

Destinations are the Phase 3 policy classes:
  query_db          -> internal   (the HR database)
  call_external_api -> external   (a third-party service, e.g. an auditor API)
  ask_llm           -> llm        (a third-party model, also a sink)
  write_log         -> log        (a logging sink)
  rag_retrieve      -> rag        (retrieval over a vector store)

The internal DB is seeded with a tainted record by ``breach_simulator``; in the
breach scenario the agent flows PII through the LLM to the external API, which
the SDK-side egress gate flags as a violation.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from taintward.sdk import instrumentation as instr

# In-memory "database" seeded by the breach simulator.
_DB: dict[str, dict] = {}

# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@instr.instrument_tool("query_db", destination=instr.DEST_INTERNAL)
def query_db(employee_id: str) -> dict:
    """Read an employee record from the internal HR database."""
    return _DB.get(employee_id, {"error": f"no record for {employee_id}"})


# In-process "internal cache", written by internal_store (Phase 4 demo).
_INTERNAL_CACHE: dict[str, dict] = {}


@instr.instrument_tool("internal_store", destination=instr.DEST_INTERNAL)
def internal_store(key: str, record: dict) -> str:
    """Write a record to the trusted internal cache. Because this is an
    INTERNAL sink, the SDK egress gate redacts sensitive fields in the
    ``record`` arg to REVERSIBLE FPE tokens before this tool runs, so the cache
    holds tokens, not raw PII, yet they can be reversed by the redactor."""
    _INTERNAL_CACHE[key] = record
    return f"stored {key} ({len(record)} fields, redacted)"


@instr.instrument_tool("ask_llm", destination=instr.DEST_LLM, jurisdiction="us")
def ask_llm(prompt: str, *, mode: str = "passthrough",
            llm: str = "stub", provider: str = "openai") -> str:
    """Ask the LLM to (re)phrase. The LLM is itself a sink, so this span is
    egress-checked. Stub modes mirror the spike; real path activated by a key.
    """
    if llm == "stub":
        if mode == "passthrough":
            return f"Summary: {prompt}"
        if mode == "reformat":
            return f"Summary: {prompt.replace('-', '')}"
        if mode == "summarize":
            return "Summary: the employee's record has been reviewed."
        raise ValueError(f"unknown stub mode {mode}")
    import openai  # type: ignore
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        raise SystemExit("OPENAI_API_KEY not set")
    resp = openai.OpenAI(api_key=key).chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": f"Summarize in one sentence: {prompt}"}],
    )
    return resp.choices[0].message.content  # type: ignore[index]


@instr.instrument_tool("call_external_api", destination=instr.DEST_EXTERNAL, jurisdiction="us")
def call_external_api(payload: str) -> str:
    """Send a payload to a third-party external API, the leak sink."""
    return f"ACK from external service (received {len(payload)} chars)"


@instr.instrument_tool("write_log", destination=instr.DEST_LOG)
def write_log(message: str) -> None:
    """Write a log line. Logs are a sink too (PII must not be logged)."""
    return None


@instr.instrument_tool("rag_retrieve", destination=instr.DEST_RAG)
def rag_retrieve(query: str, *, chunks: int = 3) -> list[str]:
    """Retrieve chunks from a vector store. Demonstrates fan-out via span
    links: each chunk retrieval is a span linked back to the agent's decision
    span (passed by the agent as ``taintward_links``).

    NOTE: embeddings are invertible (OWASP LLM08:2025), so Phase 5 will add
    redact-before-embed here. For Phase 2 we only propagate taint.
    """
    # The links (if any) were already consumed by the decorator on this span.
    # Here we just return plausible chunks; the fan-out lineage is the link.
    return [f"chunk[{i}] about {query}" for i in range(chunks)]


def seed_db(employee_id: str, record: dict) -> None:
    """Seed the in-memory DB (used by the breach simulator)."""
    _DB[employee_id] = record