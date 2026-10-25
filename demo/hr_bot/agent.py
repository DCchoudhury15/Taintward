"""A small rule-based HR agent that drives the five tools.

Phase 2 is about the SDK plumbing (taint propagation), not agent intelligence,
so the planner is deterministic: it routes a user query to a fixed tool sequence.
A real LangGraph/CrewAI loop would slot in here with no change to the SDK.

The agent emits one trace per run (``begin_run``/``end_run``) and uses **span
links** to record that every tool call was fanned out from a single decision
span, the fan-out/fan-in pattern the lineage map needs (see
docs/agentraft-mapping.md section D, span links).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from opentelemetry import trace

from demo.hr_bot import tools
from taintward.sdk import instrumentation as instr


def run_agent(
    query: str,
    *,
    employee_id: str = "alice",
    llm_mode: str = "passthrough",
    llm: str = "stub",
    provider: str = "openai",
) -> str:
    """Run the HR bot for one query. Returns the final external API ack."""
    instr.begin_run("hr_bot.run")
    tracer = trace.get_tracer("taintward")
    try:
        # The decision span captures the agent's plan. Tool calls fan out from
        # it via span links (they are siblings under the run root, each linked
        # back to the decision, giving a correct fan-out DAG for the lineage map).
        with tracer.start_as_current_span("agent.decide", kind=trace.SpanKind.INTERNAL) as decide:
            decide.set_attribute("taintward.query", query)
            decide_ctx = decide.get_span_context()

        # 1. internal: read the employee record (taint originates here in the
        #    breach scenario, where the DB holds an SSN + AWS key).
        record = tools.query_db(employee_id, taintward_links=[decide_ctx])
        # 1b. internal: persist the record to the internal cache. The SDK
        # egress gate redacts the SSN/key to REVERSIBLE FPE tokens (internal
        # sink), so the cache holds tokens, not raw PII, yet they round-trip.
        tools.internal_store(employee_id, record, taintward_links=[decide_ctx])
        # 2. llm: rephrase the record (the LLM hop, where taint must survive).
        prompt = f"employee {employee_id}: {record}"
        summary = tools.ask_llm(prompt, mode=llm_mode, llm=llm, provider=provider,
                                 taintward_links=[decide_ctx])
        # 3. rag: retrieve supporting chunks (fan-out, links to decide).
        _chunks = tools.rag_retrieve(f"policy for {employee_id}",
                                      taintward_links=[decide_ctx])
        # 4. external: send the summary to the auditor API, the leak sink.
        ack = tools.call_external_api(summary, taintward_links=[decide_ctx])
        # 5. log: write an audit line (also a sink, PII must not be logged).
        tools.write_log(f"processed {employee_id}: {summary}",
                         taintward_links=[decide_ctx])
        return ack
    finally:
        instr.end_run()