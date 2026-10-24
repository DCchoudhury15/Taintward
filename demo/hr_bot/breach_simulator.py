"""Breach simulator: injects an SSN and an AWS key so the whole pipeline fires.

The "breach-simulator button" from the original pitch: seed the internal DB
with a record containing an SSN and an AWS access key (the kind of credential
leak a static field-name mask would miss), then run the HR agent. The taint
originates at ``query_db`` (internal), flows through ``ask_llm`` (the LLM hop),
and reaches ``call_external_api`` and ``write_log``, both flagged as violations.

Run:
    python3 demo/hr_bot/breach_simulator.py
    python3 demo/hr_bot/breach_simulator.py --llm real --provider openai
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from opentelemetry import trace

from demo.hr_bot import tools
from demo.hr_bot.agent import run_agent
from sdk import instrumentation as instr


def seed_breach() -> None:
    """Seed the DB with a record that contains PII + a secret."""
    tools.seed_db("alice", {
        "employee": "Alice Lee",
        "ssn": "234-12-1234",
        "manager": "Bob Perez",
        "deploy_key": "AKIAIOSFODNN7EXAMPLE",  # the credential leak
    })


def main() -> int:
    ap = argparse.ArgumentParser(description="AgentWard HR bot breach simulator")
    ap.add_argument("--service", default="agentward-hr-bot")
    ap.add_argument("--endpoint", default=instr.DEFAULT_OTLP_HTTP,
                    help="OTLP/HTTP endpoint (default: SigNoz direct; point at the "
                         "Phase 3 sidecar at http://localhost:4319/v1/traces)")
    ap.add_argument("--console", action="store_true", help="also export spans to stdout")
    ap.add_argument("--llm", choices=["stub", "real"], default="stub")
    ap.add_argument("--provider", choices=["openai", "anthropic"], default="openai")
    ap.add_argument("--mode", choices=["passthrough", "reformat", "summarize"],
                    default="passthrough", help="stub LLM transformation mode")
    args = ap.parse_args()

    instr.configure_tracing(args.service, endpoint=args.endpoint, console=args.console)
    seed_breach()

    print("=== breach simulator: injected SSN + AWS key into HR DB ===")
    print("running agent: query_db -> internal_store -> ask_llm -> rag_retrieve -> "
          "call_external_api -> write_log\n")

    ack = run_agent(
        "Summarize Alice's record and send it to the auditor",
        employee_id="alice",
        llm_mode=args.mode,
        llm=args.llm,
        provider=args.provider,
    )

    try:
        trace.get_tracer_provider().force_flush(timeout_millis=5000)  # type: ignore[attr-defined]
    except Exception:
        pass

    print(f"\nexternal API ack: {ack}")
    print("\nInspect in SigNoz: service=agentward-hr-bot, "
          "filter agentward.violation=true (should see call_external_api + write_log)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())