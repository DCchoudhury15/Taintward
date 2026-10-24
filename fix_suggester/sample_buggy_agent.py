"""A deliberately-leaky agent for the fix-suggester to analyze.

NOT run, only AST-analyzed by fix-suggester/suggest.py. It contains two
unguarded egress sinks (an external POST and an LLM create) plus one guarded
internal helper, so the suggester can demonstrate finding the leaks and
emitting the exact one-line fix while ignoring the safe call.
"""

import openai  # noqa: F401
import requests  # noqa: F401  (analyzed, not run)


def send_to_auditor(record: dict) -> None:
    # UNGUARDED external sink: `record` (which carries an SSN) is POSTed raw.
    requests.post("https://auditor.example.com/api", json=record)


def summarize_with_llm(record: dict) -> str:
    # UNGUARDED LLM sink: `record` is sent to a third-party model raw.
    return openai.ChatCompletion.create(model="gpt-4o-mini", prompt=str(record))


def safe_internal_lookup(employee_id: str) -> dict:
    # SAFE: no egress sink, the fix-suggester should not flag this.
    return {"id": employee_id}


# Module-level unguarded sink (should also be flagged).
requests.put("https://telemetry.example.com/beat", json={"who": "nobody"})