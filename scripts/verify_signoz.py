"""Phase 1 substrate check: emit one hand-crafted OTLP/HTTP trace to local SigNoz.

No OpenTelemetry SDK dependency, it sends a raw OTLP/JSON trace to the collector's
OTLP/HTTP endpoint (localhost:4318/v1/traces). Validates that SigNoz ingests and
stores a trace before Phase 2 builds the real SDK on top of this substrate.

IMPORTANT: an OTLP/HTTP 200 only means the collector's *receiver* accepted the
payload into its pipeline -- it says nothing about whether the exporter
downstream actually got the batch into ClickHouse (that happens async, after
the response is already sent). Confirmed empirically: stopping the ClickHouse
container and re-running this script still gets HTTP 200 / partialSuccess
from the collector, and that trace_id then never appears in ClickHouse. So a
POST-status-only check can report SUCCESS for a trace that never landed. This
script therefore polls ClickHouse directly for the emitted trace_id before
declaring success.

Run:
    python3 scripts/verify_signoz.py
"""

from __future__ import annotations

import json
import secrets
import subprocess
import sys
import time
import urllib.request

OTLP_HTTP = "http://localhost:4318/v1/traces"
SERVICE_NAME = "taintward-verify"
CLICKHOUSE_CONTAINER = "signoz-telemetrystore-clickhouse-0-0"
CLICKHOUSE_POLL_TIMEOUT_S = 20
CLICKHOUSE_POLL_INTERVAL_S = 1


def _span(now_ns: int, trace_id: str, parent_id: str | None, span_id: str, name: str, attrs: dict[str, str]):
    span = {
        "traceId": trace_id,
        "spanId": span_id,
        "name": name,
        "kind": "SPAN_KIND_INTERNAL",
        "startTimeUnixNano": str(now_ns),
        "endTimeUnixNano": str(now_ns + 1_000_000),  # 1ms
        "attributes": [
            {"key": k, "value": {"stringValue": v}} for k, v in attrs.items()
        ],
    }
    if parent_id is not None:
        span["parentSpanId"] = parent_id
    return span


def emit() -> dict:
    trace_id = secrets.token_hex(16)  # 32 hex chars
    root_id = secrets.token_hex(8)    # 16 hex chars
    child_id = secrets.token_hex(8)
    now = time.time_ns()

    payload = {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": SERVICE_NAME}},
                        {"key": "taintward.phase", "value": {"stringValue": "phase1"}},
                    ]
                },
                "scopeSpans": [
                    {
                        "scope": {"name": "taintward.verify"},
                        "spans": [
                            _span(now, trace_id, None, root_id,
                                  "phase1.handcrafted.root",
                                  {"taintward.note": "substrate-verify"}),
                            _span(now + 100_000, trace_id, root_id, child_id,
                                  "phase1.handcrafted.child",
                                  {"taintward.tag": "taint.pii=true"}),
                        ],
                    }
                ],
            }
        ]
    }

    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        OTLP_HTTP,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        status = resp.status
        resp_body = resp.read().decode()
    return {
        "trace_id": trace_id,
        "root_span_id": root_id,
        "status": status,
        "response": resp_body,
    }


def _count_in_clickhouse(trace_id: str) -> int:
    """Query ClickHouse directly for spans with this trace_id. Returns the row
    count (0 if none found yet, or the query itself fails)."""
    query = (
        "SELECT count() FROM signoz_traces.distributed_signoz_index_v3 "
        f"WHERE trace_id = '{trace_id}'"
    )
    proc = subprocess.run(
        ["docker", "exec", CLICKHOUSE_CONTAINER, "clickhouse-client", "--query", query],
        capture_output=True, text=True, timeout=10,
    )
    if proc.returncode != 0:
        return 0
    try:
        return int(proc.stdout.strip())
    except ValueError:
        return 0


def confirm_landed(trace_id: str, timeout_s: float = CLICKHOUSE_POLL_TIMEOUT_S) -> bool:
    """Poll ClickHouse until the emitted trace_id actually shows up (export is
    async, so it may take a moment after the OTLP 200), or the timeout expires."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _count_in_clickhouse(trace_id) > 0:
            return True
        time.sleep(CLICKHOUSE_POLL_INTERVAL_S)
    return _count_in_clickhouse(trace_id) > 0


def main() -> int:
    print(f"POSTing hand-crafted trace to {OTLP_HTTP} ...")
    result = emit()
    print(json.dumps(result, indent=2))
    if result["status"] != 200:
        print(f"\nFAILED: OTLP ingestion returned {result['status']}", file=sys.stderr)
        return 1

    # A 200 here only confirms the collector's receiver accepted the payload,
    # NOT that it was actually exported into ClickHouse (that's async and can
    # fail silently from this script's point of view). Confirm the trace
    # really landed before calling it a success.
    print(f"\nCollector accepted the payload (HTTP 200). Polling ClickHouse "
          f"(up to {CLICKHOUSE_POLL_TIMEOUT_S}s) to confirm it actually landed...")
    try:
        landed = confirm_landed(result["trace_id"])
    except (subprocess.SubprocessError, OSError, FileNotFoundError) as exc:
        print(f"\nFAILED: could not query ClickHouse to confirm ingestion ({exc}). "
              "A 200 from the collector alone does NOT prove the trace was stored.",
              file=sys.stderr)
        return 1

    if not landed:
        print(f"\nFAILED: collector returned 200 but traceId={result['trace_id']} "
              f"never appeared in ClickHouse after {CLICKHOUSE_POLL_TIMEOUT_S}s. "
              "The substrate is NOT verified.", file=sys.stderr)
        return 1

    print("\nSUCCESS: trace ingested AND confirmed in ClickHouse. Open "
          f"http://localhost:8080/ and look for service '{SERVICE_NAME}'.")
    print(f"traceId: {result['trace_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())