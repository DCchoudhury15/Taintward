"""Record collector-policy violations from SigNoz/ClickHouse into the Merkle log.

This is the wire from the policy decision (Phase 3 collector) to the evidence
layer (Phase 5): every span the collector flagged ``taintward.policy.violation``
becomes a leaf in the tamper-evident log, turning the violation into
cryptographically verifiable GDPR Art. 30/15 evidence.

The query runs via the host's ``docker exec ... clickhouse-client`` (the same
path used throughout the project for inspecting SigNoz). It returns
JSONEachRow so the records parse cleanly.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

# add repo root so `taintward.evidence.merkle` imports when run as a script
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from taintward.evidence.merkle import MerkleLog, violation_record

CONTAINER = "signoz-telemetrystore-clickhouse-0-0"
DATABASE = "signoz_traces"
TABLE = "distributed_signoz_index_v3"

_QUERY = """
SELECT
    trace_id, span_id, name AS tool,
    attributes_string['taintward.destination'] AS destination,
    attributes_string['taintward.jurisdiction'] AS jurisdiction,
    attributes_string['taintward.taint.classes'] AS classes,
    attributes_string['taintward.policy.reasons'] AS reasons,
    toInt64(toUnixTimestamp64Nano(timestamp)) AS timestamp_ns
FROM {db}.{tbl}
WHERE serviceName = '{svc}'
  AND attributes_bool['taintward.policy.violation'] = 1
  AND timestamp > now() - INTERVAL {mins} MINUTE
FORMAT JSONEachRow
"""


# OTel service names are conventionally DNS/identifier-like; this is
# deliberately restrictive rather than trying to enumerate every character
# that would need escaping in a ClickHouse string literal.
_SAFE_SERVICE_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def _query_clickhouse(service: str, since_minutes: int) -> list[dict]:
    # `service` and `since_minutes` are interpolated directly into the SQL
    # text below (clickhouse-client has no server-side parameter binding
    # over `docker exec ... -q`), so validate both strictly first - an
    # unescaped `service` value (e.g. containing a `'`) would otherwise let
    # a caller break out of the string literal and inject arbitrary SQL.
    if not _SAFE_SERVICE_RE.match(service):
        raise ValueError(f"unsafe service name: {service!r}")
    since_minutes = int(since_minutes)  # raises if not int-like; blocks injection via this field too
    q = _QUERY.format(db=DATABASE, tbl=TABLE, svc=service, mins=since_minutes)
    proc = subprocess.run(
        ["docker", "exec", CONTAINER, "clickhouse-client", "-q", q],
        capture_output=True, text=True, timeout=60,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"clickhouse-client failed: {proc.stderr.strip()}")
    rows = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    return rows


def record_violations(log: MerkleLog, *, service: str = "taintward-hr-bot",
                      since_minutes: int = 5) -> int:
    """Append every recent collector violation to ``log``; return how many
    were new. A violation already in the log (same trace_id and span_id) is
    skipped, so recording overlapping time windows adds no duplicates."""
    rows = _query_clickhouse(service, since_minutes)
    added = 0
    for r in rows:
        idx = log.append(violation_record(
            trace_id=r["trace_id"], span_id=r["span_id"], tool=r["tool"],
            destination=r["destination"], jurisdiction=r["jurisdiction"],
            classes=r["classes"], reasons=r["reasons"],
            timestamp_ns=int(r["timestamp_ns"]),
        ), unique=True)
        added += idx is not None
    return added