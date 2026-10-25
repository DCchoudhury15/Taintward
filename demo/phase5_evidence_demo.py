"""Phase 5 evidence demo: collector violations -> tamper-evident Merkle log.

Run after a breach (e.g. via the sidecar) so ClickHouse has recent violations:
    python3 demo/hr_bot/breach_simulator.py --endpoint http://localhost:4319/v1/traces
    python3 demo/phase5_evidence_demo.py

The demo:
  1. records recent collector policy violations from SigNoz into the Merkle log,
  2. prints the current root + count,
  3. proves leaf 0 is in the log (inclusion proof + verify),
  4. demonstrates tamper detection: a modified record produces a different
     root, and the original proof no longer verifies against it.

This is the "cryptographically verifiable Article 30/15 evidence" step: the
lineage/blast-radius dashboards (metrics) become provable records.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from taintward.evidence.merkle import MerkleLog, verify_inclusion, violation_record
from taintward.evidence.recorder import record_violations


def main() -> int:
    log_path = Path(tempfile.gettempdir()) / "taintward_phase5_demo.logl"
    if log_path.exists():
        log_path.unlink()
    log = MerkleLog(log_path)

    print("=== recording recent collector violations from SigNoz ===")
    try:
        n = record_violations(log, service="taintward-hr-bot", since_minutes=60)
    except Exception as e:
        print(f"could not read ClickHouse (is SigNoz up? run a breach first?): {e}")
        # fall back to synthetic records so the demo still proves the crypto
        for tool in ["ask_llm", "call_external_api", "write_log"]:
            log.append(violation_record(
                trace_id="t" + tool, span_id="s" + tool, tool=tool,
                destination="external" if tool != "write_log" else "log",
                jurisdiction="us", classes="pii,secret",
                reasons="transfer,pii_egress" if tool != "write_log" else "pii_egress",
                timestamp_ns=1700000000_000000000,
            ))
        n = len(log)
        print(f"  (used {n} synthetic violation records as fallback)")
    else:
        print(f"  recorded {n} violation(s); log has {len(log)} leaf/leaves")

    root = log.root()
    print(f"\nMerkle root: {root.hex()}")
    print(f"leaves: {len(log)}")

    if len(log) == 0:
        print("no violations to prove, run the breach first")
        return 1

    print("\n=== inclusion proof for leaf 0 ===")
    proof = log.inclusion_proof(0)
    ok = verify_inclusion(proof.leaf_hash, proof, root)
    rec = log.record(0)
    print(json.dumps({
        "leaf_record": rec,
        "verified": ok,
        "siblings": len(proof.siblings),
    }, indent=2))
    assert ok, "inclusion proof must verify"

    print("\n=== tamper detection ===")
    # Build a log whose leaf 0 record is modified -> root must differ, and the
    # ORIGINAL proof must fail against the tampered root.
    tampered = MerkleLog()
    for i in range(len(log)):
        r = dict(log.record(i))  # copy
        if i == 0:
            r["tool"] = "TAMPERED"
        tampered.append(r)
    tampered_root = tampered.root()
    print(f"original root: {root.hex()}")
    print(f"tampered root: {tampered_root.hex()}")
    print(f"roots differ: {root != tampered_root}")
    stale_ok = verify_inclusion(proof.leaf_hash, proof, tampered_root)
    print(f"original proof verifies against tampered root: {stale_ok} (must be False)")
    assert root != tampered_root, "tamper must change the root"
    assert not stale_ok, "stale proof must not verify against tampered root"

    print("\n=== conclusion ===")
    print(f"Violations are now tamper-evident: {len(log)} leaves, root {root.hex()[:16]}…")
    print("Any edit to a record changes the root; any prior proof fails to verify.")
    print("This is cryptographically verifiable Art. 30/15 evidence, not a dashboard.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())