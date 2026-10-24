"""CLI for the AgentWard tamper-evident violation log.

Examples:
    # record recent collector violations from SigNoz into the log file
    python3 evidence/log.py record --service agentward-hr-bot --since-mins 10

    # show the current root
    python3 evidence/log.py root

    # prove leaf 0 is in the log (inclusion proof + verify)
    python3 evidence/log.py prove 0

    # verify a previously-printed proof against the current root
    python3 evidence/log.py verify '{"leaf_index":0,"leaf_hash":"...","siblings":[...]}'

The log file defaults to evidence/violations.logl (one JSON record per line,
append-only).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evidence.merkle import InclusionProof, MerkleLog, verify_inclusion
from evidence.recorder import record_violations

DEFAULT_LOG = Path(__file__).resolve().parent / "violations.logl"


def _open(path: Path) -> MerkleLog:
    return MerkleLog(path)


def main() -> int:
    ap = argparse.ArgumentParser(description="AgentWard tamper-evident violation log")
    ap.add_argument("--log-file", default=str(DEFAULT_LOG))
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_rec = sub.add_parser("record", help="record recent collector violations from SigNoz")
    p_rec.add_argument("--service", default="agentward-hr-bot")
    p_rec.add_argument("--since-mins", type=int, default=10)

    sub.add_parser("root", help="print the current Merkle root (hex)")
    p_prove = sub.add_parser("prove", help="print + verify the inclusion proof for a leaf")
    p_prove.add_argument("index", type=int)
    p_ver = sub.add_parser("verify", help="verify a proof JSON against the current root")
    p_ver.add_argument("proof_json")
    sub.add_parser("count", help="number of leaves in the log")

    args = ap.parse_args()
    log = _open(Path(args.log_file))

    if args.cmd == "record":
        n = record_violations(log, service=args.service, since_minutes=args.since_mins)
        print(f"recorded {n} violation(s); log now has {len(log)} leaf/leaves")
        print(f"root: {log.root().hex()}")
    elif args.cmd == "root":
        print(log.root().hex())
    elif args.cmd == "count":
        print(len(log))
    elif args.cmd == "prove":
        if not 0 <= args.index < len(log):
            print(f"index {args.index} out of range (log has {len(log)} leaves)", file=sys.stderr)
            return 1
        proof = log.inclusion_proof(args.index)
        root = log.root()
        ok = verify_inclusion(proof.leaf_hash, proof, root)
        print(json.dumps({
            "leaf_index": proof.leaf_index,
            "leaf_record": log.record(args.index),
            "leaf_hash": proof.leaf_hash.hex(),
            "siblings": [s.hex() for s in proof.siblings],
            "root": root.hex(),
            "verified": ok,
        }, indent=2))
        return 0 if ok else 2
    elif args.cmd == "verify":
        proof = InclusionProof.from_json(args.proof_json)
        ok = verify_inclusion(proof.leaf_hash, proof, log.root())
        print(json.dumps({"verified": ok, "root": log.root().hex()}, indent=2))
        return 0 if ok else 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())