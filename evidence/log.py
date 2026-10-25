"""CLI for the AgentWard tamper-evident violation log.

Examples:
    # record recent collector violations from SigNoz into the log file
    python3 evidence/log.py record --service agentward-hr-bot --since-mins 10

    # show the current root
    python3 evidence/log.py root

    # prove leaf 0 is in the log (inclusion proof + verify)
    python3 evidence/log.py prove 0

    # verify a previously-printed proof against the current root
    python3 evidence/log.py verify '{"leaf_index":0,"leaf_hash":"...","siblings":[...],"directions":[...]}'

The log file defaults to ./violations.logl (or $AGENTWARD_EVIDENCE_LOG) (one JSON record per line,
append-only).

Sharded log with signed checkpoints (see docs/evidence-report.md):

    # one-time: make a signing key pair (keep the private key secret)
    python3 evidence/log.py keygen --private-key evidence.key --public-key evidence.pub

    # record violations from Jaeger into <dir>/<tenant>/<YYYY-MM-DD>.logl
    python3 evidence/log.py record --source jaeger --service agentward-hr-bot \\
        --since-mins 60 --evidence-dir evidence-log --tenant acme

    # sign a checkpoint over all shards, then verify everything
    python3 evidence/log.py checkpoint --evidence-dir evidence-log --private-key evidence.key
    python3 evidence/log.py verify-checkpoints --evidence-dir evidence-log \\
        --public-key evidence.pub

    # prove one record against the newest checkpoint, verify it offline
    python3 evidence/log.py prove-shard --evidence-dir evidence-log --tenant acme \\
        --day 2026-10-24 --index 0 > proof.json
    python3 evidence/log.py verify-proof proof.json --public-key evidence.pub
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evidence.merkle import InclusionProof, MerkleLog, verify_inclusion
from evidence.recorder import record_violations

# Current directory by default, never inside the installed package.
DEFAULT_LOG = Path(os.environ.get("AGENTWARD_EVIDENCE_LOG", "violations.logl"))
DEFAULT_DIR = os.environ.get("AGENTWARD_EVIDENCE_DIR")


def _open(path: Path) -> MerkleLog:
    return MerkleLog(path)


def _dir_arg(p: argparse.ArgumentParser, required: bool = True) -> None:
    p.add_argument("--evidence-dir", default=DEFAULT_DIR,
                   required=required and not DEFAULT_DIR,
                   help="sharded evidence log directory (or $AGENTWARD_EVIDENCE_DIR)")


def _record_from_source(args) -> int:
    """Record violations from any report source into the single or sharded log."""
    from evidence.report import (
        is_tool_call,
        is_violation,
        source_from_args,
        span_violation_record,
    )

    end_ns = time.time_ns()
    start_ns = end_ns - int(args.since_mins) * 60 * 1_000_000_000
    if not args.service:
        args.service = ["agentward-hr-bot"]
    src = source_from_args(args)
    spans = sorted((s for s in src.fetch(start_ns, end_ns) if is_tool_call(s) and is_violation(s)),
                   key=lambda x: x.start_ns)
    if args.evidence_dir:
        from evidence.checkpoint import load_private_key
        from evidence.shards import ShardedLog

        key = load_private_key(args.private_key) if args.checkpoint else None
        log = ShardedLog(args.evidence_dir)
        added = sum(1 for s in spans
                    if log.append(span_violation_record(s), tenant=args.tenant, unique=True))
        print(f"recorded {added} new violation(s) ({len(spans) - added} already in the log); "
              f"log now has {len(log)} record(s)")
        if key is not None:
            print(f"checkpoint: {log.checkpoint(key)}")
        return 0
    single = _open(Path(args.log_file))
    for s in spans:
        single.append(span_violation_record(s))
    print(f"recorded {len(spans)} violation(s); log now has {len(single)} leaf/leaves")
    print(f"root: {single.root().hex()}")
    return 0


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="AgentWard tamper-evident violation log")
    ap.add_argument("--log-file", default=str(DEFAULT_LOG))
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_rec = sub.add_parser("record", help="record recent policy violations into the log")
    p_rec.add_argument("--service", action="append", default=[])
    p_rec.add_argument("--since-mins", type=int, default=10)
    p_rec.add_argument("--source", choices=("clickhouse", "jaeger", "otlp-file"),
                       default="clickhouse")
    p_rec.add_argument("--jaeger-url", default="http://localhost:16686")
    p_rec.add_argument("--jaeger-search-depth", type=int, default=1000)
    p_rec.add_argument("--otlp-file", action="append", default=[])
    p_rec.add_argument("--clickhouse-url", default=None)
    p_rec.add_argument("--clickhouse-container", default="signoz-telemetrystore-clickhouse-0-0")
    p_rec.add_argument("--clickhouse-user", default=None)
    p_rec.add_argument("--clickhouse-password", default=None)
    _dir_arg(p_rec, required=False)
    p_rec.add_argument("--tenant", default="default")
    p_rec.add_argument("--checkpoint", action="store_true",
                       help="sign a checkpoint after recording (needs a private key)")
    p_rec.add_argument("--private-key", default=None)

    sub.add_parser("root", help="print the current Merkle root (hex)")
    p_prove = sub.add_parser("prove", help="print + verify the inclusion proof for a leaf")
    p_prove.add_argument("index", type=int)
    p_ver = sub.add_parser("verify", help="verify a proof JSON against the current root")
    p_ver.add_argument("proof_json")
    sub.add_parser("count", help="number of leaves in the log")

    p_kg = sub.add_parser("keygen", help="create an Ed25519 key pair for checkpoints")
    p_kg.add_argument("--private-key", required=True)
    p_kg.add_argument("--public-key", required=True)

    p_cp = sub.add_parser("checkpoint", help="sign a checkpoint over every shard")
    _dir_arg(p_cp)
    p_cp.add_argument("--private-key", default=None,
                      help="PEM file (or $AGENTWARD_EVIDENCE_KEY_FILE / $AGENTWARD_EVIDENCE_KEY)")

    p_vc = sub.add_parser("verify-checkpoints",
                          help="verify the checkpoint chain and the shards against it")
    _dir_arg(p_vc)
    p_vc.add_argument("--public-key", default=None,
                      help="PEM file (or $AGENTWARD_EVIDENCE_PUBLIC_KEY_FILE / "
                           "$AGENTWARD_EVIDENCE_PUBLIC_KEY)")
    p_vc.add_argument("--deep", action="store_true",
                      help="check the shards against every checkpoint, not only the newest")
    p_vc.add_argument("--expect-head", default=None,
                      help="a checkpoint hash saved earlier; fail if it is not in the chain")

    p_sh = sub.add_parser("shards", help="list shards with their size and root")
    _dir_arg(p_sh)

    p_ps = sub.add_parser("prove-shard",
                          help="inclusion proof for one record against a signed checkpoint")
    _dir_arg(p_ps)
    p_ps.add_argument("--tenant", default="default")
    p_ps.add_argument("--day", required=True)
    p_ps.add_argument("--index", type=int, required=True)
    p_ps.add_argument("--checkpoint-file", default=None, help="default: the newest checkpoint")

    p_vp = sub.add_parser("verify-proof", help="verify a prove-shard output with the public key")
    p_vp.add_argument("proof_file")
    p_vp.add_argument("--public-key", default=None)
    return ap


def _sharded(args) -> int | None:
    """Commands that work on the sharded log or keys. None if not one of them."""
    if args.cmd == "keygen":
        from evidence.checkpoint import keygen

        kid = keygen(args.private_key, args.public_key)
        print(f"wrote {args.private_key} (keep it secret, mode 0600) and {args.public_key}")
        print(f"key id: {kid}")
        return 0
    if args.cmd == "checkpoint":
        from evidence.checkpoint import load_checkpoint, load_private_key
        from evidence.shards import ShardedLog

        path = ShardedLog(args.evidence_dir).checkpoint(load_private_key(args.private_key))
        body = load_checkpoint(path)["body"]
        print(f"wrote checkpoint {body['seq']} ({len(body['shards'])} shard(s), "
              f"{body['total_records']} record(s)): {path}")
        return 0
    if args.cmd == "verify-checkpoints":
        from evidence.checkpoint import load_public_key, verify_log

        res = verify_log(args.evidence_dir, load_public_key(args.public_key), deep=args.deep,
                         expect_head=args.expect_head)
        print(json.dumps(res.to_dict(), indent=2))
        return 0 if res.ok else 2
    if args.cmd == "shards":
        from evidence.shards import ShardedLog

        for h in ShardedLog(args.evidence_dir).heads():
            print(f"{h.tenant}/{h.day}  {h.size:>8}  {h.root}")
        return 0
    if args.cmd == "prove-shard":
        from evidence.checkpoint import prove_record

        print(json.dumps(prove_record(args.evidence_dir, args.tenant, args.day, args.index,
                                      args.checkpoint_file), indent=2, sort_keys=True))
        return 0
    if args.cmd == "verify-proof":
        from evidence.checkpoint import load_public_key, verify_record_proof

        bundle = json.loads(Path(args.proof_file).read_text(encoding="utf-8"))
        ok, msg = verify_record_proof(bundle, load_public_key(args.public_key))
        print(json.dumps({"verified": ok, "detail": msg}, indent=2))
        return 0 if ok else 2
    if args.cmd == "record" and (args.source != "clickhouse" or args.evidence_dir):
        return _record_from_source(args)
    return None


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        rc = _sharded(args)
    except (ValueError, OSError, IndexError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if rc is not None:
        return rc

    log = _open(Path(args.log_file))

    if args.cmd == "record":
        service = args.service[0] if args.service else "agentward-hr-bot"
        n = record_violations(log, service=service, since_minutes=args.since_mins)
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
            # needed by `verify`: without it a printed proof could not be checked
            "directions": proof.directions,
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
