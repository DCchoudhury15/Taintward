"""CLI for the Taintward tamper-evident violation log.

Examples:
    # record recent collector violations from SigNoz into the log file
    python3 taintward/evidence/log.py record --service taintward-hr-bot --since-mins 10

    # show the current root
    python3 taintward/evidence/log.py root

    # prove leaf 0 is in the log (inclusion proof + verify)
    python3 taintward/evidence/log.py prove 0

    # verify a previously-printed proof (the output of `prove`)
    python3 taintward/evidence/log.py verify "$(python3 taintward/evidence/log.py prove 0)"

    # prove that the log still starts with the first 10 records, unchanged
    python3 taintward/evidence/log.py consistency --old-size 10 --old-root <hex>

    # after a crash: move a broken last line to violations.logl.corrupt
    python3 taintward/evidence/log.py repair

The log file defaults to ./violations.logl (or $TAINTWARD_EVIDENCE_LOG) (one JSON record per line,
append-only).

Sharded log with signed checkpoints (see docs/evidence-report.md):

    # one-time: make a signing key pair (keep the private key secret)
    python3 taintward/evidence/log.py keygen --private-key evidence.key --public-key evidence.pub

    # record violations from Jaeger into <dir>/<tenant>/<YYYY-MM-DD>.logl
    python3 taintward/evidence/log.py record --source jaeger --service taintward-hr-bot \\
        --since-mins 60 --evidence-dir evidence-log --tenant acme

    # sign a checkpoint over all shards, then verify everything
    python3 taintward/evidence/log.py checkpoint --evidence-dir evidence-log --private-key evidence.key
    python3 taintward/evidence/log.py verify-checkpoints --evidence-dir evidence-log \\
        --public-key evidence.pub

    # prove one record against the newest checkpoint, verify it offline
    python3 taintward/evidence/log.py prove-shard --evidence-dir evidence-log --tenant acme \\
        --day 2026-10-24 --index 0 > proof.json
    python3 taintward/evidence/log.py verify-proof proof.json --public-key evidence.pub
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from taintward.evidence.merkle import (
    PROOF_VERSION,
    InclusionProof,
    MerkleLog,
    _hash_leaf,
    repair_log,
    verify_consistency,
    verify_inclusion,
)
from taintward.evidence.recorder import record_violations

# Current directory by default, never inside the installed package.
DEFAULT_LOG = Path(os.environ.get("TAINTWARD_EVIDENCE_LOG", "violations.logl"))
DEFAULT_DIR = os.environ.get("TAINTWARD_EVIDENCE_DIR")


def _open(path: Path) -> MerkleLog:
    return MerkleLog(path)


def _dir_arg(p: argparse.ArgumentParser, required: bool = True) -> None:
    p.add_argument("--evidence-dir", default=DEFAULT_DIR,
                   required=required and not DEFAULT_DIR,
                   help="sharded evidence log directory (or $TAINTWARD_EVIDENCE_DIR)")


def _record_from_source(args) -> int:
    """Record violations from any report source into the single or sharded log."""
    from taintward.evidence.report import (
        is_tool_call,
        is_violation,
        source_from_args,
        span_violation_record,
    )

    end_ns = time.time_ns()
    start_ns = end_ns - int(args.since_mins) * 60 * 1_000_000_000
    if not args.service:
        args.service = ["taintward-hr-bot"]
    src = source_from_args(args)
    spans = sorted((s for s in src.fetch(start_ns, end_ns) if is_tool_call(s) and is_violation(s)),
                   key=lambda x: x.start_ns)
    if args.evidence_dir:
        from taintward.evidence.checkpoint import load_private_key
        from taintward.evidence.shards import ShardedLog

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
    added = sum(1 for s in spans if single.append(span_violation_record(s), unique=True) is not None)
    print(f"recorded {added} new violation(s) ({len(spans) - added} already in the log); "
          f"log now has {len(single)} leaf/leaves")
    print(f"root: {single.root().hex()}")
    return 0


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Taintward tamper-evident violation log")
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

    p_root = sub.add_parser("root", help="print the current Merkle root (hex)")
    p_root.add_argument("--size", type=int, default=None,
                        help="root of the first SIZE records instead of all of them")
    p_prove = sub.add_parser("prove", help="print + verify the inclusion proof for a leaf")
    p_prove.add_argument("index", type=int)
    p_prove.add_argument("--size", type=int, default=None,
                         help="prove against the tree of the first SIZE records")
    p_ver = sub.add_parser("verify", help="verify a proof JSON (the output of prove)")
    p_ver.add_argument("proof_json")
    p_ver.add_argument("--root", default=None,
                       help="root (hex) to check against, for example one from a report; "
                            "default: the root of this log file at the proof's tree size")
    p_con = sub.add_parser("consistency",
                           help="prove the log extends an older version of itself")
    p_con.add_argument("--old-size", type=int, required=True)
    p_con.add_argument("--old-root", default=None,
                       help="root (hex) the old version had; checked when given")
    sub.add_parser("count", help="number of leaves in the log")
    p_rep = sub.add_parser("repair",
                           help="move a broken last line (left by a crash) to <file>.corrupt")
    _dir_arg(p_rep, required=False)

    p_kg = sub.add_parser("keygen", help="create an Ed25519 key pair for checkpoints")
    p_kg.add_argument("--private-key", required=True)
    p_kg.add_argument("--public-key", required=True)

    p_cp = sub.add_parser("checkpoint", help="sign a checkpoint over every shard")
    _dir_arg(p_cp)
    p_cp.add_argument("--private-key", default=None,
                      help="PEM file (or $TAINTWARD_EVIDENCE_KEY_FILE / $TAINTWARD_EVIDENCE_KEY)")

    p_vc = sub.add_parser("verify-checkpoints",
                          help="verify the checkpoint chain and the shards against it")
    _dir_arg(p_vc)
    p_vc.add_argument("--public-key", default=None,
                      help="PEM file (or $TAINTWARD_EVIDENCE_PUBLIC_KEY_FILE / "
                           "$TAINTWARD_EVIDENCE_PUBLIC_KEY)")
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
        from taintward.evidence.checkpoint import keygen

        kid = keygen(args.private_key, args.public_key)
        print(f"wrote {args.private_key} (keep it secret, mode 0600) and {args.public_key}")
        print(f"key id: {kid}")
        return 0
    if args.cmd == "checkpoint":
        from taintward.evidence.checkpoint import load_checkpoint, load_private_key
        from taintward.evidence.shards import ShardedLog

        path = ShardedLog(args.evidence_dir).checkpoint(load_private_key(args.private_key))
        body = load_checkpoint(path)["body"]
        print(f"wrote checkpoint {body['seq']} ({len(body['shards'])} shard(s), "
              f"{body['total_records']} record(s)): {path}")
        return 0
    if args.cmd == "verify-checkpoints":
        from taintward.evidence.checkpoint import load_public_key, verify_log

        res = verify_log(args.evidence_dir, load_public_key(args.public_key), deep=args.deep,
                         expect_head=args.expect_head)
        print(json.dumps(res.to_dict(), indent=2))
        return 0 if res.ok else 2
    if args.cmd == "shards":
        from taintward.evidence.shards import ShardedLog

        for h in ShardedLog(args.evidence_dir).heads():
            print(f"{h.tenant}/{h.day}  {h.size:>8}  {h.root}")
        return 0
    if args.cmd == "prove-shard":
        from taintward.evidence.checkpoint import prove_record

        print(json.dumps(prove_record(args.evidence_dir, args.tenant, args.day, args.index,
                                      args.checkpoint_file), indent=2, sort_keys=True))
        return 0
    if args.cmd == "verify-proof":
        from taintward.evidence.checkpoint import load_public_key, verify_record_proof

        bundle = json.loads(Path(args.proof_file).read_text(encoding="utf-8"))
        ok, msg = verify_record_proof(bundle, load_public_key(args.public_key))
        print(json.dumps({"verified": ok, "detail": msg}, indent=2))
        return 0 if ok else 2
    if args.cmd == "repair":
        if args.evidence_dir:
            from taintward.evidence.shards import ShardedLog

            done = ShardedLog(args.evidence_dir).repair()
        else:
            one = repair_log(args.log_file)
            done = [one] if one else []
        for d in done:
            print(f"moved a broken last line ({d['removed_bytes']} bytes, line {d['line']}: "
                  f"{d['reason']}) from {d['path']} to {d['corrupt_file']}; "
                  f"{d['records_kept']} record(s) kept")
        if not done:
            print("nothing to repair")
        return 0
    if args.cmd == "record" and (args.source != "clickhouse" or args.evidence_dir):
        return _record_from_source(args)
    return None


def _single(args) -> int:
    """Commands on the single-file log."""
    log = _open(Path(args.log_file))

    if args.cmd == "record":
        service = args.service[0] if args.service else "taintward-hr-bot"
        n = record_violations(log, service=service, since_minutes=args.since_mins)
        print(f"recorded {n} new violation(s); log now has {len(log)} leaf/leaves")
        print(f"root: {log.root().hex()}")
    elif args.cmd == "root":
        print((log.root() if args.size is None else log.prefix_root(args.size)).hex())
    elif args.cmd == "count":
        print(len(log))
    elif args.cmd == "prove":
        size = len(log) if args.size is None else args.size
        if not 0 <= size <= len(log):
            print(f"size {size} out of range (log has {len(log)} leaves)", file=sys.stderr)
            return 1
        if not 0 <= args.index < size:
            print(f"index {args.index} out of range (tree has {size} leaves)", file=sys.stderr)
            return 1
        proof = log.inclusion_proof(args.index, size=size)
        root = log.prefix_root(size)
        ok = verify_inclusion(proof.leaf_hash, proof, root, tree_size=size)
        print(json.dumps({
            "version": PROOF_VERSION,
            "leaf_index": proof.leaf_index,
            "tree_size": size,
            "leaf_record": log.record(args.index),
            "leaf_hash": proof.leaf_hash.hex(),
            "siblings": [s.hex() for s in proof.siblings],
            "directions": proof.directions,  # for older readers; not used to verify
            "root": root.hex(),
            "verified": ok,
        }, indent=2))
        return 0 if ok else 2
    elif args.cmd == "verify":
        data = json.loads(args.proof_json)
        proof = InclusionProof.from_dict(data)
        # a version 1 proof has no tree size: it was made against the whole log
        size = proof.tree_size if proof.tree_size is not None else len(log)
        if args.root:
            root = bytes.fromhex(args.root)
        elif size <= len(log):
            root = log.prefix_root(size)
        else:
            root = b""
        ok = verify_inclusion(proof.leaf_hash, proof, root, tree_size=size)
        if ok and "leaf_record" in data:
            ok = _hash_leaf(data["leaf_record"]) == proof.leaf_hash
        print(json.dumps({"verified": ok, "leaf_index": proof.leaf_index,
                          "tree_size": size, "root": root.hex()}, indent=2))
        return 0 if ok else 2
    elif args.cmd == "consistency":
        m = args.old_size
        if not 0 <= m <= len(log):
            print(f"old size {m} out of range (log has {len(log)} leaves)", file=sys.stderr)
            return 1
        proof = log.consistency_proof(m)
        old_root = bytes.fromhex(args.old_root) if args.old_root else log.prefix_root(m)
        ok = verify_consistency(m, len(log), old_root, log.root(), proof)
        print(json.dumps({
            "old_size": m, "old_root": old_root.hex(),
            "new_size": len(log), "new_root": log.root().hex(),
            "proof": [h.hex() for h in proof],
            "verified": ok,
        }, indent=2))
        return 0 if ok else 2
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        rc = _sharded(args)
    except (ValueError, OSError, IndexError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if rc is not None:
        return rc
    try:
        return _single(args)
    except (ValueError, OSError, IndexError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
