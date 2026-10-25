"""Signed checkpoints over the sharded evidence log.

A checkpoint is a small JSON file that says "at this time, these shards
existed, with these sizes and these Merkle roots", signed with Ed25519. Each
checkpoint also holds the hash of the previous one, so checkpoints form a
chain. With the public key a verifier can check that:

* every checkpoint was signed by the key holder and not edited,
* no checkpoint in the middle of the chain was removed,
* each checkpoint extends the one before it: for every shard that grew, an
  RFC 9162 consistency proof shows the old root is the root of the first
  ``old size`` records of the new tree (history was not rewritten),
* every shard named in a checkpoint still exists (a deleted shard is caught),
* the first ``size`` records of each shard still give the signed root (a
  rewritten, reordered or truncated shard is caught),
* a single record is in a shard, using only the record, its inclusion proof,
  the checkpoint and the public key (no access to the full log needed).

File format (``<dir>/_checkpoints/0000000001.json``)::

    {"body": {"version": 2, "seq": 1, "time": "...", "time_ns": ...,
              "prev": "<sha256 hex of previous body, or 64 zeros>",
              "key_id": "<first 16 hex of sha256(public key)>",
              "total_records": N,
              "shards": [{"tenant": "...", "day": "YYYY-MM-DD",
                          "size": n, "root": "<hex>",
                          "prev_size": m, "consistency": ["<hex>", ...]},
                         ...]},
     "signature": "<Ed25519 signature hex>"}

The signature covers ``DOMAIN || canonical_json(body)``, so it covers every
shard's size (the tree size) and root. ``prev_size`` and ``consistency`` are
present only for a shard that grew since the previous checkpoint: the proof
that the tree of ``size`` records extends the tree of ``prev_size`` records.
Version 1 checkpoints (no proofs) are still accepted; for them the verifier
builds the consistency proof from the shard file.

Keys never live in code. The private key comes from a file
(``--private-key`` or ``$AGENTWARD_EVIDENCE_KEY_FILE``) or the environment
(``$AGENTWARD_EVIDENCE_KEY``, PEM text or a 64 hex character seed). The
public key comes from ``--public-key``, ``$AGENTWARD_EVIDENCE_PUBLIC_KEY_FILE``
or ``$AGENTWARD_EVIDENCE_PUBLIC_KEY`` (PEM or 64 hex characters).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from evidence.locking import fsync_dir
from evidence.locking import locked as _locked
from evidence.merkle import (
    InclusionProof,
    LogCorruptError,
    MerkleLog,
    TornTailError,
    _hash_leaf,
    verify_audit_path,
    verify_consistency,
)
from evidence.shards import ShardedLog

CHECKPOINT_VERSION = 2

DOMAIN = b"agentward-evidence-checkpoint-v1\n"
ZERO_HASH = "0" * 64
_CP_NAME_RE = re.compile(r"^(\d{10})\.json$")

ENV_KEY = "AGENTWARD_EVIDENCE_KEY"
ENV_KEY_FILE = "AGENTWARD_EVIDENCE_KEY_FILE"
ENV_PUB = "AGENTWARD_EVIDENCE_PUBLIC_KEY"
ENV_PUB_FILE = "AGENTWARD_EVIDENCE_PUBLIC_KEY_FILE"


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# keys
# ---------------------------------------------------------------------------

def _raw_pub(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def key_id(pub: Ed25519PublicKey) -> str:
    """Short public key fingerprint: first 16 hex chars of SHA-256(raw key)."""
    return hashlib.sha256(_raw_pub(pub)).hexdigest()[:16]


def _parse_private(data: bytes) -> Ed25519PrivateKey:
    text = data.strip()
    if text.startswith(b"-----BEGIN"):
        key = serialization.load_pem_private_key(text, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("the private key is not an Ed25519 key")
        return key
    if re.fullmatch(rb"[0-9a-fA-F]{64}", text):
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(text.decode()))
    raise ValueError("private key must be PEM (PKCS8) or 64 hex characters")


def _parse_public(data: bytes) -> Ed25519PublicKey:
    text = data.strip()
    if text.startswith(b"-----BEGIN"):
        key = serialization.load_pem_public_key(text)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("the public key is not an Ed25519 key")
        return key
    if re.fullmatch(rb"[0-9a-fA-F]{64}", text):
        return Ed25519PublicKey.from_public_bytes(bytes.fromhex(text.decode()))
    raise ValueError("public key must be PEM or 64 hex characters")


def load_private_key(path: str | os.PathLike | None = None) -> Ed25519PrivateKey:
    """Private key from ``path``, else $AGENTWARD_EVIDENCE_KEY_FILE, else
    $AGENTWARD_EVIDENCE_KEY. Raises if none is set."""
    path = path or os.environ.get(ENV_KEY_FILE)
    if path:
        return _parse_private(Path(path).read_bytes())
    env = os.environ.get(ENV_KEY)
    if env:
        return _parse_private(env.encode())
    raise ValueError(f"no signing key: pass --private-key or set {ENV_KEY_FILE} / {ENV_KEY}")


def load_public_key(path: str | os.PathLike | None = None) -> Ed25519PublicKey:
    """Public key from ``path``, else $AGENTWARD_EVIDENCE_PUBLIC_KEY_FILE,
    else $AGENTWARD_EVIDENCE_PUBLIC_KEY. Raises if none is set."""
    path = path or os.environ.get(ENV_PUB_FILE)
    if path:
        return _parse_public(Path(path).read_bytes())
    env = os.environ.get(ENV_PUB)
    if env:
        return _parse_public(env.encode())
    raise ValueError(f"no public key: pass --public-key or set {ENV_PUB_FILE} / {ENV_PUB}")


def keygen(private_path: str | os.PathLike, public_path: str | os.PathLike) -> str:
    """Create a new Ed25519 key pair as PEM files. Refuses to overwrite.

    The private key file is created with mode 0600. Returns the key id.
    """
    priv_p, pub_p = Path(private_path), Path(public_path)
    for p in (priv_p, pub_p):
        if p.exists():
            raise FileExistsError(f"{p} already exists; not overwriting a key")
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    priv_p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(priv_p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    pub = key.public_key()
    pub_p.parent.mkdir(parents=True, exist_ok=True)
    pub_p.write_bytes(pub.public_bytes(serialization.Encoding.PEM,
                                       serialization.PublicFormat.SubjectPublicKeyInfo))
    return key_id(pub)


# ---------------------------------------------------------------------------
# writing
# ---------------------------------------------------------------------------

def body_hash(body: dict) -> str:
    return hashlib.sha256(canonical(body)).hexdigest()


def sign_body(body: dict, key: Ed25519PrivateKey) -> str:
    return key.sign(DOMAIN + canonical(body)).hex()


def list_checkpoints(cp_dir: str | os.PathLike) -> list[tuple[int, Path]]:
    d = Path(cp_dir)
    if not d.exists():
        return []
    out = []
    for f in d.iterdir():
        m = _CP_NAME_RE.match(f.name)
        if m:
            out.append((int(m.group(1)), f))
    return sorted(out)


def load_checkpoint(path: str | os.PathLike) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _shard_entries(log: ShardedLog, prev_body: dict | None, prev_seq: int) -> list[dict]:
    """Size and root of every shard, plus a consistency proof from the
    previous checkpoint for each shard that grew. Refuses to sign over a
    shard that no longer extends the previous checkpoint."""
    prev = {(s["tenant"], s["day"]): s for s in (prev_body or {}).get("shards", [])}
    on_disk = set(log.list_shards())
    for k in prev:
        if k not in on_disk:
            raise ValueError(f"shard {k[0]}/{k[1]} from checkpoint {prev_seq} is missing; "
                             f"not signing a checkpoint without it")
    entries = []
    for tenant, day in sorted(on_disk):
        shard = log.shard(tenant, day)
        size, root = len(shard), shard.root().hex()
        entry = {"tenant": tenant, "day": day, "size": size, "root": root}
        p = prev.get((tenant, day))
        if p is not None:
            m = int(p["size"])
            if size < m or shard.prefix_root(m).hex() != p["root"]:
                raise ValueError(f"shard {tenant}/{day} no longer matches checkpoint "
                                 f"{prev_seq} (records were changed or removed); "
                                 f"not signing over it")
            if m < size:
                entry["prev_size"] = m
                entry["consistency"] = [h.hex() for h in shard.consistency_proof(m, size)]
        entries.append(entry)
    return entries


def write_checkpoint(log: ShardedLog, key: Ed25519PrivateKey, *,
                     now_ns: int | None = None) -> Path:
    """Sign and write the next checkpoint for ``log``; return its path."""
    cp_dir = log.checkpoint_dir
    cp_dir.mkdir(parents=True, exist_ok=True)
    with _locked(cp_dir / ".lock"):
        existing = list_checkpoints(cp_dir)
        prev_body = None
        if existing:
            last_seq, last_path = existing[-1]
            prev_body = load_checkpoint(last_path)["body"]
            prev = body_hash(prev_body)
        else:
            last_seq, prev = 0, ZERO_HASH
        shards = _shard_entries(log, prev_body, last_seq)
        now_ns = time.time_ns() if now_ns is None else int(now_ns)
        body = {
            "version": CHECKPOINT_VERSION,
            "seq": last_seq + 1,
            "time_ns": now_ns,
            "time": datetime.fromtimestamp(now_ns / 1e9, tz=timezone.utc)
                            .strftime("%Y-%m-%dT%H:%M:%SZ"),
            "prev": prev,
            "key_id": key_id(key.public_key()),
            "total_records": sum(e["size"] for e in shards),
            "shards": shards,
        }
        doc = {"body": body, "signature": sign_body(body, key)}
        path = cp_dir / f"{body['seq']:010d}.json"
        tmp = path.with_suffix(".json.tmp")
        with tmp.open("w", encoding="utf-8") as f:
            f.write(json.dumps(doc, indent=1, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        fsync_dir(cp_dir)
    return path


# ---------------------------------------------------------------------------
# verifying
# ---------------------------------------------------------------------------

def verify_signature(doc: dict, pub: Ed25519PublicKey) -> bool:
    try:
        pub.verify(bytes.fromhex(doc["signature"]), DOMAIN + canonical(doc["body"]))
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False


@dataclass
class VerifyResult:
    ok: bool = True
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    checkpoints: int = 0
    head_seq: int = 0
    head_hash: str = ""
    head_time: str = ""
    shards_checked: int = 0
    records_covered: int = 0

    def error(self, msg: str) -> None:
        self.ok = False
        self.errors.append(msg)

    def to_dict(self) -> dict:
        return {
            "ok": self.ok, "errors": self.errors, "warnings": self.warnings,
            "checkpoints": self.checkpoints, "head_seq": self.head_seq,
            "head_hash": self.head_hash, "head_time": self.head_time,
            "shards_checked": self.shards_checked, "records_covered": self.records_covered,
        }


def _open_shard(path: Path) -> MerkleLog:
    """A fresh read of a shard file (never a cached copy)."""
    return MerkleLog(path)


def _check_extends(log: ShardedLog, prev_body: dict, body: dict, res: VerifyResult,
                   label: str) -> None:
    """Every shard of ``prev_body`` is in ``body`` and ``body`` provably
    extends it (RFC 9162 consistency proof)."""
    now = {(s["tenant"], s["day"]): s for s in body.get("shards", [])}
    for s in prev_body.get("shards", []):
        k = (s["tenant"], s["day"])
        name = f"{k[0]}/{k[1]}"
        if k not in now:
            res.error(f"{label}: shard {name} from the previous checkpoint is gone")
            continue
        cur = now[k]
        try:
            m, n = int(s["size"]), int(cur["size"])
            old_root, new_root = bytes.fromhex(s["root"]), bytes.fromhex(cur["root"])
        except (KeyError, TypeError, ValueError):
            res.error(f"{label}: shard {name} has a malformed entry")
            continue
        if n < m:
            res.error(f"{label}: shard {name} shrank since the previous checkpoint")
            continue
        if n == m:
            if old_root != new_root:
                res.error(f"{label}: shard {name} has the same size as in the previous "
                          f"checkpoint but a different root (history was rewritten)")
            continue
        if cur.get("prev_size") == m and "consistency" in cur:
            try:
                proof = [bytes.fromhex(h) for h in cur["consistency"]]
            except (TypeError, ValueError):
                proof = []
            where = "signed consistency proof"
        else:  # version 1 checkpoint, or a checkpoint in between is missing
            try:
                shard = _open_shard(log.shard_path(*k))
            except (OSError, ValueError):
                continue  # missing or unreadable shards are reported elsewhere
            if len(shard) < n:
                continue  # reported by the shard check
            proof = shard.consistency_proof(m, n)
            where = "consistency proof built from the shard file"
        if not verify_consistency(m, n, old_root, new_root, proof):
            res.error(f"{label}: shard {name} does not extend the previous checkpoint "
                      f"({where} fails): records signed earlier were changed")


def _check_shards_against(log: ShardedLog, body: dict, res: VerifyResult, label: str) -> None:
    for sh in body.get("shards", []):
        tenant, day, size, root = sh["tenant"], sh["day"], int(sh["size"]), sh["root"]
        name = f"{tenant}/{day}"
        path = log.shard_path(tenant, day)
        if not path.exists():
            res.error(f"{label}: shard {name} is named in the checkpoint but is missing (deleted)")
            continue
        try:
            shard = _open_shard(path)
        except TornTailError as e:
            res.error(f"{label}: shard {name} cannot be read: {e}")
            continue
        except (LogCorruptError, ValueError) as e:
            res.error(f"{label}: shard {name} cannot be read ({e})")
            continue
        if len(shard) < size:
            res.error(f"{label}: shard {name} has {len(shard)} records, the checkpoint "
                      f"signed {size} (records were removed)")
            continue
        if shard.prefix_root(size).hex() != root:
            res.error(f"{label}: shard {name} does not match the signed root "
                      f"(records were changed or reordered)")
            continue
        res.shards_checked += 1


def verify_log(root: str | os.PathLike, pub: Ed25519PublicKey, *, deep: bool = False,
               expect_head: str | None = None) -> VerifyResult:
    """Verify every checkpoint under ``root`` and the shards against them.

    The newest checkpoint is checked against the shard files. With
    ``deep=True`` every checkpoint is. ``expect_head`` is a checkpoint hash
    the verifier got from somewhere else (an earlier report, an object store
    with retention lock); verification fails if no checkpoint has that hash,
    which catches deleting the newest checkpoints.
    """
    log = ShardedLog(root)
    res = VerifyResult()
    cps = list_checkpoints(log.checkpoint_dir)
    if not cps:
        res.error("no checkpoints found")
        return res
    want_id = key_id(pub)
    prev_hash = ZERO_HASH
    prev_body: dict | None = None
    bodies: list[dict] = []
    hashes: set[str] = set()
    expected_seq = 1
    for seq, path in cps:
        label = f"checkpoint {seq}"
        gap = seq != expected_seq
        if gap:
            missing = (str(expected_seq) if seq - expected_seq == 1
                       else f"{expected_seq} to {seq - 1}")
            res.error(f"checkpoint {missing} is missing (deleted?)")
        expected_seq = seq + 1  # resync so one gap is reported once
        try:
            doc = load_checkpoint(path)
            body = doc["body"]
        except (ValueError, KeyError) as e:
            res.error(f"{label}: cannot be read ({e})")
            prev_body = None
            continue
        if body.get("key_id") != want_id:
            res.error(f"{label}: signed by key {body.get('key_id')}, expected {want_id}")
        if not verify_signature(doc, pub):
            res.error(f"{label}: signature is not valid for this public key "
                      f"(wrong key or the file was edited)")
        if body.get("seq") != seq:
            res.error(f"{label}: file name and seq field disagree ({body.get('seq')})")
        if not gap and body.get("prev") != prev_hash:
            res.error(f"{label}: previous-checkpoint hash does not match (chain broken)")
        try:
            total = sum(int(s["size"]) for s in body.get("shards", []))
        except (KeyError, TypeError, ValueError):
            total = None
        if total != body.get("total_records"):
            res.error(f"{label}: total_records does not match the shard sizes")
        if prev_body is not None:
            _check_extends(log, prev_body, body, res, label)
        h = body_hash(body)
        hashes.add(h)
        prev_hash, prev_body = h, body
        bodies.append(body)
    res.checkpoints = len(cps)
    if not bodies:
        return res
    head = bodies[-1]
    res.head_seq = int(head.get("seq", 0))
    res.head_hash = body_hash(head)
    res.head_time = str(head.get("time", ""))
    res.records_covered = int(head.get("total_records", 0))
    if expect_head and expect_head not in hashes:
        res.error(f"expected checkpoint {expect_head[:16]}... is not in the chain "
                  f"(newer checkpoints may have been deleted)")
    targets = bodies if deep else [head]
    for body in targets:
        _check_shards_against(log, body, res, f"checkpoint {body.get('seq')}")
    signed = {(s["tenant"], s["day"]): int(s["size"]) for s in head.get("shards", [])}
    for tenant, day in log.list_shards():
        try:
            n = len(log.shard(tenant, day))
        except ValueError as e:
            if (tenant, day) not in signed:  # signed shards were reported above
                res.error(f"shard {tenant}/{day} cannot be read: {e}")
            continue
        k = (tenant, day)
        if k not in signed:
            res.warnings.append(f"shard {tenant}/{day} ({n} records) is not covered by a "
                                f"checkpoint yet")
        elif n > signed[k]:
            res.warnings.append(f"shard {tenant}/{day} has {n - signed[k]} record(s) added "
                                f"after the newest checkpoint")
    return res


# ---------------------------------------------------------------------------
# single-record proofs against a checkpoint
# ---------------------------------------------------------------------------

def prove_record(root: str | os.PathLike, tenant: str, day: str, index: int,
                 checkpoint_path: str | os.PathLike | None = None) -> dict:
    """Inclusion proof for one record against a signed checkpoint.

    The output is everything a third party needs, besides the public key:
    the record, its audit path and the checkpoint itself.
    """
    log = ShardedLog(root)
    if checkpoint_path is None:
        cps = list_checkpoints(log.checkpoint_dir)
        if not cps:
            raise ValueError("no checkpoints found")
        checkpoint_path = cps[-1][1]
    cp = load_checkpoint(checkpoint_path)
    entry = next((s for s in cp["body"]["shards"]
                  if s["tenant"] == tenant and s["day"] == day), None)
    if entry is None:
        raise ValueError(f"shard {tenant}/{day} is not in checkpoint {cp['body']['seq']}")
    shard = log.shard(tenant, day)
    size = int(entry["size"])
    if not 0 <= index < size:
        raise IndexError(f"index {index} is not covered by the checkpoint (size {size})")
    if len(shard) < size or shard.prefix_root(size).hex() != entry["root"]:
        raise ValueError(f"shard {tenant}/{day} no longer matches checkpoint "
                         f"{cp['body']['seq']}; run verify-checkpoints")
    proof = shard.inclusion_proof(index, size=size)
    return {
        "version": 2,
        "tenant": tenant, "day": day, "leaf_index": index, "tree_size": size,
        "record": shard.record(index),
        "proof": proof.to_dict(),
        "checkpoint": cp,
    }


def verify_record_proof(bundle: dict, pub: Ed25519PublicKey) -> tuple[bool, str]:
    """Check a bundle from :func:`prove_record` with only the public key.

    The leaf position and tree size come from the bundle and the signed
    checkpoint, and the audit path is checked against both (RFC 9162), so a
    proof cannot be moved to another index or another tree size. Version 1
    bundles (proof without ``tree_size``) are still accepted.
    """
    try:
        cp = bundle["checkpoint"]
        if not verify_signature(cp, pub):
            return False, "checkpoint signature is not valid for this public key"
        entry = next((s for s in cp["body"]["shards"]
                      if s["tenant"] == bundle["tenant"] and s["day"] == bundle["day"]), None)
        if entry is None:
            return False, "the shard is not in the checkpoint"
        size = int(entry["size"])
        index = int(bundle["leaf_index"])
        if int(bundle["tree_size"]) != size:
            return False, "tree size does not match the checkpoint"
        proof = InclusionProof.from_dict(bundle["proof"])
        if proof.leaf_index != index:
            return False, "the proof is for a different leaf index"
        if proof.tree_size is not None and proof.tree_size != size:
            return False, "the proof is for a different tree size"
        leaf = _hash_leaf(bundle["record"])
        if leaf != proof.leaf_hash:
            return False, "the record does not match the proof's leaf hash"
        if not verify_audit_path(leaf, index, size, proof.siblings,
                                 bytes.fromhex(entry["root"])):
            return False, "inclusion proof does not lead to the signed root"
    except (KeyError, TypeError, ValueError, AttributeError) as e:
        return False, f"the proof file is malformed ({e})"
    return True, (f"record is leaf {index} of {size} in {bundle['tenant']}/{bundle['day']} "
                  f"in signed checkpoint {cp['body']['seq']}")
