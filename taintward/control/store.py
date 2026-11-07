"""Per-tenant storage on disk. Each tenant has its own directory, so no
read path can reach another tenant's files::

    <data_dir>/tenants/<tenant>/
        policy/000001.json ...   every policy version (the newest is current)
        spans/<YYYY-MM-DD>.jsonl uploaded spans (OTLP JSON lines, by day received)
        evidence/<tenant>/...    the Merkle evidence log (ShardedLog)
        fingerprint.key          HMAC key for raw value fingerprints (0600)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from taintward.evidence.locking import fsync_dir, locked
from taintward.evidence.shards import ShardedLog, check_tenant
from taintward.evidence.spans import OtlpFileSource, Span

POLICY_KEYS = frozenset({"destinations", "default_destination", "default_jurisdiction",
                         "llm_jurisdiction"})
MAX_TOOLS = 10_000
_JURIS_RE = re.compile(r"^[A-Za-z0-9_-]{0,64}$")
_VERSION_RE = re.compile(r"^(\d{6,})\.json$")


class PolicyError(ValueError):
    pass


class PreconditionFailed(Exception):
    def __init__(self, current: str) -> None:
        super().__init__(current)
        self.current = current


def _juris(v: Any, where: str) -> str:
    v = "" if v is None else str(v)
    if not _JURIS_RE.match(v):
        raise PolicyError(f"{where}: jurisdiction must be up to 64 letters, digits, '_' or '-'")
    return v.lower()


def normalize_policy(doc: Any) -> dict:
    """Check a policy document and return it in one canonical form, so equal
    policies get equal ETags. Accepts the same tool entries as the SDK
    destination map ("external", ["external", "us"], {"destination": ...})."""
    from taintward.sdk.destinations import VALID_DESTINATIONS, _to_policy

    if not isinstance(doc, Mapping):
        raise PolicyError("policy must be a JSON object")
    unknown = set(doc) - POLICY_KEYS
    if unknown:
        raise PolicyError(f"unknown policy keys: {sorted(unknown)}; use {sorted(POLICY_KEYS)}")
    dests = doc.get("destinations") or {}
    if not isinstance(dests, Mapping):
        raise PolicyError("destinations must map tool names to destinations")
    if len(dests) > MAX_TOOLS:
        raise PolicyError(f"at most {MAX_TOOLS} tools")
    out_dests = {}
    for name, value in dests.items():
        name = str(name)
        if not name or len(name) > 256:
            raise PolicyError("tool names must be 1 to 256 characters")
        try:
            p = _to_policy(value)
        except (TypeError, ValueError) as exc:
            raise PolicyError(f"destinations[{name!r}]: {exc}") from None
        out_dests[name] = {"destination": p.destination,
                           "jurisdiction": _juris(p.jurisdiction, f"destinations[{name!r}]"),
                           "allow": sorted(p.allow)}
    default = str(doc.get("default_destination") or "external")
    if default not in VALID_DESTINATIONS:
        raise PolicyError(f"default_destination must be one of {sorted(VALID_DESTINATIONS)}")
    return {
        "destinations": dict(sorted(out_dests.items())),
        "default_destination": default,
        "default_jurisdiction": _juris(doc.get("default_jurisdiction"), "default_jurisdiction"),
        "llm_jurisdiction": _juris(doc.get("llm_jurisdiction"), "llm_jurisdiction"),
    }


def policy_etag(policy: dict) -> str:
    raw = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()[:32]


def _utc_day(ns: int) -> str:
    return datetime.fromtimestamp(ns / 1e9, tz=timezone.utc).strftime("%Y-%m-%d")


def _write_new(path: Path, data: bytes, mode: int = 0o644) -> None:
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    fsync_dir(path.parent)


class TenantStore:
    def __init__(self, data_dir: str | os.PathLike, tenant: str) -> None:
        self.tenant = check_tenant(tenant)
        self.root = Path(data_dir) / "tenants" / tenant
        self.policy_dir = self.root / "policy"
        self.spans_dir = self.root / "spans"
        self.evidence_dir = self.root / "evidence"

    # --- policy -----------------------------------------------------------

    def _versions(self) -> list[int]:
        if not self.policy_dir.is_dir():
            return []
        return sorted(int(m.group(1)) for p in self.policy_dir.iterdir()
                      if (m := _VERSION_RE.match(p.name)))

    def _read_version(self, n: int) -> dict:
        return json.loads((self.policy_dir / f"{n:06d}.json").read_text(encoding="utf-8"))

    def current_policy(self) -> dict | None:
        """{"version", "etag", "created", "by", "policy"} or None (no policy yet)."""
        versions = self._versions()
        return self._read_version(versions[-1]) if versions else None

    def put_policy(self, policy: Any, *, by: str, if_match: str | None = None) -> dict:
        """Store a new version. ``if_match``: the ETag the caller last saw;
        another version written since then raises PreconditionFailed."""
        norm = normalize_policy(policy)
        self.policy_dir.mkdir(parents=True, exist_ok=True)
        with locked(self.policy_dir / ".lock"):
            cur = self.current_policy()
            cur_etag = cur["etag"] if cur else ""
            if if_match is not None and if_match not in ("*", cur_etag):
                raise PreconditionFailed(cur_etag)
            etag = policy_etag(norm)
            if cur and cur["etag"] == etag:
                return cur  # unchanged: no new version
            n = (cur["version"] if cur else 0) + 1
            rec = {"version": n, "etag": etag, "by": by,
                   "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                   "policy": norm}
            _write_new(self.policy_dir / f"{n:06d}.json",
                       json.dumps(rec, indent=1, sort_keys=True).encode() + b"\n")
            return rec

    def policy_history(self, limit: int = 100) -> list[dict]:
        out = []
        for n in reversed(self._versions()[-limit:]):
            rec = self._read_version(n)
            out.append({k: rec[k] for k in ("version", "etag", "created", "by")}
                       | {"tools": len(rec["policy"]["destinations"])})
        return out

    # --- spans ------------------------------------------------------------

    def append_spans(self, doc: dict, received_ns: int | None = None) -> Path:
        received_ns = received_ns if received_ns is not None else time.time_ns()
        self.spans_dir.mkdir(parents=True, exist_ok=True)
        path = self.spans_dir / f"{_utc_day(received_ns)}.jsonl"
        line = json.dumps(doc, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"
        with locked(self.spans_dir / ".lock"):
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
            try:
                os.write(fd, line)
                os.fsync(fd)
            finally:
                os.close(fd)
        return path

    def spans(self, start_ns: int, end_ns: int) -> list[Span]:
        """Spans that started in [start_ns, end_ns). Files are by day received,
        which is on or after the day a span started (one day of clock skew
        allowed), so files from before the window are skipped."""
        if not self.spans_dir.is_dir():
            return []
        first = _utc_day(start_ns - int(timedelta(days=1).total_seconds() * 1e9))
        files = sorted(p for p in self.spans_dir.glob("*.jsonl") if p.stem >= first)
        return OtlpFileSource(files).fetch(start_ns, end_ns) if files else []

    # --- evidence and keys ------------------------------------------------

    def evidence(self) -> ShardedLog:
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        return ShardedLog(self.evidence_dir)

    def fingerprint_key(self) -> bytes:
        """The tenant's HMAC key for raw value fingerprints, made on first use.
        The same key is used when spans are uploaded and in reports, so a
        finding can be followed from one to the other."""
        path = self.root / "fingerprint.key"
        try:
            return bytes.fromhex(path.read_text().strip())
        except FileNotFoundError:
            pass
        self.root.mkdir(parents=True, exist_ok=True)
        with locked(self.root / ".key.lock"):
            if not path.exists():
                _write_new(path, secrets.token_hex(32).encode(), 0o600)
        return bytes.fromhex(path.read_text().strip())
