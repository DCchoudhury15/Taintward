"""Sharded evidence log: one Merkle log file per tenant per UTC day.

Layout::

    <dir>/<tenant>/<YYYY-MM-DD>.logl     one MerkleLog per tenant per day
    <dir>/_checkpoints/<seq>.json         signed checkpoints (evidence/checkpoint.py)

Why shard: a single file grows forever, has one writer, and must be read in
full to compute the root. Per-day shards stay small, can be archived or moved
to object storage once the day is over, and a verifier can check one shard
without the others. Signed checkpoints tie all shards together, so a deleted
or rewritten shard is still detected.

Each shard is a normal :class:`evidence.merkle.MerkleLog` file, so every
existing tool (``agentward-evidence --log-file <shard> root``) works on it.

Writers in several processes are safe: each append takes an exclusive file
lock on the tenant directory and reloads the shard if another process
changed it since the last read.
"""

from __future__ import annotations

import os
import re
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from evidence.merkle import MerkleLog

try:  # POSIX only; on other systems appends are single-process safe only
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

SHARD_SUFFIX = ".logl"
CHECKPOINT_DIRNAME = "_checkpoints"
DEFAULT_TENANT = "default"

_TENANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def check_tenant(tenant: str) -> str:
    if not _TENANT_RE.match(tenant) or ".." in tenant:
        raise ValueError(f"invalid tenant name: {tenant!r} (use letters, digits, . _ -)")
    return tenant


def check_day(day: str) -> str:
    if not _DAY_RE.match(day):
        raise ValueError(f"invalid day: {day!r} (use YYYY-MM-DD)")
    datetime.strptime(day, "%Y-%m-%d")
    return day


def utc_day(ts_ns: int | None = None) -> str:
    """UTC calendar day for a timestamp in ns (now when None)."""
    if ts_ns is None:
        dt = datetime.now(timezone.utc)
    else:
        dt = datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc)
    return dt.strftime("%Y-%m-%d")


@dataclass(frozen=True)
class ShardHead:
    tenant: str
    day: str
    size: int
    root: str  # hex

    def to_dict(self) -> dict:
        return {"tenant": self.tenant, "day": self.day, "size": self.size, "root": self.root}


@contextmanager
def _locked(lock_path: Path) -> Iterator[None]:
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a") as fh:
        if fcntl is not None:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


class ShardedLog:
    """Merkle evidence log split by tenant and UTC day.

    ``checkpoint_every`` > 0 with a ``signing_key`` writes a signed
    checkpoint automatically after that many appends from this process.
    """

    def __init__(self, root: str | os.PathLike, *, signing_key=None,
                 checkpoint_every: int = 0):
        self.root = Path(root)
        self.signing_key = signing_key
        self.checkpoint_every = int(checkpoint_every)
        self._cache: dict[tuple[str, str], tuple[MerkleLog, int, set]] = {}
        self._since_checkpoint = 0

    # --- paths ---

    @property
    def checkpoint_dir(self) -> Path:
        return self.root / CHECKPOINT_DIRNAME

    def shard_path(self, tenant: str, day: str) -> Path:
        return self.root / check_tenant(tenant) / f"{check_day(day)}{SHARD_SUFFIX}"

    def list_shards(self) -> list[tuple[str, str]]:
        """Every (tenant, day) shard on disk, sorted."""
        out = []
        if not self.root.exists():
            return out
        for tdir in sorted(self.root.iterdir()):
            if not tdir.is_dir() or tdir.name.startswith(("_", ".")):
                continue
            for f in sorted(tdir.glob(f"*{SHARD_SUFFIX}")):
                day = f.name[: -len(SHARD_SUFFIX)]
                if _DAY_RE.match(day) and _TENANT_RE.match(tdir.name):
                    out.append((tdir.name, day))
        return out

    # --- reading ---

    def shard(self, tenant: str, day: str) -> MerkleLog:
        """The shard's MerkleLog, reloaded if the file changed on disk."""
        return self._load(tenant, day)[0]

    def _load(self, tenant: str, day: str) -> tuple[MerkleLog, int, set]:
        path = self.shard_path(tenant, day)
        size = path.stat().st_size if path.exists() else 0
        cached = self._cache.get((tenant, day))
        if cached is not None and cached[1] == size:
            return cached
        log = MerkleLog(path)
        keys = {_key(r) for r in log.records()}
        entry = (log, size, keys)
        self._cache[(tenant, day)] = entry
        return entry

    def heads(self) -> list[ShardHead]:
        return [self.head(t, d) for t, d in self.list_shards()]

    def head(self, tenant: str, day: str) -> ShardHead:
        log = self.shard(tenant, day)
        return ShardHead(tenant, day, len(log), log.root().hex())

    def __len__(self) -> int:
        return sum(len(self.shard(t, d)) for t, d in self.list_shards())

    def find(self, trace_id: str, span_id: str) -> tuple[str, str, int] | None:
        """Locate a record by trace and span id: (tenant, day, index)."""
        for t, d in self.list_shards():
            log = self.shard(t, d)
            for i, r in enumerate(log.records()):
                if r.get("trace_id") == trace_id and r.get("span_id") == span_id:
                    return t, d, i
        return None

    # --- writing ---

    def append(self, record: dict, *, tenant: str = DEFAULT_TENANT,
               day: str | None = None, unique: bool = False) -> tuple[str, str, int] | None:
        """Append ``record`` to its shard; return (tenant, day, index).

        The day defaults to the UTC day of ``record["timestamp_ns"]`` (or
        today). With ``unique=True`` a record whose (trace_id, span_id) is
        already in the shard is skipped and None is returned, so recording
        the same time window twice does not double count.
        """
        check_tenant(tenant)
        if day is None:
            ts = record.get("timestamp_ns")
            day = utc_day(int(ts) if ts is not None else None)
        check_day(day)
        with _locked(self.root / tenant / ".lock"):
            log, _, keys = self._load(tenant, day)
            key = _key(record)
            if unique and key != (None, None) and key in keys:
                return None
            idx = log.append(record)
            keys.add(key)
            path = self.shard_path(tenant, day)
            self._cache[(tenant, day)] = (log, path.stat().st_size, keys)
        self._since_checkpoint += 1
        if (self.checkpoint_every > 0 and self.signing_key is not None
                and self._since_checkpoint >= self.checkpoint_every):
            self.checkpoint()
        return tenant, day, idx

    def checkpoint(self, signing_key=None) -> Path:
        """Write a signed checkpoint over every shard now on disk."""
        from evidence.checkpoint import write_checkpoint

        key = signing_key or self.signing_key
        if key is None:
            raise ValueError("a signing key is needed to write a checkpoint")
        path = write_checkpoint(self, key)
        self._since_checkpoint = 0
        return path


def _key(record: dict) -> tuple:
    return (record.get("trace_id"), record.get("span_id"))
