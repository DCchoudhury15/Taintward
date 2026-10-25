"""Tamper-evident Merkle log of AgentWard violations.

Each violation the collector's Rego policy flags is appended as a leaf. The
log is a Merkle hash tree over SHA-256 in the shape defined by RFC 6962 /
RFC 9162 (Certificate Transparency), stored as an append-only file with one
canonical JSON record per line. Anyone can prove that a record is in the log
(inclusion proof) and that a newer log extends an older one without changing
it (consistency proof). Both proofs are O(log n) hashes.

Tree (RFC 9162 section 2.1.1)::

    leaf hash      = SHA256(0x00 || canonical_json(record))
    node hash      = SHA256(0x01 || left || right)      # ordered
    MTH([])        = SHA256("")
    MTH([d0])      = leaf hash of d0
    MTH(D[0:n])    = node(MTH(D[0:k]), MTH(D[k:n]))     # k = largest power of 2 < n

The bottom-up build in ``_root`` (pair neighbours, carry a lone last node up
unchanged) gives exactly this tree. A lone node is never paired with a copy
of itself: that is the CVE-2012-2459 bug, where n leaves and n+1 leaves (a
copy of the last one appended) give the same root.

Proofs bind the position. A verifier derives the left/right order of every
step from ``leaf_index`` and ``tree_size`` (RFC 9162 section 2.1.3.2), so a
proof for leaf 1 does not verify as leaf 3, and a proof only verifies against
the root of the tree size it was made for.

File format: one record per line, ``json.dumps(record, sort_keys=True,
separators=(",", ":"))`` followed by ``\\n``. The leaf hash is taken over
exactly those bytes, so a line that is not in this canonical form is
rejected when the file is loaded (it would let two readers see different
content under the same hash, for example with duplicate keys).

Crash safety: writers take an exclusive ``flock`` on the file, write one
full line and ``fsync`` it. Readers take a shared lock. If the process dies
in the middle of a write, the last line can be incomplete. Loading such a
file raises :class:`TornTailError`; ``repair_log`` (CLI: ``repair``) moves
the broken last line to ``<file>.corrupt``. A broken line anywhere else
raises :class:`LogCorruptError` and cannot be repaired: it means the file
was changed.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from evidence.locking import flock, fsync_dir

PROOF_VERSION = 2
EMPTY_ROOT = hashlib.sha256(b"").digest()


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------

class LogCorruptError(ValueError):
    """A line of the log file is broken. In the middle of the file this
    means the file was changed by something other than this code."""

    def __init__(self, path, line_no: int, reason: str, message: str | None = None):
        self.path = str(path)
        self.line_no = line_no
        self.reason = reason
        super().__init__(message or (
            f"{path}: line {line_no} is broken ({reason}). A broken line before the end "
            f"of the file means the log was changed; it cannot be repaired"))


class TornTailError(LogCorruptError):
    """Only the last line is broken, which is what a crash during a write
    leaves behind. ``repair_log`` moves it aside."""

    def __init__(self, path, line_no: int, reason: str, offset: int):
        self.offset = offset
        super().__init__(path, line_no, reason, (
            f"{path}: the last line (line {line_no}) is incomplete or broken ({reason}). "
            f"This usually means a crash while writing. Nothing was dropped. Run "
            f"'agentward-evidence --log-file {path} repair' to move it to {path}.corrupt"))


# ---------------------------------------------------------------------------
# hashing
# ---------------------------------------------------------------------------

def canonical_json(record: dict) -> bytes:
    """The bytes stored on disk and hashed for a record."""
    if not isinstance(record, dict):
        raise TypeError(f"a log record must be a JSON object, not {type(record).__name__}")
    return json.dumps(record, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def _leaf(blob: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + blob).digest()


def _hash_leaf(record: dict) -> bytes:
    """Leaf hash: SHA256 over 0x00 and the record's canonical JSON."""
    return _leaf(canonical_json(record))


hash_record = _hash_leaf


def _hash_parent(left: bytes, right: bytes) -> bytes:
    """Internal node hash. Ordered (left || right), so reordering leaves
    changes the root."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def _next_level(level: list[bytes]) -> list[bytes]:
    """Pair adjacent nodes; a lone last node moves up unchanged."""
    nxt: list[bytes] = []
    n = len(level)
    for i in range(0, n - 1, 2):
        nxt.append(_hash_parent(level[i], level[i + 1]))
    if n % 2:
        nxt.append(level[-1])
    return nxt


def _root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return EMPTY_ROOT
    level = list(leaves)
    while len(level) > 1:
        level = _next_level(level)
    return level[0]


def _split(n: int) -> int:
    """Largest power of two smaller than n (n >= 2)."""
    return 1 << ((n - 1).bit_length() - 1)


def _mth(leaves: list[bytes], lo: int, hi: int) -> bytes:
    """Merkle tree hash of leaves[lo:hi] (RFC 9162 2.1.1)."""
    return _root(leaves[lo:hi])


def _audit_path(leaves: list[bytes], m: int, lo: int, hi: int,
                out: list[bytes], dirs: list[bool]) -> None:
    """RFC 9162 2.1.3.1 PATH(m, D[lo:hi]), deepest sibling first."""
    n = hi - lo
    if n <= 1:
        return
    k = _split(n)
    if m < k:
        _audit_path(leaves, m, lo, lo + k, out, dirs)
        out.append(_mth(leaves, lo + k, hi))
        dirs.append(True)
    else:
        _audit_path(leaves, m - k, lo + k, hi, out, dirs)
        out.append(_mth(leaves, lo, lo + k))
        dirs.append(False)


def _subproof(leaves: list[bytes], m: int, lo: int, hi: int, whole: bool,
              out: list[bytes]) -> None:
    """RFC 9162 2.1.4.1 SUBPROOF(m, D[lo:hi], b)."""
    n = hi - lo
    if m == n:
        if not whole:
            out.append(_mth(leaves, lo, hi))
        return
    k = _split(n)
    if m <= k:
        _subproof(leaves, m, lo, lo + k, whole, out)
        out.append(_mth(leaves, lo + k, hi))
    else:
        _subproof(leaves, m - k, lo + k, hi, False, out)
        out.append(_mth(leaves, lo, lo + k))


# ---------------------------------------------------------------------------
# verification (RFC 9162)
# ---------------------------------------------------------------------------

def verify_audit_path(leaf_hash: bytes, leaf_index: int, tree_size: int,
                      path: list[bytes], root: bytes) -> bool:
    """RFC 9162 2.1.3.2: is ``leaf_hash`` leaf ``leaf_index`` of the tree of
    ``tree_size`` leaves whose root is ``root``? The side of every sibling
    comes from the index and the size, never from the proof."""
    try:
        leaf_index, tree_size = int(leaf_index), int(tree_size)
    except (TypeError, ValueError):
        return False
    if not 0 <= leaf_index < tree_size:
        return False
    fn, sn, r = leaf_index, tree_size - 1, leaf_hash
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = _hash_parent(p, r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = _hash_parent(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(old_size: int, new_size: int, old_root: bytes, new_root: bytes,
                       proof: list[bytes]) -> bool:
    """RFC 9162 2.1.4.2: does the tree of ``new_size`` leaves with root
    ``new_root`` start with the tree of ``old_size`` leaves with root
    ``old_root``, unchanged?"""
    try:
        m, n = int(old_size), int(new_size)
    except (TypeError, ValueError):
        return False
    if not 0 <= m <= n:
        return False
    if m == 0:
        return not proof and old_root == EMPTY_ROOT
    if m == n:
        return not proof and old_root == new_root
    if not proof:
        return False
    path = list(proof)
    if m & (m - 1) == 0:  # exact power of two: the old root is a subtree head
        path.insert(0, old_root)
    fn, sn = m - 1, n - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = _hash_parent(c, fr)
            sr = _hash_parent(c, sr)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = _hash_parent(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == old_root and sr == new_root and sn == 0


@dataclass
class InclusionProof:
    """Audit path for one leaf.

    Format version 2 adds ``tree_size``. ``directions`` is still written so
    older readers can check new proofs, but it is ignored here: the order
    comes from ``leaf_index`` and ``tree_size``. Version 1 proofs (no
    ``tree_size``) can still be read; the verifier must then supply the tree
    size, for example from a signed checkpoint.
    """

    leaf_index: int
    leaf_hash: bytes
    siblings: list[bytes] = field(default_factory=list)  # deepest first
    directions: list[bool] = field(default_factory=list)  # informational only
    tree_size: int | None = None

    def to_dict(self) -> dict:
        return {
            "version": PROOF_VERSION,
            "leaf_index": self.leaf_index,
            "tree_size": self.tree_size,
            "leaf_hash": self.leaf_hash.hex(),
            "siblings": [s.hex() for s in self.siblings],
            "directions": self.directions,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, d: dict) -> "InclusionProof":
        size = d.get("tree_size")
        return cls(
            leaf_index=int(d["leaf_index"]),
            leaf_hash=bytes.fromhex(d["leaf_hash"]),
            siblings=[bytes.fromhex(x) for x in d["siblings"]],
            directions=list(d.get("directions", [])),
            tree_size=None if size is None else int(size),
        )

    @classmethod
    def from_json(cls, s: str) -> "InclusionProof":
        return cls.from_dict(json.loads(s))


def verify_inclusion(leaf_hash: bytes, proof: InclusionProof, root: bytes,
                     tree_size: int | None = None) -> bool:
    """Verify that ``leaf_hash`` is leaf ``proof.leaf_index`` of the tree
    with root ``root``.

    ``tree_size`` is the size the verifier trusts (for example from a signed
    checkpoint). Without it the proof's own ``tree_size`` is used; a proof
    without one (version 1) then fails. If both are given they must agree.
    """
    if leaf_hash != proof.leaf_hash:
        return False
    size = proof.tree_size if tree_size is None else tree_size
    if size is None:
        return False
    if proof.tree_size is not None and int(proof.tree_size) != int(size):
        return False
    return verify_audit_path(leaf_hash, proof.leaf_index, size, proof.siblings, root)


# ---------------------------------------------------------------------------
# file parsing
# ---------------------------------------------------------------------------

def _parse(data: bytes, path) -> tuple[list[dict], list[bytes]]:
    """Records and leaf hashes of a log file. Raises TornTailError when only
    the last line is broken and LogCorruptError for any other broken line."""
    records: list[dict] = []
    leaves: list[bytes] = []
    pieces = data.split(b"\n")
    unterminated = pieces[-1] != b""  # the file does not end with a newline
    if unterminated:
        last = len(pieces) - 1
    else:
        last = max((i for i, p in enumerate(pieces) if p.strip()), default=-1)
    offset = 0
    for i, raw in enumerate(pieces):
        start = offset
        offset += len(raw) + 1
        tail = i == last
        if tail and unterminated:
            raise TornTailError(path, i + 1, "no newline at the end", start)
        if not raw.strip():
            continue
        try:
            rec = json.loads(raw)
        except ValueError as e:
            if tail:
                raise TornTailError(path, i + 1, f"not valid JSON: {e}", start) from None
            raise LogCorruptError(path, i + 1, f"not valid JSON: {e}") from None
        try:
            blob = canonical_json(rec)
        except (TypeError, ValueError) as e:
            raise LogCorruptError(path, i + 1, str(e)) from None
        if blob != raw:
            raise LogCorruptError(path, i + 1, "not in canonical JSON form")
        records.append(rec)
        leaves.append(_leaf(blob))
    return records, leaves


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


def repair_log(path: str | os.PathLike) -> dict | None:
    """Move a broken last line to ``<path>.corrupt`` and cut it from the log.

    Returns what was done, or None when the file has no broken last line.
    Raises LogCorruptError when a line before the end is broken: that is not
    a crash and is never repaired.
    """
    path = Path(path)
    fd = os.open(path, os.O_RDWR)
    try:
        flock(fd)
        data = _read_fd(fd)
        try:
            _parse(data, path)
            return None
        except TornTailError as e:
            tail, keep = data[e.offset:], e.offset
            line, reason = e.line_no, e.reason
        records, _ = _parse(data[:keep], path)  # the rest must be sound
        corrupt = Path(str(path) + ".corrupt")
        cfd = os.open(corrupt, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        try:
            _write_all(cfd, tail if tail.endswith(b"\n") else tail + b"\n")
            os.fsync(cfd)
        finally:
            os.close(cfd)
        os.ftruncate(fd, keep)
        os.fsync(fd)
    finally:
        os.close(fd)
    return {"path": str(path), "corrupt_file": str(corrupt), "line": line,
            "reason": reason, "removed_bytes": len(tail), "records_kept": len(records)}


def _read_fd(fd: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks = []
    while True:
        b = os.read(fd, 1 << 20)
        if not b:
            break
        chunks.append(b)
    return b"".join(chunks)


# ---------------------------------------------------------------------------
# the log
# ---------------------------------------------------------------------------

def record_key(record: dict) -> tuple:
    """Identity of a violation record for de-duplication."""
    return (record.get("trace_id"), record.get("span_id"))


class MerkleLog:
    """An append-only Merkle log of violation records.

    The leaves are kept in memory; an append-only file mirrors them on disk.
    Several processes may append to the same file: each append locks the
    file, reloads it if another process changed it, writes one line and
    fsyncs it.
    """

    def __init__(self, path: str | os.PathLike | None = None):
        self.path = Path(path) if path else None
        self._leaves: list[bytes] = []
        self._records: list[dict] = []
        self._keys: set | None = None
        self._disk_size = 0
        self._root_cache: tuple[int, bytes] | None = None
        if self.path and self.path.exists():
            fd = os.open(self.path, os.O_RDONLY)
            try:
                flock(fd, exclusive=False)
                self._load_bytes(_read_fd(fd))
            finally:
                os.close(fd)

    # --- persistence ---

    def _load_bytes(self, data: bytes) -> None:
        records, leaves = _parse(data, self.path)
        self._records, self._leaves = records, leaves
        self._keys = None
        self._root_cache = None
        self._disk_size = len(data)

    @contextmanager
    def _writer(self) -> Iterator[int | None]:
        if self.path is None:
            yield None
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        created = not self.path.exists()
        fd = os.open(self.path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o644)
        try:
            flock(fd)
            if os.fstat(fd).st_size != self._disk_size:
                self._load_bytes(_read_fd(fd))  # another writer appended
            yield fd
        finally:
            os.close(fd)
        if created:
            fsync_dir(self.path.parent)

    # --- core ---

    def append(self, record: dict, *, unique: bool = False) -> int | None:
        """Append a record; return its leaf index.

        The record is serialized and hashed before anything changes, so a
        record that cannot be stored leaves the log as it was. The log keeps
        its own copy: changing ``record`` afterwards has no effect.

        With ``unique=True`` a record whose (trace_id, span_id) is already in
        the log is skipped and None is returned.
        """
        blob = canonical_json(record)          # raises before any change
        stored = json.loads(blob)              # own deep copy, as reloaded
        leaf = _leaf(blob)
        key = record_key(stored)
        with self._writer() as fd:
            if unique and key != (None, None) and key in self._key_set():
                return None
            if fd is not None:
                line = blob + b"\n"
                size = self._disk_size
                try:
                    _write_all(fd, line)
                    os.fsync(fd)
                except BaseException:
                    try:  # do not leave half a line behind
                        os.ftruncate(fd, size)
                    except OSError:
                        self._disk_size = -1  # force a reload next time
                    raise
                self._disk_size = size + len(line)
            idx = len(self._leaves)
            self._records.append(stored)
            self._leaves.append(leaf)
            if self._keys is not None:
                self._keys.add(key)
            return idx

    def _key_set(self) -> set:
        if self._keys is None:
            self._keys = {record_key(r) for r in self._records}
        return self._keys

    def contains_key(self, trace_id, span_id) -> bool:
        return (trace_id, span_id) in self._key_set()

    def __len__(self) -> int:
        return len(self._leaves)

    @property
    def disk_size(self) -> int:
        """Bytes of the file this log was last read from or written to."""
        return self._disk_size

    def root(self) -> bytes:
        """Current Merkle root (empty log: SHA256 of empty)."""
        n = len(self._leaves)
        if self._root_cache is None or self._root_cache[0] != n:
            self._root_cache = (n, _root(self._leaves))
        return self._root_cache[1]

    def prefix_root(self, size: int) -> bytes:
        """Root of the log as it was when it had ``size`` leaves."""
        if not 0 <= size <= len(self._leaves):
            raise IndexError(size)
        if size == len(self._leaves):
            return self.root()
        return _root(self._leaves[:size])

    def inclusion_proof(self, leaf_index: int, size: int | None = None) -> InclusionProof:
        """Audit path for ``leaf_index`` in the tree of the first ``size``
        leaves (default: all of them)."""
        n = len(self._leaves) if size is None else size
        if not 0 <= n <= len(self._leaves):
            raise IndexError(size)
        if not 0 <= leaf_index < n:
            raise IndexError(leaf_index)
        path: list[bytes] = []
        dirs: list[bool] = []
        _audit_path(self._leaves, leaf_index, 0, n, path, dirs)
        return InclusionProof(leaf_index=leaf_index, leaf_hash=self._leaves[leaf_index],
                              siblings=path, directions=dirs, tree_size=n)

    def consistency_proof(self, old_size: int, size: int | None = None) -> list[bytes]:
        """RFC 9162 proof that the tree of ``size`` leaves (default: all)
        extends the tree of ``old_size`` leaves."""
        n = len(self._leaves) if size is None else size
        if not 0 <= n <= len(self._leaves):
            raise IndexError(size)
        if not 0 <= old_size <= n:
            raise IndexError(old_size)
        out: list[bytes] = []
        if 0 < old_size < n:
            _subproof(self._leaves, old_size, 0, n, True, out)
        return out

    def leaf_hash(self, leaf_index: int) -> bytes:
        return self._leaves[leaf_index]

    def record(self, leaf_index: int) -> dict:
        return copy.deepcopy(self._records[leaf_index])

    def records(self) -> list[dict]:
        """A copy of all records, in append order."""
        return copy.deepcopy(self._records)


def verify_log_consistency(old_records: list[dict], new_records: list[dict]) -> bool:
    """Is ``old_records`` an unchanged prefix of ``new_records``?

    Exact O(n) check over the full record lists. When only the two roots are
    known, use ``MerkleLog.consistency_proof`` and ``verify_consistency``.
    """
    if len(old_records) > len(new_records):
        return False
    old = [_hash_leaf(r) for r in old_records]
    new = [_hash_leaf(r) for r in new_records[: len(old_records)]]
    return _root(old) == _root(new)


# --- a violation record shape (what the collector produces) ---

def violation_record(
    *,
    trace_id: str,
    span_id: str,
    tool: str,
    destination: str,
    jurisdiction: str,
    classes: str,
    reasons: str,
    timestamp_ns: int,
) -> dict:
    """Canonical violation record (the leaf content). Keep it non-sensitive:
    no raw values, only the taint classes, policy decision, and ids."""
    return {
        "trace_id": trace_id,
        "span_id": span_id,
        "tool": tool,
        "destination": destination,
        "jurisdiction": jurisdiction,
        "classes": classes,
        "reasons": reasons,
        "timestamp_ns": timestamp_ns,
    }
