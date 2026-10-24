"""Tamper-evident Merkle log of AgentWard violations.

Each violation the collector's Rego policy flags is appended as a leaf. The
log is a Merkle (binary hash) tree over SHA-256, persisted as an append-only
file of leaf records plus a rolling root. This turns the lineage/blast-radius
dashboards from "metrics" into **cryptographically verifiable** GDPR Art. 30 /
Art. 15 evidence: anyone can prove a given violation is in the log (inclusion,
via an O(log n) sibling-hash audit path) and that the log has not been
tampered with or reordered (consistency, via ``verify_log_consistency``,
which recomputes both roots from the full record lists it is given - O(n),
not an O(log n) audit-path proof, but exact).

Design (Crosby-Wallach / Certificate-Transparency style):
  leaf_hash(i)  = SHA256(0x00 || canonical_json(record_i))
  parent_hash   = SHA256(0x01 || left || right)      # ORDERED, not sorted -
                                                       # this is what makes
                                                       # reordering detectable
  inclusion proof for leaf i = the sibling hashes on the path to the root
  consistency proof (new root from old root) = the subtree heads that changed

An odd node at any level is carried up to the next level *unchanged* rather
than being paired with a duplicate of itself. Self-pairing an odd node
(``SHA256(0x01 || C || C)``) is the classic Merkle bug (CVE-2012-2459 in
Bitcoin): it makes the root of an n-leaf tree collide with the root of an
(n+1)-leaf tree formed by appending a duplicate of the last leaf, so an
attacker (or a buggy retry) can insert a record into the log without moving
the root at all. Carrying the odd node up unhashed avoids that collision.

The append-only file stores one JSON record per line (the leaf content); the
tree is rebuilt from the file on load. A separate small manifest could persist
the rolling root, but recomputing from the file on load is simpler and the file
itself is the source of truth (an attacker editing it changes the root).
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path


def _hash_leaf(record: dict) -> bytes:
    """Leaf hash: SHA256 over a domain-prefixed canonical JSON of the record."""
    blob = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(b"\x00" + blob).digest()


def _hash_parent(left: bytes, right: bytes) -> bytes:
    """Internal node hash. ORDERED (left || right), not sorted, so the append
    sequence is preserved in the tree structure. This is what makes the log
    tamper-evident against reordering: a reordered prefix produces a different
    root (Crosby-Wallach / Certificate-Transparency style)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def _next_level(level: list[bytes]) -> list[bytes]:
    """Combine one tree level into the next: pair adjacent nodes; an unpaired
    trailing node (odd-length level) is carried up *unchanged*, never paired
    with a duplicate of itself (see module docstring: CVE-2012-2459)."""
    nxt: list[bytes] = []
    n = len(level)
    i = 0
    while i < n:
        if i + 1 < n:
            nxt.append(_hash_parent(level[i], level[i + 1]))
            i += 2
        else:
            nxt.append(level[i])  # odd one out: promote unchanged
            i += 1
    return nxt


def _root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    level = list(leaves)
    while len(level) > 1:
        level = _next_level(level)
    return level[0]


@dataclass
class InclusionProof:
    leaf_index: int
    leaf_hash: bytes
    siblings: list[bytes] = field(default_factory=list)  # ordered rootward
    # directions[i] is True iff siblings[i] sits to the *right* of the
    # accumulated hash at that step (False = sibling on the left). Stored
    # explicitly (rather than re-derived from leaf_index parity at verify
    # time) because odd levels can be skipped (see _next_level), so parity
    # of leaf_index alone is not enough to reconstruct which side a sibling
    # was on.
    directions: list[bool] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps({
            "leaf_index": self.leaf_index,
            "leaf_hash": self.leaf_hash.hex(),
            "siblings": [s.hex() for s in self.siblings],
            "directions": self.directions,
        })

    @classmethod
    def from_json(cls, s: str) -> "InclusionProof":
        d = json.loads(s)
        return cls(
            leaf_index=d["leaf_index"],
            leaf_hash=bytes.fromhex(d["leaf_hash"]),
            siblings=[bytes.fromhex(x) for x in d["siblings"]],
            directions=list(d.get("directions", [])),
        )


class MerkleLog:
    """An append-only Merkle log of violation records.

    The leaves are kept in memory; an append-only file mirrors them on disk so
    the log survives restarts. The root recomputes from the leaves on demand.
    """

    def __init__(self, path: str | os.PathLike | None = None):
        self.path = Path(path) if path else None
        self._leaves: list[bytes] = []          # leaf hashes
        self._records: list[dict] = []          # the records themselves
        if self.path and self.path.exists():
            self._load()

    # --- persistence ---

    def _load(self) -> None:
        assert self.path is not None
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                self._records.append(rec)
                self._leaves.append(_hash_leaf(rec))

    def _append_file(self, record: dict) -> None:
        if self.path is None:
            return
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")

    # --- core ---

    def append(self, record: dict) -> int:
        """Append a violation record; return its leaf index."""
        idx = len(self._leaves)
        self._records.append(record)
        self._leaves.append(_hash_leaf(record))
        self._append_file(record)
        return idx

    def __len__(self) -> int:
        return len(self._leaves)

    def root(self) -> bytes:
        """Current Merkle root (empty log -> SHA256 of empty)."""
        return _root(self._leaves)

    def prefix_root(self, size: int) -> bytes:
        """Root of the log as it was when it had ``size`` leaves.

        Used to check a log file against a signed checkpoint taken earlier:
        records appended after the checkpoint do not change this value.
        """
        if not 0 <= size <= len(self._leaves):
            raise IndexError(size)
        return _root(self._leaves[:size])

    def inclusion_proof(self, leaf_index: int, size: int | None = None) -> InclusionProof:
        """Audit path for ``leaf_index``. With ``size``, the path is against
        the root of the first ``size`` leaves (see ``prefix_root``)."""
        n_leaves = len(self._leaves) if size is None else size
        if not 0 <= n_leaves <= len(self._leaves):
            raise IndexError(size)
        if not 0 <= leaf_index < n_leaves:
            raise IndexError(leaf_index)
        siblings: list[bytes] = []
        directions: list[bool] = []
        idx = leaf_index
        level = list(self._leaves[:n_leaves])
        while len(level) > 1:
            n = len(level)
            if idx % 2 == 0:
                if idx + 1 < n:
                    siblings.append(level[idx + 1])
                    directions.append(True)  # sibling on the right
                # else: idx is the unpaired trailing node at this level; it is
                # promoted unchanged (see _next_level) so there is no sibling
                # to record and no hash combination happens at this level.
            else:
                siblings.append(level[idx - 1])
                directions.append(False)  # sibling on the left
            level = _next_level(level)
            idx //= 2
        return InclusionProof(leaf_index=leaf_index,
                              leaf_hash=self._leaves[leaf_index],
                              siblings=siblings,
                              directions=directions)

    def record(self, leaf_index: int) -> dict:
        return self._records[leaf_index]

    def records(self) -> list[dict]:
        """A copy of all records, in append order."""
        return list(self._records)


def verify_inclusion(leaf_hash: bytes, proof: InclusionProof, root: bytes) -> bool:
    """Verify that ``leaf_hash`` is in the log whose root is ``root``.

    Rebuild the path from the leaf upward using the proof's sibling hashes,
    combining on the side recorded in ``proof.directions`` (not re-derived
    from ``leaf_index`` parity, since odd tree levels can skip a combination
    step entirely - see ``_next_level``).
    """
    if len(proof.siblings) != len(proof.directions):
        return False
    h = leaf_hash
    for sib, sibling_is_right in zip(proof.siblings, proof.directions):
        if sibling_is_right:
            h = _hash_parent(h, sib)
        else:
            h = _hash_parent(sib, h)
    return h == root


def verify_log_consistency(old_records: list[dict], new_records: list[dict]) -> bool:
    """Consistency: is ``old_records`` a prefix of ``new_records`` (by content)?

    For an append-only log this is the Crosby-Wallach consistency check reduced
    to: every old leaf must appear, in order, as a prefix of the new leaves,
    AND the old root must equal the root of the new log's first len(old) leaves.
    """
    if len(old_records) > len(new_records):
        return False
    old_log = MerkleLog()
    for r in old_records:
        old_log.append(r)
    new_prefix = MerkleLog()
    for r in new_records[: len(old_records)]:
        new_prefix.append(r)
    return old_log.root() == new_prefix.root()


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