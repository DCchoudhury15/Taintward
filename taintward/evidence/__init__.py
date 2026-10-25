"""Taintward evidence layer: tamper-evident Merkle log of violations.

* ``merkle``: the Merkle log itself (one file), RFC 9162 inclusion and
  consistency proofs, crash repair.
* ``locking``: file locks and fsync helpers.
* ``shards``: the log split per tenant and per UTC day.
* ``checkpoint``: Ed25519 signed checkpoints over the shards.
* ``recorder``: record collector violations from SigNoz.
* ``spans`` / ``report``: span sources and the evidence report.
"""

from taintward.evidence import merkle, recorder

__all__ = ["merkle", "recorder"]
