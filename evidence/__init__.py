"""AgentWard evidence layer: tamper-evident Merkle log of violations.

* ``merkle``: the Merkle log itself (one file).
* ``shards``: the log split per tenant and per UTC day.
* ``checkpoint``: Ed25519 signed checkpoints over the shards.
* ``recorder``: record collector violations from SigNoz.
* ``spans`` / ``report``: span sources and the evidence report.
"""

from evidence import merkle, recorder

__all__ = ["merkle", "recorder"]
