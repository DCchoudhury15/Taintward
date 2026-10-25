# Phase 5: record, lineage, blast-radius, SLO, and tamper-evident evidence

**Status:** done (local, 2026-09-04). Verified with real collector violations
from SigNoz plus 8 unit tests.

AgentRaft produces *metrics* (57%, F1). Phase 5 turns the violation trail into
**cryptographically verifiable GDPR Art. 30/15 evidence**: a tamper-evident
Merkle log of every violation the collector's Rego policy flags, plus
lineage/blast-radius/SLO dashboards whose queries are the runtime data-flow
record.

## Pieces

- `evidence/merkle.py`: an append-only Merkle (SHA-256) log over violation
  records.
  - `leaf_hash = SHA256(0x00 || canonical_json(record))`
  - `parent_hash = SHA256(0x01 || left || right)`, **ordered** (not sorted) so
    the append sequence is preserved; reordering a prefix yields a different
    root (Crosby-Wallach / CT style).
  - `append` / `root` / `inclusion_proof(i)` / `record(i)`; append-only file
    persistence (rebuilt on load).
  - `verify_inclusion(leaf_hash, proof, root)`: O(log n).
  - `verify_log_consistency(old, new)`: the old prefix's root must equal the
    new log's first `len(old)` leaves' root.
  - `violation_record(...)`: a non-sensitive leaf shape (ids, taint classes,
    policy reasons, never raw values).
- `evidence/recorder.py`: `record_violations(log, service, since_minutes)`
  queries SigNoz/ClickHouse for spans with `agentward.policy.violation=1`
  (JSONEachRow via `docker exec clickhouse-client`) and appends each as a leaf.
- `evidence/log.py`: a CLI with `record` / `root` / `prove <i>` / `verify
  <json>` / `count`.
- `dashboards/lineage.json`, `blast_radius.json`, `slo.json`: ClickHouse SQL
  artifacts covering the lineage path per run (Art. 30 recipients/transfers),
  blast radius (distinct tools/destinations per tainted trace, for Art. 30
  disclosure and Art. 15 access), and a clean-run SLO (99% leak-free runs,
  where a violation burns the error budget) plus alerts.

## Verified end-to-end with real data

```
recorded 3 violation(s); log has 3 leaf/leaves           # ask_llm, call_external_api, write_log
Merkle root: f80576da8ff7a61f93e7fbfc316f025caae68a8b5b021c2f9b7245c4d75a1e43
inclusion proof for leaf 0 (ask_llm): verified=true
tamper detection: modified record -> root differs; original proof fails (False)
```

The `ask_llm` violation (real trace_id `203389...`, span_id, timestamp) is in
the log with a verifiable inclusion proof. Editing any record changes the
root and invalidates prior proofs.

## Out of scope (deferred)

- `analysis/fcg.py` + `prompt_synth.py` (AgentRaft's offline FCG / prompt
  synthesis as an audit/fuzz mode). The portfolio goal favors the runtime
  enforcement plus evidence story over the offline audit mode. The synthesized
  prompts would double as the integration-test corpus; left as a future
  addition on top of the Merkle evidence layer.
- Auto-importing the dashboards via the SigNoz MCP (`signoz_create_dashboard`).
  The MCP server isn't enabled in `casting.yaml` yet, so the SQL is the
  artifact for now, and it imports via the UI or MCP once that's enabled.

## Tests

- `tests/test_merkle.py`: 8 green (empty root, append, inclusion, tamper
  detection, stale-proof-after-append, consistency, persistence roundtrip,
  proof JSON roundtrip).
- Full suite: 39 Python green (14 DOE + 8 SDK + 9 redact + 8 merkle).

## Update (v0.2): evidence report, shards and signed checkpoints

- `evidence/report.py` (`python -m evidence.report`): a self-contained HTML
  or JSON report for a time window, built from Jaeger, OTLP JSON files or
  SigNoz/ClickHouse (`evidence/spans.py`). It covers calls, sensitive data by
  class, destinations, violations and their outcome, Art. 44 transfers, the
  Art. 30 recipients view, a raw value check on what was sent out, and the
  evidence log state. Sample: [`sample-report.html`](sample-report.html).
- `evidence/shards.py`: the log split per tenant and per UTC day
  (`<dir>/<tenant>/<YYYY-MM-DD>.logl`), safe for several writers.
- `evidence/checkpoint.py`: Ed25519 signed checkpoints (shard roots, sizes,
  time, previous checkpoint hash). Verification catches edited, reordered,
  truncated or deleted shards, edited or re-signed checkpoints and gaps in
  the chain; single records can be proved offline.
- `MerkleLog` gained `prefix_root(n)`, `inclusion_proof(i, size=n)` and
  `records()`. The `prove` CLI output now includes `directions`, so it can be
  passed to `verify` (before, a printed proof with siblings did not verify).
- Tests: `tests/test_report.py`, `tests/test_checkpoints.py`, two new cases
  in `tests/test_merkle.py`.

Usage and the verification steps for a third party: [`evidence-report.md`](evidence-report.md).

## Update: stronger proofs and crash safety

A security review of the log found five problems. All are fixed, with tests
in `tests/test_merkle.py` and `tests/test_checkpoints.py`.

- **Proofs now bind the position.** Before, the verifier took the left/right
  order of each step from the proof itself, so a proof for leaf 1 with
  `leaf_index` changed to 3 still passed. Now the order is worked out from
  `leaf_index` and `tree_size` (RFC 9162 section 2.1.3.2), so checking a
  proof needs the leaf, its index, the tree size, the path and the root.
  The tree shape did not change (it already matched RFC 6962, and the tests
  check the RFC test vectors), so old roots and checkpoints stay valid.
- **Consistency proofs.** `MerkleLog.consistency_proof(old_size)` and
  `verify_consistency(...)` (RFC 9162 section 2.1.4) show that a bigger tree
  starts with an older tree, unchanged, using O(log n) hashes. Each new
  checkpoint carries this proof for every shard that grew, and
  verification checks it. So a key holder who rewrites a record and signs a
  fresh checkpoint over the new files is still caught: the new checkpoint
  does not extend the old one. The writer also refuses to sign over a shard
  that no longer matches the previous checkpoint.
- **Append is atomic.** The record is turned into canonical JSON and hashed
  before anything changes. A record that cannot be stored (a set, NaN, not
  a dict) leaves the log as it was. The log keeps its own copy, so changing
  the dict later has no effect. A failed write is cut back off the file.
- **Crash safety.** Writers take an exclusive file lock, reload the file if
  another process added to it, write one line and fsync it. Readers take a
  shared lock. A broken last line (a crash during a write) is not dropped
  quietly: loading stops with a clear error, and `agentward-evidence repair`
  moves that line to `<file>.corrupt` and says what it moved. A broken line
  anywhere else is always a hard failure, because only a change to the file
  can cause it. Lines must be in canonical JSON form, so the bytes on disk
  are exactly the bytes that were hashed.
- **No duplicates in the single-file log.** `record` skips violations whose
  trace id and span id are already in the log, the same as the sharded log,
  so recording overlapping time windows does not add copies.

Format changes:

- Inclusion proof JSON is now version 2: it has `version` and `tree_size`.
  `directions` is still written so older tools can read new proofs, but it
  is ignored when verifying. Version 1 proofs (no `tree_size`) still load;
  the tree size then comes from the checkpoint, or from the log file for
  the CLI `verify` command.
- Checkpoint body is now version 2: a shard that grew has `prev_size` and
  `consistency` (hex hashes). Version 1 checkpoints still verify; for them
  the consistency proof is built from the shard file.
- New CLI options: `root --size N`, `prove I --size N`, `verify --root HEX`,
  `consistency --old-size M [--old-root HEX]` and `repair` (single file, or
  every shard with `--evidence-dir`).
