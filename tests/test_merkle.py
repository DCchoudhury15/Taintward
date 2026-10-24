"""Tests for the tamper-evident Merkle violation log."""

from __future__ import annotations

import tempfile
import unittest

from evidence.merkle import (
    MerkleLog,
    verify_inclusion,
    verify_log_consistency,
    violation_record,
)


def _viol(tool, dest="external", reasons="pii_egress"):
    return violation_record(
        trace_id="t" + tool, span_id="s" + tool, tool=tool,
        destination=dest, jurisdiction="us", classes="pii,secret",
        reasons=reasons, timestamp_ns=1700000000_000000000,
    )


class TestMerkleLog(unittest.TestCase):
    def test_empty_root_is_stable(self):
        a = MerkleLog()
        b = MerkleLog()
        self.assertEqual(a.root(), b.root())
        self.assertEqual(len(a), 0)

    def test_append_changes_root_and_grows(self):
        log = MerkleLog()
        r0 = log.root()
        log.append(_viol("call_external_api"))
        self.assertEqual(len(log), 1)
        self.assertNotEqual(log.root(), r0)

    def test_inclusion_proof_verifies(self):
        log = MerkleLog()
        for t in ["ask_llm", "call_external_api", "write_log", "query_db"]:
            log.append(_viol(t))
        for i in range(len(log)):
            proof = log.inclusion_proof(i)
            self.assertTrue(verify_inclusion(proof.leaf_hash, proof, log.root()),
                            f"inclusion proof for leaf {i} failed")

    def test_tamper_detection_modified_record_changes_root(self):
        log = MerkleLog()
        log.append(_viol("call_external_api"))
        root_before = log.root()
        proof = log.inclusion_proof(0)
        # tamper: rebuild a log with the same count but a changed record
        tampered = MerkleLog()
        v = _viol("call_external_api")
        v["tool"] = "TAMPERED"
        tampered.append(v)
        root_after = tampered.root()
        self.assertNotEqual(root_after, root_before)
        # the old proof does NOT verify against the tampered root
        self.assertFalse(verify_inclusion(proof.leaf_hash, proof, root_after))

    def test_stale_proof_fails_after_more_appends(self):
        log = MerkleLog()
        log.append(_viol("call_external_api"))
        proof = log.inclusion_proof(0)
        root1 = log.root()
        self.assertTrue(verify_inclusion(proof.leaf_hash, proof, root1))
        # append more: root changes, the OLD root/proof no longer match the new root
        log.append(_viol("ask_llm"))
        log.append(_viol("write_log"))
        root2 = log.root()
        self.assertNotEqual(root1, root2)
        # but a fresh proof for leaf 0 DOES verify against the new root
        fresh = log.inclusion_proof(0)
        self.assertTrue(verify_inclusion(fresh.leaf_hash, fresh, root2))

    def test_odd_leaf_count_duplicate_append_changes_root(self):
        """Regression for the classic CVE-2012-2459 Merkle bug: pairing an
        unpaired trailing leaf with a duplicate of itself makes an n-leaf
        tree's root collide with the root of an (n+1)-leaf tree formed by
        appending a copy of the last leaf. That would let an attacker (or a
        buggy retry) insert a duplicate record into the log without moving
        the root at all - silently defeating the log's whole purpose."""
        log = MerkleLog()
        for t in ["a", "b", "c"]:  # odd leaf count
            log.append(_viol(t))
        root_before = log.root()
        log.append(_viol("c"))  # duplicate of the last leaf
        root_after = log.root()
        self.assertNotEqual(root_before, root_after)

    def test_inclusion_proof_verifies_for_odd_leaf_counts(self):
        for n in (1, 3, 5, 7, 9):
            log = MerkleLog()
            for i in range(n):
                log.append(_viol(f"t{i}"))
            root = log.root()
            for i in range(n):
                proof = log.inclusion_proof(i)
                self.assertTrue(
                    verify_inclusion(proof.leaf_hash, proof, root),
                    f"inclusion proof failed for n={n} leaf={i}",
                )

    def test_consistency_prefix_root_matches(self):
        records = [_viol(t) for t in ["a", "b", "c", "d"]]
        old = records[:2]
        new = records
        self.assertTrue(verify_log_consistency(old, new))
        # a reordered/replaced prefix is NOT consistent
        bad = [records[1], records[0]]
        self.assertFalse(verify_log_consistency(bad, new))

    def test_persistence_roundtrip(self,):
        with tempfile.NamedTemporaryFile(suffix=".logl", delete=False) as f:
            path = f.name
        log = MerkleLog(path)
        for t in ["ask_llm", "call_external_api"]:
            log.append(_viol(t))
        root1 = log.root()
        # reopen from disk
        log2 = MerkleLog(path)
        self.assertEqual(len(log2), 2)
        self.assertEqual(log2.root(), root1)
        import os
        os.unlink(path)

    def test_proof_json_roundtrip(self):
        log = MerkleLog()
        log.append(_viol("call_external_api"))
        proof = log.inclusion_proof(0)
        from evidence.merkle import InclusionProof
        restored = InclusionProof.from_json(proof.to_json())
        self.assertEqual(restored.leaf_hash, proof.leaf_hash)
        self.assertEqual(restored.siblings, proof.siblings)
        self.assertTrue(verify_inclusion(restored.leaf_hash, restored, log.root()))

    def test_prefix_root_and_prefix_proof(self):
        log = MerkleLog()
        old = MerkleLog()
        for i in range(7):
            log.append(_viol(f"t{i}"))
            if i < 5:
                old.append(_viol(f"t{i}"))
        self.assertEqual(log.prefix_root(5), old.root())
        self.assertEqual(log.prefix_root(7), log.root())
        for i in range(5):
            proof = log.inclusion_proof(i, size=5)
            self.assertTrue(verify_inclusion(proof.leaf_hash, proof, old.root()))
        with self.assertRaises(IndexError):
            log.inclusion_proof(5, size=5)

    def test_cli_prove_output_verifies(self):
        # `prove` prints directions, so its output can be fed to `verify`
        import contextlib
        import io
        import json
        import os

        from evidence.log import main

        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "v.logl")
            log = MerkleLog(path)
            for t in ["a", "b", "c"]:
                log.append(_viol(t))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertEqual(main(["--log-file", path, "prove", "2"]), 0)
            printed = buf.getvalue()
            self.assertIn("directions", json.loads(printed))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--log-file", path, "verify", printed]), 0)


if __name__ == "__main__":
    unittest.main()