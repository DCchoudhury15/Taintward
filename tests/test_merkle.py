"""Tests for the tamper-evident Merkle violation log."""

from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import random
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from evidence.merkle import (
    InclusionProof,
    LogCorruptError,
    MerkleLog,
    TornTailError,
    repair_log,
    verify_audit_path,
    verify_consistency,
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



RFC_LEAVES = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657",
              "606162636465666768696a6b6c6d6e6f"]
RFC_ROOTS = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
]



def _raw_leaves(n):
    from evidence.merkle import _leaf
    return [_leaf(bytes.fromhex(d)) for d in RFC_LEAVES[:n]]


def _log_with_leaves(leaves):
    log = MerkleLog()
    log._leaves = list(leaves)
    log._records = [{} for _ in leaves]
    return log


class TestRfc9162(unittest.TestCase):
    """The tree shape and proofs follow RFC 6962 / RFC 9162."""

    def test_roots_match_rfc_test_vectors(self):
        from evidence.merkle import _root
        leaves = _raw_leaves(8)
        for n in range(1, 9):
            self.assertEqual(_root(leaves[:n]).hex(), RFC_ROOTS[n - 1], n)

    def test_inclusion_path_matches_rfc_vector(self):
        log = _log_with_leaves(_raw_leaves(8))
        proof = log.inclusion_proof(0)
        self.assertEqual([h.hex() for h in proof.siblings], [
            "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
        ])

    def test_moved_index_does_not_verify(self):
        """The reported bug: a proof for leaf 1 with leaf_index set to 3
        verified, because the sides came from the proof. Now they come from
        the index and the tree size."""
        log = MerkleLog()
        for i in range(4):
            log.append({"i": i})
        proof = log.inclusion_proof(1)
        self.assertTrue(verify_inclusion(proof.leaf_hash, proof, log.root()))
        proof.leaf_index = 3
        self.assertFalse(verify_inclusion(proof.leaf_hash, proof, log.root()))
        # flipping the stored directions does not help or hurt: they are ignored
        proof.leaf_index = 1
        proof.directions = [not d for d in proof.directions]
        self.assertTrue(verify_inclusion(proof.leaf_hash, proof, log.root()))

    def test_wrong_tree_size_does_not_verify(self):
        log = MerkleLog()
        for i in range(6):
            log.append({"i": i})
        proof = log.inclusion_proof(4)
        root = log.root()
        self.assertFalse(verify_inclusion(proof.leaf_hash, proof, root, tree_size=7))
        proof.tree_size = None  # a version 1 proof needs a size from the verifier
        self.assertFalse(verify_inclusion(proof.leaf_hash, proof, root))
        self.assertTrue(verify_inclusion(proof.leaf_hash, proof, root, tree_size=6))

    def test_version1_proof_json_still_reads(self):
        log = MerkleLog()
        for i in range(5):
            log.append({"i": i})
        p = log.inclusion_proof(2)
        old = json.dumps({"leaf_index": 2, "leaf_hash": p.leaf_hash.hex(),
                          "siblings": [x.hex() for x in p.siblings],
                          "directions": p.directions})
        restored = InclusionProof.from_json(old)
        self.assertIsNone(restored.tree_size)
        self.assertTrue(verify_inclusion(restored.leaf_hash, restored, log.root(), tree_size=5))

    def test_property_random_trees(self):
        """For random trees every (index, size) proof verifies, and every
        changed index, size, path entry or path length fails."""
        rng = random.Random(9162)
        for n in list(range(1, 34)) + [rng.randint(34, 300) for _ in range(6)]:
            leaves = [hashlib.sha256(rng.randbytes(8)).digest() for _ in range(n)]
            log = _log_with_leaves(leaves)
            sizes = range(1, n + 1) if n <= 33 else rng.sample(range(1, n + 1), 8)
            for size in sizes:
                root = log.prefix_root(size)
                idxs = range(size) if size <= 33 else rng.sample(range(size), 8)
                for i in idxs:
                    p = log.inclusion_proof(i, size=size)
                    path = p.siblings
                    self.assertTrue(verify_audit_path(leaves[i], i, size, path, root))
                    for j in {0, i - 1, i + 1, size - 1, size, rng.randrange(size)}:
                        if j != i:
                            self.assertFalse(verify_audit_path(leaves[i], j, size, path, root),
                                             (n, size, i, j))
                    # another size, checked against the true root of that size
                    for s2 in {size - 1, size + 1, rng.randint(1, n)}:
                        if s2 != size and i < s2 <= n:
                            self.assertFalse(verify_audit_path(leaves[i], i, s2, path,
                                                               log.prefix_root(s2)),
                                             (n, size, i, s2))
                    for k in range(len(path)):
                        bad = list(path)
                        bad[k] = hashlib.sha256(bad[k]).digest()
                        self.assertFalse(verify_audit_path(leaves[i], i, size, bad, root))
                    if path:
                        self.assertFalse(verify_audit_path(leaves[i], i, size, path[:-1], root))
                    self.assertFalse(verify_audit_path(leaves[i], i, size, path + [root], root))
                    other = hashlib.sha256(b"x" + leaves[i]).digest()
                    self.assertFalse(verify_audit_path(other, i, size, path, root))

    def test_property_consistency(self):
        from evidence.merkle import _root

        rng = random.Random(6962)
        for n in list(range(1, 30)) + [rng.randint(30, 200) for _ in range(4)]:
            leaves = [hashlib.sha256(rng.randbytes(8)).digest() for _ in range(n)]
            log = _log_with_leaves(leaves)
            new_root = log.root()
            olds = range(0, n + 1) if n < 30 else rng.sample(range(0, n + 1), 10)
            for m in olds:
                old_root = log.prefix_root(m)
                proof = log.consistency_proof(m)
                self.assertTrue(verify_consistency(m, n, old_root, new_root, proof), (m, n))
                for k in range(len(proof)):
                    bad = list(proof)
                    bad[k] = hashlib.sha256(bad[k]).digest()
                    self.assertFalse(verify_consistency(m, n, old_root, new_root, bad))
                if 0 < m < n:
                    self.assertFalse(verify_consistency(m, n, hashlib.sha256(old_root).digest(),
                                                        new_root, proof))
                    self.assertFalse(verify_consistency(m, n, old_root,
                                                        hashlib.sha256(new_root).digest(), proof))
                    # other sizes, each with the true root of that size
                    for m2 in {m - 1, m + 1}:
                        if 0 < m2 < n:
                            self.assertFalse(verify_consistency(m2, n, log.prefix_root(m2),
                                                                new_root, proof))
                    bigger = _root(leaves + [hashlib.sha256(b"extra").digest()])
                    self.assertFalse(verify_consistency(m, n + 1, old_root, bigger, proof))
                    self.assertFalse(verify_consistency(m, n, old_root, new_root, proof[:-1]))

    def test_rewritten_history_fails_consistency(self):
        a = MerkleLog()
        for i in range(5):
            a.append({"i": i})
        old_size, old_root = len(a), a.root()
        b = MerkleLog()
        for i in range(8):
            b.append({"i": i if i != 2 else "changed"})
        proof = b.consistency_proof(old_size)
        self.assertFalse(verify_consistency(old_size, 8, old_root, b.root(), proof))


class TestAppendSafety(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.path = Path(self._td.name) / "v.logl"

    def tearDown(self):
        self._td.cleanup()

    def test_unserializable_record_changes_nothing(self):
        log = MerkleLog(self.path)
        log.append(_viol("a"))
        before = (len(log), log.root(), self.path.read_bytes())
        for bad in ({"x": {1, 2}}, {"x": float("nan")}, {"x": object()}, ["not", "a", "dict"]):
            with self.assertRaises((TypeError, ValueError)):
                log.append(bad)
            self.assertEqual((len(log), log.root(), self.path.read_bytes()), before)
            self.assertEqual(len(log.records()), len(log))
        self.assertEqual(log.append(_viol("b")), 1)
        self.assertEqual(MerkleLog(self.path).root(), log.root())

    def test_caller_mutation_after_append_has_no_effect(self):
        log = MerkleLog(self.path)
        r = _viol("a")
        r["nested"] = {"k": [1, 2]}
        log.append(r)
        r["tool"] = "CHANGED"
        r["nested"]["k"].append(3)
        self.assertEqual(log.record(0)["tool"], "a")
        self.assertEqual(log.record(0)["nested"], {"k": [1, 2]})
        log.record(0)["tool"] = "CHANGED"      # returned copies are copies
        log.records()[0]["tool"] = "CHANGED"
        self.assertEqual(log.record(0)["tool"], "a")
        self.assertEqual(MerkleLog(self.path).root(), log.root())

    def test_failed_write_is_rolled_back(self):
        from evidence import merkle

        log = MerkleLog(self.path)
        log.append(_viol("a"))
        before = self.path.read_bytes()

        def half_then_fail(fd, data):
            os.write(fd, data[: len(data) // 2])
            raise OSError("disk full")

        with mock.patch.object(merkle, "_write_all", half_then_fail):
            with self.assertRaises(OSError):
                log.append(_viol("b"))
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(len(log), 1)
        self.assertEqual(log.append(_viol("b")), 1)
        self.assertEqual(len(MerkleLog(self.path)), 2)

    def test_append_fsyncs(self):
        from evidence import merkle

        log = MerkleLog(self.path)
        with mock.patch.object(merkle.os, "fsync", wraps=os.fsync) as fs:
            log.append(_viol("a"))
        self.assertGreaterEqual(fs.call_count, 1)

    def test_two_instances_share_the_file(self):
        a, b = MerkleLog(self.path), MerkleLog(self.path)
        self.assertEqual(a.append(_viol("a")), 0)
        self.assertEqual(b.append(_viol("b")), 1)   # reloaded a's line first
        self.assertEqual(a.append(_viol("c")), 2)
        self.assertEqual(len(MerkleLog(self.path)), 3)
        self.assertEqual(MerkleLog(self.path).root(), a.root())

    def test_several_processes_append(self):
        ctx = multiprocessing.get_context("fork")
        procs = [ctx.Process(target=_append_many, args=(str(self.path), w, 40))
                 for w in range(4)]
        for p in procs:
            p.start()
        for p in procs:
            p.join(30)
            self.assertEqual(p.exitcode, 0)
        log = MerkleLog(self.path)
        self.assertEqual(len(log), 160)
        self.assertEqual(len({(r["w"], r["i"]) for r in log.records()}), 160)

    def test_unique_append(self):
        log = MerkleLog(self.path)
        self.assertEqual(log.append(_viol("a"), unique=True), 0)
        self.assertIsNone(log.append(_viol("a"), unique=True))
        self.assertEqual(log.append(_viol("b"), unique=True), 1)
        self.assertIsNone(MerkleLog(self.path).append(_viol("b"), unique=True))
        self.assertEqual(log.append(_viol("a")), 2)  # default: no de-duplication
        self.assertEqual(len(MerkleLog(self.path)), 3)


def _append_many(path, w, n):
    log = MerkleLog(path)
    for i in range(n):
        log.append({"w": w, "i": i})


class TestBrokenFile(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.path = Path(self._td.name) / "v.logl"
        log = MerkleLog(self.path)
        for t in ["a", "b", "c"]:
            log.append(_viol(t))
        self.root = log.root()
        self.good = self.path.read_bytes()

    def tearDown(self):
        self._td.cleanup()

    def test_torn_last_line_is_refused_not_dropped(self):
        line = json.dumps(_viol("d"), sort_keys=True, separators=(",", ":"))
        self.path.write_bytes(self.good + line[:20].encode())
        with self.assertRaises(TornTailError) as cm:
            MerkleLog(self.path)
        self.assertIn("repair", str(cm.exception))
        self.assertEqual(cm.exception.line_no, 4)

    def test_full_record_without_newline_is_torn(self):
        line = json.dumps(_viol("d"), sort_keys=True, separators=(",", ":"))
        self.path.write_bytes(self.good + line.encode())
        with self.assertRaises(TornTailError):
            MerkleLog(self.path)

    def test_writer_refuses_to_append_after_torn_line(self):
        log = MerkleLog(self.path)
        with self.path.open("ab") as f:
            f.write(b'{"trace_id":"t')
        with self.assertRaises(TornTailError):
            log.append(_viol("e"))
        self.assertTrue(self.path.read_bytes().endswith(b'{"trace_id":"t'))

    def test_repair_moves_tail_to_corrupt_file(self):
        self.path.write_bytes(self.good + b'{"trace_id":"tx","sp')
        done = repair_log(self.path)
        self.assertEqual(done["records_kept"], 3)
        self.assertEqual(done["line"], 4)
        self.assertEqual(self.path.read_bytes(), self.good)
        corrupt = Path(str(self.path) + ".corrupt")
        self.assertEqual(corrupt.read_bytes(), b'{"trace_id":"tx","sp\n')
        self.assertEqual(MerkleLog(self.path).root(), self.root)
        self.assertIsNone(repair_log(self.path))  # nothing left to do

    def test_garbage_terminated_last_line_is_torn(self):
        self.path.write_bytes(self.good + b"\x00\x00\x00\n")
        with self.assertRaises(TornTailError):
            MerkleLog(self.path)
        self.assertIsNotNone(repair_log(self.path))
        self.assertEqual(MerkleLog(self.path).root(), self.root)

    def test_broken_middle_line_is_hard_failure(self):
        lines = self.good.split(b"\n")
        lines[1] = lines[1][:30]
        self.path.write_bytes(b"\n".join(lines))
        with self.assertRaises(LogCorruptError) as cm:
            MerkleLog(self.path)
        self.assertNotIsInstance(cm.exception, TornTailError)
        self.assertEqual(cm.exception.line_no, 2)
        with self.assertRaises(LogCorruptError):
            repair_log(self.path)
        self.assertFalse(Path(str(self.path) + ".corrupt").exists())

    def test_broken_middle_and_torn_tail_is_hard_failure(self):
        lines = self.good.split(b"\n")
        lines[0] = b"{oops"
        self.path.write_bytes(b"\n".join(lines) + b'{"half')
        with self.assertRaises(LogCorruptError) as cm:
            MerkleLog(self.path)
        self.assertNotIsInstance(cm.exception, TornTailError)

    def test_non_canonical_line_is_rejected(self):
        # duplicate keys: different JSON parsers would read different values
        lines = self.good.split(b"\n")
        lines[0] = lines[0][:-1] + b',"tool":"other"}'
        self.path.write_bytes(b"\n".join(lines))
        with self.assertRaises(LogCorruptError):
            MerkleLog(self.path)
        lines = self.good.split(b"\n")
        lines[0] = json.dumps(json.loads(lines[0]), indent=None).encode()  # spaces
        self.path.write_bytes(b"\n".join(lines))
        with self.assertRaises(LogCorruptError):
            MerkleLog(self.path)

    def test_cli_reports_and_repairs(self):
        import contextlib
        import io

        from evidence.log import main

        self.path.write_bytes(self.good + b'{"tr')
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["--log-file", str(self.path), "root"]), 1)
        self.assertIn("repair", err.getvalue())
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main(["--log-file", str(self.path), "repair"]), 0)
        self.assertIn(".corrupt", out.getvalue())
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main(["--log-file", str(self.path), "root"]), 0)
        self.assertEqual(out.getvalue().strip(), self.root.hex())


class TestCliProofs(unittest.TestCase):
    def _run(self, *argv):
        import contextlib
        import io

        from evidence.log import main

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            rc = main(list(argv))
        return rc, buf.getvalue()

    def test_prove_verify_with_size_and_tampering(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "v.logl")
            log = MerkleLog(path)
            for i in range(5):
                log.append(_viol(f"t{i}"))
            rc, out = self._run("--log-file", path, "root", "--size", "3")
            root3 = out.strip()
            self.assertEqual(root3, log.prefix_root(3).hex())
            rc, printed = self._run("--log-file", path, "prove", "1", "--size", "3")
            self.assertEqual(rc, 0)
            d = json.loads(printed)
            self.assertEqual((d["tree_size"], d["version"]), (3, 2))
            log.append(_viol("t5"))  # the log grows; the proof still checks at size 3
            self.assertEqual(self._run("--log-file", path, "verify", printed)[0], 0)
            self.assertEqual(self._run("--log-file", path, "verify", printed,
                                       "--root", root3)[0], 0)
            for change in ({"leaf_index": 2}, {"tree_size": 4}, {"tree_size": 6}):
                bad = json.dumps(dict(d, **change))
                self.assertEqual(self._run("--log-file", path, "verify", bad)[0], 2, change)
            bad = dict(d, leaf_record=dict(d["leaf_record"], tool="changed"))
            self.assertEqual(self._run("--log-file", path, "verify", json.dumps(bad))[0], 2)

    def test_consistency_command(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "v.logl")
            log = MerkleLog(path)
            for i in range(3):
                log.append(_viol(f"t{i}"))
            old = log.root().hex()
            for i in range(3, 7):
                log.append(_viol(f"t{i}"))
            rc, out = self._run("--log-file", path, "consistency", "--old-size", "3",
                                "--old-root", old)
            self.assertEqual(rc, 0)
            self.assertTrue(json.loads(out)["verified"])
            rc, _ = self._run("--log-file", path, "consistency", "--old-size", "3",
                              "--old-root", "00" * 32)
            self.assertEqual(rc, 2)

    def test_record_single_file_dedups(self):
        from evidence.recorder import record_violations

        rows = [{"trace_id": "t1", "span_id": "s1", "tool": "x", "destination": "llm",
                 "jurisdiction": "us", "classes": "pii", "reasons": "r",
                 "timestamp_ns": 1}]
        with tempfile.TemporaryDirectory() as td:
            log = MerkleLog(os.path.join(td, "v.logl"))
            with mock.patch("evidence.recorder._query_clickhouse", return_value=rows):
                self.assertEqual(record_violations(log), 1)
                self.assertEqual(record_violations(log), 0)  # overlapping window
                rows.append(dict(rows[0], span_id="s2"))
                self.assertEqual(record_violations(log), 1)
            self.assertEqual(len(MerkleLog(os.path.join(td, "v.logl"))), 2)

if __name__ == "__main__":
    unittest.main()