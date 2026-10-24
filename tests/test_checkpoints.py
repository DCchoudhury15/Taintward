"""Tests for the sharded evidence log and signed checkpoints."""

from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evidence.checkpoint import (
    ENV_KEY,
    keygen,
    list_checkpoints,
    load_private_key,
    load_public_key,
    prove_record,
    verify_log,
    verify_record_proof,
)
from evidence.log import main as log_main
from evidence.merkle import MerkleLog, violation_record
from evidence.shards import ShardedLog

DAY1_NS = 1_792_800_000_000_000_000   # 2026-10-24
DAY2_NS = DAY1_NS + 86_400 * 10**9      # 2026-10-25


def rec(i: int, ts: int = DAY1_NS) -> dict:
    return violation_record(trace_id=f"t{i}", span_id=f"s{i}", tool="ask_llm",
                            destination="llm", jurisdiction="us", classes="pii",
                            reasons="pii_egress", timestamp_ns=ts + i)


class Base(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.td = Path(self._td.name)
        self.kid = keygen(self.td / "k.pem", self.td / "k.pub")
        self.key = load_private_key(self.td / "k.pem")
        self.pub = load_public_key(self.td / "k.pub")
        self.dir = self.td / "ev"
        self.log = ShardedLog(self.dir)
        for i in range(5):
            self.log.append(rec(i), tenant="acme")
        for i in range(3):
            self.log.append(rec(i, DAY2_NS), tenant="acme")
        for i in range(2):
            self.log.append(rec(i), tenant="globex")
        self.log.checkpoint(self.key)

    def tearDown(self):
        self._td.cleanup()


class TestSharding(Base):
    def test_layout(self):
        self.assertEqual(self.log.list_shards(), [("acme", "2026-10-24"), ("acme", "2026-10-25"),
                                                  ("globex", "2026-10-24")])
        self.assertTrue((self.dir / "acme" / "2026-10-24.logl").exists())
        self.assertEqual(len(self.log), 10)
        # every shard is a plain MerkleLog file
        self.assertEqual(len(MerkleLog(self.dir / "acme" / "2026-10-25.logl")), 3)

    def test_unique_append(self):
        self.assertIsNone(self.log.append(rec(0), tenant="acme", unique=True))
        self.assertEqual(self.log.append(rec(99), tenant="acme", unique=True)[2], 5)

    def test_two_writers_see_each_other(self):
        other = ShardedLog(self.dir)
        other.append(rec(50), tenant="acme")
        idx = self.log.append(rec(51), tenant="acme")[2]
        self.assertEqual(idx, 6)  # reloaded the other writer's record first
        self.assertEqual(len(MerkleLog(self.dir / "acme" / "2026-10-24.logl")), 7)

    def test_bad_tenant(self):
        for bad in ("../x", "_checkpoints", "", "a/b"):
            with self.assertRaises(ValueError):
                self.log.append(rec(1), tenant=bad)

    def test_auto_checkpoint(self):
        log = ShardedLog(self.dir, signing_key=self.key, checkpoint_every=2)
        log.append(rec(60), tenant="acme")
        self.assertEqual(len(list_checkpoints(log.checkpoint_dir)), 1)
        log.append(rec(61), tenant="acme")
        self.assertEqual(len(list_checkpoints(log.checkpoint_dir)), 2)
        self.assertTrue(verify_log(self.dir, self.pub).ok)


class TestVerify(Base):
    def test_clean_log_verifies(self):
        res = verify_log(self.dir, self.pub, deep=True)
        self.assertTrue(res.ok, res.errors)
        self.assertEqual(res.shards_checked, 3)
        self.assertEqual(res.records_covered, 10)

    def test_appends_after_checkpoint_are_fine(self):
        self.log.append(rec(7), tenant="acme")
        res = verify_log(self.dir, self.pub)
        self.assertTrue(res.ok, res.errors)
        self.assertTrue(any("added after" in w for w in res.warnings))

    def test_chain_of_checkpoints(self):
        self.log.append(rec(8), tenant="acme")
        self.log.checkpoint(self.key)
        self.log.append(rec(9), tenant="new")
        self.log.checkpoint(self.key)
        res = verify_log(self.dir, self.pub, deep=True)
        self.assertTrue(res.ok, res.errors)
        self.assertEqual(res.checkpoints, 3)

    def test_rewritten_record_detected(self):
        p = self.dir / "acme" / "2026-10-24.logl"
        lines = p.read_text().splitlines()
        r = json.loads(lines[2])
        r["destination"] = "internal"   # quietly downgrade a violation
        lines[2] = json.dumps(r, sort_keys=True, separators=(",", ":"))
        p.write_text("\n".join(lines) + "\n")
        res = verify_log(self.dir, self.pub)
        self.assertFalse(res.ok)
        self.assertTrue(any("acme/2026-10-24" in e and "changed" in e for e in res.errors))

    def test_reordered_records_detected(self):
        p = self.dir / "acme" / "2026-10-24.logl"
        lines = p.read_text().splitlines()
        lines[0], lines[1] = lines[1], lines[0]
        p.write_text("\n".join(lines) + "\n")
        self.assertFalse(verify_log(self.dir, self.pub).ok)

    def test_truncated_shard_detected(self):
        p = self.dir / "acme" / "2026-10-24.logl"
        lines = p.read_text().splitlines()
        p.write_text("\n".join(lines[:-1]) + "\n")
        res = verify_log(self.dir, self.pub)
        self.assertFalse(res.ok)
        self.assertTrue(any("removed" in e for e in res.errors))

    def test_deleted_shard_detected(self):
        (self.dir / "acme" / "2026-10-25.logl").unlink()
        res = verify_log(self.dir, self.pub)
        self.assertFalse(res.ok)
        self.assertTrue(any("2026-10-25" in e and "missing" in e for e in res.errors))

    def test_wrong_key_rejected(self):
        other = Ed25519PrivateKey.generate().public_key()
        res = verify_log(self.dir, other)
        self.assertFalse(res.ok)
        self.assertTrue(any("signature is not valid" in e for e in res.errors))

    def test_edited_checkpoint_rejected(self):
        _, path = list_checkpoints(self.log.checkpoint_dir)[-1]
        doc = json.loads(path.read_text())
        doc["body"]["shards"] = [s for s in doc["body"]["shards"] if s["day"] != "2026-10-25"]
        path.write_text(json.dumps(doc))
        res = verify_log(self.dir, self.pub)
        self.assertFalse(res.ok)

    def test_resigned_by_attacker_key_rejected(self):
        # an attacker who rewrites a shard and signs a new checkpoint with
        # their own key does not pass, because the verifier pins the key
        p = self.dir / "acme" / "2026-10-24.logl"
        p.unlink()
        evil = Ed25519PrivateKey.generate()
        self.log.checkpoint(evil)
        self.assertFalse(verify_log(self.dir, self.pub).ok)

    def test_deleted_middle_checkpoint_detected(self):
        self.log.checkpoint(self.key)
        self.log.checkpoint(self.key)
        list_checkpoints(self.log.checkpoint_dir)[1][1].unlink()
        res = verify_log(self.dir, self.pub)
        self.assertFalse(res.ok)
        self.assertTrue(any("checkpoint 2 is missing" in e for e in res.errors))

    def test_deleted_newest_checkpoint_needs_expect_head(self):
        self.log.append(rec(70), tenant="acme")
        self.log.checkpoint(self.key)
        head = verify_log(self.dir, self.pub).head_hash
        list_checkpoints(self.log.checkpoint_dir)[-1][1].unlink()
        self.assertTrue(verify_log(self.dir, self.pub).ok)  # undetectable alone
        res = verify_log(self.dir, self.pub, expect_head=head)
        self.assertFalse(res.ok)


class TestProofs(Base):
    def test_record_proof_offline(self):
        bundle = prove_record(self.dir, "acme", "2026-10-24", 3)
        bundle = json.loads(json.dumps(bundle))  # as if sent as a file
        ok, msg = verify_record_proof(bundle, self.pub)
        self.assertTrue(ok, msg)

    def test_record_proof_tampered_record(self):
        bundle = prove_record(self.dir, "acme", "2026-10-24", 3)
        bundle["record"]["destination"] = "internal"
        self.assertFalse(verify_record_proof(bundle, self.pub)[0])

    def test_record_proof_wrong_key(self):
        bundle = prove_record(self.dir, "acme", "2026-10-24", 3)
        other = Ed25519PrivateKey.generate().public_key()
        self.assertFalse(verify_record_proof(bundle, other)[0])

    def test_record_after_checkpoint_not_provable(self):
        self.log.append(rec(80), tenant="acme")
        with self.assertRaises(IndexError):
            prove_record(self.dir, "acme", "2026-10-24", 5)


class TestKeys(unittest.TestCase):
    def test_keygen_refuses_overwrite_and_sets_mode(self):
        with tempfile.TemporaryDirectory() as td:
            keygen(Path(td) / "k", Path(td) / "k.pub")
            mode = stat.S_IMODE(os.stat(Path(td) / "k").st_mode)
            self.assertEqual(mode, 0o600)
            with self.assertRaises(FileExistsError):
                keygen(Path(td) / "k", Path(td) / "k2.pub")

    def test_key_from_env_hex(self):
        seed = "11" * 32
        with mock.patch.dict(os.environ, {ENV_KEY: seed}, clear=False):
            os.environ.pop("AGENTWARD_EVIDENCE_KEY_FILE", None)
            k = load_private_key()
        self.assertEqual(len(k.sign(b"x")), 64)

    def test_missing_key_errors(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith("AGENTWARD_EVIDENCE")}
        with mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaises(ValueError):
                load_private_key()
            with self.assertRaises(ValueError):
                load_public_key()


class TestCli(unittest.TestCase):
    def test_keygen_checkpoint_verify(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            self.assertEqual(log_main(["keygen", "--private-key", str(d / "k"),
                                       "--public-key", str(d / "k.pub")]), 0)
            log = ShardedLog(d / "ev")
            log.append(rec(1), tenant="acme")
            self.assertEqual(log_main(["checkpoint", "--evidence-dir", str(d / "ev"),
                                       "--private-key", str(d / "k")]), 0)
            self.assertEqual(log_main(["verify-checkpoints", "--evidence-dir", str(d / "ev"),
                                       "--public-key", str(d / "k.pub")]), 0)
            (d / "ev" / "acme" / "2026-10-24.logl").write_text("")
            self.assertEqual(log_main(["verify-checkpoints", "--evidence-dir", str(d / "ev"),
                                       "--public-key", str(d / "k.pub")]), 2)
            self.assertEqual(log_main(["checkpoint", "--evidence-dir", str(d / "ev"),
                                       "--private-key", str(d / "missing")]), 1)


if __name__ == "__main__":
    unittest.main()
