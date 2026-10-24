"""Tests for sdk/vault.py and the Redactor's vault, key and short-value handling."""

from __future__ import annotations

import os
import tempfile
import time
import unittest
from unittest import mock

from core.doe import Sensitivity
from sdk import redact as redact_mod
from sdk.destinations import DEST_EXTERNAL, DEST_INTERNAL
from sdk.redact import Redactor
from sdk.vault import MemoryVault, SQLiteVault, Vault, get_vault

SSN = "234-12-1234"
FPE_KEY = "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94"
VAULT_KEY = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"


class _TmpDir(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "vault.db")
        self._env = mock.patch.dict(os.environ, {"AGENTWARD_VAULT_KEY": VAULT_KEY})
        self._env.start()

    def tearDown(self):
        self._env.stop()
        self._tmp.cleanup()


class TestSQLiteVault(_TmpDir):
    def test_protocol(self):
        self.assertIsInstance(MemoryVault(), Vault)
        self.assertIsInstance(SQLiteVault(self.path), Vault)

    def test_persistence_across_instances(self):
        v1 = SQLiteVault(self.path)
        v1.put("tok-1", SSN)
        v1.close()
        v2 = SQLiteVault(self.path)  # e.g. after a restart or in another process
        self.assertEqual(v2.get("tok-1"), SSN)

    def test_redactor_tokens_survive_restart(self):
        a = Redactor(FPE_KEY, vault=SQLiteVault(self.path))
        tok = a.redact_value("EMP4521XQ", Sensitivity.SECRET, DEST_INTERNAL)
        b = Redactor(FPE_KEY, vault=SQLiteVault(self.path))
        self.assertEqual(b.reverse(tok), "EMP4521XQ")  # exact, case included

    def test_encrypted_at_rest(self):
        v = SQLiteVault(self.path)
        v.put("tok-1", SSN, subject="alice@example.com")
        v.close()
        raw = b""
        for name in os.listdir(self._tmp.name):  # db plus any -wal / -shm files
            with open(os.path.join(self._tmp.name, name), "rb") as f:
                raw += f.read()
        self.assertGreater(len(raw), 0)
        self.assertNotIn(SSN.encode(), raw)
        self.assertNotIn(SSN.replace("-", "").encode(), raw)
        self.assertNotIn(b"alice@example.com", raw)  # subject is only a blind index

    def test_ciphertext_bound_to_token(self):
        v = SQLiteVault(self.path)
        v.put("tok-a", "secret-a")
        v.put("tok-b", "secret-b")
        conn = v._conn()
        nonce, ct = conn.execute("SELECT nonce, ct FROM tokens WHERE token='tok-a'").fetchone()
        with conn:
            conn.execute("UPDATE tokens SET nonce=?, ct=? WHERE token='tok-b'", (nonce, ct))
        with self.assertRaises(Exception):  # AES-GCM tag check fails
            v.get("tok-b")

    def test_wrong_key_cannot_read(self):
        SQLiteVault(self.path).put("tok-1", SSN)
        other = SQLiteVault(self.path, key_hex="ff" * 32)
        with self.assertRaises(Exception):
            other.get("tok-1")

    def test_requires_key_and_separate_from_fpe_key(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                SQLiteVault(self.path)
        with mock.patch.dict(os.environ, {"AGENTWARD_FPE_KEY": VAULT_KEY}):
            with self.assertRaises(ValueError):
                SQLiteVault(self.path)

    def test_ttl_expiry(self):
        v = SQLiteVault(self.path)
        v.put("tok-1", SSN, ttl=0.05)
        v.put("tok-2", SSN)
        self.assertEqual(v.get("tok-1"), SSN)
        time.sleep(0.1)
        self.assertIsNone(v.get("tok-1"))
        self.assertEqual(v.get("tok-2"), SSN)

    def test_delete_and_forget_subject(self):
        v = SQLiteVault(self.path)
        v.put("t1", "a1", subject="alice")
        v.put("t2", "a2", subject="alice")
        v.put("t3", "b1", subject="bob")
        self.assertTrue(v.delete("t3"))
        self.assertFalse(v.delete("t3"))
        self.assertEqual(v.forget_subject("alice"), 2)
        self.assertIsNone(v.get("t1"))
        self.assertIsNone(v.get("t2"))
        self.assertEqual(SQLiteVault(self.path).forget_subject("alice"), 0)

    def test_redactor_gdpr_erasure_is_final(self):
        r = Redactor(FPE_KEY, vault=SQLiteVault(self.path))
        self.assertFalse(r.structural_fallback)  # off for persistent vaults
        tok = r.redact_value(SSN, Sensitivity.PII, DEST_INTERNAL, subject="alice")
        self.assertEqual(r.reverse(tok), SSN)
        self.assertEqual(r.forget_subject("alice"), 1)
        self.assertIsNone(r.reverse(tok))
        self.assertIsNone(Redactor(FPE_KEY, vault=SQLiteVault(self.path)).reverse(tok))

    def test_key_id_stored_with_token(self):
        v = SQLiteVault(self.path)
        r = Redactor(FPE_KEY, vault=v, key_id="2026-10")
        tok = r.redact_value(SSN, Sensitivity.PII, DEST_INTERNAL)
        self.assertEqual(v.key_id(tok), "2026-10")
        # After rotating to a new FPE key, old tokens still reverse via the vault.
        rotated = Redactor("11" * 32, vault=v, key_id="2027-01")
        self.assertEqual(rotated.reverse(tok), SSN)


def _writer(path: str, prefix: str, n: int) -> None:
    v = SQLiteVault(path, key_hex=VAULT_KEY)
    for i in range(n):
        v.put(f"{prefix}-{i}", f"value-{prefix}-{i}")


class TestSQLiteVaultMultiProcess(_TmpDir):
    def test_concurrent_writers(self):
        import multiprocessing as mp
        SQLiteVault(self.path)  # create the schema first
        ctx = mp.get_context("spawn")
        procs = [ctx.Process(target=_writer, args=(self.path, p, 100)) for p in ("a", "b", "c")]
        for p in procs:
            p.start()
        for p in procs:
            p.join(60)
            self.assertEqual(p.exitcode, 0)
        v = SQLiteVault(self.path)
        for p in ("a", "b", "c"):
            for i in (0, 57, 99):
                self.assertEqual(v.get(f"{p}-{i}"), f"value-{p}-{i}")
        n = v._conn().execute("SELECT COUNT(*) FROM tokens").fetchone()[0]
        self.assertEqual(n, 300)


class TestGetVault(_TmpDir):
    def test_default_is_memory(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsInstance(get_vault(), MemoryVault)
        self.assertIsInstance(get_vault("memory"), MemoryVault)

    def test_sqlite_spec_from_env(self):
        with mock.patch.dict(os.environ, {"AGENTWARD_VAULT": "sqlite://" + self.path}):
            v = get_vault()
            self.assertIsInstance(v, SQLiteVault)
            self.assertEqual(v.path, self.path)

    def test_bad_spec(self):
        with self.assertRaises(ValueError):
            get_vault("redis://x")


class TestMemoryVault(unittest.TestCase):
    def test_ttl_delete_forget(self):
        v = MemoryVault()
        v.put("t1", "x", subject="alice", ttl=0.05)
        v.put("t2", "y", subject="alice")
        v.put("t3", "z", subject="bob")
        self.assertEqual(v.get("t1"), "x")
        time.sleep(0.1)
        self.assertIsNone(v.get("t1"))
        self.assertEqual(v.forget_subject("alice"), 1)
        self.assertTrue(v.delete("t3"))
        self.assertEqual(len(v), 0)


class TestRedactorKeysAndShortValues(unittest.TestCase):
    def test_short_values_are_masked_not_tokenized(self):
        # FF1 needs radix**len >= 1e6: at least 6 digits or 4 alnum chars.
        r = Redactor(FPE_KEY)
        self.assertEqual(r.redact_value("12345", Sensitivity.PII, DEST_INTERNAL), "[PII]")
        self.assertEqual(r.redact_value("12-34", Sensitivity.PII, DEST_INTERNAL), "[PII]")
        self.assertEqual(r.redact_value("Bob", Sensitivity.PII, DEST_INTERNAL), "[PII]")
        tok6 = r.redact_value("123456", Sensitivity.PII, DEST_INTERNAL)
        self.assertTrue(tok6.isdigit() and len(tok6) == 6)
        tok4 = r.redact_value("Anna", Sensitivity.PII, DEST_INTERNAL)
        self.assertEqual(len(tok4), 4)
        self.assertEqual(r.reverse(tok4), "Anna")

    def test_case_variants_do_not_collide(self):
        r = Redactor(FPE_KEY)
        t1 = r.redact_value("EMP4521XQ", Sensitivity.SECRET, DEST_INTERNAL)
        t2 = r.redact_value("emp4521xq", Sensitivity.SECRET, DEST_INTERNAL)
        self.assertNotEqual(t1, t2)
        self.assertEqual(r.reverse(t1), "EMP4521XQ")
        self.assertEqual(r.reverse(t2), "emp4521xq")

    def test_deterministic_with_fixed_key(self):
        a = Redactor(FPE_KEY).redact_value(SSN, Sensitivity.PII, DEST_INTERNAL)
        b = Redactor(FPE_KEY).redact_value(SSN, Sensitivity.PII, DEST_INTERNAL)
        c = Redactor("11" * 32).redact_value(SSN, Sensitivity.PII, DEST_INTERNAL)
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_no_key_means_random_process_key_with_warning(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.object(redact_mod, "_PROCESS_KEY", None):
            with self.assertWarns(RuntimeWarning):
                r1 = Redactor()
            self.assertNotEqual(r1.key, redact_mod._DEMO_KEY)
            r2 = Redactor()  # same process -> same key, no new key
            self.assertEqual(r1.key, r2.key)

    def test_demo_key_needs_explicit_opt_in(self):
        with mock.patch.dict(os.environ, {"AGENTWARD_ALLOW_DEMO_KEY": "1"}, clear=True):
            self.assertEqual(Redactor().key, redact_mod._DEMO_KEY)

    def test_env_key_used(self):
        with mock.patch.dict(os.environ, {"AGENTWARD_FPE_KEY": FPE_KEY}, clear=True):
            self.assertEqual(Redactor().key, FPE_KEY)

    def test_bad_key_rejected(self):
        with self.assertRaises(ValueError):
            Redactor("abcd")
        with self.assertRaises(ValueError):
            Redactor("zz" * 16)

    def test_external_still_masked(self):
        r = Redactor(FPE_KEY)
        self.assertEqual(r.redact_value(SSN, Sensitivity.PII, DEST_EXTERNAL), "[PII]")


if __name__ == "__main__":
    unittest.main()
