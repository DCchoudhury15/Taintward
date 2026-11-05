"""KMS-only key mode and scheduled key rotation (taintward/sdk/keys.py).

Keys are made with os.urandom in each test; a fake GCP KMS (the same one as
tests/test_keys.py) wraps them, and a fake Vault KV holds a ring in memory.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import timedelta
from unittest import mock

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from taintward.sdk import keys as K
from taintward.sdk.redact import Redactor
from taintward.sdk.vault import SQLiteVault

GCP = "gcp-kms:projects/p/locations/global/keyRings/r/cryptoKeys/taintward"


class FakeGcpKms:
    def __init__(self):
        self.k = AESGCM(AESGCM.generate_key(256))

    def encrypt(self, request):
        n = os.urandom(12)
        return mock.Mock(ciphertext=n + self.k.encrypt(n, request["plaintext"],
                                                       request["additional_authenticated_data"]))

    def decrypt(self, request):
        c = request["ciphertext"]
        return mock.Mock(plaintext=self.k.decrypt(c[:12], c[12:],
                                                  request["additional_authenticated_data"]))


@pytest.fixture
def clean_env():
    drop = [k for k in os.environ if k.startswith("TAINTWARD_") and ("KEY" in k or "VAULT" in k)]
    with mock.patch.dict(os.environ, {}, clear=False):
        for k in drop:
            os.environ.pop(k, None)
        K.reload_keys()
        yield
    K.reload_keys()


@pytest.fixture
def kms():
    fake = FakeGcpKms()
    with mock.patch.dict(K.CLIENTS, {"gcp": lambda: fake}):
        yield fake


def wrapped_ring(path, *, kms_only=False) -> str:
    doc = {"kms": GCP,
           "fpe": {"active": "f1", "keys": {"f1": {"wrapped": K.wrap(GCP, os.urandom(32), "fpe")}}},
           "vault": {"active": "v1", "keys": {"v1": {"wrapped": K.wrap(GCP, os.urandom(32), "vault")}}}}
    if kms_only:
        doc["kms_only"] = True
    path.write_text(json.dumps(doc))
    K.reload_keys()
    return f"file:{path}"


def days_from_now(n: int):
    today = K._today()
    return mock.patch.object(K, "_today", lambda: today + timedelta(days=n))


# ---------------------------------------------------------------------------
# KMS-only mode
# ---------------------------------------------------------------------------

def test_kms_only_accepts_wrapped_keys(clean_env, tmp_path, kms):
    spec = wrapped_ring(tmp_path / "k.json")
    with mock.patch.dict(os.environ, {"TAINTWARD_KEYS": spec, "TAINTWARD_KEYS_KMS_ONLY": "1"}):
        assert K.load_keys().fpe.active == "f1"
        assert Redactor().key_id == "f1"
        vault = SQLiteVault(str(tmp_path / "v.db"))
        vault.put("tok", "234-12-1234")
        assert vault.get("tok") == "234-12-1234"


@pytest.mark.parametrize("ring_flag", [False, True])
def test_kms_only_refuses_plain_keys_in_the_ring(clean_env, tmp_path, ring_flag):
    doc = {"fpe": {"active": "f1", "keys": {"f1": os.urandom(32).hex()}}}
    env = {}
    if ring_flag:
        doc["kms_only"] = True  # the ring itself says so
    else:
        env["TAINTWARD_KEYS_KMS_ONLY"] = "1"
    (tmp_path / "k.json").write_text(json.dumps(doc))
    with mock.patch.dict(os.environ, {"TAINTWARD_KEYS": f"file:{tmp_path / 'k.json'}", **env}):
        with pytest.raises(K.KeyConfigError, match="KMS-only"):
            K.load_keys()


def test_kms_only_needs_a_ring(clean_env):
    with mock.patch.dict(os.environ, {"TAINTWARD_KEYS_KMS_ONLY": "1"}):
        with pytest.raises(K.KeyConfigError, match="needs a key ring"):
            K.load_keys()


def test_kms_only_refuses_plain_keys_next_to_a_good_ring(clean_env, tmp_path, kms):
    spec = wrapped_ring(tmp_path / "k.json")
    with mock.patch.dict(os.environ, {"TAINTWARD_KEYS": spec, "TAINTWARD_KEYS_KMS_ONLY": "1"}):
        with pytest.raises(K.KeyConfigError, match="FPE key must come from a key ring"):
            Redactor(os.urandom(32).hex())
        with pytest.raises(K.KeyConfigError, match="vault key must come from a key ring"):
            SQLiteVault(str(tmp_path / "v.db"), key_hex=os.urandom(32).hex())
        with mock.patch.dict(os.environ, {"TAINTWARD_VAULT_KEY": os.urandom(32).hex()}):
            with pytest.raises(K.KeyConfigError, match="TAINTWARD_VAULT_KEY"):
                K.load_keys()


def test_kms_only_never_makes_a_random_key(clean_env, tmp_path, kms):
    doc = {"kms": GCP, "vault": {"active": "v1", "keys": {
        "v1": {"wrapped": K.wrap(GCP, os.urandom(32), "vault")}}}}  # no fpe key
    (tmp_path / "k.json").write_text(json.dumps(doc))
    with mock.patch.dict(os.environ, {"TAINTWARD_KEYS": f"file:{tmp_path / 'k.json'}",
                                      "TAINTWARD_KEYS_KMS_ONLY": "1"}):
        K.reload_keys()
        with pytest.raises(K.KeyConfigError, match="has no fpe key"):
            Redactor()


def test_kms_only_cli_will_not_make_plain_keys(clean_env, tmp_path, capsys):
    f = tmp_path / "k.json"
    with mock.patch.dict(os.environ, {"TAINTWARD_KEYS_KMS_ONLY": "1"}):
        assert K.main(["rotate", "--file", str(f), "--purpose", "vault"]) == 1
        assert K.main(["generate", "--purpose", "fpe"]) == 1
    assert not f.exists()
    assert "--kms" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# key ages and scheduled rotation
# ---------------------------------------------------------------------------

def test_rotate_records_the_day_and_status_checks_the_age(clean_env, tmp_path, capsys):
    f = str(tmp_path / "k.json")
    assert K.main(["rotate", "--file", f, "--purpose", "vault"]) == 0
    entry = json.loads(open(f).read())["vault"]["keys"]["v1"]
    assert entry["created"] == K._today().isoformat()
    K.reload_keys()
    assert K.main(["status", "--keys", f"file:{f}", "--max-age", "90"]) == 0
    with days_from_now(100):
        assert K.main(["status", "--keys", f"file:{f}", "--max-age", "90d"]) == 1
    assert "older than 90 days" in capsys.readouterr().out


def test_key_with_no_day_counts_as_too_old(clean_env, tmp_path, capsys):
    (tmp_path / "k.json").write_text(json.dumps(
        {"vault": {"active": "v1", "keys": {"v1": os.urandom(32).hex()}}}))
    K.reload_keys()
    assert K.main(["status", "--keys", f"file:{tmp_path / 'k.json'}", "--max-age", "90"]) == 1
    assert "age is unknown" in capsys.readouterr().out
    assert K.main(["status", "--keys", f"file:{tmp_path / 'k.json'}"]) == 0  # no limit given


def test_rotate_if_older_than_is_safe_to_run_daily(clean_env, tmp_path):
    f = str(tmp_path / "k.json")
    run = ["rotate", "--file", f, "--purpose", "vault", "--if-older-than", "90"]
    assert K.main(run) == 0  # nothing yet: makes v1
    assert K.main(run) == 0  # v1 is new: nothing happens
    assert json.loads(open(f).read())["vault"]["active"] == "v1"
    with days_from_now(91):
        assert K.main(run) == 0
    doc = json.loads(open(f).read())
    assert doc["vault"]["active"] == "v2" and set(doc["vault"]["keys"]) == {"v1", "v2"}


def test_rotate_and_reseal_in_one_step(clean_env, tmp_path, capsys):
    f = str(tmp_path / "k.json")
    db = tmp_path / "v.db"
    assert K.main(["rotate", "--file", f, "--purpose", "vault"]) == 0
    with mock.patch.dict(os.environ, {"TAINTWARD_KEYS": f"file:{f}", "TAINTWARD_VAULT": f"sqlite://{db}"}):
        K.reload_keys()
        SQLiteVault(str(db)).put("tok", "234-12-1234")
        assert K.main(["rotate", "--file", f, "--purpose", "vault", "--reseal"]) == 0
        assert "resealed 1 vault rows" in capsys.readouterr().out
        nonce = sqlite3.connect(db).execute("select nonce from tokens").fetchone()[0]
        assert SQLiteVault(str(db))._sealer.sealed_by(nonce) == "v2"


def test_running_vault_picks_up_a_rotated_key(clean_env, tmp_path):
    f = str(tmp_path / "k.json")
    assert K.main(["rotate", "--file", f, "--purpose", "vault"]) == 0
    clock = [1000.0]
    env = {"TAINTWARD_KEYS": f"file:{f}", "TAINTWARD_KEYS_RELOAD_SECONDS": "60"}
    with mock.patch.dict(os.environ, env), mock.patch("time.monotonic", lambda: clock[0]):
        K.reload_keys()
        vault = SQLiteVault(str(tmp_path / "v.db"))
        vault.put("t1", "first")
        assert K.main(["rotate", "--file", f, "--purpose", "vault"]) == 0  # another process
        vault.put("t2", "second")  # within 60 s: still the old key
        clock[0] += 61
        vault.put("t3", "third")   # read the ring again: the new key
        rows = dict(sqlite3.connect(tmp_path / "v.db").execute("select token, nonce from tokens"))
        sealed_by = {t: vault._sealer.sealed_by(n) for t, n in rows.items()}
        assert sealed_by == {"t1": "v1", "t2": "v1", "t3": "v2"}
        assert [vault.get(t) for t in ("t1", "t2", "t3")] == ["first", "second", "third"]


def test_without_reload_seconds_the_key_stays(clean_env, tmp_path):
    f = str(tmp_path / "k.json")
    assert K.main(["rotate", "--file", f, "--purpose", "vault"]) == 0
    clock = [1000.0]
    with mock.patch.dict(os.environ, {"TAINTWARD_KEYS": f"file:{f}"}), \
            mock.patch("time.monotonic", lambda: clock[0]):
        K.reload_keys()
        vault = SQLiteVault(str(tmp_path / "v.db"))
        assert K.main(["rotate", "--file", f, "--purpose", "vault"]) == 0
        clock[0] += 10_000
        vault.put("t", "x")
        nonce = sqlite3.connect(tmp_path / "v.db").execute("select nonce from tokens").fetchone()[0]
        assert vault._sealer.sealed_by(nonce) == "v1"


# ---------------------------------------------------------------------------
# a ring in Vault KV
# ---------------------------------------------------------------------------

class FakeKV:
    """Vault KV v2 for one secret, with check-and-set."""

    def __init__(self):
        self.data = None
        self.version = 0

    def request(self, method, path, body=None):
        assert path == "secret/data/taintward"
        if method == "GET":
            if self.data is None:
                raise K.KeyConfigError("HashiCorp Vault GET secret/data/taintward: HTTP 404")
            return {"data": {"data": self.data, "metadata": {"version": self.version}}}
        cas = (body.get("options") or {}).get("cas")
        if cas is not None and cas != self.version:  # what Vault answers
            raise K.KeyConfigError("HashiCorp Vault POST secret/data/taintward: HTTP 400")
        self.data, self.version = body["data"], self.version + 1
        return {"data": {"version": self.version}}


def test_rotate_a_ring_in_vault_kv(clean_env, kms, capsys):
    kv = FakeKV()
    with mock.patch.object(K, "_vault_request", kv.request):
        run = ["rotate", "--keys", "vault-kv:secret/taintward", "--purpose", "vault",
               "--kms", GCP, "--if-older-than", "30"]
        assert K.main(run) == 0
        assert kv.version == 1 and "wrapped" in kv.data["keyring"]
        assert K.main(run) == 0 and kv.version == 1  # too new: no write
        with days_from_now(31):
            assert K.main(run) == 0
        assert kv.version == 2
        K.reload_keys()
        ring = K.load_keys("vault-kv:secret/taintward").vault
        assert ring.active == "v2" and set(ring.keys) == {"v1", "v2"}


def test_vault_kv_write_conflict_is_an_error(clean_env, kms, capsys):
    kv = FakeKV()
    with mock.patch.object(K, "_vault_request", kv.request):
        assert K.main(["rotate", "--keys", "vault-kv:secret/taintward", "--purpose", "vault",
                       "--kms", GCP]) == 0
        real_get = kv.request

        def racing(method, path, body=None):
            out = real_get(method, path, body)
            if method == "GET":
                kv.version += 1  # someone else wrote after our read
            return out
        with mock.patch.object(K, "_vault_request", racing):
            assert K.main(["rotate", "--keys", "vault-kv:secret/taintward",
                           "--purpose", "vault"]) == 1
        assert "changed after it was read" in capsys.readouterr().err
