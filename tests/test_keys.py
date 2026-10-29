"""Tests for key rings, KMS wrapped keys and rotation (taintward/sdk/keys.py).

Keys are made with os.urandom in each test, so no key text is in the repo.
GCP KMS has no local emulator, so a fake client stands in for it here; real
HashiCorp Vault and AWS KMS (LocalStack) are in tests/test_keys_services.py.
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from unittest import mock

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from taintward.core.doe import Sensitivity
from taintward.sdk import keys as K
from taintward.sdk.destinations import DEST_INTERNAL
from taintward.sdk.redact import Redactor
from taintward.sdk.vault import MemoryVault, SQLiteVault

SSN = "234-12-1234"


def hexkey() -> str:
    return os.urandom(32).hex()


@pytest.fixture
def clean_env():
    """No key settings from the outside, and an empty ring cache."""
    drop = [k for k in os.environ if k.startswith("TAINTWARD_") and "KEY" in k] + ["TAINTWARD_KEYS"]
    with mock.patch.dict(os.environ, {}, clear=False):
        for k in drop:
            os.environ.pop(k, None)
        K.reload_keys()
        yield
    K.reload_keys()


def write_ring(path, doc) -> str:
    path.write_text(json.dumps(doc))
    K.reload_keys()
    return f"file:{path}"


# ---------------------------------------------------------------------------
# env provider: unchanged behaviour
# ---------------------------------------------------------------------------

def test_env_provider_matches_old_key_ids(clean_env):
    fk, vk = hexkey(), hexkey()
    with mock.patch.dict(os.environ, {"TAINTWARD_FPE_KEY": fk, "TAINTWARD_VAULT_KEY": vk}):
        ks = K.load_keys()
        assert ks.source == "env"
        assert ks.fpe.active == K.key_id_for(bytes.fromhex(fk))
        assert Redactor().key_id == ks.fpe.active
        assert ks.vault.active_key == bytes.fromhex(vk)


def test_env_previous_vault_keys(clean_env):
    new, old = hexkey(), hexkey()
    with mock.patch.dict(os.environ, {"TAINTWARD_VAULT_KEY": new,
                                      "TAINTWARD_VAULT_KEY_PREVIOUS": old}):
        ring = K.load_keys().vault
        assert ring.active_key == bytes.fromhex(new)
        assert bytes.fromhex(old) in ring.keys.values()


# ---------------------------------------------------------------------------
# file provider
# ---------------------------------------------------------------------------

def test_file_ring_drives_redactor_and_vault(clean_env, tmp_path):
    spec = write_ring(tmp_path / "keys.json", {
        "fpe": {"active": "f2", "keys": {"f1": hexkey(), "f2": {"hex": hexkey()}}},
        "vault": {"active": "v1", "keys": {"v1": hexkey()}},
    })
    with mock.patch.dict(os.environ, {"TAINTWARD_KEYS": spec}):
        vault = SQLiteVault(str(tmp_path / "v.db"))
        r = Redactor(vault=vault)
        assert r.key_id == "f2"
        tok = r.redact_value(SSN, Sensitivity.PII, DEST_INTERNAL)
        assert tok != SSN and r.reverse(tok) == SSN
        assert vault.key_id(tok) == "f2"
        (nonce,) = sqlite3.connect(tmp_path / "v.db").execute("SELECT nonce FROM tokens").fetchone()
        assert vault._sealer.sealed_by(nonce) == "v1"


def test_env_key_wins_over_ring(clean_env, tmp_path):
    env_key = hexkey()
    spec = write_ring(tmp_path / "keys.json", {"fpe": {"active": "f1", "keys": {"f1": hexkey()}}})
    with mock.patch.dict(os.environ, {"TAINTWARD_KEYS": spec, "TAINTWARD_FPE_KEY": env_key}):
        assert Redactor().key == env_key
        assert "f1" in K.load_keys().fpe.keys  # still readable


def test_fpe_rotation_keeps_old_tokens_reversible(clean_env, tmp_path):
    path = tmp_path / "keys.json"
    k1 = hexkey()
    vault = MemoryVault()
    spec = write_ring(path, {"fpe": {"active": "f1", "keys": {"f1": k1}}})
    with mock.patch.dict(os.environ, {"TAINTWARD_KEYS": spec}):
        old = Redactor(vault=vault, structural_fallback=False)
        t1 = old.redact_value(SSN, Sensitivity.PII, DEST_INTERNAL)
    write_ring(path, {"fpe": {"active": "f2", "keys": {"f1": k1, "f2": hexkey()}}})
    with mock.patch.dict(os.environ, {"TAINTWARD_KEYS": spec}):
        new = Redactor(vault=vault, structural_fallback=False)
        t2 = new.redact_value(SSN, Sensitivity.PII, DEST_INTERNAL)
    assert t1 != t2                      # new key, new token
    assert new.reverse(t1) == SSN        # old token still reverses via the vault
    assert vault.key_id(t1) == "f1" and vault.key_id(t2) == "f2"


# ---------------------------------------------------------------------------
# vault key rotation
# ---------------------------------------------------------------------------

def test_vault_rotation_reseal_and_retire(clean_env, tmp_path):
    path = tmp_path / "keys.json"
    v1, v2 = hexkey(), hexkey()
    db = str(tmp_path / "v.db")
    spec = write_ring(path, {"vault": {"active": "v1", "keys": {"v1": v1}}})
    with mock.patch.dict(os.environ, {"TAINTWARD_KEYS": spec}):
        a = SQLiteVault(db)
        a.put("tok-a", "alpha", subject="user-1")
        a.put("tok-b", "beta")
        a.close()

    # rotate: v2 active, v1 kept for reading
    write_ring(path, {"vault": {"active": "v2", "keys": {"v1": v1, "v2": v2}}})
    with mock.patch.dict(os.environ, {"TAINTWARD_KEYS": spec}):
        b = SQLiteVault(db)
        assert b.get("tok-a") == "alpha"
        b.put("tok-c", "gamma", subject="user-1")
        assert b.reseal() == 2          # tok-a, tok-b; tok-c is already on v2
        assert b.reseal() == 0
        b.close()

    # retire v1: everything still opens
    write_ring(path, {"vault": {"active": "v2", "keys": {"v2": v2}}})
    with mock.patch.dict(os.environ, {"TAINTWARD_KEYS": spec}):
        c = SQLiteVault(db)
        assert [c.get(t) for t in ("tok-a", "tok-b", "tok-c")] == ["alpha", "beta", "gamma"]
        assert c.forget_subject("user-1") == 2   # reseal rebuilt tok-a's index
        c.close()


def test_erasure_finds_rows_from_before_rotation(clean_env, tmp_path):
    path = tmp_path / "keys.json"
    v1 = hexkey()
    db = str(tmp_path / "v.db")
    spec = write_ring(path, {"vault": {"active": "v1", "keys": {"v1": v1}}})
    with mock.patch.dict(os.environ, {"TAINTWARD_KEYS": spec}):
        SQLiteVault(db).put("tok-old", "x", subject="user-9")
    write_ring(path, {"vault": {"active": "v2", "keys": {"v1": v1, "v2": hexkey()}}})
    with mock.patch.dict(os.environ, {"TAINTWARD_KEYS": spec}):
        v = SQLiteVault(db)
        v.put("tok-new", "y", subject="user-9")
        assert v.forget_subject("user-9") == 2
        assert v.get("tok-old") is None and v.get("tok-new") is None


def test_rows_from_before_key_rings_still_open(clean_env, tmp_path):
    """A row written by an older build has a bare 12 byte nonce."""
    vk = hexkey()
    db = str(tmp_path / "v.db")
    with mock.patch.dict(os.environ, {"TAINTWARD_VAULT_KEY": vk}):
        v = SQLiteVault(db)
        nonce = os.urandom(12)
        ct = AESGCM(bytes.fromhex(vk)).encrypt(nonce, b"legacy", b"tok-l")
        with v._conn() as c:
            c.execute("INSERT INTO tokens VALUES (?, ?, ?, NULL, NULL, NULL)", ("tok-l", nonce, ct))
        assert v.get("tok-l") == "legacy"
        assert v.reseal() == 1
        assert v._sealer.sealed_by(v._conn().execute(
            "SELECT nonce FROM tokens").fetchone()[0]) == v._sealer.active


def test_row_sealed_by_unknown_key_says_so(clean_env, tmp_path):
    path = tmp_path / "keys.json"
    db = str(tmp_path / "v.db")
    spec = write_ring(path, {"vault": {"active": "v1", "keys": {"v1": hexkey()}}})
    with mock.patch.dict(os.environ, {"TAINTWARD_KEYS": spec}):
        SQLiteVault(db).put("tok", "x")
    write_ring(path, {"vault": {"active": "v2", "keys": {"v2": hexkey()}}})
    with mock.patch.dict(os.environ, {"TAINTWARD_KEYS": spec}):
        with pytest.raises(Exception, match="'v1'"):
            SQLiteVault(db).get("tok")


# ---------------------------------------------------------------------------
# wrapped keys (fake GCP KMS)
# ---------------------------------------------------------------------------

class FakeGcpKms:
    """AES-GCM under a key only this object holds, with the AAD checked."""

    def __init__(self):
        self.k = AESGCM(AESGCM.generate_key(256))
        self.calls = 0

    def encrypt(self, request):
        n = os.urandom(12)
        ct = n + self.k.encrypt(n, request["plaintext"], request["additional_authenticated_data"])
        return mock.Mock(ciphertext=ct)

    def decrypt(self, request):
        self.calls += 1
        c = request["ciphertext"]
        return mock.Mock(plaintext=self.k.decrypt(c[:12], c[12:],
                                                  request["additional_authenticated_data"]))


@pytest.fixture
def fake_gcp():
    kms = FakeGcpKms()
    with mock.patch.dict(K.CLIENTS, {"gcp": lambda: kms}):
        yield kms


GCP = "gcp-kms:projects/p/locations/global/keyRings/r/cryptoKeys/taintward"


def test_wrapped_keys_unwrap_once(clean_env, tmp_path, fake_gcp):
    raw = os.urandom(32)
    spec = write_ring(tmp_path / "keys.json", {
        "kms": GCP,
        "fpe": {"active": "f1", "keys": {"f1": {"wrapped": K.wrap(GCP, raw, "fpe")}}},
    })
    with mock.patch.dict(os.environ, {"TAINTWARD_KEYS": spec}):
        assert K.load_keys().fpe.active_key == raw
        K.load_keys()
        assert fake_gcp.calls == 1    # cached
        assert Redactor().key == raw.hex()


def test_wrapped_key_is_bound_to_its_purpose(clean_env, tmp_path, fake_gcp):
    vault_wrap = K.wrap(GCP, os.urandom(32), "vault")
    spec = write_ring(tmp_path / "keys.json", {
        "kms": GCP, "fpe": {"active": "f1", "keys": {"f1": {"wrapped": vault_wrap}}}})
    with pytest.raises(K.KeyConfigError, match="could not unwrap the fpe key"):
        K.load_keys(spec)


# ---------------------------------------------------------------------------
# bad rings: clear errors, never key material
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("doc,msg", [
    ({"fpe": {"active": "x", "keys": {"f1": "00" * 32}}}, "active key 'x'"),
    ({"fpe": {"keys": {"bad id!": "00" * 32}}}, "key id"),
    ({"fpe": {"keys": {"f1": "zz"}}}, "must be hex"),
    ({"fpe": {"keys": {"f1": "00" * 7}}}, "16, 24 or 32 bytes"),
    ({"fpe": {"keys": {"f1": {"wrapped": "abc"}}}}, "no 'kms'"),
    ({"fpe": {"keys": {}}}, "non-empty"),
    ({"fpe": {"keys": {"f1": "11" * 32}}, "vault": {"keys": {"v1": "11" * 32}}},
     "must not also be"),
])
def test_bad_rings(clean_env, tmp_path, doc, msg):
    with pytest.raises(K.KeyConfigError, match=msg) as e:
        K.load_keys(write_ring(tmp_path / "keys.json", doc))
    assert "11" * 16 not in str(e.value)


def test_unknown_sources(clean_env, tmp_path):
    with pytest.raises(K.KeyConfigError, match="unknown TAINTWARD_KEYS"):
        K.load_keys("s3:bucket/keys")
    with pytest.raises(K.KeyConfigError, match="cannot read"):
        K.load_keys(f"file:{tmp_path}/missing.json")
    with pytest.raises(K.KeyConfigError, match="unknown kms"):
        K.unwrap("azure-kv:x", "abc", "fpe")


def test_vault_key_cannot_equal_fpe_key_in_ring(clean_env, tmp_path):
    same = hexkey()
    spec = write_ring(tmp_path / "keys.json", {"vault": {"keys": {"v1": same}}})
    with mock.patch.dict(os.environ, {"TAINTWARD_KEYS": spec, "TAINTWARD_FPE_KEY": same}):
        with pytest.raises(ValueError, match="must not be the same"):
            SQLiteVault(str(tmp_path / "v.db"))


def test_keyring_repr_hides_keys():
    raw = os.urandom(16)
    assert raw.hex() not in repr(K.KeyRing("fpe", "a", {"a": raw}))


# ---------------------------------------------------------------------------
# taintward-keys CLI
# ---------------------------------------------------------------------------

def test_cli_rotate_show_retire(clean_env, tmp_path, capsys):
    f = str(tmp_path / "keys.json")
    assert K.main(["rotate", "--file", f, "--purpose", "fpe"]) == 0
    assert K.main(["rotate", "--file", f, "--purpose", "vault"]) == 0
    assert K.main(["rotate", "--file", f, "--purpose", "vault"]) == 0
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o600
    doc = json.loads(open(f).read())
    assert doc["vault"]["active"] == "v2" and set(doc["vault"]["keys"]) == {"v1", "v2"}

    capsys.readouterr()
    K.reload_keys()
    assert K.main(["show", "--keys", f"file:{f}"]) == 0
    out = capsys.readouterr().out
    assert "vault: v1, v2 (active)" in out
    for entry in doc["vault"]["keys"].values():
        assert entry["hex"] not in out

    assert K.main(["retire", "--file", f, "--purpose", "vault", "--id", "v2"]) == 2
    assert K.main(["retire", "--file", f, "--purpose", "vault", "--id", "v1"]) == 0
    assert set(json.loads(open(f).read())["vault"]["keys"]) == {"v2"}


def test_cli_rotate_with_kms_and_reseal(clean_env, tmp_path, fake_gcp, capsys):
    f = str(tmp_path / "keys.json")
    db = tmp_path / "v.db"
    assert K.main(["rotate", "--file", f, "--purpose", "vault", "--kms", GCP]) == 0
    assert "wrapped" in json.loads(open(f).read())["vault"]["keys"]["v1"]
    with mock.patch.dict(os.environ, {"TAINTWARD_KEYS": f"file:{f}"}):
        K.reload_keys()
        SQLiteVault(str(db)).put("tok", "x")
        assert K.main(["rotate", "--file", f, "--purpose", "vault"]) == 0  # uses the ring's kms
        K.reload_keys()
        assert K.main(["reseal", "--vault", f"sqlite://{db}"]) == 0
        assert "resealed 1 vault rows" in capsys.readouterr().out


def test_cli_generate(clean_env, capsys):
    assert K.main(["generate", "--purpose", "fpe"]) == 0
    entry = json.loads(capsys.readouterr().out)
    assert len(bytes.fromhex(entry["hex"])) == 32
