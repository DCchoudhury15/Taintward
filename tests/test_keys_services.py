"""Key providers against real services, in docker:

  * HashiCorp Vault (hashicorp/vault:1.20, dev mode): KV v2 key ring and
    Transit wrapped keys.
  * AWS KMS on LocalStack (localstack/localstack:4.9): wrapped keys.

Each service's tests are skipped when docker or its image is not there.
Keys and the Vault token are made fresh for each run.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import socket
import subprocess
import time
import urllib.request
import uuid
from unittest import mock

import pytest

from taintward.core.doe import Sensitivity
from taintward.sdk import keys as K
from taintward.sdk.destinations import DEST_INTERNAL
from taintward.sdk.redact import Redactor
from taintward.sdk.vault import MemoryVault, SQLiteVault

VAULT_IMAGE = "hashicorp/vault:1.20"
LOCALSTACK_IMAGE = "localstack/localstack:4.9"
SSN = "234-12-1234"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def have_image(image: str) -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "image", "inspect", image],
                              capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def wait_http(url: str, seconds: float) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2):
                return True
        except Exception:
            time.sleep(0.5)
    return False


def container(image: str, port: int, inner: int, *env_and_args: str) -> str:
    name = f"taintward-test-{uuid.uuid4().hex[:10]}"
    run = subprocess.run(["docker", "run", "-d", "--rm", "--name", name,
                          "-p", f"127.0.0.1:{port}:{inner}", *env_and_args],
                         capture_output=True, text=True, timeout=120)
    if run.returncode != 0:
        pytest.skip(f"cannot start {image}: {run.stderr.strip()[:200]}")
    return name


@pytest.fixture(scope="module")
def hcvault():
    if not have_image(VAULT_IMAGE):
        pytest.skip(f"docker or {VAULT_IMAGE} not available")
    port, token = free_port(), uuid.uuid4().hex
    name = container(VAULT_IMAGE, port, 8200, "--cap-add", "IPC_LOCK",
                     "-e", f"VAULT_DEV_ROOT_TOKEN_ID={token}", VAULT_IMAGE)
    try:
        addr = f"http://127.0.0.1:{port}"
        if not wait_http(f"{addr}/v1/sys/health", 60):
            pytest.skip("vault did not start")
        with mock.patch.dict(os.environ, {"VAULT_ADDR": addr, "VAULT_TOKEN": token}):
            K._vault_request("POST", "sys/mounts/transit", {"type": "transit"})
            K._vault_request("POST", "transit/keys/taintward", {"type": "aes256-gcm96"})
            yield addr
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=60)


@pytest.fixture(scope="module")
def localstack():
    pytest.importorskip("boto3")
    if not have_image(LOCALSTACK_IMAGE):
        pytest.skip(f"docker or {LOCALSTACK_IMAGE} not available")
    port = free_port()
    name = container(LOCALSTACK_IMAGE, port, 4566, "-e", "SERVICES=kms", LOCALSTACK_IMAGE)
    try:
        url = f"http://127.0.0.1:{port}"
        if not wait_http(f"{url}/_localstack/health", 120):
            pytest.skip("localstack did not start")
        env = {"AWS_ENDPOINT_URL": url, "AWS_ACCESS_KEY_ID": "test",
               "AWS_SECRET_ACCESS_KEY": "test", "AWS_DEFAULT_REGION": "eu-central-1"}
        with mock.patch.dict(os.environ, env):
            import boto3
            kms = boto3.client("kms")
            for _ in range(60):  # the KMS provider can lag behind /health
                try:
                    arn = kms.create_key()["KeyMetadata"]["Arn"]
                    break
                except Exception:
                    time.sleep(1)
            else:
                pytest.skip("localstack kms not ready")
            kms.create_alias(AliasName="alias/taintward", TargetKeyId=arn)
            yield arn
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=60)


@pytest.fixture
def clean_env():
    with mock.patch.dict(os.environ, {}):
        for k in ("TAINTWARD_FPE_KEY", "TAINTWARD_VAULT_KEY", "TAINTWARD_KEYS"):
            os.environ.pop(k, None)
        K.reload_keys()
        yield
    K.reload_keys()


# ---------------------------------------------------------------------------
# HashiCorp Vault
# ---------------------------------------------------------------------------

def test_vault_kv_ring(hcvault, clean_env, tmp_path):
    fk, vk = os.urandom(32), os.urandom(32)
    K._vault_request("POST", "secret/data/taintward", {"data": {
        "fpe": {"active": "f1", "keys": {"f1": fk.hex()}},
        "vault": {"active": "v1", "keys": {"v1": vk.hex()}},
    }})
    with mock.patch.dict(os.environ, {"TAINTWARD_KEYS": "vault-kv:secret/taintward"}):
        ks = K.load_keys()
        assert ks.source == "vault-kv:secret/taintward"
        assert ks.fpe.active_key == fk and ks.vault.active_key == vk
        v = SQLiteVault(str(tmp_path / "v.db"))
        r = Redactor(vault=v)
        tok = r.redact_value(SSN, Sensitivity.PII, DEST_INTERNAL)
        assert r.reverse(tok) == SSN and v.key_id(tok) == "f1"


def test_vault_kv_ring_as_json_string(hcvault, clean_env):
    fk = os.urandom(32)
    ring = {"fpe": {"keys": {"f1": fk.hex()}}}
    K._vault_request("POST", "secret/data/tw-str", {"data": {"keyring": json.dumps(ring)}})
    assert K.load_keys("vault-kv:secret/tw-str").fpe.active_key == fk


def test_vault_transit_wrapped_key(hcvault, clean_env, tmp_path):
    raw = os.urandom(32)
    wrapped = K.wrap("vault-transit:taintward", raw, "fpe")
    assert wrapped.startswith("vault:v1:") and raw.hex() not in wrapped
    path = tmp_path / "keys.json"
    path.write_text(json.dumps({"kms": "vault-transit:transit/taintward",
                                "fpe": {"keys": {"f1": {"wrapped": wrapped}}}}))
    assert K.load_keys(f"file:{path}").fpe.active_key == raw


def test_vault_bad_token_is_a_clear_error(hcvault, clean_env):
    with mock.patch.dict(os.environ, {"VAULT_TOKEN": "wrong"}):
        with pytest.raises(K.KeyConfigError, match="HTTP 403"):
            K.load_keys("vault-kv:secret/taintward")


def test_cli_rotate_with_transit(hcvault, clean_env, tmp_path):
    f = str(tmp_path / "keys.json")
    assert K.main(["rotate", "--file", f, "--purpose", "fpe",
                   "--kms", "vault-transit:taintward"]) == 0
    assert K.main(["rotate", "--file", f, "--purpose", "fpe"]) == 0
    doc = json.loads(open(f).read())
    assert all("wrapped" in e for e in doc["fpe"]["keys"].values())
    ring = K.load_keys(f"file:{f}").fpe
    assert ring.active == "v2" and len(ring.keys) == 2


# ---------------------------------------------------------------------------
# AWS KMS (LocalStack)
# ---------------------------------------------------------------------------

def test_aws_kms_wrapped_keys(localstack, clean_env, tmp_path):
    raw_f, raw_v = os.urandom(32), os.urandom(32)
    path = tmp_path / "keys.json"
    path.write_text(json.dumps({
        "kms": "aws-kms:alias/taintward",
        "fpe": {"keys": {"f1": {"wrapped": K.wrap("aws-kms:alias/taintward", raw_f, "fpe")}}},
        "vault": {"keys": {"v1": {"wrapped": K.wrap(f"aws-kms:{localstack}", raw_v, "vault")}}},
    }))
    with mock.patch.dict(os.environ, {"TAINTWARD_KEYS": f"file:{path}"}):
        ks = K.load_keys()
        assert ks.fpe.active_key == raw_f and ks.vault.active_key == raw_v
        r = Redactor(vault=MemoryVault())
        assert r.key == raw_f.hex()


def test_aws_kms_purpose_is_bound(localstack, clean_env, tmp_path):
    wrapped = K.wrap("aws-kms:alias/taintward", os.urandom(32), "vault")
    with pytest.raises(K.KeyConfigError, match="could not unwrap the fpe key"):
        K.unwrap("aws-kms:alias/taintward", wrapped, "fpe")
    assert len(K.unwrap("aws-kms:alias/taintward", wrapped, "vault")) == 32


def test_aws_kms_wrapped_is_not_the_key(localstack, clean_env):
    raw = os.urandom(32)
    wrapped = base64.b64decode(K.wrap("aws-kms:alias/taintward", raw, "fpe"))
    assert raw not in wrapped
