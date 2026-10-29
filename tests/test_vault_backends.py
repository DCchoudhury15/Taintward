"""Tests for the shared vault backends: PostgresVault and RedisVault.

They run against real services:
  * Redis: a redis-server started on a free port in a temp dir.
  * Postgres: the postgres:18 docker image on a free host port.
A backend's tests are skipped when its server binary, docker (or the
postgres:18 image) or its Python driver is not available.

The redis_url fixture is also used by tests/test_gateway_http.py.
"""

from __future__ import annotations

import multiprocessing as mp
import os
import shutil
import socket
import subprocess
import time
import uuid
from unittest import mock

import pytest

from taintward.core.doe import Sensitivity
from taintward.sdk.destinations import DEST_INTERNAL
from taintward.sdk.redact import Redactor
from taintward.sdk.vault import PostgresVault, RedisVault, Vault, VaultError, get_vault

SSN = "234-12-1234"
SUBJECT = "alice@example.com"
FPE_KEY = "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94"
VAULT_KEY = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
PG_IMAGE = "postgres:18"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------------------
# services
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def redis_url(tmp_path_factory):
    """A throwaway redis-server; yields its url, stops it afterwards."""
    redis = pytest.importorskip("redis")
    exe = shutil.which("redis-server") or (
        "/usr/bin/redis-server" if os.path.exists("/usr/bin/redis-server") else None)
    if exe is None:
        pytest.skip("redis-server not installed")
    workdir = tmp_path_factory.mktemp("redis")
    port = free_port()
    proc = subprocess.Popen(
        [exe, "--port", str(port), "--bind", "127.0.0.1", "--dir", str(workdir),
         "--save", "", "--appendonly", "no", "--daemonize", "no"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    url = f"redis://127.0.0.1:{port}/0"
    client = redis.Redis.from_url(url)
    try:
        deadline = time.time() + 20
        while True:
            try:
                client.ping()
                break
            except redis.ConnectionError:
                if proc.poll() is not None or time.time() > deadline:
                    pytest.skip("redis-server did not start")
                time.sleep(0.05)
        yield url
    finally:
        client.close()
        proc.terminate()
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


@pytest.fixture
def redis_clean(redis_url):
    import redis
    r = redis.Redis.from_url(redis_url)
    r.flushdb()
    yield redis_url
    r.flushdb()
    r.close()


def _docker_ok() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "image", "inspect", PG_IMAGE],
                              capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


@pytest.fixture(scope="session")
def pg_dsn():
    """A throwaway postgres:18 container; yields a DSN, removes it afterwards."""
    psycopg = pytest.importorskip("psycopg")
    if not _docker_ok():
        pytest.skip(f"docker or the {PG_IMAGE} image is not available")
    port = free_port()
    name = f"taintward-test-pg-{uuid.uuid4().hex[:10]}"
    run = subprocess.run(
        ["docker", "run", "-d", "--rm", "--name", name,
         "-e", "POSTGRES_PASSWORD=awtest", "-e", "POSTGRES_DB=taintward",
         "-p", f"127.0.0.1:{port}:5432", PG_IMAGE],
        capture_output=True, text=True, timeout=120,
    )
    if run.returncode != 0:
        pytest.skip(f"cannot start {PG_IMAGE}: {run.stderr.strip()[:200]}")
    dsn = f"postgresql://postgres:awtest@127.0.0.1:{port}/taintward"
    try:
        deadline = time.time() + 90
        while True:
            try:
                with psycopg.connect(dsn, connect_timeout=2) as c:
                    c.execute("SELECT 1")
                break
            except psycopg.OperationalError:
                if time.time() > deadline:
                    pytest.skip("postgres did not become ready")
                time.sleep(0.5)
        yield dsn
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=60)


@pytest.fixture(autouse=True)
def _vault_key_env():
    with mock.patch.dict(os.environ, {"TAINTWARD_VAULT_KEY": VAULT_KEY}):
        yield


class _PG:
    name = "postgres"

    def __init__(self, dsn):
        self.dsn = dsn
        self.table = "t_" + uuid.uuid4().hex[:12]

    def make(self, **kw):
        return PostgresVault(self.dsn, table=self.table, **kw)

    def raw_bytes(self) -> bytes:
        """Every byte the table holds: the rows as text, plus the table's
        heap and TOAST files on disk after a checkpoint."""
        import psycopg
        out = b""
        with psycopg.connect(self.dsn, autocommit=True) as c:
            for (row,) in c.execute(f"SELECT t::text FROM {self.table} t"):
                out += row.encode()
            for nonce, ct in c.execute(f"SELECT nonce, ct FROM {self.table}"):
                out += bytes(nonce) + bytes(ct)
            c.execute("CHECKPOINT")
            rels = [self.table]
            toast = c.execute("SELECT reltoastrelid::regclass::text FROM pg_class "
                              "WHERE relname = %s AND reltoastrelid <> 0",
                              (self.table,)).fetchone()
            if toast:
                rels.append(toast[0])
            for rel in rels:
                (data,) = c.execute(
                    "SELECT pg_read_binary_file(pg_relation_filepath(%s::regclass))", (rel,)
                ).fetchone()
                out += bytes(data)
        return out

    def swap_ct(self, src: str, dst: str) -> None:
        import psycopg
        with psycopg.connect(self.dsn, autocommit=True) as c:
            nonce, ct = c.execute(f"SELECT nonce, ct FROM {self.table} WHERE token = %s",
                                  (src,)).fetchone()
            c.execute(f"UPDATE {self.table} SET nonce = %s, ct = %s WHERE token = %s",
                      (nonce, ct, dst))

    def count(self) -> int:
        import psycopg
        with psycopg.connect(self.dsn, autocommit=True) as c:
            return c.execute(f"SELECT count(*) FROM {self.table}").fetchone()[0]


class _Redis:
    name = "redis"

    def __init__(self, url):
        self.url = url
        self.prefix = f"aw-test:{uuid.uuid4().hex[:8]}:"

    def make(self, **kw):
        return RedisVault(self.url, prefix=self.prefix, **kw)

    def _r(self):
        import redis
        return redis.Redis.from_url(self.url)

    def raw_bytes(self) -> bytes:
        """Every key name, its serialized value (DUMP) and its fields."""
        r = self._r()
        out = b""
        for key in r.scan_iter(match=self.prefix + "*"):
            out += key + (r.dump(key) or b"")
            kind = r.type(key)
            if kind == b"hash":
                for k, v in r.hgetall(key).items():
                    out += k + v
            elif kind == b"set":
                out += b"".join(r.smembers(key))
            elif kind == b"string":
                out += r.get(key) or b""
        r.close()
        return out

    def swap_ct(self, src: str, dst: str) -> None:
        r = self._r()
        r.hset(self.prefix + "t:" + dst, "ct", r.hget(self.prefix + "t:" + src, "ct"))
        r.close()

    def count(self) -> int:
        r = self._r()
        n = sum(1 for _ in r.scan_iter(match=self.prefix + "t:*"))
        r.close()
        return n


@pytest.fixture(params=["postgres", "redis"])
def backend(request):
    if request.param == "postgres":
        return _PG(request.getfixturevalue("pg_dsn"))
    return _Redis(request.getfixturevalue("redis_clean"))


# ---------------------------------------------------------------------------
# shared behaviour, both backends
# ---------------------------------------------------------------------------

def test_protocol_and_roundtrip(backend):
    v = backend.make()
    assert isinstance(v, Vault)
    v.put("tok-1", SSN)
    assert v.get("tok-1") == SSN
    assert v.get("missing") is None
    v.put("tok-1", "replaced")  # put on an existing token replaces it
    assert v.get("tok-1") == "replaced"
    v.close()


def test_persistence_across_instances(backend):
    v1 = backend.make()
    v1.put("tok-1", SSN, key_id="2026-10")
    v1.close()
    v2 = backend.make()  # a restart, or another replica
    assert v2.get("tok-1") == SSN
    assert v2.key_id("tok-1") == "2026-10"


def test_redactor_tokens_survive_restart(backend):
    a = Redactor(FPE_KEY, vault=backend.make())
    assert a.structural_fallback is False
    tok = a.redact_value("EMP4521XQ", Sensitivity.SECRET, DEST_INTERNAL)
    b = Redactor(FPE_KEY, vault=backend.make())
    assert b.reverse(tok) == "EMP4521XQ"


def test_encrypted_at_rest(backend):
    v = backend.make()
    r = Redactor(FPE_KEY, vault=v)
    tok = r.redact_value(SSN, Sensitivity.PII, DEST_INTERNAL, subject=SUBJECT)
    v.put("tok-direct", SSN, subject=SUBJECT)
    assert r.reverse(tok) == SSN
    raw = backend.raw_bytes()
    assert len(raw) > 0
    for needle in (SSN, SSN.replace("-", ""), SUBJECT):
        assert needle.encode() not in raw
        assert needle.encode().hex().encode() not in raw  # nor as bytea hex text
    assert b"tok-direct" in raw  # sanity: we did read the stored data


def test_ciphertext_bound_to_token(backend):
    v = backend.make()
    v.put("tok-a", "secret-a")
    v.put("tok-b", "secret-b")
    backend.swap_ct("tok-a", "tok-b")
    with pytest.raises(Exception):  # AES-GCM tag check fails
        v.get("tok-b")


def test_wrong_key_cannot_read(backend):
    backend.make().put("tok-1", SSN)
    other = backend.make(key_hex="ff" * 32)
    with pytest.raises(Exception):
        other.get("tok-1")


def test_requires_key_and_separate_from_fpe_key(backend):
    with mock.patch.dict(os.environ, {}, clear=True):
        with pytest.raises(ValueError):
            backend.make()
    with mock.patch.dict(os.environ, {"TAINTWARD_FPE_KEY": VAULT_KEY}):
        with pytest.raises(ValueError):
            backend.make()


def test_ttl_expiry(backend):
    v = backend.make()
    v.put("tok-1", SSN, ttl=0.3)
    v.put("tok-2", SSN)
    assert v.get("tok-1") == SSN
    time.sleep(0.6)
    assert v.get("tok-1") is None
    assert v.get("tok-2") == SSN


def test_delete_and_forget_subject(backend):
    v = backend.make()
    v.put("t1", "a1", subject="alice")
    v.put("t2", "a2", subject="alice", ttl=60)
    v.put("t3", "b1", subject="bob")
    v.put("t4", "a3", subject="alice")
    v.put("t4", "now-bob", subject="bob")  # t4 changed owner: alice must not erase it
    assert v.delete("t3") is True
    assert v.delete("t3") is False
    assert v.forget_subject("alice") == 2
    assert v.get("t1") is None and v.get("t2") is None
    assert v.get("t4") == "now-bob"
    assert backend.make().forget_subject("alice") == 0
    assert v.forget_subject("bob") == 1


def test_redactor_gdpr_erasure_is_final(backend):
    r = Redactor(FPE_KEY, vault=backend.make())
    tok = r.redact_value(SSN, Sensitivity.PII, DEST_INTERNAL, subject="alice")
    assert r.reverse(tok) == SSN
    assert r.forget_subject("alice") == 1
    assert r.reverse(tok) is None
    assert Redactor(FPE_KEY, vault=backend.make()).reverse(tok) is None


def _writer(kind: str, where: str, scope: str, prefix: str, n: int) -> None:
    os.environ["TAINTWARD_VAULT_KEY"] = VAULT_KEY
    if kind == "postgres":
        v = PostgresVault(where, table=scope)
    else:
        v = RedisVault(where, prefix=scope)
    for i in range(n):
        v.put(f"{prefix}-{i}", f"value-{prefix}-{i}", subject=prefix)
        v.put(f"shared-{i}", f"from-{prefix}")  # every process writes these


def test_concurrent_writers_several_processes(backend):
    backend.make()  # create the schema first
    where = backend.dsn if backend.name == "postgres" else backend.url
    scope = backend.table if backend.name == "postgres" else backend.prefix
    ctx = mp.get_context("spawn")
    procs = [ctx.Process(target=_writer, args=(backend.name, where, scope, p, 60))
             for p in ("a", "b", "c", "d")]
    for p in procs:
        p.start()
    for p in procs:
        p.join(120)
        assert p.exitcode == 0
    v = backend.make()
    for p in ("a", "b", "c", "d"):
        for i in (0, 31, 59):
            assert v.get(f"{p}-{i}") == f"value-{p}-{i}"
    for i in (0, 59):
        assert v.get(f"shared-{i}") in {"from-a", "from-b", "from-c", "from-d"}
    assert backend.count() == 4 * 60 + 60
    assert v.forget_subject("c") == 60


# ---------------------------------------------------------------------------
# backend specific
# ---------------------------------------------------------------------------

def test_postgres_schema_indexes_and_purge(pg_dsn):
    import psycopg
    b = _PG(pg_dsn)
    v = b.make()
    v.put("old", "x", ttl=0.05)
    v.put("keep", "y")
    time.sleep(0.2)
    assert v.purge_expired() == 1
    assert v.get("keep") == "y"
    with psycopg.connect(pg_dsn, autocommit=True) as c:
        idx = {r[0] for r in c.execute("SELECT indexname FROM pg_indexes WHERE tablename = %s",
                                       (b.table,))}
    assert {f"{b.table}_pkey", f"{b.table}_subject", f"{b.table}_expires"} <= idx
    # Two vaults creating the same schema at once (replicas starting
    # together) must not fail.
    import threading
    errors = []
    t2 = "t_" + uuid.uuid4().hex[:12]

    def make():
        try:
            PostgresVault(pg_dsn, table=t2)
        except Exception as exc:  # pragma: no cover - reported below
            errors.append(exc)

    threads = [threading.Thread(target=make) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []


def test_postgres_pool_reconnects_after_server_side_kill(pg_dsn):
    import psycopg
    b = _PG(pg_dsn)
    v = b.make(pool_size=2)
    v.put("t", "v")
    with psycopg.connect(pg_dsn, autocommit=True) as c:
        c.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                  "WHERE datname = 'taintward' AND pid <> pg_backend_pid()")
    assert v.get("t") == "v"  # dead pooled connection replaced transparently


def test_redis_native_ttl_and_subject_set(redis_clean):
    import redis
    b = _Redis(redis_clean)
    v = b.make()
    v.put("t1", "x", ttl=30, subject="alice")
    v.put("t2", "y", subject="bob")
    r = redis.Redis.from_url(redis_clean)
    assert 0 < r.pttl(b.prefix + "t:t1") <= 30_000
    assert r.pttl(b.prefix + "t:t2") == -1  # no expiry
    sets = [k for k in r.scan_iter(match=b.prefix + "s:*")]
    assert len(sets) == 2
    assert all(b"alice" not in k and b"bob" not in k for k in sets)  # blind index only
    r.close()


def test_get_vault_specs(pg_dsn, redis_clean):
    with mock.patch.dict(os.environ, {"TAINTWARD_VAULT": pg_dsn}):
        assert isinstance(get_vault(), PostgresVault)
    assert isinstance(get_vault(redis_clean), RedisVault)


def test_clear_errors_without_password():
    pytest.importorskip("psycopg")
    pytest.importorskip("redis")
    port = free_port()  # nothing listens here
    with pytest.raises(VaultError) as e1:
        PostgresVault(f"postgresql://u:hunter2pw@127.0.0.1:{port}/x", connect_timeout=1)
    assert "hunter2pw" not in str(e1.value)
    assert f"127.0.0.1:{port}" in str(e1.value)
    with pytest.raises(VaultError) as e2:
        RedisVault(f"redis://:hunter2pw@127.0.0.1:{port}/0", socket_timeout=1)
    assert "hunter2pw" not in str(e2.value)
    with pytest.raises(ValueError):
        PostgresVault(f"postgresql://127.0.0.1:{port}/x", table="bad; DROP TABLE x")


def test_vault_key_rotation_reseal(backend):
    """Rotate the vault key: old rows still open, erasure still finds them,
    reseal moves them to the new key, then the old key can go."""
    new_key = os.urandom(32).hex()
    v = backend.make()
    v.put("tok-old", SSN, subject=SUBJECT, ttl=3600)
    v.put("tok-keep", "kept")
    v.close()
    with mock.patch.dict(os.environ, {"TAINTWARD_VAULT_KEY": new_key,
                                      "TAINTWARD_VAULT_KEY_PREVIOUS": VAULT_KEY}):
        v = backend.make()
        assert v.get("tok-old") == SSN
        v.put("tok-new", "fresh", subject=SUBJECT)
        assert v.reseal() == 2
        assert v.reseal() == 0
        v.close()
    with mock.patch.dict(os.environ, {"TAINTWARD_VAULT_KEY": new_key,
                                      "TAINTWARD_VAULT_KEY_PREVIOUS": ""}):
        v = backend.make()
        assert [v.get(t) for t in ("tok-old", "tok-keep", "tok-new")] == [SSN, "kept", "fresh"]
        assert v.forget_subject(SUBJECT) == 2
        assert v.get("tok-keep") == "kept"
        v.close()
