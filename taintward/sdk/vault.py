"""Token vault: token -> exact original value, for reversing internal tokens.

FPE alone cannot give back the exact original in every case (taintward/sdk/redact.py
lowercases letters before encrypting, and short values are masked), so the
Redactor keeps a mapping from each token it issues to the original value.
This module makes that mapping pluggable:

    MemoryVault   in-process dict (the old behaviour). Lost on restart and
                  not shared between processes. Default.
    SQLiteVault   persistent file, safe for several processes on one host
                  (WAL mode + busy timeout). The original value is stored
                  ENCRYPTED with AES-256-GCM under a vault key that is
                  separate from the FPE key. Plaintext is never written.
    PostgresVault shared table in PostgreSQL (psycopg 3), for several
                  replicas on several hosts. Same encryption as SQLiteVault.
    RedisVault    shared Redis (redis-py), native TTL, one set per subject
                  blind index for erasure. Same encryption as SQLiteVault.

Every backend supports:
    put(token, original, ttl=None, subject=None, key_id=None)
    get(token) -> original or None (expired rows count as missing)
    delete(token) -> bool
    forget_subject(subject) -> number of tokens erased  (GDPR erasure)

Subjects (e.g. a user id or email) are stored only as an HMAC-SHA256 blind
index, so the vault file does not list who the data belongs to.

Configuration (see get_vault()):
    TAINTWARD_VAULT        "memory" (default), "sqlite://<path>",
                           "postgresql://user:pass@host/db" or
                           "redis://host:6379/0" (rediss:// for TLS)
    TAINTWARD_VAULT_KEY    hex AES key (16/24/32 bytes). Required for every
                           backend except memory. Must differ from the FPE key.
                           Or a vault key ring from TAINTWARD_KEYS (see
                           taintward/sdk/keys.py), which allows rotation:
                           rows name the key that sealed them, and reseal()
                           moves old rows to the active key.

psycopg and redis are optional dependencies: they are imported only when a
PostgresVault or RedisVault is created.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import queue
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Any, Iterator, Protocol, runtime_checkable
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from taintward.sdk.keys import KeyRing, key_id_for, load_keys, parse_hex_key


@runtime_checkable
class Vault(Protocol):
    def put(self, token: str, original: str, *, ttl: float | None = None,
            subject: str | None = None, key_id: str | None = None) -> None: ...

    def get(self, token: str) -> str | None: ...

    def delete(self, token: str) -> bool: ...

    def forget_subject(self, subject: str) -> int: ...


class MemoryVault:
    """In-process vault. Fast, but lost on restart and not shared."""

    def __init__(self) -> None:
        # token -> (original, expires_at or None, subject or None, key_id)
        self._rows: dict[str, tuple[str, float | None, str | None, str | None]] = {}
        self._lock = threading.Lock()

    def put(self, token, original, *, ttl=None, subject=None, key_id=None):
        exp = time.time() + ttl if ttl is not None else None
        with self._lock:
            self._rows[token] = (original, exp, subject, key_id)

    def get(self, token):
        with self._lock:
            row = self._rows.get(token)
            if row is None:
                return None
            if row[1] is not None and row[1] <= time.time():
                del self._rows[token]
                return None
            return row[0]

    def key_id(self, token):
        with self._lock:
            row = self._rows.get(token)
            return row[3] if row else None

    def delete(self, token):
        with self._lock:
            return self._rows.pop(token, None) is not None

    def forget_subject(self, subject):
        with self._lock:
            gone = [t for t, r in self._rows.items() if r[2] == subject]
            for t in gone:
                del self._rows[t]
            return len(gone)

    def __len__(self):
        return len(self._rows)


def _parse_key(key_hex: str, what: str) -> bytes:
    return parse_hex_key(key_hex, what)


class VaultError(RuntimeError):
    """The vault backend could not be reached or used (connection refused,
    timeout, missing driver). The message never contains the password."""


_SUBJECT_INDEX_LABEL = b"taintward-vault-subject-index-v1"
# A sealed row's nonce field is MAGIC + len(kid) + kid + 12 byte nonce, so
# each row names the vault key that sealed it, and its plaintext is
# len(subject) (2 bytes) + subject + original, so reseal() can rebuild the
# subject index under a new key. Rows from before key rings have a bare 12
# byte nonce and only the original as plaintext; they are opened by trying
# each key in the ring (the GCM tag tells which one is right).
_MAGIC = b"tw1"


class _Sealer:
    """AES-GCM sealing and the subject blind index, shared by every
    persistent backend so they all give the same guarantees.

    The token is the associated data, so a ciphertext copied to another
    token's row fails the tag check. The subject index is HMAC-SHA256 under a
    key derived from the vault key.

    Keys come from a key ring (taintward/sdk/keys.py): new rows are sealed
    with the active key, older rows are opened with the key they name.
    """

    def __init__(self, key_hex: str | None, backend: str) -> None:
        if key_hex:
            key = _parse_key(key_hex, "TAINTWARD_VAULT_KEY")
            ring = KeyRing("vault", key_id_for(key), {key_id_for(key): key})
            keyset = load_keys("env")
        else:
            keyset = load_keys()
            ring = keyset.vault
            if ring is None:
                raise ValueError(
                    f"{backend} needs an encryption key: set TAINTWARD_VAULT_KEY "
                    "(hex, 32/48/64 chars), separate from TAINTWARD_FPE_KEY, "
                    "or a vault key ring in TAINTWARD_KEYS"
                )
        fpe_keys = set(keyset.fpe.keys.values()) if keyset.fpe else set()
        if fpe_keys & set(ring.keys.values()):
            raise ValueError("TAINTWARD_VAULT_KEY must not be the same as TAINTWARD_FPE_KEY")
        self.ring = ring
        self._aeads = {kid: AESGCM(k) for kid, k in ring.keys.items()}
        self._index_keys = {kid: self._index_key(k) for kid, k in ring.keys.items()}
        self.aead = self._aeads[ring.active]
        self.index_key = self._index_keys[ring.active]

    @staticmethod
    def _index_key(key: bytes) -> bytes:
        return hmac.new(key, _SUBJECT_INDEX_LABEL, hashlib.sha256).digest()

    @property
    def active(self) -> str:
        return self.ring.active

    def seal(self, token: str, original: str,
             subject: str | None = None) -> tuple[bytes, bytes]:
        nonce = os.urandom(12)
        kid = self.ring.active.encode()
        sub = (subject or "").encode()
        if len(sub) > 0xFFFF:
            raise ValueError("subject is longer than 65535 bytes")
        plain = len(sub).to_bytes(2, "big") + sub + original.encode()
        ct = self.aead.encrypt(nonce, plain, token.encode())
        return _MAGIC + bytes([len(kid)]) + kid + nonce, ct

    @staticmethod
    def sealed_by(nonce_field: bytes) -> str | None:
        """Key id named by a nonce field, or None for a legacy bare nonce."""
        nf = bytes(nonce_field)
        if len(nf) > 12 and nf[:3] == _MAGIC and len(nf) == 4 + nf[3] + 12:
            return nf[4:4 + nf[3]].decode(errors="replace")
        return None

    def open(self, token: str, nonce: bytes, ct: bytes) -> str:
        return self.open_row(token, nonce, ct)[0]

    def open_row(self, token: str, nonce: bytes, ct: bytes) -> tuple[str, str | None, bool]:
        """(original, subject, subject known). Legacy rows do not hold the
        subject, so for them the last value is False."""
        nf, ct, aad = bytes(nonce), bytes(ct), token.encode()
        kid = self.sealed_by(nf)
        if kid is not None:
            aead = self._aeads.get(kid)
            if aead is None:
                raise VaultError(f"vault row sealed with key {kid!r}, which is not in "
                                 "the vault key ring")
            plain = aead.decrypt(nf[-12:], ct, aad)
            n = int.from_bytes(plain[:2], "big")
            return plain[2 + n:].decode(), plain[2:2 + n].decode() or None, True
        for aead in [self.aead, *self._aeads.values()]:
            try:
                return aead.decrypt(nf, ct, aad).decode(), None, False
            except InvalidTag:
                continue
        raise InvalidTag("no vault key in the ring opens this row")

    def resealed(self, token: str, nonce: bytes, ct: bytes,
                 old_idx: str | None) -> tuple[bytes, bytes, str | None]:
        """A row sealed again under the active key, with its subject index
        rebuilt when the subject is known (kept as is for legacy rows)."""
        original, subject, known = self.open_row(token, nonce, ct)
        nonce2, ct2 = self.seal(token, original, subject)
        return nonce2, ct2, self.subject_idx(subject) if known else old_idx

    def needs_reseal(self, nonce: bytes) -> bool:
        return self.sealed_by(nonce) != self.ring.active

    def split_blob(self, blob: bytes) -> tuple[bytes, bytes]:
        """Split Redis's nonce field || ciphertext."""
        blob = bytes(blob)
        if blob[:3] == _MAGIC and len(blob) > 4:
            n = 4 + blob[3] + 12
            if self.sealed_by(blob[:n]) in self._aeads:
                return blob[:n], blob[n:]
        return blob[:12], blob[12:]

    def subject_idx(self, subject: str | None) -> str | None:
        if subject is None:
            return None
        return hmac.new(self.index_key, subject.encode(), hashlib.sha256).hexdigest()

    def subject_idxs(self, subject: str) -> list[str]:
        """The subject's index under every key in the ring (active first), so
        erasure also finds rows written before a rotation."""
        out = [self.subject_idx(subject)]
        for k in self._index_keys.values():
            idx = hmac.new(k, subject.encode(), hashlib.sha256).hexdigest()
            if idx not in out:
                out.append(idx)
        return out


def _safe_url(url: str) -> str:
    """The url without user name or password, for error messages."""
    try:
        u = urlsplit(url)
        host = u.hostname or ""
        if u.port:
            host = f"{host}:{u.port}"
        return f"{u.scheme}://{host}{u.path}"
    except ValueError:
        return "<unparseable url>"


class SQLiteVault:
    """Persistent vault in a SQLite file, original values encrypted at rest.

    Each row stores: token, a random 12-byte nonce, AES-GCM ciphertext of the
    original (the token is the associated data, so a ciphertext cannot be
    moved to another token's row), an optional expiry time, an optional
    HMAC blind index of the subject, and the FPE key id used.

    Safe for multiple processes on the same host: WAL journal mode, a busy
    timeout, and one short transaction per call. Do not put the file on a
    network filesystem (SQLite locking is not reliable there).
    """

    def __init__(self, path: str, key_hex: str | None = None, *,
                 busy_timeout_ms: int = 5000) -> None:
        self._sealer = _Sealer(key_hex, "SQLiteVault")
        self.path = path
        self._busy_ms = busy_timeout_ms
        self._local = threading.local()
        with self._conn() as c:
            c.execute(
                "CREATE TABLE IF NOT EXISTS tokens ("
                " token TEXT PRIMARY KEY,"
                " nonce BLOB NOT NULL,"
                " ct BLOB NOT NULL,"
                " expires_at REAL,"
                " subject_idx TEXT,"
                " key_id TEXT)"
            )
            c.execute("CREATE INDEX IF NOT EXISTS tokens_subject ON tokens(subject_idx)")

    def _conn(self) -> sqlite3.Connection:
        # One connection per thread; sqlite3 connections are not thread-safe.
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=self._busy_ms / 1000)
            conn.execute(f"PRAGMA busy_timeout={int(self._busy_ms)}")
            conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn = conn
        return conn

    def _subject_idx(self, subject: str | None) -> str | None:
        return self._sealer.subject_idx(subject)

    def put(self, token, original, *, ttl=None, subject=None, key_id=None):
        nonce, ct = self._sealer.seal(token, original, subject)
        exp = time.time() + ttl if ttl is not None else None
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO tokens VALUES (?, ?, ?, ?, ?, ?)",
                (token, nonce, ct, exp, self._subject_idx(subject), key_id),
            )

    def get(self, token):
        row = self._conn().execute(
            "SELECT nonce, ct, expires_at FROM tokens WHERE token = ?", (token,)
        ).fetchone()
        if row is None:
            return None
        nonce, ct, exp = row
        if exp is not None and exp <= time.time():
            self.delete(token)
            return None
        return self._sealer.open(token, nonce, ct)

    def key_id(self, token):
        row = self._conn().execute(
            "SELECT key_id FROM tokens WHERE token = ?", (token,)
        ).fetchone()
        return row[0] if row else None

    def delete(self, token):
        with self._conn() as c:
            return c.execute("DELETE FROM tokens WHERE token = ?", (token,)).rowcount > 0

    def forget_subject(self, subject):
        idxs = self._sealer.subject_idxs(subject)
        with self._conn() as c:
            return c.execute(
                f"DELETE FROM tokens WHERE subject_idx IN ({','.join('?' * len(idxs))})", idxs
            ).rowcount

    def purge_expired(self) -> int:
        with self._conn() as c:
            return c.execute(
                "DELETE FROM tokens WHERE expires_at IS NOT NULL AND expires_at <= ?",
                (time.time(),),
            ).rowcount

    def reseal(self) -> int:
        """Re-encrypt every row not sealed with the active vault key.

        Run it after rotating the vault key; then the old key can be retired.
        The subject index is rebuilt under the active key too. Rows written
        before key rings do not hold their subject, so their index is kept;
        erasure finds them while the key that wrote them is in the ring.
        """
        rows = self._conn().execute(
            "SELECT token, nonce, ct, subject_idx FROM tokens").fetchall()
        n = 0
        for token, nonce, ct, idx in rows:
            if not self._sealer.needs_reseal(nonce):
                continue
            nonce2, ct2, idx2 = self._sealer.resealed(token, nonce, ct, idx)
            with self._conn() as c:
                n += c.execute("UPDATE tokens SET nonce = ?, ct = ?, subject_idx = ?"
                               " WHERE token = ? AND nonce = ?",
                               (nonce2, ct2, idx2, token, nonce)).rowcount
        return n

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None


def _first_line(exc: BaseException) -> str:
    text = str(exc).strip()
    return text.splitlines()[0] if text else type(exc).__name__


_PG_IDENT_OK = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_")


class PostgresVault:
    """Vault in a PostgreSQL table, shared by any number of replicas.

    One row per token: the token (primary key), a 12-byte nonce, the AES-GCM
    ciphertext of the original (token as associated data), the FPE key id,
    the HMAC blind index of the subject and the expiry time. Plaintext and
    subject ids are never sent to the server.

    Expiry uses the database clock (``now()``), so replicas with skewed
    clocks still agree on what has expired. ``put`` is a single
    ``INSERT ... ON CONFLICT (token) DO UPDATE``, so concurrent writers never
    fail on a duplicate key. There is an index on the subject index (for
    erasure) and a partial index on the expiry (for ``purge_expired``).

    Connections come from a small built in pool (``pool_size``), each in
    autocommit mode with a connect timeout and a statement timeout. A broken
    connection is dropped and the call is retried once on a fresh one. After
    ``os.fork()`` the child starts with an empty pool.
    """

    def __init__(self, dsn: str, key_hex: str | None = None, *,
                 table: str = "taintward_vault_tokens", pool_size: int = 5,
                 connect_timeout: float = 5.0, statement_timeout_ms: int = 5000,
                 pool_wait: float = 10.0) -> None:
        try:
            import psycopg  # noqa: F401
        except ImportError:
            raise VaultError(
                "PostgresVault needs psycopg 3: pip install 'psycopg[binary]'"
            ) from None
        if not table or set(table) - _PG_IDENT_OK or table[0].isdigit():
            raise ValueError("table name must be lower case letters, digits and _")
        self._sealer = _Sealer(key_hex, "PostgresVault")
        self.dsn = dsn
        self.table = table
        self._where = _safe_url(dsn) if "://" in dsn else "postgres (dsn)"
        self._pool_size = max(1, int(pool_size))
        self._connect_timeout = connect_timeout
        self._stmt_timeout = int(statement_timeout_ms)
        self._pool_wait = pool_wait
        self._lock = threading.Lock()
        self._reset_pool()
        self._create_schema()

    # --- pool ---

    def _reset_pool(self) -> None:
        self._pid = os.getpid()
        self._idle: queue.LifoQueue = queue.LifoQueue()
        self._slots = threading.BoundedSemaphore(self._pool_size)

    def _connect(self):
        import psycopg
        try:
            return psycopg.connect(
                self.dsn,
                autocommit=True,
                connect_timeout=max(1, int(self._connect_timeout)),
                options=f"-c statement_timeout={self._stmt_timeout}",
            )
        except psycopg.Error as exc:
            raise VaultError(f"PostgresVault cannot connect to {self._where}: "
                             f"{_first_line(exc)}") from None

    @contextmanager
    def _conn(self) -> Iterator[Any]:
        if os.getpid() != self._pid:
            with self._lock:
                if os.getpid() != self._pid:
                    # Never reuse a socket inherited from the parent process.
                    self._reset_pool()
        slots = self._slots
        if not slots.acquire(timeout=self._pool_wait):
            raise VaultError(f"PostgresVault: no free connection after {self._pool_wait}s "
                             f"(pool_size={self._pool_size})")
        conn = None
        try:
            try:
                conn = self._idle.get_nowait()
            except queue.Empty:
                conn = self._connect()
            if conn.closed:
                conn = self._connect()
            yield conn
        except BaseException:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
                conn = None
            raise
        finally:
            if conn is not None and not conn.closed:
                self._idle.put(conn)
            slots.release()

    def _run(self, fn):
        """Run fn(conn); retry once on a fresh connection if the old one died."""
        import psycopg
        try:
            with self._conn() as conn:
                return fn(conn)
        except psycopg.OperationalError:
            pass
        try:
            with self._conn() as conn:
                return fn(conn)
        except psycopg.OperationalError as exc:
            raise VaultError(f"PostgresVault query failed on {self._where}: "
                             f"{_first_line(exc)}") from None

    def _create_schema(self) -> None:
        t = self.table

        def ddl(conn):
            with conn.transaction():
                # CREATE TABLE IF NOT EXISTS can still race between processes;
                # an advisory lock makes the first replica do it alone.
                conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (t,))
                conn.execute(
                    f"CREATE TABLE IF NOT EXISTS {t} ("
                    " token TEXT PRIMARY KEY,"
                    " nonce BYTEA NOT NULL,"
                    " ct BYTEA NOT NULL,"
                    " key_id TEXT,"
                    " subject_idx TEXT,"
                    " expires_at DOUBLE PRECISION,"
                    " created_at TIMESTAMPTZ NOT NULL DEFAULT now())"
                )
                conn.execute(f"CREATE INDEX IF NOT EXISTS {t}_subject ON {t} (subject_idx)"
                             " WHERE subject_idx IS NOT NULL")
                conn.execute(f"CREATE INDEX IF NOT EXISTS {t}_expires ON {t} (expires_at)"
                             " WHERE expires_at IS NOT NULL")

        self._run(ddl)

    # --- Vault protocol ---

    _NOW = "extract(epoch FROM now())::float8"

    def put(self, token, original, *, ttl=None, subject=None, key_id=None):
        nonce, ct = self._sealer.seal(token, original, subject)
        t = self.table
        self._run(lambda c: c.execute(
            f"INSERT INTO {t} (token, nonce, ct, key_id, subject_idx, expires_at)"
            " VALUES (%s, %s, %s, %s, %s,"
            f" CASE WHEN %s::float8 IS NULL THEN NULL ELSE {self._NOW} + %s::float8 END)"
            " ON CONFLICT (token) DO UPDATE SET nonce = EXCLUDED.nonce, ct = EXCLUDED.ct,"
            " key_id = EXCLUDED.key_id, subject_idx = EXCLUDED.subject_idx,"
            " expires_at = EXCLUDED.expires_at, created_at = now()",
            (token, nonce, ct, key_id, self._sealer.subject_idx(subject), ttl, ttl),
        ))

    def get(self, token):
        t = self.table
        row = self._run(lambda c: c.execute(
            f"SELECT nonce, ct, expires_at IS NOT NULL AND expires_at <= {self._NOW}"
            f" FROM {t} WHERE token = %s", (token,),
        ).fetchone())
        if row is None:
            return None
        nonce, ct, expired = row
        if expired:
            self._run(lambda c: c.execute(
                f"DELETE FROM {t} WHERE token = %s AND expires_at <= {self._NOW}", (token,)))
            return None
        return self._sealer.open(token, nonce, ct)

    def key_id(self, token):
        t = self.table
        row = self._run(lambda c: c.execute(
            f"SELECT key_id FROM {t} WHERE token = %s", (token,)).fetchone())
        return row[0] if row else None

    def delete(self, token):
        t = self.table
        return self._run(lambda c: c.execute(
            f"DELETE FROM {t} WHERE token = %s", (token,)).rowcount) > 0

    def forget_subject(self, subject):
        t = self.table
        idxs = self._sealer.subject_idxs(subject)
        return self._run(lambda c: c.execute(
            f"DELETE FROM {t} WHERE subject_idx = ANY(%s)", (idxs,)).rowcount)

    def reseal(self) -> int:
        """Re-encrypt every row not sealed with the active vault key (see
        SQLiteVault.reseal). An update only lands if the row was not
        rewritten in the meantime."""
        t = self.table
        rows = self._run(lambda c: c.execute(
            f"SELECT token, nonce, ct, subject_idx FROM {t}").fetchall())
        n = 0
        for token, nonce, ct, idx in rows:
            if not self._sealer.needs_reseal(nonce):
                continue
            nonce2, ct2, idx2 = self._sealer.resealed(token, nonce, ct, idx)
            n += self._run(lambda c: c.execute(
                f"UPDATE {t} SET nonce = %s, ct = %s, subject_idx = %s"
                " WHERE token = %s AND nonce = %s",
                (nonce2, ct2, idx2, token, nonce)).rowcount)
        return n

    def purge_expired(self) -> int:
        t = self.table
        return self._run(lambda c: c.execute(
            f"DELETE FROM {t} WHERE expires_at <= {self._NOW}").rowcount)

    def close(self) -> None:
        while True:
            try:
                conn = self._idle.get_nowait()
            except queue.Empty:
                return
            try:
                conn.close()
            except Exception:
                pass


# put: store the sealed value, add the token to its subject's set, and keep
# the set alive at least as long as its longest lived member.
# KEYS[1] token hash, KEYS[2] subject set (unused when there is no subject)
# ARGV[1] sealed value, ARGV[2] key id, ARGV[3] subject index or "",
# ARGV[4] ttl in ms (0 = no expiry), ARGV[5] token
_REDIS_PUT = """
redis.call('DEL', KEYS[1])
redis.call('HSET', KEYS[1], 'ct', ARGV[1], 'kid', ARGV[2], 'sub', ARGV[3])
local ttl = tonumber(ARGV[4])
if ttl > 0 then redis.call('PEXPIRE', KEYS[1], ttl) end
if ARGV[3] ~= '' then
  local existed = redis.call('EXISTS', KEYS[2])
  redis.call('SADD', KEYS[2], ARGV[5])
  if ttl == 0 then
    redis.call('PERSIST', KEYS[2])
  else
    local cur = redis.call('PTTL', KEYS[2])
    if existed == 0 or (cur >= 0 and cur < ttl) then redis.call('PEXPIRE', KEYS[2], ttl) end
  end
end
return 1
"""

# forget_subject: delete every token in the subject's set that still belongs
# to that subject (a token may have been put again for someone else since).
# KEYS[1] subject set; ARGV[1] token key prefix, ARGV[2] subject index
_REDIS_FORGET = """
local n = 0
for _, tok in ipairs(redis.call('SMEMBERS', KEYS[1])) do
  local k = ARGV[1] .. tok
  if redis.call('HGET', k, 'sub') == ARGV[2] then
    n = n + redis.call('DEL', k)
  end
end
redis.call('DEL', KEYS[1])
return n
"""

# reseal: replace the sealed value and subject index only if the value is
# still the one we read, and list the token in its (new) subject set. HSET
# keeps the token's TTL; the set lives at least as long as the token.
# KEYS[1] token hash, KEYS[2] subject set; ARGV[1] old sealed value,
# ARGV[2] new sealed value, ARGV[3] subject index or "", ARGV[4] token
_REDIS_SWAP = """
if redis.call('HGET', KEYS[1], 'ct') ~= ARGV[1] then return 0 end
redis.call('HSET', KEYS[1], 'ct', ARGV[2], 'sub', ARGV[3])
if ARGV[3] ~= '' then
  local existed = redis.call('EXISTS', KEYS[2])
  redis.call('SADD', KEYS[2], ARGV[4])
  local ttl = redis.call('PTTL', KEYS[1])
  if ttl < 0 then
    redis.call('PERSIST', KEYS[2])
  else
    local cur = redis.call('PTTL', KEYS[2])
    if existed == 0 or (cur >= 0 and cur < ttl) then redis.call('PEXPIRE', KEYS[2], ttl) end
  end
end
return 1
"""


class RedisVault:
    """Vault in Redis, shared by any number of replicas.

    Each token is a hash ``<prefix>t:<token>`` holding the sealed original
    (``nonce || AES-GCM ciphertext``, token as associated data), the FPE key
    id and the subject blind index. A TTL is a native Redis expiry, so
    expired tokens disappear without a purge job. Each subject blind index
    has a set ``<prefix>s:<index>`` of its tokens, used by
    ``forget_subject``. Writes and erasure run as Lua scripts, so each one is
    atomic.

    redis-py keeps a connection pool (``max_connections``), is safe to use
    from several threads, and opens new connections after a fork. The
    erasure script reads keys it builds itself, so use a single Redis (a
    primary with replicas or Sentinel is fine), not Redis Cluster.

    Run Redis with persistence (``appendonly yes``): a Redis that loses its
    data loses the token mapping.
    """

    def __init__(self, url: str, key_hex: str | None = None, *,
                 prefix: str = "taintward:vault:", socket_timeout: float = 5.0,
                 max_connections: int = 20) -> None:
        try:
            import redis
        except ImportError:
            raise VaultError("RedisVault needs redis-py: pip install redis") from None
        self._sealer = _Sealer(key_hex, "RedisVault")
        self.url = url
        self.prefix = prefix
        self._where = _safe_url(url)
        self._redis_errors = (redis.ConnectionError, redis.TimeoutError)
        pool = redis.ConnectionPool.from_url(
            url, socket_timeout=socket_timeout, socket_connect_timeout=socket_timeout,
            max_connections=max_connections, health_check_interval=30,
        )
        self._r = redis.Redis(connection_pool=pool)
        self._put = self._r.register_script(_REDIS_PUT)
        self._forget = self._r.register_script(_REDIS_FORGET)
        self._swap = self._r.register_script(_REDIS_SWAP)
        self._call(self._r.ping)  # fail fast with a clear error

    def _call(self, fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except self._redis_errors as exc:
            raise VaultError(f"RedisVault cannot reach {self._where}: {_first_line(exc)}") from None

    def _tkey(self, token: str) -> str:
        return f"{self.prefix}t:{token}"

    def _skey(self, idx: str) -> str:
        return f"{self.prefix}s:{idx}"

    def put(self, token, original, *, ttl=None, subject=None, key_id=None):
        nonce, ct = self._sealer.seal(token, original, subject)
        idx = self._sealer.subject_idx(subject) or ""
        ttl_ms = 0 if ttl is None else max(1, int(ttl * 1000))
        self._call(self._put, keys=[self._tkey(token), self._skey(idx or "-")],
                   args=[nonce + ct, key_id or "", idx, ttl_ms, token])

    def get(self, token):
        blob = self._call(self._r.hget, self._tkey(token), "ct")
        if blob is None:
            return None
        return self._sealer.open(token, *self._sealer.split_blob(blob))

    def key_id(self, token):
        kid = self._call(self._r.hget, self._tkey(token), "kid")
        return kid.decode() if kid else None

    def delete(self, token):
        # The token may stay listed in its subject set; forget_subject skips it.
        return self._call(self._r.delete, self._tkey(token)) > 0

    def forget_subject(self, subject):
        return sum(int(self._call(self._forget, keys=[self._skey(idx)],
                                  args=[f"{self.prefix}t:", idx]))
                   for idx in self._sealer.subject_idxs(subject))

    def purge_expired(self) -> int:
        return 0  # Redis expires keys by itself

    def reseal(self) -> int:
        """Re-encrypt every token not sealed with the active vault key (see
        SQLiteVault.reseal). HSET keeps the key's TTL; the swap only lands if
        the value did not change since it was read."""
        n = 0
        for key in self._call(lambda: list(self._r.scan_iter(f"{self.prefix}t:*", count=500))):
            blob, sub = self._call(self._r.hmget, key, "ct", "sub")
            if blob is None:
                continue
            nonce, ct = self._sealer.split_blob(blob)
            if not self._sealer.needs_reseal(nonce):
                continue
            token = key.decode()[len(f"{self.prefix}t:"):]
            old_idx = sub.decode() if sub else None
            nonce2, ct2, idx = self._sealer.resealed(token, nonce, ct, old_idx)
            n += int(self._call(self._swap, keys=[key, self._skey(idx or "-")],
                                args=[blob, nonce2 + ct2, idx or "", token]))
        return n

    def close(self) -> None:
        self._r.close()


def get_vault(spec: str | None = None) -> Vault:
    """Build a vault from a spec string or TAINTWARD_VAULT.

    "memory" (or empty)          -> MemoryVault
    "sqlite://<path>"            -> SQLiteVault(<path>); sqlite:///abs/path.db
                                    gives /abs/path.db, sqlite://rel.db gives rel.db
    "postgresql://..." or "postgres://..."  -> PostgresVault(spec)
    "redis://..." or "rediss://..."         -> RedisVault(spec)
    """
    spec = (spec if spec is not None else os.environ.get("TAINTWARD_VAULT", "")).strip()
    if spec in ("", "memory", "memory://"):
        return MemoryVault()
    if spec.startswith("sqlite://"):
        path = spec[len("sqlite://"):]
        if not path:
            raise ValueError("sqlite vault spec needs a path, e.g. sqlite:///var/lib/taintward/vault.db")
        return SQLiteVault(path)
    if spec.startswith(("postgresql://", "postgres://")):
        return PostgresVault(spec)
    if spec.startswith(("redis://", "rediss://")):
        return RedisVault(spec)
    raise ValueError(f"unknown TAINTWARD_VAULT {_safe_url(spec)!r}; use 'memory', "
                     "'sqlite://<path>', 'postgresql://...' or 'redis://...'")
