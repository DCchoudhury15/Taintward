"""Token vault: token -> exact original value, for reversing internal tokens.

FPE alone cannot give back the exact original in every case (sdk/redact.py
lowercases letters before encrypting, and short values are masked), so the
Redactor keeps a mapping from each token it issues to the original value.
This module makes that mapping pluggable:

    MemoryVault   in-process dict (the old behaviour). Lost on restart and
                  not shared between processes. Default.
    SQLiteVault   persistent file, safe for several processes on one host
                  (WAL mode + busy timeout). The original value is stored
                  ENCRYPTED with AES-256-GCM under a vault key that is
                  separate from the FPE key. Plaintext is never written.

Every backend supports:
    put(token, original, ttl=None, subject=None, key_id=None)
    get(token) -> original or None (expired rows count as missing)
    delete(token) -> bool
    forget_subject(subject) -> number of tokens erased  (GDPR erasure)

Subjects (e.g. a user id or email) are stored only as an HMAC-SHA256 blind
index, so the vault file does not list who the data belongs to.

Configuration (see get_vault()):
    AGENTWARD_VAULT        "memory" (default) or "sqlite://<path>",
                           e.g. sqlite:///var/lib/agentward/vault.db
    AGENTWARD_VAULT_KEY    hex AES key (16/24/32 bytes) for SQLiteVault.
                           Required for sqlite. Must differ from the FPE key.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
import threading
import time
from typing import Protocol, runtime_checkable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


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
    try:
        key = bytes.fromhex(key_hex)
    except ValueError:
        raise ValueError(f"{what} must be hex") from None
    if len(key) not in (16, 24, 32):
        raise ValueError(f"{what} must be 16, 24 or 32 bytes (32, 48 or 64 hex chars)")
    return key


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
        key_hex = key_hex or os.environ.get("AGENTWARD_VAULT_KEY")
        if not key_hex:
            raise ValueError(
                "SQLiteVault needs an encryption key: set AGENTWARD_VAULT_KEY "
                "(hex, 32/48/64 chars), separate from AGENTWARD_FPE_KEY"
            )
        key = _parse_key(key_hex, "AGENTWARD_VAULT_KEY")
        fpe = os.environ.get("AGENTWARD_FPE_KEY")
        if fpe and fpe.strip().lower() == key_hex.strip().lower():
            raise ValueError("AGENTWARD_VAULT_KEY must not be the same as AGENTWARD_FPE_KEY")
        self._aead = AESGCM(key)
        self._index_key = hmac.new(key, b"agentward-vault-subject-index-v1",
                                   hashlib.sha256).digest()
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
        if subject is None:
            return None
        return hmac.new(self._index_key, subject.encode(), hashlib.sha256).hexdigest()

    def put(self, token, original, *, ttl=None, subject=None, key_id=None):
        nonce = os.urandom(12)
        ct = self._aead.encrypt(nonce, original.encode(), token.encode())
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
        return self._aead.decrypt(nonce, ct, token.encode()).decode()

    def key_id(self, token):
        row = self._conn().execute(
            "SELECT key_id FROM tokens WHERE token = ?", (token,)
        ).fetchone()
        return row[0] if row else None

    def delete(self, token):
        with self._conn() as c:
            return c.execute("DELETE FROM tokens WHERE token = ?", (token,)).rowcount > 0

    def forget_subject(self, subject):
        with self._conn() as c:
            return c.execute(
                "DELETE FROM tokens WHERE subject_idx = ?", (self._subject_idx(subject),)
            ).rowcount

    def purge_expired(self) -> int:
        with self._conn() as c:
            return c.execute(
                "DELETE FROM tokens WHERE expires_at IS NOT NULL AND expires_at <= ?",
                (time.time(),),
            ).rowcount

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None


def get_vault(spec: str | None = None) -> Vault:
    """Build a vault from a spec string or AGENTWARD_VAULT.

    "memory" (or empty)   -> MemoryVault
    "sqlite://<path>"     -> SQLiteVault(<path>); sqlite:///abs/path.db gives
                             /abs/path.db, sqlite://rel.db gives rel.db
    """
    spec = (spec if spec is not None else os.environ.get("AGENTWARD_VAULT", "")).strip()
    if spec in ("", "memory", "memory://"):
        return MemoryVault()
    if spec.startswith("sqlite://"):
        path = spec[len("sqlite://"):]
        if not path:
            raise ValueError("sqlite vault spec needs a path, e.g. sqlite:///var/lib/agentward/vault.db")
        return SQLiteVault(path)
    raise ValueError(f"unknown AGENTWARD_VAULT {spec!r}; use 'memory' or 'sqlite://<path>'")
