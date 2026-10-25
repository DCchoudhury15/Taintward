"""Session taint stores for the MCP gateway.

The gateway remembers, per MCP session, which sensitive classes the agent
has seen (the session taint). With one gateway process that can live in
memory. With several replicas behind a load balancer, any replica can get
the next request of a session, so the taint must live in a shared store.

    MemorySessionStore  in process (default). One replica only.
    RedisSessionStore   shared Redis. Taint classes are a Redis set and every
                        merge is one Lua script (SADD + expiry refresh), so
                        two replicas merging at the same time never lose a
                        class.

Both keep each session for ``ttl`` seconds after its last use (a sliding
expiry). Stores only hold class names (``pii``, ``secret``) and a random
taint id, never data values.

Taint only grows: there is no call that removes a class from a session.
``delete`` drops the whole session, used when the client ends it.
"""

from __future__ import annotations

import re
import time
import uuid
from typing import Protocol, runtime_checkable

from taintward.core.doe import Sensitivity
from taintward.sdk import taint as tnt

DEFAULT_SESSION_TTL = 24 * 3600.0

# Session ids come from a client header; only accept a safe shape so they can
# be used in store keys as is. The gateway issues uuid4 hex ids.
_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


class SessionStoreError(RuntimeError):
    """The session store could not be reached. The gateway fails closed:
    the tool call is refused rather than run with unknown taint."""


def valid_session_id(sid: str | None) -> bool:
    return bool(sid) and _SESSION_ID_RE.match(sid) is not None


def new_session_id() -> str:
    return uuid.uuid4().hex


def _label(taint_id: str | None, classes) -> tnt.TaintLabel:
    parsed = set()
    for c in classes:
        if isinstance(c, bytes):
            c = c.decode()
        try:
            parsed.add(Sensitivity(c))
        except ValueError:
            # Unknown class from a newer replica: keep the session tainted
            # rather than drop it (safe over-approximation).
            parsed.add(Sensitivity.SECRET)
    if isinstance(taint_id, bytes):
        taint_id = taint_id.decode()
    return tnt.TaintLabel.of(parsed, id=taint_id or None)


@runtime_checkable
class SessionStore(Protocol):
    async def open(self) -> None: ...

    async def close(self) -> None: ...

    async def create(self, sid: str) -> None: ...

    async def exists(self, sid: str) -> bool: ...

    async def get(self, sid: str) -> tnt.TaintLabel: ...

    async def merge(self, sid: str, label: tnt.TaintLabel) -> tnt.TaintLabel: ...

    async def delete(self, sid: str) -> None: ...


class MemorySessionStore:
    """In-process store. Fine for stdio and for a single HTTP replica.

    All methods run on the event loop without awaiting in between reads and
    writes, so a merge cannot interleave with another one.
    """

    def __init__(self, ttl: float = DEFAULT_SESSION_TTL) -> None:
        self.ttl = ttl
        # sid -> [classes, taint id, expires_at]
        self._rows: dict[str, list] = {}

    async def open(self) -> None:
        pass

    async def close(self) -> None:
        pass

    def _row(self, sid: str, create: bool) -> list | None:
        now = time.monotonic()
        row = self._rows.get(sid)
        if row is not None and row[2] <= now:
            del self._rows[sid]
            row = None
        if row is None and create:
            row = [set(), None, 0.0]
            self._rows[sid] = row
        if row is not None:
            row[2] = now + self.ttl
        if len(self._rows) > 1024 and create:
            self._sweep(now)
        return row

    def _sweep(self, now: float) -> None:
        for k in [k for k, r in self._rows.items() if r[2] <= now]:
            del self._rows[k]

    async def create(self, sid: str) -> None:
        self._row(sid, True)

    async def exists(self, sid: str) -> bool:
        return self._row(sid, False) is not None

    async def get(self, sid: str) -> tnt.TaintLabel:
        row = self._row(sid, True)
        return _label(row[1], row[0])

    async def merge(self, sid: str, label: tnt.TaintLabel) -> tnt.TaintLabel:
        row = self._row(sid, True)
        if label.is_tainted:
            row[0].update(c.value for c in label.classes)
            if row[1] is None:
                row[1] = label.id
        return _label(row[1], row[0])

    async def delete(self, sid: str) -> None:
        self._rows.pop(sid, None)

    def __len__(self) -> int:
        return len(self._rows)


# KEYS[1] classes set, KEYS[2] meta hash (taint id + a marker that the
# session exists). ARGV[1] ttl in ms, ARGV[2] taint id, ARGV[3..] classes.
# Adds the classes, sets the id only if none is set yet, refreshes both
# expiries and returns {id, classes}. One script, so it is atomic.
_MERGE = """
redis.call('HSET', KEYS[2], 'seen', '1')
if #ARGV >= 3 then
  for i = 3, #ARGV do redis.call('SADD', KEYS[1], ARGV[i]) end
  redis.call('HSETNX', KEYS[2], 'id', ARGV[2])
end
local ttl = tonumber(ARGV[1])
redis.call('PEXPIRE', KEYS[2], ttl)
if redis.call('EXISTS', KEYS[1]) == 1 then redis.call('PEXPIRE', KEYS[1], ttl) end
return {redis.call('HGET', KEYS[2], 'id'), redis.call('SMEMBERS', KEYS[1])}
"""


class RedisSessionStore:
    """Session taint in Redis, shared by every gateway replica.

    Keys per session (the ``{sid}`` hash tag keeps both in one slot):
        <prefix>{<sid>}:c   set of taint classes
        <prefix>{<sid>}:m   hash: taint id, existence marker
    """

    def __init__(self, url: str, *, ttl: float = DEFAULT_SESSION_TTL,
                 prefix: str = "taintward:gw:", socket_timeout: float = 5.0,
                 max_connections: int = 50) -> None:
        try:
            import redis.asyncio  # noqa: F401
        except ImportError:
            raise SessionStoreError("session_store: redis needs redis-py: pip install redis") from None
        self.url = url
        self.ttl = ttl
        self.prefix = prefix
        self._socket_timeout = socket_timeout
        self._max_connections = max_connections
        self._r = None
        self._merge = None
        self._users = 0  # open() / close() pairs, one per server lifespan

    async def open(self) -> None:
        import redis.asyncio as aredis

        self._users += 1
        if self._r is not None:
            return
        self._r = aredis.Redis.from_url(
            self.url, socket_timeout=self._socket_timeout,
            socket_connect_timeout=self._socket_timeout,
            max_connections=self._max_connections, health_check_interval=30,
        )
        self._merge = self._r.register_script(_MERGE)
        try:
            await self._call(self._r.ping)
        except SessionStoreError:
            await self.close()
            raise

    async def close(self) -> None:
        self._users = max(0, self._users - 1)
        if self._users == 0 and self._r is not None:
            r, self._r, self._merge = self._r, None, None
            await r.aclose()

    async def _call(self, fn, *args, **kwargs):
        import redis

        if self._r is None:
            raise SessionStoreError("RedisSessionStore is not open")
        try:
            return await fn(*args, **kwargs)
        except (redis.ConnectionError, redis.TimeoutError) as exc:
            from taintward.sdk.vault import _safe_url
            raise SessionStoreError(
                f"session store {_safe_url(self.url)} unavailable: {exc}") from None

    def _keys(self, sid: str) -> list[str]:
        base = f"{self.prefix}{{{sid}}}"
        return [base + ":c", base + ":m"]

    def _ttl_ms(self) -> int:
        return max(1, int(self.ttl * 1000))

    async def create(self, sid: str) -> None:
        await self._call(self._merge, keys=self._keys(sid), args=[self._ttl_ms(), ""])

    async def exists(self, sid: str) -> bool:
        return bool(await self._call(self._r.exists, self._keys(sid)[1]))

    async def get(self, sid: str) -> tnt.TaintLabel:
        return await self.merge(sid, tnt.TaintLabel.of(set()))

    async def merge(self, sid: str, label: tnt.TaintLabel) -> tnt.TaintLabel:
        args = [self._ttl_ms(), label.id]
        if label.is_tainted:
            args += sorted(c.value for c in label.classes)
        taint_id, classes = await self._call(self._merge, keys=self._keys(sid), args=args)
        return _label(taint_id, classes)

    async def delete(self, sid: str) -> None:
        await self._call(self._r.delete, *self._keys(sid))


def make_session_store(spec: str | None, ttl: float = DEFAULT_SESSION_TTL) -> SessionStore:
    """``memory`` (or empty) or ``redis://...`` / ``rediss://...``."""
    spec = (spec or "").strip()
    if spec in ("", "memory", "memory://"):
        return MemorySessionStore(ttl=ttl)
    if spec.startswith(("redis://", "rediss://", "unix://")):
        return RedisSessionStore(spec, ttl=ttl)
    raise ValueError(f"unknown session_store {spec!r}; use 'memory' or 'redis://host:6379/0'")
