"""Tests for the gateway over streamable HTTP (gateway/http.py) and the
session taint stores (gateway/session_store.py).

The HTTP tests start the real CLI, ``python -m gateway --listen``, as a
subprocess with the example HR server as a stdio upstream, and talk to it
over the network with the mcp client or raw HTTP. The Redis tests use the
throwaway redis-server from tests/test_vault_backends.py and are skipped
when redis-server or redis-py is missing.
"""

from __future__ import annotations

import json
import multiprocessing as mp
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import anyio
import pytest

mcp = pytest.importorskip("mcp")
httpx = pytest.importorskip("httpx")

from mcp import Client  # noqa: E402
from mcp.shared.exceptions import MCPError  # noqa: E402

from core.doe import Sensitivity  # noqa: E402
from gateway import BLOCKED_ERROR_CODE, parse_config  # noqa: E402
from gateway.config import ConfigError  # noqa: E402
from gateway.examples import hr_server  # noqa: E402
from gateway.http import parse_listen  # noqa: E402
from gateway.session_store import (  # noqa: E402
    MemorySessionStore,
    RedisSessionStore,
    make_session_store,
    valid_session_id,
)
from sdk.taint import TaintLabel  # noqa: E402
from tests import test_vault_backends as services  # noqa: E402

free_port = services.free_port
# The throwaway redis-server fixture (session scoped, shared with
# tests/test_vault_backends.py).
redis_url = services.redis_url

REPO = Path(__file__).resolve().parent.parent
SSN = hr_server.SSN
AWS_KEY = hr_server.AWS_KEY
RAW_BODY = f"Employee SSN is {SSN} and the key is {AWS_KEY}"
PROTO = "2025-11-25"
TOKEN = "s3cret-gateway-token"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def redis_db(redis_url):
    """The test redis-server, emptied before and after the test."""
    import redis
    r = redis.Redis.from_url(redis_url)
    r.flushdb()
    yield redis_url
    r.flushdb()
    r.close()


class GatewayProc:
    def __init__(self, proc: subprocess.Popen, port: int, outbox: Path):
        self.proc = proc
        self.port = port
        self.outbox = outbox
        self.base = f"http://127.0.0.1:{port}"
        self.url = self.base + "/mcp"

    def sent(self) -> str:
        return self.outbox.read_text() if self.outbox.exists() else ""

    def stop(self) -> int:
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                return self.proc.wait(30)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                return self.proc.wait()
        return self.proc.returncode


@pytest.fixture
def start_gateway(tmp_path):
    started: list[GatewayProc] = []

    def start(mode: str = "redact", *, session_store: str | None = None,
              token: str | None = None, name: str = "gw") -> GatewayProc:
        outbox = tmp_path / "outbox.jsonl"  # shared by every gateway in a test
        cfg = tmp_path / f"{name}.yaml"
        cfg.write_text(
            "upstreams:\n"
            "  - name: hr\n"
            "    command: python\n"
            "    args: [\"-m\", \"gateway.examples.hr_server\"]\n"
            f"    cwd: {REPO}\n"
            "    env:\n"
            f"      AGENTWARD_HR_OUTBOX: {outbox}\n"
            + (f"session_store: {session_store}\n" if session_store else "")
            + "tools:\n"
            "  - match: \"get_*\"\n"
            "    destination: internal\n"
            "  - match: send_email\n"
            "    destination: external\n"
            f"    mode: {mode}\n"
        )
        port = free_port()
        env = {k: v for k, v in os.environ.items()
               if k not in ("AGENTWARD_GATEWAY_TOKEN", "AGENTWARD_SESSION_STORE")}
        if token:
            env["AGENTWARD_GATEWAY_TOKEN"] = token
        proc = subprocess.Popen(
            [sys.executable, "-m", "gateway", "--config", str(cfg),
             "--listen", f"127.0.0.1:{port}"],
            cwd=str(REPO), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        gw = GatewayProc(proc, port, outbox)
        started.append(gw)
        deadline = time.time() + 180
        while True:
            if proc.poll() is not None:
                raise AssertionError("gateway exited: " + proc.stderr.read().decode()[-2000:])
            try:
                if httpx.get(gw.base + "/healthz", timeout=2).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            if time.time() > deadline:
                raise AssertionError("gateway did not become healthy")
            time.sleep(0.2)
        return gw

    yield start
    for gw in started:
        gw.stop()


def _headers(sid: str | None = None, token: str | None = None) -> dict[str, str]:
    h = {"Accept": "application/json, text/event-stream",
         "Content-Type": "application/json", "MCP-Protocol-Version": PROTO}
    if sid:
        h["Mcp-Session-Id"] = sid
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _decode(resp: httpx.Response) -> dict:
    if resp.headers.get("content-type", "").startswith("text/event-stream"):
        for line in resp.text.splitlines():
            if line.startswith("data:"):
                msg = json.loads(line[5:])
                if "id" in msg:
                    return msg
        raise AssertionError("no response in SSE stream: " + resp.text)
    return resp.json()


_ids = iter(range(1, 1_000_000))


def _rpc(url: str, method: str, params: dict | None = None, *, sid: str | None = None,
         token: str | None = None) -> tuple[httpx.Response, dict]:
    body = {"jsonrpc": "2.0", "id": next(_ids), "method": method, "params": params or {}}
    resp = httpx.post(url, json=body, headers=_headers(sid, token), timeout=60)
    return resp, (_decode(resp) if resp.content else {})


def _initialize(url: str, token: str | None = None) -> str:
    resp, msg = _rpc(url, "initialize", {
        "protocolVersion": PROTO, "capabilities": {},
        "clientInfo": {"name": "test", "version": "1"},
    }, token=token)
    assert resp.status_code == 200, resp.text
    assert "result" in msg, msg
    sid = resp.headers["mcp-session-id"]
    assert valid_session_id(sid)
    note = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    r = httpx.post(url, json=note, headers=_headers(sid, token), timeout=30)
    assert r.status_code in (200, 202), r.text
    return sid


def _call(url, sid, tool, args, token=None) -> dict:
    resp, msg = _rpc(url, "tools/call", {"name": tool, "arguments": args}, sid=sid, token=token)
    return msg


def _client(url: str, token: str | None = None) -> Client:
    from mcp.client.streamable_http import streamable_http_client
    from mcp.shared._httpx_utils import create_mcp_http_client

    headers = {"Authorization": f"Bearer {token}"} if token else None
    return Client(streamable_http_client(url, http_client=create_mcp_http_client(headers=headers)),
                  read_timeout_seconds=120)


# ---------------------------------------------------------------------------
# session stores (unit)
# ---------------------------------------------------------------------------

def _label(*classes: Sensitivity) -> TaintLabel:
    return TaintLabel.of(set(classes))


def test_memory_session_store_merge_and_ttl():
    async def main():
        s = MemorySessionStore(ttl=0.2)
        assert not (await s.get("a")).is_tainted
        first = await s.merge("a", _label(Sensitivity.PII))
        second = await s.merge("a", _label(Sensitivity.SECRET))
        assert second.classes == {Sensitivity.PII, Sensitivity.SECRET}
        assert second.id == first.id  # origin id is kept
        assert not (await s.get("b")).is_tainted  # sessions are separate
        await anyio.sleep(0.3)
        assert not await s.exists("a")  # expired
        await s.create("c")
        assert await s.exists("c")
        await s.delete("c")
        assert not await s.exists("c")

    anyio.run(main)


def test_session_store_config_and_factory():
    cfg = parse_config({"upstreams": [{"name": "a", "command": "x"}],
                        "session_store": "redis://cache:6379/1", "session_ttl": 600})
    assert cfg.session_store == "redis://cache:6379/1" and cfg.session_ttl == 600
    assert parse_config({"upstreams": [{"name": "a", "command": "x"}]}).session_store == "memory"
    with pytest.raises(ConfigError):
        parse_config({"upstreams": [{"name": "a", "command": "x"}], "session_store": "etcd://x"})
    with pytest.raises(ConfigError):
        parse_config({"upstreams": [{"name": "a", "command": "x"}], "session_ttl": -1})
    assert isinstance(make_session_store("memory"), MemorySessionStore)
    with pytest.raises(ValueError):
        make_session_store("etcd://x")
    assert parse_listen("0.0.0.0:8811") == ("0.0.0.0", 8811)
    assert parse_listen(":8811") == ("0.0.0.0", 8811)
    assert parse_listen("[::]:8811") == ("::", 8811)
    with pytest.raises(ValueError):
        parse_listen("8811")
    assert not valid_session_id("bad id\r\nX-Injected: 1")


def test_redis_session_store_merge_ttl_delete(redis_db):
    async def main():
        s = RedisSessionStore(redis_db, ttl=0.5)
        await s.open()
        try:
            assert not await s.exists("s1")
            await s.create("s1")
            assert await s.exists("s1")
            a = await s.merge("s1", _label(Sensitivity.PII))
            b = await s.merge("s1", _label(Sensitivity.SECRET))
            assert b.classes == {Sensitivity.PII, Sensitivity.SECRET} and b.id == a.id
            other = RedisSessionStore(redis_db, ttl=0.5)  # a second replica
            await other.open()
            assert (await other.get("s1")).classes == b.classes
            await other.close()
            await anyio.sleep(0.8)
            assert not await s.exists("s1")  # TTL ran out
            assert not (await s.get("s1")).is_tainted
            await s.merge("s2", _label(Sensitivity.PII))
            await s.delete("s2")
            assert not await s.exists("s2")
        finally:
            await s.close()

    anyio.run(main)


def _merger(url: str, cls: str, n: int) -> None:
    async def main():
        s = RedisSessionStore(url, ttl=60)
        await s.open()
        for i in range(n):
            await s.merge(f"race-{i}", TaintLabel.of({Sensitivity(cls)}))
        await s.close()

    anyio.run(main)


def test_redis_session_merges_from_several_processes_never_lose_a_class(redis_db):
    ctx = mp.get_context("spawn")
    procs = [ctx.Process(target=_merger, args=(redis_db, c, 200))
             for c in ("pii", "secret", "pii", "secret")]
    for p in procs:
        p.start()
    for p in procs:
        p.join(120)
        assert p.exitcode == 0

    async def check():
        s = RedisSessionStore(redis_db)
        await s.open()
        for i in range(200):
            assert (await s.get(f"race-{i}")).classes == {Sensitivity.PII, Sensitivity.SECRET}
        await s.close()

    anyio.run(check)


# ---------------------------------------------------------------------------
# HTTP gateway end to end
# ---------------------------------------------------------------------------

def test_http_end_to_end_redacts_and_shuts_down_cleanly(start_gateway):
    gw = start_gateway("redact")
    h = httpx.get(gw.base + "/healthz", timeout=5)
    assert h.status_code == 200 and h.json() == {"status": "ok"}
    seen = {}

    async def main():
        with anyio.fail_after(180):
            async with _client(gw.url) as client:
                seen["proto"] = client.protocol_version
                seen["tools"] = {t.name for t in (await client.list_tools()).tools}
                emp = await client.call_tool("get_employee", {"employee_id": "E100"})
                seen["emp"] = "\n".join(getattr(b, "text", "") for b in emp.content)
                await client.call_tool("send_email",
                                       {"to": "x@example.org", "subject": "s", "body": RAW_BODY})

    anyio.run(main)
    assert seen["proto"] == PROTO  # the client fell back to the session handshake
    assert {"get_employee", "send_email", "list_departments"} <= seen["tools"]
    assert SSN not in seen["emp"] and AWS_KEY not in seen["emp"]
    sent = gw.sent()
    assert sent and SSN not in sent and AWS_KEY not in sent
    assert "[PII]" in sent
    # Graceful shutdown on SIGTERM: clean exit code.
    assert gw.stop() == 0


def test_http_session_rules(start_gateway):
    gw = start_gateway("block")
    url = gw.url
    # No session id: only initialize is accepted.
    resp, msg = _rpc(url, "tools/list")
    assert resp.status_code == 400 and "initialize" in msg["error"]["message"]
    # Unknown or made up session ids: 404, so the client starts over.
    resp, _ = _rpc(url, "tools/list", sid="0" * 32)
    assert resp.status_code == 404
    resp, _ = _rpc(url, "tools/list", sid="bad id!")
    assert resp.status_code == 400
    # The 2026-07-28 session-less revision is refused with -32022 naming the
    # handshake versions, so clients fall back to initialize.
    r = httpx.post(url, json={"jsonrpc": "2.0", "id": 1, "method": "server/discover"},
                   headers={**_headers(), "MCP-Protocol-Version": "2026-07-28"}, timeout=10)
    assert r.status_code == 400
    err = r.json()["error"]
    assert err["code"] == -32022 and PROTO in err["data"]["supported"]

    sid = _initialize(url)
    msg = _call(url, sid, "send_email", {"to": "a@b.c", "subject": "s", "body": "hi"})
    assert "result" in msg and not msg["result"].get("isError")
    # Session taint: after a sensitive read the clean call is blocked.
    _call(url, sid, "get_employee", {"employee_id": "E100"})
    msg = _call(url, sid, "send_email", {"to": "a@b.c", "subject": "s", "body": "hi"})
    assert msg["error"]["code"] == BLOCKED_ERROR_CODE
    # Another session is not affected.
    sid2 = _initialize(url)
    assert sid2 != sid
    msg = _call(url, sid2, "send_email", {"to": "a@b.c", "subject": "s", "body": "hi"})
    assert "result" in msg
    # No server to client stream.
    r = httpx.get(url, headers={**_headers(sid), "Accept": "text/event-stream"}, timeout=10)
    assert r.status_code == 405
    # DELETE ends the session.
    r = httpx.delete(url, headers=_headers(sid), timeout=10)
    assert r.status_code == 200
    resp, _ = _rpc(url, "tools/list", sid=sid)
    assert resp.status_code == 404
    assert gw.sent().count("\n") == 2  # exactly the two allowed emails


def test_http_auth_on(start_gateway):
    gw = start_gateway("redact", token=TOKEN)
    assert httpx.get(gw.base + "/healthz", timeout=5).status_code == 200  # probes need no token
    resp, _ = _rpc(gw.url, "initialize", {"protocolVersion": PROTO, "capabilities": {},
                                          "clientInfo": {"name": "t", "version": "1"}})
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"].startswith("Bearer")
    resp, _ = _rpc(gw.url, "initialize", {}, token="wrong-token")
    assert resp.status_code == 401
    sid = _initialize(gw.url, token=TOKEN)
    # A valid session id is not enough without the token.
    resp, _ = _rpc(gw.url, "tools/list", sid=sid)
    assert resp.status_code == 401

    names = set()

    async def main():
        with anyio.fail_after(120):
            async with _client(gw.url, token=TOKEN) as client:
                names.update(t.name for t in (await client.list_tools()).tools)

    anyio.run(main)
    assert "send_email" in names


def test_http_auth_off_accepts_requests_without_token(start_gateway):
    gw = start_gateway("redact")
    sid = _initialize(gw.url)
    resp, msg = _rpc(gw.url, "tools/list", sid=sid)
    assert resp.status_code == 200 and msg["result"]["tools"]


def test_two_replicas_share_taint_through_redis(start_gateway, redis_db):
    a = start_gateway("block", session_store=redis_db, name="a")
    b = start_gateway("block", session_store=redis_db, name="b")
    # The session is opened on replica A ...
    sid = _initialize(a.url)
    # ... and B knows it (a load balancer may send any request anywhere).
    resp, msg = _rpc(b.url, "tools/list", sid=sid)
    assert resp.status_code == 200 and msg["result"]["tools"]
    # A clean email from B is fine before anything sensitive was read.
    msg = _call(b.url, sid, "send_email", {"to": "a@b.c", "subject": "s", "body": "hi"})
    assert "result" in msg
    # The agent reads the employee record through A ...
    msg = _call(a.url, sid, "get_employee", {"employee_id": "E100"})
    assert SSN not in json.dumps(msg)
    # ... so B now blocks even a clean looking email in that session.
    msg = _call(b.url, sid, "send_email", {"to": "a@b.c", "subject": "s", "body": "hi"})
    assert msg["error"]["code"] == BLOCKED_ERROR_CODE
    # Raw data never reaches the external tool from either replica.
    msg = _call(a.url, sid, "send_email", {"to": "a@b.c", "subject": "s", "body": RAW_BODY})
    assert msg["error"]["code"] == BLOCKED_ERROR_CODE
    sent = a.sent()
    assert SSN not in sent and sent.count("\n") == 1
    # Ending the session on B ends it on A too.
    assert httpx.delete(b.url, headers=_headers(sid), timeout=10).status_code == 200
    resp, _ = _rpc(a.url, "tools/list", sid=sid)
    assert resp.status_code == 404


def test_session_store_down_fails_closed():
    """If the store cannot be read, tool calls are refused, not run untainted."""
    from gateway import Gateway
    from gateway.session_store import SessionStoreError

    class DownStore(MemorySessionStore):
        async def merge(self, sid, label):
            raise SessionStoreError("down")

    cfg = parse_config({
        "upstreams": [{"name": "hr", "command": "python"}],
        "tools": [{"match": "send_email", "destination": "external", "mode": "audit"}],
    })
    cfg.upstreams[0].server_object = hr_server.mcp
    hr_server.OUTBOX.clear()
    server = Gateway(cfg, session_store=DownStore()).build_server()

    async def main():
        async with Client(server) as client:
            with pytest.raises(MCPError):
                await client.call_tool("send_email", {"to": "a@b.c", "subject": "s",
                                                      "body": RAW_BODY})

    anyio.run(main)
    assert hr_server.OUTBOX == []
