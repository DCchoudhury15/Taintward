"""Serve the Taintward MCP gateway over streamable HTTP.

    python -m taintward.gateway --config gateway.yaml --listen 0.0.0.0:8811

Endpoints:
    POST /mcp      MCP streamable HTTP (JSON-RPC requests)
    DELETE /mcp    end the session given in Mcp-Session-Id
    GET /healthz   200 while the process is up (Kubernetes probes, no auth)

How sessions work, and why this is safe with several replicas:

* The mcp SDK's streamable HTTP server runs in *stateless* mode, so any
  replica can answer any request. The SDK keeps no per-session state.
* This module issues the session id itself. The response to ``initialize``
  carries a new ``Mcp-Session-Id``, and the id is recorded in the session
  store. Every later request must send it; an id the store does not know
  (never issued, ended, or expired) gets 404, so the client starts a new
  session, as the MCP spec says.
* The session taint is in the session store, keyed by that id. With
  ``session_store: redis://...`` every replica sees the same taint.
* A request without a session id is only accepted for ``initialize``.
  Session-less requests of the 2026-07-28 protocol revision are answered
  with error -32022 listing the handshake versions, so clients fall back to
  the ``initialize`` handshake and get a session. The gateway needs a
  session to track taint, so it does not serve session-less calls.
* There is no server to client stream (GET answers 405): the gateway does
  not forward server initiated messages.

Auth: when ``TAINTWARD_GATEWAY_TOKEN`` is set, every request except
``/healthz`` needs ``Authorization: Bearer <token>``; others get 401.
"""

from __future__ import annotations

import hmac
import json
import logging
from typing import Any

from taintward.gateway.session_store import (
    SessionStore,
    SessionStoreError,
    new_session_id,
    valid_session_id,
)

logger = logging.getLogger("taintward.gateway.http")

MCP_PATH = "/mcp"
HEALTH_PATH = "/healthz"
MAX_BODY_BYTES = 4 * 1024 * 1024
DEFAULT_SHUTDOWN_TIMEOUT = 25.0

_SESSION_HEADER = b"mcp-session-id"
_VERSION_HEADER = b"mcp-protocol-version"


def parse_listen(value: str) -> tuple[str, int]:
    """``HOST:PORT``, ``:PORT`` (all interfaces) or ``[v6addr]:PORT``."""
    host, sep, port = value.rpartition(":")
    if not sep or not port.isdigit():
        raise ValueError(f"--listen {value!r}: expected HOST:PORT, e.g. 0.0.0.0:8811")
    host = host.strip("[]") or "0.0.0.0"
    p = int(port)
    if not 0 < p < 65536:
        raise ValueError(f"--listen {value!r}: port out of range")
    return host, p


def _handshake_versions() -> list[str]:
    from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS
    return list(HANDSHAKE_PROTOCOL_VERSIONS)


async def _send_json(send, status: int, body: Any, headers: list[tuple[bytes, bytes]] = ()) -> None:
    data = json.dumps(body).encode() if body is not None else b""
    hdrs = [(b"content-length", str(len(data)).encode())]
    if body is not None:
        hdrs.append((b"content-type", b"application/json"))
    await send({"type": "http.response.start", "status": status, "headers": hdrs + list(headers)})
    await send({"type": "http.response.body", "body": data})


async def _rpc_error(send, status: int, code: int, message: str, data: Any = None,
                     headers: list[tuple[bytes, bytes]] = ()) -> None:
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    await _send_json(send, status, {"jsonrpc": "2.0", "id": None, "error": err}, headers)


class GatewayHTTPApp:
    """ASGI wrapper around the SDK's streamable HTTP app: health endpoint,
    bearer auth, and session ids backed by the session store."""

    def __init__(self, app, store: SessionStore, *, token: str | None = None,
                 mcp_path: str = MCP_PATH, max_body: int = MAX_BODY_BYTES) -> None:
        self.app = app
        self.store = store
        self.token = token or None
        self.mcp_path = mcp_path.rstrip("/") or "/"
        self.max_body = max_body

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)  # lifespan, websocket
            return
        path = scope.get("path", "")
        method = scope.get("method", "GET")
        if path == HEALTH_PATH:
            if method in ("GET", "HEAD"):
                await _send_json(send, 200, {"status": "ok"})
            else:
                await _send_json(send, 405, None, [(b"allow", b"GET, HEAD")])
            return
        headers = {k.lower(): v for k, v in scope.get("headers", [])}
        if self.token and not self._authorized(headers):
            await _rpc_error(send, 401, -32001, "Unauthorized: missing or wrong bearer token",
                             headers=[(b"www-authenticate", b'Bearer realm="taintward-gateway"')])
            return
        if (path.rstrip("/") or "/") != self.mcp_path:
            await self.app(scope, receive, send)
            return
        try:
            await self._mcp(scope, receive, send, headers, method)
        except SessionStoreError as exc:
            logger.error("session store error: %s", exc)
            await _rpc_error(send, 503, -32603, "session store unavailable")

    def _authorized(self, headers: dict[bytes, bytes]) -> bool:
        auth = headers.get(b"authorization", b"").decode("latin-1")
        scheme, _, given = auth.partition(" ")
        if scheme.lower() != "bearer":
            return False
        return hmac.compare_digest(given.strip().encode(), self.token.encode())

    async def _mcp(self, scope, receive, send, headers, method) -> None:
        version = headers.get(_VERSION_HEADER, b"").decode("latin-1")
        if version and version not in _handshake_versions():
            # Session-less protocol revision: ask the client to use the
            # handshake, which gives it a session.
            from mcp_types import UNSUPPORTED_PROTOCOL_VERSION
            await _rpc_error(send, 400, UNSUPPORTED_PROTOCOL_VERSION,
                             "Taintward gateway needs an MCP session; use initialize",
                             {"supported": _handshake_versions(), "requested": version})
            return

        raw_sid = headers.get(_SESSION_HEADER)
        if raw_sid is None:
            await self._open_session(scope, receive, send, method)
            return

        sid = raw_sid.decode("latin-1")
        if not valid_session_id(sid):
            await _rpc_error(send, 400, -32600, "Bad Request: malformed Mcp-Session-Id")
            return
        if not await self.store.exists(sid):
            await _rpc_error(send, 404, -32600, "Session not found")
            return
        if method == "DELETE":
            await self.store.delete(sid)
            await _send_json(send, 200, None)
            return
        if method == "GET":
            # No server to client stream: nothing is pushed by the gateway.
            await _send_json(send, 405, None, [(b"allow", b"POST, DELETE")])
            return
        await self.app(scope, receive, send)

    async def _open_session(self, scope, receive, send, method) -> None:
        if method != "POST":
            await _rpc_error(send, 400, -32600, "Bad Request: missing Mcp-Session-Id")
            return
        body = await self._read_body(receive)
        if body is None:
            await _rpc_error(send, 413, -32600, "Request body too large")
            return
        try:
            msg = json.loads(body)
        except ValueError:
            msg = None
        if not isinstance(msg, dict) or msg.get("method") != "initialize":
            await _rpc_error(send, 400, -32600,
                             "Bad Request: missing Mcp-Session-Id (send initialize first)")
            return

        sid = new_session_id()
        # Record the id before the client can see it, so its next request
        # (possibly to another replica) finds it.
        await self.store.create(sid)
        status = 0

        async def send_with_sid(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                if status < 400:
                    message = {**message, "headers": [*message.get("headers", []),
                                                      (_SESSION_HEADER, sid.encode())]}
            await send(message)

        replayed = False

        async def replay():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        try:
            await self.app(scope, replay, send_with_sid)
        finally:
            if not 0 < status < 400:
                try:
                    await self.store.delete(sid)
                except SessionStoreError:
                    pass

    async def _read_body(self, receive) -> bytes | None:
        chunks: list[bytes] = []
        size = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                break
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > self.max_body:
                return None
            chunks.append(chunk)
            if not message.get("more_body", False):
                break
        return b"".join(chunks)


def build_http_app(gateway, *, host: str = "127.0.0.1", token: str | None = None):
    """The full ASGI app: SDK streamable HTTP (stateless) inside
    :class:`GatewayHTTPApp`. ``gateway`` must have ``require_session_id``
    set, so no call falls back to a shared default session."""
    gateway.require_session_id = True
    server = gateway.build_server()
    inner = server.streamable_http_app(
        streamable_http_path=MCP_PATH,
        stateless_http=True,
        host=host,
        max_request_body_size=MAX_BODY_BYTES,
    )
    return GatewayHTTPApp(inner, gateway.store, token=token)


def serve_http(gateway, host: str, port: int, *, token: str | None = None,
               shutdown_timeout: float = DEFAULT_SHUTDOWN_TIMEOUT,
               log_level: str = "warning") -> None:
    """Run uvicorn until SIGTERM / SIGINT. On a signal uvicorn stops
    accepting connections, lets in flight requests finish (up to
    ``shutdown_timeout`` seconds), then the lifespan closes the upstream
    connections and the session store."""
    import contextlib

    import uvicorn

    class _Server(uvicorn.Server):
        # uvicorn re-raises the caught SIGTERM after a clean shutdown, which
        # makes the process exit with -15. A clean stop should exit 0.
        @contextlib.contextmanager
        def capture_signals(self):
            with super().capture_signals():
                yield
                captured = getattr(self, "_captured_signals", None)
                if isinstance(captured, list):
                    captured.clear()

    app = build_http_app(gateway, host=host, token=token)
    config = uvicorn.Config(
        app, host=host, port=port, lifespan="on", log_level=log_level.lower(),
        timeout_graceful_shutdown=shutdown_timeout, access_log=False,
    )
    _Server(config).run()
