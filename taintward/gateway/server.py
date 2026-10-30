"""The Taintward MCP gateway: a proxy MCP server that enforces Taintward
policy on every ``tools/call`` between an MCP client and upstream servers.

Per ``tools/call`` the gateway:

1. resolves the tool's policy (destination, jurisdiction, mode) from config,
2. detects sensitive data in the arguments (``taintward.sdk.detect``),
3. merges that with the session taint (once any earlier argument or result
   in this session was sensitive, every later call is tainted; this is the
   session-level analogue of the SDK's baggage chain taint). The taint is
   kept in a session store (``taintward.gateway.session_store``) keyed by the MCP
   session id, so several replicas can share it,
4. evaluates the policy (``taintward.gateway.policy``, the Rego rules in Python),
5. mode ``block`` with a violation: returns an MCP error, nothing is sent
   upstream; mode ``redact`` / ``block``: redacts the arguments for the
   tool's destination (``taintward.sdk.redact.redact_payload``); mode ``audit``: passes
   the raw arguments through and only records the violation,
6. forwards the call upstream with the chain taint in OTel baggage,
7. scans the result, merges its taint into the session, and masks
   sensitive values in the result before the agent sees it,
8. emits one OTel span with the same attribute names the SDK uses.

Tool listing is checked too: two upstreams exposing the same name is an
error (gap G3), and a tool whose description or schema changes after it was
first seen, or differs from its pin in ``tool_pins``, is reported and with
``on_tool_change: hide`` no longer exposed (gap G2).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from typing import Any, AsyncIterator

import anyio
import mcp_types as types
from mcp import Client, StdioServerParameters
from mcp.client.stdio import get_default_environment
from mcp.server import Server
from mcp.shared.exceptions import MCPError
from opentelemetry import context as context_api
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

from taintward.gateway.config import (
    MODE_AUDIT,
    MODE_BLOCK,
    TOOL_CHANGE_HIDE,
    ConfigError,
    GatewayConfig,
    ToolPolicy,
    UpstreamConfig,
)
from taintward.gateway.policy import PolicyInput, evaluate
from taintward.gateway.session_store import (
    SessionStore,
    SessionStoreError,
    make_session_store,
    new_session_id,
)
from taintward.sdk import detect as _detect
from taintward.sdk import instrumentation as _instr
from taintward.sdk import taint as tnt
from taintward.sdk.destinations import DEST_INTERNAL, DEST_LLM
from taintward.sdk.detect import detect_mapping, detect_text, mask_value, taint_for
from taintward.sdk.instrumentation import ATTR_ARGS_REDACTED as SDK_ATTR_ARGS_REDACTED
from taintward.sdk.instrumentation import (
    ATTR_DEST,
    ATTR_JURISDICTION,
    ATTR_VIOLATION,
    record_masked_exception,
)
from taintward.sdk.redact import redact_payload

logger = logging.getLogger("taintward.gateway")

# JSON-RPC error code returned when a call is blocked (implementation-defined
# server error range -32000..-32099).
BLOCKED_ERROR_CODE = -32001

# HTTP header that carries the MCP session id (lower case, as in ASGI).
MCP_SESSION_HEADER = "mcp-session-id"
# Set by GatewayHTTPApp after auth to the client name of the token; a value
# sent by the client itself is removed first.
CLIENT_HEADER = "x-taintward-client"
# Session store key prefix for taint kept per client (gap G4).
CLIENT_TAINT_PREFIX = "client:"

# Span attribute keys. The ones shared with the SDK are imported above; these
# are gateway specific.
ATTR_TOOL_NAME = "gen_ai.tool.name"
ATTR_TOOL_ARGS = "gen_ai.tool.call.arguments"
ATTR_TOOL_RESULT = "gen_ai.tool.call.result"
ATTR_OPERATION = "gen_ai.operation.name"
ATTR_MCP_METHOD = "mcp.method.name"
ATTR_VIOLATION_REASON = "taintward.violation.reason"
ATTR_RULES = "taintward.policy.rules"
ATTR_MODE = "taintward.mode"
ATTR_BLOCKED = "taintward.blocked"
ATTR_DRY_RUN = "taintward.dry_run"
ATTR_ARGS_REDACTED = "taintward.args.redacted"
# Read by the collector: the stored arguments need no more masking.
ATTR_ARGS_STORED_REDACTED = SDK_ATTR_ARGS_REDACTED
ATTR_RESULT_REDACTED = "taintward.result.redacted"
ATTR_UPSTREAM = "taintward.gateway.upstream"
ATTR_TOOL_ERROR = "taintward.tool.error"
ATTR_CLIENT = "taintward.gateway.client"
ATTR_TOOL_FP = "taintward.gateway.tool.fingerprint"
ATTR_TOOL_FP_EXPECTED = "taintward.gateway.tool.expected_fingerprint"
ATTR_TOOL_HIDDEN = "taintward.gateway.tool.hidden"


_CLASH = "offered by several upstreams"


def tool_fingerprint(tool: types.Tool) -> str:
    """SHA-256 over what the agent's model reads about a tool: description,
    title, input and output schema (gap G2). The exposed name is the key it
    is stored under, not part of the hash."""
    data = tool.model_dump(mode="json", by_alias=True, exclude_none=True)
    shown = {k: data.get(k) for k in ("description", "title", "inputSchema", "outputSchema")}
    raw = json.dumps(shown, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _jsonable(obj: Any) -> str:
    try:
        return json.dumps(obj, default=str, ensure_ascii=False)
    except Exception:
        return repr(obj)


def _classes_str(label: tnt.TaintLabel) -> str:
    return ",".join(sorted(c.value for c in label.classes))


def _result_payload(result: types.CallToolResult) -> list[Any]:
    """The scannable values of a tool result: text blocks, embedded text
    resources and structured content."""
    out: list[Any] = []
    for block in result.content:
        if isinstance(block, types.TextContent):
            out.append(block.text)
        elif isinstance(block, types.EmbeddedResource) and isinstance(
            block.resource, types.TextResourceContents
        ):
            out.append(block.resource.text)
    if result.structured_content is not None:
        out.append(result.structured_content)
    return out


def _redact_result(result: types.CallToolResult, destination: str) -> types.CallToolResult:
    """Redact sensitive values in a result for ``destination`` (sync, run in
    a worker thread)."""
    content = []
    for block in result.content:
        if isinstance(block, types.TextContent):
            block = block.model_copy(update={"text": redact_payload(block.text, destination)})
        elif isinstance(block, types.EmbeddedResource) and isinstance(
            block.resource, types.TextResourceContents
        ):
            res = block.resource.model_copy(
                update={"text": redact_payload(block.resource.text, destination)}
            )
            block = block.model_copy(update={"resource": res})
        content.append(block)
    update: dict[str, Any] = {"content": content}
    if result.structured_content is not None:
        update["structured_content"] = redact_payload(result.structured_content, destination)
    return result.model_copy(update=update)


@dataclass
class _Route:
    upstream: str
    client: Client
    tool_name: str  # name on the upstream


class GatewaySession:
    """State for one server lifespan: the upstream clients and the tool
    routing table.

    Over stdio (and in process) a lifespan is one client connection, so
    calls without an MCP session id use ``default_session_id``. Over HTTP the
    lifespan lasts as long as the process and is shared by every HTTP
    session; each call then passes its Mcp-Session-Id. The taint itself is
    always in the gateway's session store.
    """

    def __init__(self, gateway: "Gateway"):
        self.gateway = gateway
        self.clients: dict[str, Client] = {}
        self.routes: dict[str, _Route] = {}
        self.default_session_id = new_session_id()
        # Gap G2: fingerprint first seen per exposed tool, and tools hidden
        # because they changed (on_tool_change: hide) or clash (gap G3).
        self.seen: dict[str, str] = {}
        self.hidden: dict[str, str] = {}
        self._reported: set[tuple[str, str]] = set()

    async def taint(self, session_id: str | None = None) -> tnt.TaintLabel:
        """The current taint of a session (the default one when None)."""
        return await self.gateway.store.get(session_id or self.default_session_id)

    async def _merge_taint(self, sid: str, label: tnt.TaintLabel,
                           client: str | None = None) -> tnt.TaintLabel:
        """Merge into the session taint and, for a named client, into the
        client's taint too (gap G4), so ending the session does not clear
        it. Returns the union of both."""
        try:
            merged = await self.gateway.store.merge(sid, label)
            if client:
                merged = merged.merge(
                    await self.gateway.store.merge(CLIENT_TAINT_PREFIX + client, label))
            return merged
        except SessionStoreError as exc:
            # Fail closed: without the session taint the policy cannot decide.
            logger.error("session store error: %s", exc)
            raise MCPError(types.INTERNAL_ERROR,
                           "Taintward gateway: session store unavailable, call refused") from None

    # --- upstreams ---

    @staticmethod
    def _client_for(u: UpstreamConfig) -> Client:
        if u.server_object is not None:
            return Client(u.server_object)
        if u.url:
            return Client(u.url)
        env = {**get_default_environment(), **u.env}
        return Client(StdioServerParameters(command=u.command, args=u.args, env=env, cwd=u.cwd))

    async def connect(self, stack: AsyncExitStack) -> None:
        for u in self.gateway.config.upstreams:
            client = await stack.enter_async_context(self._client_for(u))
            self.clients[u.name] = client
        await self.refresh_tools(startup=True)

    async def _list_upstream(self, u: UpstreamConfig) -> list[types.Tool]:
        client = self.clients[u.name]
        tools: list[types.Tool] = []
        cursor: str | None = None
        while True:
            page = await client.list_tools(cursor=cursor)
            tools.extend(page.tools)
            cursor = page.next_cursor
            if not cursor:
                return tools

    async def refresh_tools(self, *, startup: bool = False) -> list[types.Tool]:
        """List every upstream's tools and rebuild the routing table.

        Two upstreams exposing the same name is an error (gap G3): at
        startup the gateway refuses to start, later both tools are hidden.
        Use ``prefix:`` per upstream to tell them apart. A tool that differs
        from its pin or from the version first seen is reported, and with
        ``on_tool_change: hide`` not exposed (gap G2)."""
        cfg = self.gateway.config
        found: dict[str, list[tuple[UpstreamConfig, types.Tool]]] = {}
        for u in cfg.upstreams:
            for tool in await self._list_upstream(u):
                found.setdefault(u.prefix + tool.name, []).append((u, tool))

        clashes = {n: [u.name for u, _ in v] for n, v in found.items() if len(v) > 1}
        if clashes and startup:
            detail = "; ".join(f"{n!r} from {', '.join(ups)}" for n, ups in sorted(clashes.items()))
            raise ConfigError(f"tool name clash between upstreams: {detail}. "
                              "Give the upstreams a prefix.")

        exposed: list[types.Tool] = []
        routes: dict[str, _Route] = {}
        for name, entries in found.items():
            if name in clashes:
                if (name, "clash") not in self._reported:
                    self._reported.add((name, "clash"))
                    self._tool_event(name, ",".join(clashes[name]), "clash")
                self.hidden[name] = _CLASH
                continue
            if self.hidden.get(name) == _CLASH:  # the clash is gone
                del self.hidden[name]
            u, tool = entries[0]
            if not self._tool_ok(name, u.name, tool):
                continue
            routes[name] = _Route(upstream=u.name, client=self.clients[u.name],
                                  tool_name=tool.name)
            exposed.append(tool if name == tool.name
                           else tool.model_copy(update={"name": name}))
        self.routes = routes
        return exposed

    def _tool_ok(self, name: str, upstream: str, tool: types.Tool) -> bool:
        """Gap G2: compare the tool with its pin or first seen version."""
        cfg = self.gateway.config
        fp = tool_fingerprint(tool)
        expected = cfg.tool_pins.get(name) or self.seen.setdefault(name, fp)
        if name in self.hidden:
            return False
        if fp == expected:
            return True
        hide = cfg.on_tool_change == TOOL_CHANGE_HIDE
        if (name, fp) not in self._reported:  # once per new version, not per tools/list
            self._reported.add((name, fp))
            self._tool_event(name, upstream, "changed", fp=fp, expected=expected, hidden=hide)
        if hide:
            self.hidden[name] = "its description or schema changed"
        return not hide

    def _tool_event(self, name: str, upstream: str, kind: str, *, fp: str = "",
                    expected: str = "", hidden: bool = True) -> None:
        if kind == "clash":
            logger.error("tool %r is offered by several upstreams (%s); it is hidden. "
                         "Give the upstreams a prefix.", name, upstream)
        else:
            logger.warning("tool %r from upstream %r changed (%s, expected %s)%s", name,
                           upstream, fp, expected, "; it is hidden" if hidden else "")
        attrs = {ATTR_TOOL_NAME: name, ATTR_UPSTREAM: upstream, ATTR_TOOL_HIDDEN: hidden}
        if fp:
            attrs[ATTR_TOOL_FP] = fp
            attrs[ATTR_TOOL_FP_EXPECTED] = expected
        with self.gateway.tracer.start_as_current_span(
                f"taintward.gateway tool_{kind}", kind=trace.SpanKind.INTERNAL,
                attributes={ATTR_MCP_METHOD: "tools/list", **attrs}) as span:
            span.set_status(Status(StatusCode.ERROR, f"tool {kind}"))

    async def fingerprints(self) -> dict[str, str]:
        """Exposed tool name -> fingerprint, for ``tool_pins``."""
        out: dict[str, str] = {}
        for u in self.gateway.config.upstreams:
            for tool in await self._list_upstream(u):
                out.setdefault(u.prefix + tool.name, tool_fingerprint(tool))
        return dict(sorted(out.items()))

    # --- tools/call ---

    async def call_tool(self, name: str, arguments: dict[str, Any],
                        session_id: str | None = None,
                        client: str | None = None) -> types.CallToolResult:
        gw = self.gateway
        if session_id is None:
            if gw.require_session_id:
                raise MCPError(types.INVALID_REQUEST, "missing Mcp-Session-Id")
            session_id = self.default_session_id
        client = client or gw.config.client
        route = self.routes.get(name)
        if route is None:
            await self.refresh_tools()
            route = self.routes.get(name)
        if route is None:
            if name in self.hidden:
                raise MCPError(BLOCKED_ERROR_CODE,
                               f"Taintward hid tool {name}: {self.hidden[name]}",
                               data={"tool": name, "reason": self.hidden[name]})
            raise MCPError(types.INVALID_PARAMS, f"Unknown tool: {name}")

        policy: ToolPolicy = gw.config.policy_for(name, route.upstream)
        if (_instr.FAIL_CLOSED and policy.destination != DEST_INTERNAL
                and await anyio.to_thread.run_sync(_detect.is_degraded)):
            raise MCPError(
                BLOCKED_ERROR_CODE,
                f"Taintward refused tools/call {name}: sensitive-data detection is "
                "degraded and TAINTWARD_FAIL_CLOSED is on",
                data={"tool": name, "destination": policy.destination,
                      "detection": _detect.health()},
            )

        # Arguments listed in passthrough_args skip scanning and redaction.
        passthrough = {k: v for k, v in arguments.items() if k in policy.passthrough_args}
        scanned = {k: v for k, v in arguments.items() if k not in policy.passthrough_args}

        # Field-level taint on the arguments, merged with the session taint.
        in_dets = await anyio.to_thread.run_sync(detect_mapping, scanned)
        args_label = taint_for(in_dets)
        # The agent's context now holds whatever it sent, so the session
        # keeps it. The store merge is atomic and returns the whole session
        # taint, including classes other replicas added.
        merged_in = await self._merge_taint(session_id, args_label, client)

        pre = evaluate(PolicyInput(
            sensitive=merged_in.is_tainted,
            classes=_classes_str(merged_in),
            destination=policy.destination,
            jurisdiction=policy.jurisdiction,
            tool=name,
        ))
        blocked = policy.mode == MODE_BLOCK and pre.is_violation

        # Passthrough values are forwarded as is but still masked on the span.
        stored_passthrough = (await anyio.to_thread.run_sync(mask_value, passthrough)
                              if passthrough else {})
        if policy.mode == MODE_AUDIT or blocked:
            forwarded = arguments
            # Never store raw values on the span: mask them for the span only.
            stored_args = {**await anyio.to_thread.run_sync(mask_value, scanned),
                           **stored_passthrough}
        else:
            redacted = await anyio.to_thread.run_sync(
                redact_payload, scanned, policy.destination
            )
            forwarded = {**redacted, **passthrough}
            stored_args = {**redacted, **stored_passthrough}
        args_redacted = forwarded != arguments
        # The stored arguments are redacted for the destination (reversible
        # tokens for internal), so the collector must keep them as they are.
        marker = {} if policy.mode == MODE_AUDIT or blocked else {ATTR_ARGS_STORED_REDACTED: True}

        # Chain taint rides to the upstream as OTel baggage (the mcp SDK
        # injects the current context into the request _meta).
        ctx = tnt.attach(merged_in) if merged_in.is_tainted else context_api.get_current()
        token = context_api.attach(ctx)
        try:
            with gw.tracer.start_as_current_span(
                f"taintward.gateway {name}",
                kind=trace.SpanKind.INTERNAL,
                # Exceptions are recorded below with sensitive data masked.
                record_exception=False,
                set_status_on_exception=False,
                attributes={
                    ATTR_TOOL_NAME: name,
                    ATTR_OPERATION: "execute_tool",
                    ATTR_MCP_METHOD: "tools/call",
                    ATTR_UPSTREAM: route.upstream,
                    **({ATTR_CLIENT: client} if client else {}),
                    ATTR_MODE: policy.mode,
                    ATTR_DEST: policy.destination,
                    ATTR_JURISDICTION: policy.jurisdiction,
                    ATTR_TOOL_ARGS: _jsonable(stored_args),
                    ATTR_ARGS_REDACTED: args_redacted,
                    **marker,
                    **merged_in.to_span_attrs(),
                },
            ) as span:
                if policy.mode == MODE_AUDIT:
                    span.set_attribute(ATTR_DRY_RUN, True)

                if blocked:
                    self._record_decision(span, pre, policy, blocked=True)
                    span.set_status(Status(StatusCode.ERROR, "blocked by policy"))
                    reason = ", ".join(pre.rules())
                    raise MCPError(
                        BLOCKED_ERROR_CODE,
                        f"Taintward blocked tools/call {name}: {reason} "
                        f"(destination={policy.destination})",
                        data={"tool": name, "destination": policy.destination,
                              "violations": pre.violations},
                    )

                try:
                    result = await route.client.call_tool(route.tool_name, forwarded)
                except Exception as exc:
                    # The arguments still went upstream: record the decision.
                    self._record_decision(span, pre, policy, blocked=False)
                    record_masked_exception(span, exc)
                    raise

                payload = _result_payload(result)
                out_dets = await anyio.to_thread.run_sync(detect_mapping, payload)
                out_label = taint_for(
                    out_dets,
                    source_span_id=format(span.get_span_context().span_id, "016x"),
                )
                stored = await self._merge_taint(session_id, out_label, client)
                merged_out = merged_in.merge(out_label).merge(stored)
                if merged_out.is_tainted:
                    span.set_attributes(merged_out.to_span_attrs())

                final = evaluate(PolicyInput(
                    sensitive=merged_out.is_tainted,
                    classes=_classes_str(merged_out),
                    destination=policy.destination,
                    jurisdiction=policy.jurisdiction,
                    tool=name,
                ))
                self._record_decision(span, final, policy, blocked=False)

                result_redacted = False
                if policy.redact_results and policy.mode != MODE_AUDIT and out_label.is_tainted:
                    # Results go back into the agent's model context: an llm sink.
                    new = await anyio.to_thread.run_sync(_redact_result, result, DEST_LLM)
                    result_redacted = new != result
                    result = new
                span.set_attribute(ATTR_RESULT_REDACTED, result_redacted)
                stored_result = await anyio.to_thread.run_sync(
                    mask_value, _result_payload(result)
                )
                span.set_attribute(ATTR_TOOL_RESULT, _jsonable(stored_result))
                if result.is_error:
                    span.set_attribute(ATTR_TOOL_ERROR, True)
                return result
        finally:
            context_api.detach(token)

    @staticmethod
    def _record_decision(span, decision, policy: ToolPolicy, *, blocked: bool) -> None:
        span.set_attribute(ATTR_VIOLATION, decision.is_violation)
        span.set_attribute(ATTR_BLOCKED, blocked)
        if decision.is_violation:
            rules = decision.rules()
            span.set_attribute(ATTR_RULES, ",".join(rules))
            span.set_attribute(
                ATTR_VIOLATION_REASON,
                f"tainted session reached {policy.destination} sink"
                if "pii_egress" in rules
                else f"pii transfer to jurisdiction {policy.jurisdiction}",
            )


def _http_session_id(ctx) -> str | None:
    """The Mcp-Session-Id of the HTTP request behind ``ctx``, if any. Over
    stdio and in process there is no HTTP request and this is None."""
    request = getattr(ctx, "request", None)
    headers = getattr(request, "headers", None)
    if headers is None:
        return None
    return headers.get(MCP_SESSION_HEADER) or None


def _http_client(ctx) -> str | None:
    """The client name GatewayHTTPApp set from the bearer token, if any."""
    headers = getattr(getattr(ctx, "request", None), "headers", None)
    return headers.get(CLIENT_HEADER) or None if headers is not None else None


class Gateway:
    """Build a proxy MCP :class:`~mcp.server.Server` for a config.

    ``tracer`` defaults to the global ``taintward.gateway`` tracer. Over
    stdio each client connection gets its own :class:`GatewaySession` (own
    upstream connections). Session taint lives in ``session_store``
    (default: built from ``config.session_store``, or the
    ``TAINTWARD_SESSION_STORE`` env var when set).
    """

    def __init__(self, config: GatewayConfig, tracer: trace.Tracer | None = None,
                 *, warm_detector: bool = True, session_store: SessionStore | None = None,
                 require_session_id: bool = False):
        self.config = config
        self.tracer = tracer or trace.get_tracer("taintward.gateway")
        self.warm_detector = warm_detector
        if session_store is None:
            spec = os.environ.get("TAINTWARD_SESSION_STORE") or config.session_store
            session_store = make_session_store(spec, ttl=config.session_ttl)
        self.store: SessionStore = session_store
        # HTTP mode: every call must name its MCP session (no shared default).
        self.require_session_id = require_session_id

    @asynccontextmanager
    async def _lifespan(self, _server: Server) -> AsyncIterator[GatewaySession]:
        session = GatewaySession(self)
        async with AsyncExitStack() as stack:
            await self.store.open()
            stack.push_async_callback(self.store.close)
            if self.warm_detector:
                # Presidio loads spaCy on first use; do it before the first call.
                await anyio.to_thread.run_sync(detect_text, "warm up")
            await session.connect(stack)
            yield session

    async def tool_pins(self) -> dict[str, str]:
        """Connect to the upstreams once and return the ``tool_pins`` for
        the tools they offer now (``--print-tool-pins``)."""
        session = GatewaySession(self)
        try:
            async with AsyncExitStack() as stack:
                await session.connect(stack)
                return await session.fingerprints()
        except BaseExceptionGroup as group:  # the MCP client's task group wraps it
            config = group.subgroup(ConfigError)
            if config is None:
                raise
            while isinstance(config, BaseExceptionGroup):
                config = config.exceptions[0]
            raise config from None

    def build_server(self) -> Server:
        async def on_list_tools(ctx, params) -> types.ListToolsResult:
            session: GatewaySession = ctx.lifespan_context
            return types.ListToolsResult(tools=await session.refresh_tools())

        async def on_call_tool(ctx, params: types.CallToolRequestParams) -> types.CallToolResult:
            session: GatewaySession = ctx.lifespan_context
            return await session.call_tool(params.name, dict(params.arguments or {}),
                                           session_id=_http_session_id(ctx),
                                           client=_http_client(ctx))

        return Server(
            "taintward-gateway",
            version="0.1.0",
            instructions="Taintward MCP gateway: tools are proxied with data-exposure policy.",
            lifespan=self._lifespan,
            on_list_tools=on_list_tools,
            on_call_tool=on_call_tool,
        )
