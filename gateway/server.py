"""The AgentWard MCP gateway: a proxy MCP server that enforces AgentWard
policy on every ``tools/call`` between an MCP client and upstream servers.

Per ``tools/call`` the gateway:

1. resolves the tool's policy (destination, jurisdiction, mode) from config,
2. detects sensitive data in the arguments (``sdk.detect``),
3. merges that with the session taint (once any earlier argument or result
   in this session was sensitive, every later call is tainted; this is the
   session-level analogue of the SDK's baggage chain taint). The taint is
   kept in a session store (``gateway.session_store``) keyed by the MCP
   session id, so several replicas can share it,
4. evaluates the policy (``gateway.policy``, the Rego rules in Python),
5. mode ``block`` with a violation: returns an MCP error, nothing is sent
   upstream; mode ``redact`` / ``block``: redacts the arguments for the
   tool's destination (``sdk.redact.redact_payload``); mode ``audit``: passes
   the raw arguments through and only records the violation,
6. forwards the call upstream with the chain taint in OTel baggage,
7. scans the result, merges its taint into the session, and masks
   sensitive values in the result before the agent sees it,
8. emits one OTel span with the same attribute names the SDK uses.
"""

from __future__ import annotations

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

from gateway.config import (
    MODE_AUDIT,
    MODE_BLOCK,
    GatewayConfig,
    ToolPolicy,
    UpstreamConfig,
)
from gateway.policy import PolicyInput, evaluate
from gateway.session_store import (
    SessionStore,
    SessionStoreError,
    make_session_store,
    new_session_id,
)
from sdk import taint as tnt
from sdk.destinations import DEST_LLM
from sdk.detect import detect_mapping, detect_text, mask_value, taint_for
from sdk.instrumentation import ATTR_DEST, ATTR_JURISDICTION, ATTR_VIOLATION
from sdk.redact import redact_payload

logger = logging.getLogger("agentward.gateway")

# JSON-RPC error code returned when a call is blocked (implementation-defined
# server error range -32000..-32099).
BLOCKED_ERROR_CODE = -32001

# HTTP header that carries the MCP session id (lower case, as in ASGI).
MCP_SESSION_HEADER = "mcp-session-id"

# Span attribute keys. The ones shared with the SDK are imported above; these
# are gateway specific.
ATTR_TOOL_NAME = "gen_ai.tool.name"
ATTR_TOOL_ARGS = "gen_ai.tool.call.arguments"
ATTR_TOOL_RESULT = "gen_ai.tool.call.result"
ATTR_OPERATION = "gen_ai.operation.name"
ATTR_MCP_METHOD = "mcp.method.name"
ATTR_VIOLATION_REASON = "agentward.violation.reason"
ATTR_RULES = "agentward.policy.rules"
ATTR_MODE = "agentward.mode"
ATTR_BLOCKED = "agentward.blocked"
ATTR_DRY_RUN = "agentward.dry_run"
ATTR_ARGS_REDACTED = "agentward.args.redacted"
ATTR_RESULT_REDACTED = "agentward.result.redacted"
ATTR_UPSTREAM = "agentward.gateway.upstream"
ATTR_TOOL_ERROR = "agentward.tool.error"


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

    async def taint(self, session_id: str | None = None) -> tnt.TaintLabel:
        """The current taint of a session (the default one when None)."""
        return await self.gateway.store.get(session_id or self.default_session_id)

    async def _merge_taint(self, sid: str, label: tnt.TaintLabel) -> tnt.TaintLabel:
        try:
            return await self.gateway.store.merge(sid, label)
        except SessionStoreError as exc:
            # Fail closed: without the session taint the policy cannot decide.
            logger.error("session store error: %s", exc)
            raise MCPError(types.INTERNAL_ERROR,
                           "AgentWard gateway: session store unavailable, call refused") from None

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
        await self.refresh_tools()

    async def refresh_tools(self) -> list[types.Tool]:
        """List every upstream's tools and rebuild the routing table. On a
        name clash the first upstream in config order wins."""
        exposed: list[types.Tool] = []
        routes: dict[str, _Route] = {}
        for u in self.gateway.config.upstreams:
            client = self.clients[u.name]
            cursor: str | None = None
            while True:
                page = await client.list_tools(cursor=cursor)
                for tool in page.tools:
                    name = u.prefix + tool.name
                    if name in routes:
                        logger.warning("tool %r from upstream %r hidden by upstream %r",
                                       name, u.name, routes[name].upstream)
                        continue
                    routes[name] = _Route(upstream=u.name, client=client, tool_name=tool.name)
                    exposed.append(tool if name == tool.name
                                   else tool.model_copy(update={"name": name}))
                cursor = page.next_cursor
                if not cursor:
                    break
        self.routes = routes
        return exposed

    # --- tools/call ---

    async def call_tool(self, name: str, arguments: dict[str, Any],
                        session_id: str | None = None) -> types.CallToolResult:
        gw = self.gateway
        if session_id is None:
            if gw.require_session_id:
                raise MCPError(types.INVALID_REQUEST, "missing Mcp-Session-Id")
            session_id = self.default_session_id
        route = self.routes.get(name)
        if route is None:
            await self.refresh_tools()
            route = self.routes.get(name)
        if route is None:
            raise MCPError(types.INVALID_PARAMS, f"Unknown tool: {name}")

        policy: ToolPolicy = gw.config.policy_for(name, route.upstream)

        # Arguments listed in passthrough_args skip scanning and redaction.
        passthrough = {k: v for k, v in arguments.items() if k in policy.passthrough_args}
        scanned = {k: v for k, v in arguments.items() if k not in policy.passthrough_args}

        # Field-level taint on the arguments, merged with the session taint.
        in_dets = await anyio.to_thread.run_sync(detect_mapping, scanned)
        args_label = taint_for(in_dets)
        # The agent's context now holds whatever it sent, so the session
        # keeps it. The store merge is atomic and returns the whole session
        # taint, including classes other replicas added.
        merged_in = await self._merge_taint(session_id, args_label)

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

        # Chain taint rides to the upstream as OTel baggage (the mcp SDK
        # injects the current context into the request _meta).
        ctx = tnt.attach(merged_in) if merged_in.is_tainted else context_api.get_current()
        token = context_api.attach(ctx)
        try:
            with gw.tracer.start_as_current_span(
                f"agentward.gateway {name}",
                kind=trace.SpanKind.INTERNAL,
                attributes={
                    ATTR_TOOL_NAME: name,
                    ATTR_OPERATION: "execute_tool",
                    ATTR_MCP_METHOD: "tools/call",
                    ATTR_UPSTREAM: route.upstream,
                    ATTR_MODE: policy.mode,
                    ATTR_DEST: policy.destination,
                    ATTR_JURISDICTION: policy.jurisdiction,
                    ATTR_TOOL_ARGS: _jsonable(stored_args),
                    ATTR_ARGS_REDACTED: args_redacted,
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
                        f"AgentWard blocked tools/call {name}: {reason} "
                        f"(destination={policy.destination})",
                        data={"tool": name, "destination": policy.destination,
                              "violations": pre.violations},
                    )

                try:
                    result = await route.client.call_tool(route.tool_name, forwarded)
                except Exception as exc:
                    span.record_exception(exc)
                    span.set_attribute(ATTR_TOOL_ERROR, str(exc))
                    raise

                payload = _result_payload(result)
                out_dets = await anyio.to_thread.run_sync(detect_mapping, payload)
                out_label = taint_for(
                    out_dets,
                    source_span_id=format(span.get_span_context().span_id, "016x"),
                )
                stored = await self._merge_taint(session_id, out_label)
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


class Gateway:
    """Build a proxy MCP :class:`~mcp.server.Server` for a config.

    ``tracer`` defaults to the global ``agentward.gateway`` tracer. Over
    stdio each client connection gets its own :class:`GatewaySession` (own
    upstream connections). Session taint lives in ``session_store``
    (default: built from ``config.session_store``, or the
    ``AGENTWARD_SESSION_STORE`` env var when set).
    """

    def __init__(self, config: GatewayConfig, tracer: trace.Tracer | None = None,
                 *, warm_detector: bool = True, session_store: SessionStore | None = None,
                 require_session_id: bool = False):
        self.config = config
        self.tracer = tracer or trace.get_tracer("agentward.gateway")
        self.warm_detector = warm_detector
        if session_store is None:
            spec = os.environ.get("AGENTWARD_SESSION_STORE") or config.session_store
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

    def build_server(self) -> Server:
        async def on_list_tools(ctx, params) -> types.ListToolsResult:
            session: GatewaySession = ctx.lifespan_context
            return types.ListToolsResult(tools=await session.refresh_tools())

        async def on_call_tool(ctx, params: types.CallToolRequestParams) -> types.CallToolResult:
            session: GatewaySession = ctx.lifespan_context
            return await session.call_tool(params.name, dict(params.arguments or {}),
                                           session_id=_http_session_id(ctx))

        return Server(
            "agentward-gateway",
            version="0.1.0",
            instructions="AgentWard MCP gateway: tools are proxied with data-exposure policy.",
            lifespan=self._lifespan,
            on_list_tools=on_list_tools,
            on_call_tool=on_call_tool,
        )
