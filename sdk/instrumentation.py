"""OTel instrumentation for agent tool calls: the runtime taint tracker.

Wraps each tool call in an OTel span using GenAI semantic conventions
(``gen_ai.tool.*``) and propagates the taint label via OTel baggage. This is
AgentRaft's LA-DTP (runtime taint tracking) on OpenTelemetry, with Φ replaced
by structural baggage propagation plus per-I/O detection re-fire (see
docs/agentraft-mapping.md sections D/E).

Per tool call the wrapper:

1. reads the incoming chain-level taint from baggage,
2. detects sensitive data in the tool's *input* (field-level taint),
3. merges input taint with the chain taint and attaches it to the context so
   nested calls inherit it (this is the value-independent propagation that
   survives any LLM transformation),
4. runs the tool,
5. detects sensitive data in the tool's *output* and merges again,
6. materializes the merged taint as span attributes,
7. stores the tool I/O on the span **masked** so SigNoz never stores raw PII,
8. tags the span with its ``destination`` (internal/external/llm/log/rag) and,
   for external/llm sinks, records an SDK-side egress violation when the chain
   is tainted (the Phase 4 redaction gate hardens this from "record" to "block").

Span *links* model fan-out/fan-in (one parent, many children, cross-trace),
used by the RAG tool's retrieval fan-out in the demo. Parent-child links for
linear flows are automatic via OTel context.
"""

from __future__ import annotations

import contextvars
import functools
import inspect
import json
import logging
import threading
from typing import Any, Callable, Iterable, Mapping

from opentelemetry import baggage, context as context_api, trace

from sdk import taint as tnt
from sdk.detect import detect_mapping, mask_value, taint_for
from sdk.redact import redact_payload

logger = logging.getLogger("agentward.sdk")

DEFAULT_OTLP_HTTP = "http://localhost:4318/v1/traces"

# Destination classes, Phase 3's Rego policy reads these.
from sdk.destinations import (  # noqa: E402 - leaf module to avoid circular imports
    DEST_INTERNAL, DEST_EXTERNAL, DEST_LLM, DEST_LOG, DEST_RAG,
)
# Sinks where raw sensitive data must not land. external/llm leave the system;
# log is routinely shipped to centralized/aggregated stores, so it is a leak
# surface too. Phase 3's Rego is the source of truth and can refine this (e.g.
# an internal-only log may redact-not-violate); the SDK gate is the backstop.
_EGRESS_SINKS = {DEST_EXTERNAL, DEST_LLM, DEST_LOG}

# Span attribute keys.
ATTR_DEST = "agentward.destination"
ATTR_JURISDICTION = "agentward.jurisdiction"  # GDPR Art. 44 (us|eu|""...)
ATTR_VIOLATION = "agentward.violation"
ATTR_REDACTED = "agentward.redacted"  # the gate changed the sink's input
ATTR_TaintSource = "agentward.taint.source_span"  # noqa: N816 - keep readable

# When a Phase 3 sidecar collector applies the authoritative Rego redaction,
# set AGENTWARD_MASK_IN_SDK=0 so the SDK sends raw tool I/O to the trusted
# local sidecar (which redacts before SigNoz). Default "1" masks in-process
# (the Phase 2 behavior, for when no sidecar is present).
import os as _os
MASK_IN_PROCESS = _os.environ.get("AGENTWARD_MASK_IN_SDK", "1") != "0"
# DLP simulation mode (Phase 6): log the violation but DON'T redact args, an
# audit/dry-run for safe rollout (see what would be flagged before enforcing).
# When set, raw args flow to the tool and a agentward.dry_run=true attr is set.
DRY_RUN = _os.environ.get("AGENTWARD_DRY_RUN", "") != ""


def configure_tracing(
    service_name: str,
    *,
    endpoint: str = DEFAULT_OTLP_HTTP,
    console: bool = False,
) -> trace.Tracer:
    """Set up the global TracerProvider with an OTLP/HTTP exporter to SigNoz.

    Call once at process start. Returns the tracer to pass to ``instrument_tool``
    (or use ``trace.get_tracer(...)`` elsewhere). ``console=True`` adds a
    console exporter for debugging without SigNoz.
    """
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

    resource = Resource.create({
        "service.name": service_name,
        "service.namespace": "agentward",
    })
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    if console:
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
    trace.set_tracer_provider(provider)
    return provider.get_tracer("agentward")


def _jsonable(obj: Any) -> str:
    """Best-effort JSON serialization for span attributes."""
    try:
        return json.dumps(obj, default=str, ensure_ascii=False)
    except Exception:
        return repr(obj)


class GuardedCall:
    """One call into a sink, run under the egress gate.

    This is the shared core behind ``instrument_tool`` and the framework
    adapters in ``sdk.integrations``. Use it as a context manager::

        with GuardedCall("send_email", destination=DEST_EXTERNAL,
                         kwargs={"to": to, "body": body}) as call:
            result = real_send(*call.args, **call.kwargs)  # redacted args
            call.record_result(result)

    On enter it reads the chain taint, detects sensitive data in the input,
    redacts the input for ``destination`` and opens the span. ``call.args`` /
    ``call.kwargs`` hold the redacted input the sink must receive. On exit it
    sets the egress violation flag, ends the span and carries the outgoing
    taint forward to the next call. It works the same inside ``async`` code.

    ``redact`` replaces ``redact_payload`` when a caller needs a structure-aware
    walk (LLM message lists). ``passthrough`` names keyword args that are an
    explicit, reviewed exception and reach the sink unredacted (they are still
    scanned, so the taint label stays correct). ``attributes`` adds extra span attributes and
    ``input_attr`` / ``output_attr`` name the attributes that store the
    (redacted / masked) input and output.
    """

    def __init__(
        self,
        name: str,
        *,
        destination: str = DEST_INTERNAL,
        jurisdiction: str = "",
        tracer: trace.Tracer | None = None,
        args: tuple | list = (),
        kwargs: Mapping[str, Any] | None = None,
        links: list | None = None,
        attributes: Mapping[str, Any] | None = None,
        input_attr: str = "gen_ai.tool.call.arguments",
        output_attr: str = "gen_ai.tool.call.result",
        input_view: Callable[[list, dict], Any] | None = None,
        redact: Callable[[Any, str], Any] | None = None,
        kind: trace.SpanKind = trace.SpanKind.INTERNAL,
        passthrough: Iterable[str] = (),
    ) -> None:
        self.name = name
        self.destination = destination
        self.jurisdiction = jurisdiction
        self._tracer = tracer
        self._raw_args = list(args)
        self._raw_kwargs = dict(kwargs or {})
        self._link_ctxs = links or []
        self._attributes = dict(attributes or {})
        self._input_attr = input_attr
        self._output_attr = output_attr
        self._input_view = input_view
        self._redact = redact or redact_payload
        self._kind = kind
        self._passthrough = frozenset(passthrough)
        self.args: list = []
        self.kwargs: dict = {}
        self.span = None
        self.merged_in: tnt.TaintLabel | None = None
        self.merged_out: tnt.TaintLabel | None = None
        self._cm = None

    # -- enter: detect, redact, open span ----------------------------------
    def __enter__(self) -> "GuardedCall":
        links = []
        for sc in self._link_ctxs:
            try:
                links.append(trace.Link(sc))
            except Exception:
                pass

        tr = self._tracer or trace.get_tracer("agentward")
        incoming = _incoming_taint()  # chain-level taint (baggage + run box)

        # Field-level taint on the input, computed from the ORIGINAL input so
        # the label reflects what was actually requested.
        payload = [*self._raw_args, *self._raw_kwargs.values()]
        in_detections = detect_mapping(payload) if payload else []
        input_label = taint_for(in_detections)

        # Phase 4 egress gate: redact the ACTUAL input for this destination
        # BEFORE the call. internal -> reversible token; external/llm/log/rag
        # -> non-reversible mask. DLP simulation mode (DRY_RUN) skips it.
        if DRY_RUN:
            self.args, self.kwargs = list(self._raw_args), dict(self._raw_kwargs)
        else:
            self.args = [self._redact(a, self.destination) for a in self._raw_args]
            self.kwargs = {
                k: (v if k in self._passthrough else self._redact(v, self.destination))
                for k, v in self._raw_kwargs.items()
            }

        merged_in = (incoming or tnt.TaintLabel.of(set())).merge(input_label)
        self.merged_in = merged_in
        ctx = tnt.attach(merged_in)  # nested calls inherit the taint

        view = (self._input_view(self.args, self.kwargs) if self._input_view
                else {"args": self.args, "kwargs": self.kwargs})
        attrs = dict(self._attributes)
        attrs[self._input_attr] = _jsonable(view)  # already redacted
        self._cm = tr.start_as_current_span(
            self.name, kind=self._kind, context=ctx, links=links, attributes=attrs,
        )
        span = self._cm.__enter__()
        self.span = span
        if merged_in.is_tainted:
            span.set_attributes(merged_in.to_span_attrs())
            span.set_attribute(ATTR_TaintSource, merged_in.source_span_id or "")
        else:
            span.set_attributes(merged_in.to_span_attrs())
        span.set_attribute(ATTR_DEST, self.destination)
        span.set_attribute(ATTR_JURISDICTION, self.jurisdiction)
        # True when the gate changed what the sink receives.
        try:
            changed = bool(self.args != self._raw_args or self.kwargs != self._raw_kwargs)
        except Exception:
            changed = True
        span.set_attribute(ATTR_REDACTED, changed)
        if DRY_RUN:
            span.set_attribute("agentward.dry_run", True)
        return self

    # -- output ------------------------------------------------------------
    def record_result(self, result: Any, *, view: Any = None) -> None:
        """Detect taint in the sink's output and store it masked on the span.

        ``view`` is what gets scanned and stored when the raw result is not a
        plain value (for example a framework message object).
        """
        seen = result if view is None else view
        out_detections = detect_mapping([seen])
        output_label = taint_for(
            out_detections,
            source_span_id=format(self.span.get_span_context().span_id, "016x"),
        )
        self.merged_out = self.merged_in.merge(output_label)
        if self.merged_out.is_tainted:
            self.span.set_attributes(self.merged_out.to_span_attrs())
        stored = mask_value(seen) if MASK_IN_PROCESS else seen
        self.span.set_attribute(self._output_attr, _jsonable(stored))

    # -- exit: violation flag, end span, carry taint forward ---------------
    def __exit__(self, exc_type, exc, tb) -> bool:
        span = self.span
        if exc is not None:
            if isinstance(exc, Exception):
                span.record_exception(exc)
                span.set_attribute("agentward.tool.error", str(exc))
        else:
            final = self.merged_out or self.merged_in
            # SDK-side egress gate: the input was already redacted; this flag
            # records that a tainted chain reached an egress sink, the same
            # policy decision the collector also makes.
            if self.destination in _EGRESS_SINKS and final.is_tainted:
                span.set_attribute(ATTR_VIOLATION, True)
                span.set_attribute(
                    "agentward.violation.reason",
                    f"tainted chain reached {self.destination} sink",
                )
        self._cm.__exit__(exc_type, exc, tb)

        # Outside the span: carry the outgoing chain taint to the *next*
        # sibling call (value-independent propagation, survives any LLM
        # transformation). Tokens are tracked so end_run() can reset.
        if exc is None:
            final = self.merged_out or self.merged_in
            if final.is_tainted:
                _attach_outgoing(final)
        return False


def instrument_tool(
    name: str | None = None,
    *,
    destination: str = DEST_INTERNAL,
    jurisdiction: str = "",
    tracer: trace.Tracer | None = None,
):
    """Decorator that wraps a tool function with taint-aware OTel tracing.

    The wrapped function's positional/keyword args are treated as the tool's
    input payload; the return value as the output. The caller may pass an
    extra ``agentward_links=[span_context, ...]`` kwarg to add span links
    for fan-out/fan-in (consumed, not forwarded to the tool). ``async def``
    tools are supported: the span then covers the awaited call.
    """
    def decorator(fn: Callable) -> Callable:
        span_name = name or fn.__name__
        attrs = {"gen_ai.tool.name": span_name}

        def _call(args, kwargs) -> GuardedCall:
            # Pop our private link contexts (for fan-out/fan-in) before calling.
            link_ctxs = kwargs.pop("agentward_links", None) or []
            return GuardedCall(
                span_name, destination=destination, jurisdiction=jurisdiction,
                tracer=tracer, args=args, kwargs=kwargs, links=link_ctxs,
                attributes=attrs,
            )

        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*args, **kwargs):
                with _call(args, kwargs) as call:
                    result = await fn(*call.args, **call.kwargs)
                    call.record_result(result)
                return result
            return async_wrapper

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            with _call(args, kwargs) as call:
                result = fn(*call.args, **call.kwargs)
                call.record_result(result)
            return result

        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Run scoping: one trace per run, clean taint slate per run
# ---------------------------------------------------------------------------

# Per-thread bookkeeping, NOT plain module-level lists. A context_api.attach
# token can only be detached on the same OS thread that created it (it's tied
# to that thread's own contextvars Context); with shared globals, concurrent
# begin_run()/end_run() calls on different threads clobbered each other's
# lists, dropping most root spans and raising "Failed to detach context ...
# was created in a different Context". threading.local() gives every thread
# its own attach_tokens/root_spans so concurrent runs no longer collide.
_run_state = threading.local()


class _RunTaint:
    """Mutable taint holder shared by every call inside one run.

    Agent frameworks often run a tool inside a *copied* context (LangChain
    runs ``_run`` via ``Context.run``, LangGraph uses a thread pool, asyncio
    runs each task in its own copy). Taint attached to the ambient context in
    such a copy is lost when the copy ends, so the next tool would not see it.
    A copied context still points at the same object stored in a context
    variable, so a run-scoped box keeps the chain taint visible across all of
    those copies. It only ever grows within a run (safe over-approximation)
    and is replaced on the next ``begin_run``.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.label: tnt.TaintLabel | None = None

    def merge(self, label: tnt.TaintLabel) -> None:
        with self._lock:
            self.label = label if self.label is None else self.label.merge(label)


_RUN_TAINT: contextvars.ContextVar[_RunTaint | None] = contextvars.ContextVar(
    "agentward_run_taint", default=None
)


def _run_lists() -> tuple[list, list]:
    if not hasattr(_run_state, "attach_tokens"):
        _run_state.attach_tokens = []
        _run_state.root_spans = []
        _run_state.box_tokens = []
    return _run_state.attach_tokens, _run_state.root_spans


def begin_run(name: str = "agent.run", *, tracer: trace.Tracer | None = None) -> object:
    """Start a run: attach a root span as current so every tool span in the
    run shares one trace, and reset the taint slate. Pair with ``end_run()``.
    ``tracer`` defaults to the global ``agentward`` tracer.
    """
    attach_tokens, root_spans = _run_lists()
    attach_tokens.clear()
    root_spans.clear()
    _run_state.box_tokens.clear()
    tr = tracer or trace.get_tracer("agentward")
    root = tr.start_span(name, kind=trace.SpanKind.INTERNAL)
    root_spans.append(root)
    # Drop taint baggage left on the ambient context by calls made outside a
    # run, so the new run really starts clean.
    base = context_api.get_current()
    for key in (tnt.KEY_ID, tnt.KEY_CLASSES, tnt.KEY_LEVEL):
        base = baggage.remove_baggage(key, context=base)
    tok = context_api.attach(trace.set_span_in_context(root, context=base))
    attach_tokens.append(tok)
    _run_state.box_tokens.append(_RUN_TAINT.set(_RunTaint()))
    return root


def end_run() -> None:
    """End a run: detach all frames added during the run (clearing taint) and
    end the root span(s)."""
    attach_tokens, root_spans = _run_lists()
    for tok in reversed(attach_tokens):
        try:
            context_api.detach(tok)
        except Exception:
            pass
    attach_tokens.clear()
    for tok in reversed(_run_state.box_tokens):
        try:
            _RUN_TAINT.reset(tok)
        except Exception:
            _RUN_TAINT.set(None)
    _run_state.box_tokens.clear()
    for root in root_spans:
        try:
            root.end()
        except Exception:
            pass
    root_spans.clear()


def _incoming_taint() -> tnt.TaintLabel | None:
    """Chain taint seen by the next call: ambient baggage plus the run box."""
    label = tnt.current()
    box = _RUN_TAINT.get()
    if box is not None and box.label is not None:
        label = box.label if label is None else label.merge(box.label)
    return label


def _attach_outgoing(label: tnt.TaintLabel) -> None:
    """Attach an outgoing taint label to the ambient context (frame leaks
    forward within the run by design); record the token for ``end_run``.

    Inside a run (``begin_run``) the label goes into the run box instead:
    every later call reads the box, in this context or in a framework's copied
    one, and puts the label back into baggage on its own span. Skipping the
    ambient attach there also avoids tokens that were attached in a copied
    context and can never be detached from ``end_run``."""
    box = _RUN_TAINT.get()
    if box is not None:
        box.merge(label)
        return
    attach_tokens, _ = _run_lists()
    ctx = tnt.attach(label)  # base = current ambient; adds baggage
    tok = context_api.attach(ctx)
    attach_tokens.append(tok)


def current_taint() -> tnt.TaintLabel | None:
    """Convenience: the taint label on the current OTel context (including
    taint recorded earlier in the current run)."""
    return _incoming_taint()
