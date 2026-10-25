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
import traceback
from typing import Any, Callable, Iterable, Mapping

from opentelemetry import baggage, trace
from opentelemetry import context as context_api
from opentelemetry.trace import Status, StatusCode

from taintward.sdk import detect as _detect
from taintward.sdk import taint as tnt
from taintward.sdk.detect import detect_mapping, detection_scope, mask_value, taint_for
from taintward.sdk.envflags import env_flag
from taintward.sdk.redact import redact_payload

logger = logging.getLogger("taintward.sdk")

DEFAULT_OTLP_HTTP = "http://localhost:4318/v1/traces"

# Destination classes, Phase 3's Rego policy reads these.
from taintward.sdk.destinations import (  # noqa: E402, F401 - re-exported; leaf module to avoid circular imports
    DEST_EXTERNAL,
    DEST_INTERNAL,
    DEST_LLM,
    DEST_LOG,
    DEST_RAG,
)

# Sinks where raw sensitive data must not land. external/llm leave the system;
# log is routinely shipped to centralized/aggregated stores, so it is a leak
# surface too. Phase 3's Rego is the source of truth and can refine this (e.g.
# an internal-only log may redact-not-violate); the SDK gate is the backstop.
_EGRESS_SINKS = {DEST_EXTERNAL, DEST_LLM, DEST_LOG}

# Span attribute keys.
ATTR_DEST = "taintward.destination"
ATTR_JURISDICTION = "taintward.jurisdiction"  # GDPR Art. 44 (us|eu|""...)
ATTR_VIOLATION = "taintward.violation"
ATTR_REDACTED = "taintward.redacted"  # the gate changed the sink's input
# The stored tool arguments are already redacted, so the collector keeps
# them as they are (including reversible tokens) instead of masking them.
ATTR_ARGS_REDACTED = "taintward.args_redacted"
ATTR_TaintSource = "taintward.taint.source_span"  # noqa: N816 - keep readable
ATTR_TOOL_ERROR = "taintward.tool.error"

_TOOL_ARGS_ATTR = "gen_ai.tool.call.arguments"

# When a Phase 3 sidecar collector applies the authoritative Rego redaction,
# set TAINTWARD_MASK_IN_SDK=0 so the SDK sends raw tool I/O to the trusted
# local sidecar (which redacts before SigNoz). Default "1" masks in-process
# (the Phase 2 behavior, for when no sidecar is present).
MASK_IN_PROCESS = env_flag("TAINTWARD_MASK_IN_SDK", True)
# DLP simulation mode (Phase 6): log the violation but DON'T redact args, an
# audit/dry-run for safe rollout (see what would be flagged before enforcing).
# When set, raw args flow to the tool and a taintward.dry_run=true attr is set.
DRY_RUN = env_flag("TAINTWARD_DRY_RUN", False)
# Refuse calls to non-internal sinks while detection is degraded (spaCy or
# Presidio failed to load, see taintward.sdk.detect.health). Off by default: degraded
# detection still finds SSNs, cards, emails and secrets with regexes.
FAIL_CLOSED = env_flag("TAINTWARD_FAIL_CLOSED", False)


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
        "service.namespace": "taintward",
    })
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    if console:
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
    trace.set_tracer_provider(provider)
    return provider.get_tracer("taintward")


def _mask_str(text: str | None) -> str:
    if text is None:
        return "[REDACTED]"  # cannot be checked, so it cannot be stored
    return _detect.mask_text(text, _detect.detect_text(text))


def _json_default(obj: Any) -> str:
    # An object json cannot serialize is stored as its masked str form, so
    # an SSN inside its __str__ never reaches a span raw.
    return _mask_str(_detect.safe_str(obj))


def _jsonable(obj: Any) -> str:
    """Best-effort JSON serialization for span attributes."""
    try:
        return json.dumps(obj, default=_json_default, ensure_ascii=False)
    except Exception:
        return _mask_str(_detect.safe_str(obj))


# The GuardedCall whose sink is running right now. A call made inside it
# (a tool that calls another wrapped tool) hands its taint to this parent,
# so the parent's own result and the calls after it see that taint even
# when the parent returns a clean summary.
_CURRENT_CALL: contextvars.ContextVar["GuardedCall | None"] = contextvars.ContextVar(
    "taintward_current_call", default=None)


class GuardedCall:
    """One call into a sink, run under the egress gate.

    This is the shared core behind ``instrument_tool`` and the framework
    adapters in ``taintward.sdk.integrations``. Use it as a context manager::

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
        self._parent: GuardedCall | None = None
        self._call_token = None
        self._nested: tnt.TaintLabel | None = None
        self._nested_lock = threading.Lock()

    def absorb(self, label: tnt.TaintLabel) -> None:
        """Take the taint of a call that ran inside this one."""
        if not label.is_tainted:
            return
        with self._nested_lock:
            self._nested = label if self._nested is None else self._nested.merge(label)

    # -- enter: detect, redact, open span ----------------------------------
    def __enter__(self) -> "GuardedCall":
        if FAIL_CLOSED and self.destination != DEST_INTERNAL and _detect.is_degraded():
            raise _detect.DetectionDegradedError(
                f"taintward: refusing {self.name!r} ({self.destination} sink): "
                f"sensitive-data detection is degraded ({_detect.health()['mode']}) "
                "and TAINTWARD_FAIL_CLOSED is on")

        links = []
        for sc in self._link_ctxs:
            try:
                links.append(trace.Link(sc))
            except Exception:
                pass

        tr = self._tracer or trace.get_tracer("taintward")
        incoming = _incoming_taint()  # chain-level taint (baggage + run box)

        # Field-level taint on the input, computed from the ORIGINAL input so
        # the label reflects what was actually requested. Keyword names are
        # kept so they count as context (a kwarg ``ssn="536228491"``).
        #
        # One detection_scope covers detection and redaction: every value is
        # detected once here and the redactor's own lookups reuse the result
        # (including hits that only fired because of the key).
        with detection_scope():
            if self._raw_args or self._raw_kwargs:
                in_detections = detect_mapping([self._raw_args, self._raw_kwargs])
            else:
                in_detections = []
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

            if self._input_view:
                view = self._input_view(self.args, self.kwargs)
            else:
                # The span is a log sink: passthrough values reach the sink
                # as they are, but the stored copy is redacted for ``log``.
                view = {"args": self.args, "kwargs": {
                    k: (redact_payload(v, DEST_LOG) if k in self._passthrough else v)
                    for k, v in self.kwargs.items()}}
            if DRY_RUN and MASK_IN_PROCESS:
                view = mask_value(view)  # the sink gets raw values, the span never

        merged_in = (incoming or tnt.TaintLabel.of(set())).merge(input_label)
        self.merged_in = merged_in
        ctx = tnt.attach(merged_in)  # nested calls inherit the taint

        attrs = dict(self._attributes)
        attrs[self._input_attr] = _jsonable(view)
        # Tell the collector the stored arguments are already redacted. Not
        # set in dry run or when a sidecar collector does the masking.
        if self._input_attr == _TOOL_ARGS_ATTR and not DRY_RUN and MASK_IN_PROCESS:
            attrs[ATTR_ARGS_REDACTED] = True
        # Exceptions are recorded by __exit__ with the message masked.
        self._cm = tr.start_as_current_span(
            self.name, kind=self._kind, context=ctx, links=links, attributes=attrs,
            record_exception=False, set_status_on_exception=False,
        )
        span = self._cm.__enter__()
        self.span = span
        span.set_attributes(merged_in.to_span_attrs())
        if merged_in.source_span_id:
            span.set_attribute(ATTR_TaintSource, merged_in.source_span_id)
        span.set_attribute(ATTR_DEST, self.destination)
        span.set_attribute(ATTR_JURISDICTION, self.jurisdiction)
        # True when the gate changed what the sink receives.
        try:
            changed = bool(self.args != self._raw_args or self.kwargs != self._raw_kwargs)
        except Exception:
            changed = True
        span.set_attribute(ATTR_REDACTED, changed)
        if DRY_RUN:
            span.set_attribute("taintward.dry_run", True)
        self._parent = _CURRENT_CALL.get()
        self._call_token = _CURRENT_CALL.set(self)
        return self

    # -- output ------------------------------------------------------------
    def record_result(self, result: Any, *, view: Any = None) -> None:
        """Detect taint in the sink's output and store it masked on the span.

        ``view`` is what gets scanned and stored when the raw result is not a
        plain value (for example a framework message object).
        """
        seen = result if view is None else view
        # Detect once; masking below reuses the result inside the scope.
        with detection_scope():
            out_detections = detect_mapping([seen])
            output_label = taint_for(
                out_detections,
                source_span_id=format(self.span.get_span_context().span_id, "016x"),
            )
            stored = mask_value(seen) if MASK_IN_PROCESS else seen
        self.merged_out = self.merged_in.merge(output_label)
        self.span.set_attribute(self._output_attr, _jsonable(stored))

    # -- exit: violation flag, end span, carry taint forward ---------------
    def __exit__(self, exc_type, exc, tb) -> bool:
        span = self.span
        if self._call_token is not None:
            try:
                _CURRENT_CALL.reset(self._call_token)
            except ValueError:  # exited in another context
                _CURRENT_CALL.set(self._parent)
            self._call_token = None
        final = (self.merged_out or self.merged_in).merge(self._nested)
        try:
            if final.is_tainted:
                span.set_attributes(final.to_span_attrs())
                if final.source_span_id:
                    span.set_attribute(ATTR_TaintSource, final.source_span_id)
            # SDK-side egress gate: the input was already redacted; this flag
            # records that a tainted chain reached an egress sink, the same
            # policy decision the collector also makes. It is set even when
            # the sink raised: the input still went to it.
            if self.destination in _EGRESS_SINKS and final.is_tainted:
                span.set_attribute(ATTR_VIOLATION, True)
                span.set_attribute(
                    "taintward.violation.reason",
                    f"tainted chain reached {self.destination} sink",
                )
            if exc is not None:
                record_masked_exception(span, exc)
        finally:
            self._cm.__exit__(exc_type, exc, tb)

        # Outside the span: carry the outgoing chain taint to the *next*
        # call (value-independent propagation, survives any LLM
        # transformation). A call nested inside another wrapped call hands
        # it to that call instead. A sink that raised may still have seen
        # sensitive data, so its taint is carried forward too.
        if final.is_tainted:
            if self._parent is not None:
                self._parent.absorb(final)
            else:
                _attach_outgoing(final)
        return False


def record_masked_exception(span, exc: BaseException) -> None:
    """Record an exception on the span with sensitive data masked in its
    message and stack trace (the message often echoes the input)."""
    message = _mask_str(_detect.safe_str(exc))
    stack = _mask_str("".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))
    span.add_event("exception", {
        "exception.type": type(exc).__qualname__,
        "exception.message": message,
        "exception.stacktrace": stack,
        "exception.escaped": True,
    })
    span.set_attribute(ATTR_TOOL_ERROR, message)
    span.set_status(Status(StatusCode.ERROR, f"{type(exc).__name__}: {message}"))


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
    extra ``taintward_links=[span_context, ...]`` kwarg to add span links
    for fan-out/fan-in (consumed, not forwarded to the tool). ``async def``
    tools are supported: the span then covers the awaited call.
    """
    def decorator(fn: Callable) -> Callable:
        span_name = name or fn.__name__
        attrs = {"gen_ai.tool.name": span_name}

        def _call(args, kwargs) -> GuardedCall:
            # Pop our private link contexts (for fan-out/fan-in) before calling.
            link_ctxs = kwargs.pop("taintward_links", None) or []
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
    "taintward_run_taint", default=None
)


class _RunFrame:
    """What ``begin_run`` changed, so ``end_run`` can undo exactly that."""

    __slots__ = ("root", "otel_token", "box_token", "stack_token")

    def __init__(self, root, otel_token, box_token) -> None:
        self.root = root
        self.otel_token = otel_token
        self.box_token = box_token
        self.stack_token = None


# All run state lives in context variables, not in threading.local: asyncio
# tasks share one thread but each has its own context, so concurrent runs in
# tasks (or threads) never see each other's frames, and a nested begin_run
# keeps the outer run.
_RUNS: contextvars.ContextVar[tuple[_RunFrame, ...]] = contextvars.ContextVar(
    "taintward_runs", default=())

# Chain taint left by calls made outside any run. Kept in a context variable
# instead of attaching baggage, so there is no context token that could be
# detached in the wrong context. Every call reads it (``_incoming_taint``)
# and puts it into baggage on its own span.
_LOOSE_TAINT: contextvars.ContextVar[tnt.TaintLabel | None] = contextvars.ContextVar(
    "taintward_loose_taint", default=None)


def begin_run(name: str = "agent.run", *, tracer: trace.Tracer | None = None) -> object:
    """Start a run: attach a root span as current so every tool span in the
    run shares one trace, and reset the taint slate. Pair with ``end_run()``.
    ``tracer`` defaults to the global ``taintward`` tracer.

    Runs nest: ``end_run`` ends the innermost run and the outer one goes on.
    """
    tr = tracer or trace.get_tracer("taintward")
    # Drop taint baggage left on the ambient context, so the new run really
    # starts clean.
    base = context_api.get_current()
    for key in tnt.BAGGAGE_KEYS:
        base = baggage.remove_baggage(key, context=base)
    root = tr.start_span(name, kind=trace.SpanKind.INTERNAL, context=base)
    otel_token = context_api.attach(trace.set_span_in_context(root, context=base))
    frame = _RunFrame(root, otel_token, _RUN_TAINT.set(_RunTaint()))
    frame.stack_token = _RUNS.set(_RUNS.get() + (frame,))
    return root


def end_run() -> None:
    """End the innermost run: restore the context from before its
    ``begin_run`` (clearing its taint) and end its root span. With no run
    active it clears the taint left by calls made outside a run."""
    frames = _RUNS.get()
    if not frames:
        _LOOSE_TAINT.set(None)
        return
    frame = frames[-1]
    try:
        _RUNS.reset(frame.stack_token)
    except ValueError:  # ended in another context
        _RUNS.set(frames[:-1])
    try:
        _RUN_TAINT.reset(frame.box_token)
    except ValueError:
        _RUN_TAINT.set(None)
    try:
        context_api.detach(frame.otel_token)
    except Exception:
        pass
    try:
        frame.root.end()
    except Exception:
        pass


def _incoming_taint() -> tnt.TaintLabel | None:
    """Chain taint seen by the next call: ambient baggage, the run box (or
    the taint left outside a run) and what earlier calls nested in the
    enclosing calls found."""
    label = tnt.current()
    box = _RUN_TAINT.get()
    extra = [box.label if box is not None else _LOOSE_TAINT.get()]
    call = _CURRENT_CALL.get()
    while call is not None:
        extra.append(call._nested)
        call = call._parent
    for x in extra:
        if x is not None:
            label = x if label is None else label.merge(x)
    return label


def _attach_outgoing(label: tnt.TaintLabel) -> None:
    """Carry an outgoing taint label forward to the next call.

    Inside a run (``begin_run``) the label goes into the run box: every later
    call reads the box, in this context or in a framework's copied one.
    Outside a run it goes into a context variable read the same way."""
    box = _RUN_TAINT.get()
    if box is not None:
        box.merge(label)
        return
    prev = _LOOSE_TAINT.get()
    _LOOSE_TAINT.set(label if prev is None else prev.merge(label))


def current_taint() -> tnt.TaintLabel | None:
    """Convenience: the taint label on the current OTel context (including
    taint recorded earlier in the current run)."""
    return _incoming_taint()
