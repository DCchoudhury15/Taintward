"""Structure-aware redaction for LLM request payloads.

``redact_payload`` walks any dict/list/str. An LLM request also carries
protocol fields (roles, ids, tool call ids, base64 image data) that must reach
the provider unchanged or the request breaks. This walker skips those keys and
sends every other string through ``redact_payload``. Detection and redaction
stay in ``taintward.sdk.detect`` / ``taintward.sdk.redact``.
"""

from __future__ import annotations

from typing import Any, Mapping

from taintward.sdk import _walk
from taintward.sdk.destinations import DEST_LOG
from taintward.sdk.redact import redact_payload

# Keys whose values are protocol data, never user content.
STRUCTURAL_KEYS = frozenset({
    "role", "type", "id", "call_id", "tool_call_id", "tool_use_id", "name",
    "model", "signature", "cache_control", "media_type", "data", "file_id",
    "image_url", "input_audio", "file_data", "source", "status", "index",
    "finish_reason", "stop_reason", "response_format", "tool_choice",
    "mime_type", "detail", "format",
})


def to_plain(obj: Any) -> Any:
    """Turn pydantic objects (e.g. a returned ``ChatCompletionMessage`` that the
    caller appended to ``messages``) into dicts so they can be walked."""
    dump = getattr(obj, "model_dump", None)
    if callable(dump) and not isinstance(obj, type):
        try:
            return dump(exclude_none=True)
        except TypeError:
            return dump()
    return obj


def redact_structure(value: Any, destination: str, placeholders=None) -> Any:
    """Redact user content in an LLM payload, leaving protocol fields alone.

    ``placeholders`` (a PlaceholderMap) switches the ``llm`` destination from
    masks to stable placeholders (see ``taintward.sdk.placeholders``)."""
    value = to_plain(value)
    if isinstance(value, str):
        return redact_payload(value, destination, placeholders=placeholders)
    if isinstance(value, Mapping):
        # Keys are data too ({"234-12-1234": ...}); protocol keys are kept.
        return _walk.rebuild_mapping(value, _walk.unique_keys(
            (k,
             k if k in STRUCTURAL_KEYS or not isinstance(k, str)
             else redact_payload(k, destination, placeholders=placeholders),
             v if k in STRUCTURAL_KEYS else redact_structure(v, destination, placeholders))
            for k, v in value.items()))
    if _walk.is_collection(value):
        return _walk.rebuild_collection(
            value, [redact_structure(v, destination, placeholders) for v in value])
    if _walk.is_scalar_leaf(value):
        return value
    # Numbers and other objects: redact_payload checks their str form.
    return redact_payload(value, destination, placeholders=placeholders)


def structure_redactor(placeholders):
    """A ``redact(value, destination)`` callable for GuardedCall that uses the
    placeholder map (or the plain masks when ``placeholders`` is None)."""
    if placeholders is None:
        return redact_structure
    return lambda value, destination: redact_structure(value, destination, placeholders)


def payload_redactor(placeholders):
    """Like ``structure_redactor`` but for tool arguments (``redact_payload``)."""
    if placeholders is None:
        return redact_payload
    return lambda value, destination: redact_payload(value, destination,
                                                     placeholders=placeholders)


def allow_masked_view(allow, placeholders=None):
    """Span ``input_view`` for a tool with an ``allow`` list.

    Allow-listed arguments reach the tool unredacted, but the span is a log
    sink, so the stored copy of those arguments is redacted for ``log``.
    Returns None (the default view) when nothing is allow-listed."""
    if not allow:
        return None

    def view(args, kwargs):
        return {"args": args, "kwargs": {
            k: (redact_payload(v, DEST_LOG, placeholders=placeholders) if k in allow else v)
            for k, v in kwargs.items()}}
    return view


def plain_view(out: Any) -> Any:
    """What to scan and store for a tool output (a message object -> its
    content). Unknown objects become their text so they are masked, never
    stored raw."""
    view = getattr(out, "content", out)
    if view is None or isinstance(view, (str, int, float, bool, dict, list, tuple)):
        return view
    return str(view)
