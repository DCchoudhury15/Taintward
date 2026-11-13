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

# Protocol keys. Their value is protocol data when it is a plain value
# ("role": "user", "id": "call_1", "data": "<base64>"), never user content.
LEAF_KEYS = frozenset({
    "role", "type", "id", "call_id", "tool_call_id", "tool_use_id", "name",
    "model", "signature", "media_type", "data", "file_id", "status", "index",
    "finish_reason", "stop_reason", "mime_type", "detail", "format",
})
# Protocol keys whose whole value is kept, also when it is a dict or a list.
OPAQUE_KEYS = frozenset({
    "cache_control", "image_url", "input_audio", "file_data", "response_format",
    "tool_choice",
})
# Keys that hold free data when their value is a dict: the arguments of an
# earlier tool call and structured tool results. Inside them every key is
# the application's own ("name", "id", "data" are fields of a customer
# record there, not protocol), so nothing in them is skipped.
FREE_KEYS = frozenset({
    "input", "args", "arguments", "response", "output", "result", "parsed",
    "content", "artifact", "structured_content", "structuredContent",
    # request fields that are the application's own data: the variables of a
    # stored prompt and the metadata kept with a request
    "variables", "metadata",
})
# Every key that is kept as it is (not redacted as data).
STRUCTURAL_KEYS = LEAF_KEYS | OPAQUE_KEYS | {"source"}


def to_plain(obj: Any) -> Any:
    """Turn pydantic objects (e.g. a returned ``ChatCompletionMessage`` that the
    caller appended to ``messages``) into dicts so they can be walked."""
    dump = getattr(obj, "model_dump", None)
    if callable(dump) and not isinstance(obj, type):
        # warnings=False: a parse() answer types ``parsed`` as None in its
        # schema and pydantic would warn on every call.
        for kw in ({"exclude_none": True, "warnings": False}, {"exclude_none": True}, {}):
            try:
                return dump(**kw)
            except TypeError:
                continue
    return obj


def _redact_source(value: Any, destination: str, placeholders) -> Any:
    """An Anthropic image or document ``source``. ``url``, ``file_id`` and
    base64 ``data`` are kept; the text of a plain text document and the
    blocks of a ``content`` document are user content."""
    value = to_plain(value)
    if not isinstance(value, Mapping):
        return redact_structure(value, destination, placeholders)
    text = value.get("type") == "text"
    return _walk.rebuild_mapping(value, [
        (k,
         redact_payload(v, destination, placeholders=placeholders) if k == "data" and text
         else redact_structure(v, destination, placeholders) if k == "content"
         else v)
        for k, v in value.items()])


def _redact_item(key: Any, v: Any, destination: str, placeholders) -> Any:
    """The value of one key of a protocol dict."""
    if key in OPAQUE_KEYS:
        return v
    if key == "source":
        return _redact_source(v, destination, placeholders)
    plain = to_plain(v)
    container = isinstance(plain, Mapping) or _walk.is_collection(plain)
    if key in LEAF_KEYS:
        # A protocol value is a string or a number. A dict or a list under
        # one of these names is the application's data.
        return redact_payload(plain, destination, placeholders=placeholders) if container else v
    if key in FREE_KEYS and isinstance(plain, Mapping):
        return redact_payload(plain, destination, placeholders=placeholders)
    return redact_structure(v, destination, placeholders)


def redact_structure(value: Any, destination: str, placeholders=None) -> Any:
    """Redact user content in an LLM payload, leaving protocol fields alone.

    Protocol fields are skipped only where the protocol puts them: a plain
    value under a protocol key (``LEAF_KEYS``) and the few whole values in
    ``OPAQUE_KEYS``. The arguments of an earlier tool call and structured
    tool results (a dict under one of ``FREE_KEYS``) are redacted in full.

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
             _redact_item(k, v, destination, placeholders))
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
