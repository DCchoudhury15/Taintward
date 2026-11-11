"""Span upload: decode an OTLP/HTTP request, stamp the tenant, mask raw values.

The SDK already masks or redacts what it records, so a stored span should
hold no raw value. This is the backstop for a misconfigured client: before
a span is stored, every string attribute (resource, span, events, links,
status message) is scanned with the report's raw value patterns and each
hit is replaced by ``[<TYPE>]``. The control plane therefore never keeps a
raw value those patterns find. A hit in a call's recorded input is noted on
the span (``taintward.control.raw_input``: types and keyed fingerprints), so
the tenant's report still counts the call as one that sent raw data.
"""

from __future__ import annotations

import base64
import json
import zlib
from typing import Any

from taintward.evidence.report import INGEST_RAW_ATTR, INPUT_ATTRS, _fp, find_raw
from taintward.evidence.spans import TENANT_ATTR

MASKED_ATTR = "taintward.control.raw_masked"
_OWN_ATTRS = (TENANT_ATTR, INGEST_RAW_ATTR, MASKED_ATTR)

JSON_TYPES = ("application/json",)
PROTOBUF_TYPES = ("application/x-protobuf", "application/protobuf")


class IngestError(ValueError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def _inflate(body: bytes, encoding: str, limit: int) -> bytes:
    encoding = (encoding or "identity").strip().lower()
    if encoding in ("", "identity"):
        return body
    if encoding not in ("gzip", "deflate"):
        raise IngestError(415, f"unsupported Content-Encoding {encoding!r}")
    d = zlib.decompressobj(16 + zlib.MAX_WBITS if encoding == "gzip" else zlib.MAX_WBITS)
    try:
        out = d.decompress(body, limit + 1)
    except zlib.error:
        raise IngestError(400, f"body is not valid {encoding}") from None
    if len(out) > limit or d.unconsumed_tail:
        raise IngestError(413, f"body is larger than {limit} bytes once decompressed")
    return out


def _b64_to_hex(v: Any) -> Any:
    if not isinstance(v, str) or not v:
        return v
    try:
        return base64.b64decode(v, validate=True).hex()
    except (ValueError, TypeError):
        return v


def _ids_to_hex(doc: dict) -> None:
    """protobuf JSON gives ids as base64; OTLP JSON files use hex."""
    for rs in doc.get("resourceSpans") or []:
        for ss in rs.get("scopeSpans") or []:
            for s in ss.get("spans") or []:
                for k in ("traceId", "spanId", "parentSpanId"):
                    if k in s:
                        s[k] = _b64_to_hex(s[k])
                for link in s.get("links") or []:
                    for k in ("traceId", "spanId"):
                        if k in link:
                            link[k] = _b64_to_hex(link[k])


def decode(body: bytes, content_type: str, content_encoding: str, limit: int) -> tuple[dict, bool]:
    """(OTLP JSON document, request was protobuf)."""
    ctype = (content_type or "").split(";")[0].strip().lower()
    raw = _inflate(body, content_encoding, limit)
    if ctype in JSON_TYPES:
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise IngestError(400, "body is not valid JSON") from None
        if not isinstance(doc, dict):
            raise IngestError(400, "body must be an OTLP traces object")
        return doc, False
    if ctype in PROTOBUF_TYPES:
        from google.protobuf.json_format import MessageToDict
        from google.protobuf.message import DecodeError
        from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
            ExportTraceServiceRequest,
        )
        try:
            req = ExportTraceServiceRequest.FromString(raw)
        except DecodeError:
            raise IngestError(400, "body is not a valid OTLP protobuf request") from None
        doc = MessageToDict(req)
        _ids_to_hex(doc)
        return doc, True
    raise IngestError(415, "Content-Type must be application/json or application/x-protobuf")


def protobuf_response() -> bytes:
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
        ExportTraceServiceResponse,
    )
    return ExportTraceServiceResponse().SerializeToString()


def mask_string(text: str) -> tuple[str, list[tuple[str, str]]]:
    """(text with raw values replaced, [(type, raw value)])."""
    hits = sorted(find_raw(text), key=lambda h: (h[0], -(h[1] - h[0])))
    kept: list[tuple[int, int, str]] = []
    for a, b, kind in hits:
        if kept and a < kept[-1][1]:
            # Inside an earlier match: dropped. Reaching past its end: the
            # two are masked as one, so no part of either stays.
            if b > kept[-1][1]:
                kept[-1] = (kept[-1][0], b, kept[-1][2])
            continue
        kept.append((a, b, kind))
    if not kept:
        return text, []
    out, pos, found = [], 0, []
    for a, b, kind in kept:
        out.append(text[pos:a])
        out.append(f"[{kind}]")
        found.append((kind, text[a:b]))
        pos = b
    out.append(text[pos:])
    return "".join(out), found


def _mask_any(v: Any, found: list) -> Any:
    if not isinstance(v, dict):
        return v
    if isinstance(v.get("stringValue"), str):
        text, hits = mask_string(v["stringValue"])
        if hits:
            found.extend(hits)
            return {"stringValue": text}
        return v
    if isinstance(v.get("arrayValue"), dict):
        items = v["arrayValue"].get("values") or []
        for i, item in enumerate(items):
            items[i] = _mask_any(item, found)
    if isinstance(v.get("kvlistValue"), dict):
        for kv in v["kvlistValue"].get("values") or []:
            if isinstance(kv, dict):
                kv["value"] = _mask_any(kv.get("value"), found)
    return v


def _mask_attrs(attrs: list | None, found: list, *, inputs: list | None = None,
                drop: tuple[str, ...] = ()) -> list:
    out = []
    for kv in attrs or []:
        if not isinstance(kv, dict) or kv.get("key") in drop:
            continue
        hits: list = []
        kv["value"] = _mask_any(kv.get("value"), hits)
        found.extend(hits)
        if inputs is not None and kv.get("key") in INPUT_ATTRS:
            inputs.extend(hits)
        out.append(kv)
    return out


def stamp_and_mask(doc: dict, tenant: str, fp_key: bytes) -> tuple[int, int]:
    """Set the tenant on every resource (any tenant the client sent is
    dropped), mask raw values. Returns (spans, raw values masked)."""
    rss = doc.get("resourceSpans")
    if not isinstance(rss, list):
        raise IngestError(400, "body has no resourceSpans list")
    n_spans = n_masked = 0
    for rs in rss:
        if not isinstance(rs, dict):
            raise IngestError(400, "resourceSpans entries must be objects")
        res = rs.setdefault("resource", {})
        found: list = []
        res["attributes"] = _mask_attrs(res.get("attributes"), found, drop=(TENANT_ATTR,))
        res["attributes"].append({"key": TENANT_ATTR, "value": {"stringValue": tenant}})
        n_masked += len(found)
        for ss in rs.get("scopeSpans") or []:
            for s in (ss.get("spans") or []) if isinstance(ss, dict) else []:
                if not isinstance(s, dict):
                    continue
                n_spans += 1
                found, inputs = [], []
                s["attributes"] = _mask_attrs(s.get("attributes"), found, inputs=inputs,
                                              drop=_OWN_ATTRS)
                for part in ("events", "links"):
                    for item in s.get(part) or []:
                        if isinstance(item, dict):
                            item["attributes"] = _mask_attrs(item.get("attributes"), found)
                for holder, key in ((s.get("status"), "message"), (s, "name")):
                    if isinstance(holder, dict) and isinstance(holder.get(key), str):
                        holder[key], hits = mask_string(holder[key])
                        found.extend(hits)
                if found:
                    n_masked += len(found)
                    s["attributes"].append({"key": MASKED_ATTR,
                                            "value": {"intValue": str(len(found))}})
                if inputs:
                    tags = sorted({f"{kind}:{_fp(raw, fp_key)}" for kind, raw in inputs})
                    s["attributes"].append({"key": INGEST_RAW_ATTR,
                                            "value": {"stringValue": ",".join(tags)}})
    return n_spans, n_masked
