"""Span sources for the evidence report.

Every source returns the same small :class:`Span` shape, so the report code
does not care where the data came from. Three sources ship:

* :class:`OtlpFileSource`: OTLP JSON files, one ``ExportTraceServiceRequest``
  per line, as written by the OpenTelemetry collector ``file`` exporter. A
  file holding one plain OTLP JSON document also works.
* :class:`JaegerSource`: the Jaeger v3 HTTP API (``/api/v3/traces``), which
  returns the same OTLP JSON shape.
* :class:`ClickHouseSource`: SigNoz's ClickHouse span table, through
  ``docker exec ... clickhouse-client`` (the same path as
  ``evidence/recorder.py``) or the ClickHouse HTTP interface.

A source is any object with ``fetch(start_ns, end_ns) -> list[Span]`` and a
``describe() -> str``, so adding a new backend means adding one class.
"""

from __future__ import annotations

import base64
import gzip
import json
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Protocol


@dataclass
class Span:
    trace_id: str
    span_id: str
    name: str
    start_ns: int
    service: str = ""
    parent_span_id: str = ""
    attrs: dict[str, Any] = field(default_factory=dict)


class SpanSource(Protocol):
    def fetch(self, start_ns: int, end_ns: int) -> list[Span]: ...

    def describe(self) -> str: ...


# ---------------------------------------------------------------------------
# OTLP JSON parsing (shared by the file and Jaeger sources)
# ---------------------------------------------------------------------------

def _any_value(v: dict) -> Any:
    """Decode one OTLP JSON ``AnyValue``."""
    if not isinstance(v, dict):
        return v
    if "stringValue" in v:
        return v["stringValue"]
    if "boolValue" in v:
        return bool(v["boolValue"])
    if "intValue" in v:
        return int(v["intValue"])  # int64 is a JSON string in OTLP JSON
    if "doubleValue" in v:
        return float(v["doubleValue"])
    if "arrayValue" in v:
        return [_any_value(x) for x in v["arrayValue"].get("values", [])]
    if "kvlistValue" in v:
        return {kv["key"]: _any_value(kv.get("value", {}))
                for kv in v["kvlistValue"].get("values", [])}
    if "bytesValue" in v:
        return v["bytesValue"]
    return None


def _attrs(items: Iterable[dict] | None) -> dict[str, Any]:
    return {kv["key"]: _any_value(kv.get("value", {})) for kv in (items or [])}


def _hex_id(raw: str | None) -> str:
    """OTLP JSON ids are hex; protobuf-style JSON uses base64. Accept both."""
    if not raw:
        return ""
    if re.fullmatch(r"[0-9a-fA-F]+", raw) and len(raw) in (16, 32):
        return raw.lower()
    try:
        return base64.b64decode(raw).hex()
    except Exception:
        return raw


def spans_from_otlp(doc: dict) -> list[Span]:
    """Turn one OTLP JSON traces document into spans.

    Accepts ``{"resourceSpans": [...]}`` and the Jaeger v3 wrapper
    ``{"result": {"resourceSpans": [...]}}``.
    """
    if "result" in doc and isinstance(doc["result"], dict):
        doc = doc["result"]
    out: list[Span] = []
    for rs in doc.get("resourceSpans", []) or []:
        res = _attrs((rs.get("resource") or {}).get("attributes"))
        service = str(res.get("service.name", ""))
        for ss in rs.get("scopeSpans", []) or rs.get("instrumentationLibrarySpans", []) or []:
            for s in ss.get("spans", []) or []:
                out.append(Span(
                    trace_id=_hex_id(s.get("traceId")),
                    span_id=_hex_id(s.get("spanId")),
                    parent_span_id=_hex_id(s.get("parentSpanId")),
                    name=s.get("name", ""),
                    start_ns=int(s.get("startTimeUnixNano", 0) or 0),
                    service=service,
                    attrs=_attrs(s.get("attributes")),
                ))
    return out


def iter_json_docs(text: str) -> Iterator[dict]:
    """Yield every JSON object in ``text``.

    Handles one object per line (the collector file exporter), a single
    pretty-printed object, and back-to-back objects (Jaeger's streamed
    responses).
    """
    dec = json.JSONDecoder()
    i, n = 0, len(text)
    while i < n:
        while i < n and text[i] in " \t\r\n":
            i += 1
        if i >= n:
            break
        obj, i = dec.raw_decode(text, i)
        if isinstance(obj, dict):
            yield obj


def _in_window(spans: list[Span], start_ns: int, end_ns: int) -> list[Span]:
    return [s for s in spans if start_ns <= s.start_ns < end_ns]


def _dedupe(spans: list[Span]) -> list[Span]:
    seen: set[tuple[str, str]] = set()
    out = []
    for s in spans:
        key = (s.trace_id, s.span_id)
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return out


# ---------------------------------------------------------------------------
# OTLP JSON files
# ---------------------------------------------------------------------------

class OtlpFileSource:
    """OTLP JSON lines files (the collector ``file`` exporter output).

    ``paths`` may name files or directories (every ``*.json``, ``*.jsonl``
    and ``*.json.gz`` file inside is read, rotated files included).
    """

    def __init__(self, paths: Iterable[str | Path], services: Iterable[str] = ()):
        self.paths = [Path(p) for p in paths]
        self.services = set(services)

    def _files(self) -> list[Path]:
        files: list[Path] = []
        for p in self.paths:
            if p.is_dir():
                for pat in ("*.json", "*.jsonl", "*.json.gz", "*.jsonl.gz"):
                    files.extend(sorted(p.rglob(pat)))
            else:
                files.append(p)
        return files

    def fetch(self, start_ns: int, end_ns: int) -> list[Span]:
        spans: list[Span] = []
        for f in self._files():
            raw = f.read_bytes()
            if f.suffix == ".gz":
                raw = gzip.decompress(raw)
            for doc in iter_json_docs(raw.decode("utf-8")):
                spans.extend(spans_from_otlp(doc))
        if self.services:
            spans = [s for s in spans if s.service in self.services]
        return _dedupe(_in_window(spans, start_ns, end_ns))

    def describe(self) -> str:
        return "OTLP JSON files: " + ", ".join(str(p) for p in self.paths)


# ---------------------------------------------------------------------------
# Jaeger v3 API
# ---------------------------------------------------------------------------

def _rfc3339(ns: int) -> str:
    dt = datetime.fromtimestamp(ns / 1e9, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class JaegerSource:
    """Jaeger v3 HTTP API.

    Jaeger returns at most ``search_depth`` traces per query (its limit is
    10000). When a query comes back full, the window is split in half and
    each half is fetched again, so a busy window is not silently cut short.
    If a window still comes back full at one second wide, the result is
    marked as possibly truncated (see ``truncated``).
    """

    def __init__(self, url: str, services: Iterable[str], *, search_depth: int = 1000,
                 timeout: float = 30.0):
        self.url = url.rstrip("/")
        self.services = list(services)
        if not self.services:
            raise ValueError("the Jaeger source needs at least one service name")
        self.search_depth = int(search_depth)
        self.timeout = timeout
        self.truncated = False

    def _get(self, service: str, start_ns: int, end_ns: int) -> list[Span]:
        q = urllib.parse.urlencode({
            "query.service_name": service,
            "query.start_time_min": _rfc3339(start_ns),
            "query.start_time_max": _rfc3339(end_ns),
            "query.search_depth": str(self.search_depth),
        })
        try:
            with urllib.request.urlopen(f"{self.url}/api/v3/traces?{q}",
                                        timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            if e.code == 404:  # Jaeger answers 404 "No traces found"
                return []
            raise RuntimeError(f"Jaeger query failed: HTTP {e.code} {e.read()[:200]!r}") from e
        spans: list[Span] = []
        for doc in iter_json_docs(body):
            if "error" in doc:
                err = doc["error"]
                if isinstance(err, dict) and err.get("httpCode") == 404:
                    continue
                raise RuntimeError(f"Jaeger query failed: {err}")
            spans.extend(spans_from_otlp(doc))
        return spans

    def _fetch_window(self, service: str, start_ns: int, end_ns: int) -> list[Span]:
        spans = self._get(service, start_ns, end_ns)
        n_traces = len({s.trace_id for s in spans})
        if n_traces >= self.search_depth:
            if end_ns - start_ns <= 1_000_000_000:
                self.truncated = True
                return spans
            mid = start_ns + (end_ns - start_ns) // 2
            return (self._fetch_window(service, start_ns, mid)
                    + self._fetch_window(service, mid, end_ns))
        return spans

    def fetch(self, start_ns: int, end_ns: int) -> list[Span]:
        spans: list[Span] = []
        for svc in self.services:
            spans.extend(self._fetch_window(svc, start_ns, end_ns))
        # Jaeger matches traces whose span times overlap the window; keep
        # only the spans that started inside it.
        return _dedupe(_in_window(spans, start_ns, end_ns))

    def describe(self) -> str:
        return f"Jaeger v3 API at {self.url} (services: {', '.join(self.services)})"


# ---------------------------------------------------------------------------
# SigNoz / ClickHouse
# ---------------------------------------------------------------------------

_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")

_CH_QUERY = """
SELECT
    trace_id, span_id, parent_span_id, name, serviceName AS service,
    toInt64(toUnixTimestamp64Nano(timestamp)) AS start_ns,
    attributes_string, attributes_bool, attributes_number
FROM {db}.{tbl}
WHERE ts_bucket_start >= {bucket_min} AND ts_bucket_start <= {bucket_max}
  AND timestamp >= fromUnixTimestamp64Nano(toInt64({start_ns}))
  AND timestamp < fromUnixTimestamp64Nano(toInt64({end_ns}))
  {svc_clause}
FORMAT JSONEachRow
"""


def spans_from_clickhouse_rows(rows: Iterable[dict]) -> list[Span]:
    """Map SigNoz ``signoz_index_v3`` rows to spans."""
    out = []
    for r in rows:
        attrs: dict[str, Any] = {}
        attrs.update(r.get("attributes_string") or {})
        attrs.update({k: float(v) for k, v in (r.get("attributes_number") or {}).items()})
        attrs.update({k: bool(v) for k, v in (r.get("attributes_bool") or {}).items()})
        out.append(Span(
            trace_id=str(r.get("trace_id", "")), span_id=str(r.get("span_id", "")),
            parent_span_id=str(r.get("parent_span_id", "") or ""),
            name=str(r.get("name", "")), start_ns=int(r.get("start_ns", 0)),
            service=str(r.get("service", "")), attrs=attrs,
        ))
    return out


class ClickHouseSource:
    """SigNoz ClickHouse span table.

    Default transport is ``docker exec <container> clickhouse-client``, the
    same as ``evidence/recorder.py``. Pass ``http_url`` (for example
    ``http://localhost:8123``) to use the ClickHouse HTTP interface instead.
    """

    def __init__(self, services: Iterable[str] = (), *,
                 container: str = "signoz-telemetrystore-clickhouse-0-0",
                 database: str = "signoz_traces", table: str = "distributed_signoz_index_v3",
                 http_url: str | None = None, user: str | None = None,
                 password: str | None = None, timeout: float = 120.0):
        self.services = list(services)
        for name in [*self.services, container, database, table]:
            if not _SAFE_NAME_RE.match(name):
                raise ValueError(f"unsafe name: {name!r}")
        self.container = container
        self.database = database
        self.table = table
        self.http_url = http_url.rstrip("/") if http_url else None
        self.user = user
        self.password = password
        self.timeout = timeout

    def query(self, start_ns: int, end_ns: int) -> str:
        start_ns, end_ns = int(start_ns), int(end_ns)
        svc_clause = ""
        if self.services:
            names = ", ".join(f"'{s}'" for s in self.services)  # validated above
            svc_clause = f"AND serviceName IN ({names})"
        return _CH_QUERY.format(
            db=self.database, tbl=self.table,
            bucket_min=start_ns // 1_000_000_000 - 1800,
            bucket_max=end_ns // 1_000_000_000,
            start_ns=start_ns, end_ns=end_ns, svc_clause=svc_clause,
        )

    def _run(self, q: str) -> str:
        if self.http_url:
            req = urllib.request.Request(self.http_url + "/", data=q.encode("utf-8"),
                                         method="POST")
            if self.user:
                req.add_header("X-ClickHouse-User", self.user)
            if self.password:
                req.add_header("X-ClickHouse-Key", self.password)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.read().decode("utf-8")
        proc = subprocess.run(
            ["docker", "exec", self.container, "clickhouse-client", "-q", q],
            capture_output=True, text=True, timeout=self.timeout,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"clickhouse-client failed: {proc.stderr.strip()}")
        return proc.stdout

    def fetch(self, start_ns: int, end_ns: int) -> list[Span]:
        out = self._run(self.query(start_ns, end_ns))
        rows = [json.loads(line) for line in out.splitlines() if line.strip()]
        return _dedupe(spans_from_clickhouse_rows(rows))

    def describe(self) -> str:
        where = self.http_url or f"docker container {self.container}"
        svcs = ", ".join(self.services) if self.services else "all services"
        return f"SigNoz ClickHouse {self.database}.{self.table} via {where} ({svcs})"
