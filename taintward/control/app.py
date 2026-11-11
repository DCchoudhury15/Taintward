"""The control plane HTTP API and server.

    taintward-control new-token                  a token and its sha256
    taintward-control check --config control.yaml
    taintward-control serve --config control.yaml --listen 127.0.0.1:8820

Every request except ``GET /healthz`` needs ``Authorization: Bearer
<token>``. The token decides the tenant and the role (config.py), so a
caller can only ever see and change its own tenant.

    GET  /v1/policy            policy:read   current policy (ETag, If-None-Match -> 304)
    PUT  /v1/policy            policy:write  new version (If-Match -> 412 if stale)
    GET  /v1/policy/history    policy:read   versions, newest first
    POST /v1/traces            traces:write  OTLP/HTTP spans (JSON or protobuf)
    GET  /v1/report            report:read   ?since=7d|start=&end= &format=html|json
                                             &frameworks=gdpr,eu-ai-act,hipaa,soc2|all
    POST /v1/audit             audit:run     {"tools": <MCP tools/list>, "max_hops", "since"}
    GET  /v1/evidence          evidence:read the tenant's evidence log shard heads
    GET  /v1/evidence/proof    evidence:read ?trace_id=&span_id= inclusion proof
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import ssl
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import parse_qs, urlsplit

from taintward.control import ingest
from taintward.control.config import (
    ConfigError,
    ControlConfig,
    Principal,
    load_config,
    new_token,
)
from taintward.control.store import (
    PolicyError,
    PreconditionFailed,
    TenantStore,
    normalize_policy,
)

log = logging.getLogger("taintward.control")


@dataclass
class Response:
    status: int
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)


def _json(status: int, obj: Any, **headers: str) -> Response:
    body = json.dumps(obj, indent=1, sort_keys=True).encode() + b"\n"
    return Response(status, body, {"Content-Type": "application/json", **headers})


def _error(status: int, message: str, **headers: str) -> Response:
    return _json(status, {"error": message}, **headers)


class _Headers:
    """Case-insensitive header lookup."""

    def __init__(self, items: Mapping[str, str] | None) -> None:
        self._h = {k.lower(): v for k, v in (items or {}).items()}

    def get(self, name: str, default: str = "") -> str:
        return self._h.get(name.lower(), default)


def _unquote_etag(v: str) -> str:
    v = v.strip()
    if v.startswith("W/"):
        v = v[2:]
    return v.strip('"')


def _window(q: dict[str, str], default: str = "7d") -> tuple[int, int]:
    from taintward.evidence.report import parse_duration, parse_time
    end = parse_time(q["end"]) if q.get("end") else datetime.now(timezone.utc)
    try:
        start = parse_time(q["start"]) if q.get("start") else \
            end - parse_duration(q.get("since") or default)
    except argparse.ArgumentTypeError as exc:
        raise ValueError(str(exc)) from None
    if start >= end:
        raise ValueError("the start of the window must be before the end")
    return int(start.timestamp() * 1e9), int(end.timestamp() * 1e9)


def _policy_fn(policy: dict) -> Callable[[str], tuple[str, str, bool]]:
    from taintward.analysis.audit import policy_from_destinations
    return policy_from_destinations(
        policy["destinations"], default_destination=policy["default_destination"],
        default_jurisdiction=policy["default_jurisdiction"])


class App:
    """The API without the HTTP server, so it can be tested and embedded."""

    def __init__(self, config: ControlConfig | None = None, *,
                 config_path: str | os.PathLike | None = None) -> None:
        if config is None and config_path is None:
            raise ValueError("give a config or a config_path")
        self._path = Path(config_path) if config_path else None
        self._mtime = self._path.stat().st_mtime_ns if self._path else 0
        self.config = config if config is not None else load_config(self._path)
        self._lock = threading.Lock()

    def _maybe_reload(self) -> None:
        """Pick up an edited config (new tenants, revoked tokens) without a restart.
        A config that no longer loads keeps the current one and logs why."""
        if self._path is None:
            return
        try:
            mtime = self._path.stat().st_mtime_ns
        except OSError:
            return
        if mtime == self._mtime:
            return
        with self._lock:
            if mtime == self._mtime:
                return
            try:
                self.config = load_config(self._path)
                log.info("taintward-control: config reloaded")
            except (ConfigError, OSError, ValueError) as exc:
                log.error("taintward-control: config reload failed, keeping the old one: %s", exc)
            self._mtime = mtime

    def _auth(self, headers: _Headers) -> Principal | None:
        scheme, _, token = headers.get("authorization").partition(" ")
        if scheme.lower() != "bearer":
            return None
        return self.config.principal(token.strip())

    def store(self, tenant: str) -> TenantStore:
        return TenantStore(self.config.data_dir, tenant)

    # --- entry point --------------------------------------------------------

    def handle(self, method: str, target: str, headers: Mapping[str, str] | None = None,
               body: bytes = b"") -> Response:
        self._maybe_reload()
        h = _Headers(headers)
        url = urlsplit(target)
        path = url.path.rstrip("/") or "/"
        q = {k: v[-1] for k, v in parse_qs(url.query).items()}
        if path == "/healthz":
            return Response(200, b"ok\n", {"Content-Type": "text/plain"})
        route = ROUTES.get(path)
        if route is None:
            return _error(404, "not found")
        who = self._auth(h)
        if who is None:
            return _error(401, "missing or unknown token", **{"WWW-Authenticate": "Bearer"})
        handler_perm = route.get(method)
        if handler_perm is None:
            return _error(405, f"{method} not allowed here",
                          Allow=", ".join(sorted(route)))
        fn, perm = handler_perm
        if not who.can(perm):
            return _error(403, f"role {who.role!r} cannot {perm}")
        try:
            return fn(self, who, h, q, body)
        except (ValueError, PolicyError) as exc:
            return _error(400, str(exc))

    # --- handlers -------------------------------------------------------------

    def get_policy(self, who, h, q, body) -> Response:
        cur = self.store(who.tenant).current_policy()
        if cur is None:
            from taintward.control.store import policy_etag
            empty = normalize_policy({})
            cur = {"version": 0, "etag": policy_etag(empty), "policy": empty}
        etag = f'"{cur["etag"]}"'
        inm = h.get("if-none-match")
        if inm and any(_unquote_etag(x) in (cur["etag"], "*") for x in inm.split(",")):
            return Response(304, b"", {"ETag": etag})
        return _json(200, {"tenant": who.tenant, "version": cur["version"],
                           "etag": cur["etag"], "policy": cur["policy"]}, ETag=etag)

    def put_policy(self, who, h, q, body) -> Response:
        try:
            doc = json.loads(body or b"null")
        except ValueError:
            return _error(400, "body is not valid JSON")
        if_match = h.get("if-match")
        try:
            rec = self.store(who.tenant).put_policy(
                doc, by=who.name, if_match=_unquote_etag(if_match) if if_match else None)
        except PreconditionFailed as exc:
            return _error(412, "the policy changed since you read it; read it again",
                          ETag=f'"{exc.current}"')
        log.info("taintward-control: tenant %s policy v%s by %s", who.tenant, rec["version"],
                 who.name)
        return _json(200, {"tenant": who.tenant, "version": rec["version"], "etag": rec["etag"]},
                     ETag=f'"{rec["etag"]}"')

    def policy_history(self, who, h, q, body) -> Response:
        limit = max(1, min(int(q.get("limit") or 100), 1000))
        return _json(200, {"tenant": who.tenant,
                           "versions": self.store(who.tenant).policy_history(limit)})

    def post_traces(self, who, h, q, body) -> Response:
        from taintward.evidence.report import (
            is_tool_call,
            is_violation,
            span_violation_record,
        )
        from taintward.evidence.spans import spans_from_otlp
        try:
            doc, proto = ingest.decode(body, h.get("content-type"), h.get("content-encoding"),
                                       self.config.max_body_bytes)
            st = self.store(who.tenant)
            n_spans, n_masked = ingest.stamp_and_mask(doc, who.tenant, st.fingerprint_key())
        except ingest.IngestError as exc:
            return _error(exc.status, str(exc))
        if n_spans:
            st.append_spans(doc)
            ev = None
            for s in spans_from_otlp(doc):
                if is_tool_call(s) and is_violation(s):
                    ev = ev or st.evidence()
                    ev.append(span_violation_record(s), tenant=who.tenant, unique=True)
        if n_masked:
            log.warning("taintward-control: tenant %s uploaded %d raw value(s); masked before "
                        "storing", who.tenant, n_masked)
        extra = {"X-Taintward-Spans": str(n_spans), "X-Taintward-Raw-Masked": str(n_masked)}
        if proto:
            return Response(200, ingest.protobuf_response(),
                            {"Content-Type": "application/x-protobuf", **extra})
        return _json(200, {}, **extra)

    def get_report(self, who, h, q, body) -> Response:
        from taintward.evidence import compliance
        from taintward.evidence.report import build_report, render_html
        fmt = q.get("format") or "html"
        if fmt not in ("html", "json"):
            return _error(400, "format must be html or json")
        frameworks = compliance.parse_frameworks(q.get("frameworks") or "")
        start_ns, end_ns = _window(q)
        st = self.store(who.tenant)
        data = build_report(
            st.spans(start_ns, end_ns), start_ns=start_ns, end_ns=end_ns,
            source=f"Taintward control plane, tenant {who.tenant}",
            organization=who.tenant, title=q.get("title") or "Sensitive data flow report",
            evidence_dir=str(st.evidence_dir) if st.evidence_dir.is_dir() else None,
            fingerprint_key=st.fingerprint_key(), frameworks=frameworks)
        if data.get("evidence_log") and data["evidence_log"].get("path"):
            data["evidence_log"]["path"] = f"control plane, tenant {who.tenant}"  # not the disk path
        if fmt == "json":
            return _json(200, data)
        return Response(200, render_html(data).encode(), {"Content-Type": "text/html; charset=utf-8"})

    def post_audit(self, who, h, q, body) -> Response:
        from taintward.analysis.audit import audit, render_markdown
        try:
            req = json.loads(body or b"null")
        except ValueError:
            return _error(400, "body is not valid JSON")
        if not isinstance(req, dict) or "tools" not in req:
            return _error(400, 'body must be {"tools": <MCP tools/list result>, ...}')
        st = self.store(who.tenant)
        cur = st.current_policy()
        policy = cur["policy"] if cur else normalize_policy({})
        start_ns, end_ns = _window({"since": str(req.get("since") or "30d")})
        hops = int(req.get("max_hops") or 3)
        if not 1 <= hops <= 6:
            return _error(400, "max_hops must be 1 to 6")
        res, _ = audit(req["tools"], _policy_fn(policy), spans=st.spans(start_ns, end_ns),
                       max_hops=hops, home=self.config.tenants[who.tenant].home)
        res["policy_version"] = cur["version"] if cur else 0
        if q.get("format") == "md":
            return Response(200, render_markdown(res).encode(),
                            {"Content-Type": "text/markdown; charset=utf-8"})
        return _json(200, res)

    def get_evidence(self, who, h, q, body) -> Response:
        st = self.store(who.tenant)
        heads = [x.to_dict() for x in st.evidence().heads()] if st.evidence_dir.is_dir() else []
        return _json(200, {"tenant": who.tenant, "shards": heads})

    def get_proof(self, who, h, q, body) -> Response:
        trace_id, span_id = q.get("trace_id", ""), q.get("span_id", "")
        if not trace_id or not span_id:
            return _error(400, "give trace_id and span_id")
        st = self.store(who.tenant)
        found = st.evidence().find(trace_id.lower(), span_id.lower()) \
            if st.evidence_dir.is_dir() else None
        if found is None:
            return _error(404, "no evidence record for that span")
        tenant, day, idx = found
        shard = st.evidence().shard(tenant, day)
        return _json(200, {"tenant": tenant, "day": day, "index": idx, "size": len(shard),
                           "root": shard.root().hex(), "record": shard.record(idx),
                           "proof": shard.inclusion_proof(idx).to_dict()})


ROUTES: dict[str, dict[str, tuple[Callable, str]]] = {
    "/v1/policy": {"GET": (App.get_policy, "policy:read"), "PUT": (App.put_policy, "policy:write")},
    "/v1/policy/history": {"GET": (App.policy_history, "policy:read")},
    "/v1/traces": {"POST": (App.post_traces, "traces:write")},
    "/v1/report": {"GET": (App.get_report, "report:read")},
    "/v1/audit": {"POST": (App.post_audit, "audit:run")},
    "/v1/evidence": {"GET": (App.get_evidence, "evidence:read")},
    "/v1/evidence/proof": {"GET": (App.get_proof, "evidence:read")},
}


# --- HTTP server ---------------------------------------------------------------

def make_handler(app: App) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "taintward-control"
        protocol_version = "HTTP/1.1"

        def _send(self, r: Response) -> None:
            self.send_response(r.status)
            for k, v in r.headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(r.body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(r.body)

        def _do(self) -> None:
            body = b""
            if self.command in ("POST", "PUT"):
                if self.headers.get("Transfer-Encoding"):
                    self.close_connection = True
                    return self._send(_error(411, "send a Content-Length, not chunked"))
                try:
                    n = int(self.headers.get("Content-Length", ""))
                except ValueError:
                    self.close_connection = True
                    return self._send(_error(411, "Content-Length required"))
                if n < 0 or n > app.config.max_body_bytes:
                    self.close_connection = True
                    return self._send(_error(413, f"body is larger than "
                                                  f"{app.config.max_body_bytes} bytes"))
                body = self.rfile.read(n)
            try:
                r = app.handle(self.command, self.path, dict(self.headers.items()), body)
            except Exception:  # noqa: BLE001 - one bad request must not stop the server
                log.exception("taintward-control: %s %s failed", self.command, self.path)
                r = _error(500, "internal error")
            self._send(r)

        do_GET = do_PUT = do_POST = do_DELETE = _do

        def log_message(self, fmt: str, *args: Any) -> None:
            log.info("%s %s", self.address_string(), fmt % args)

    return Handler


def serve(app: App, host: str, port: int, *, tls_cert: str | None = None,
          tls_key: str | None = None) -> ThreadingHTTPServer:
    """Start serving in a background thread; returns the server (``shutdown()`` stops it)."""
    httpd = ThreadingHTTPServer((host, port), make_handler(app))
    httpd.daemon_threads = True
    if tls_cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(tls_cert, tls_key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, name="taintward-control", daemon=True).start()
    return httpd


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="taintward-control",
                                 description="Taintward control plane for many tenants.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("new-token", help="print a new random token and its sha256")
    c = sub.add_parser("check", help="check a config file")
    c.add_argument("--config", required=True)
    s = sub.add_parser("serve", help="run the API")
    s.add_argument("--config", required=True)
    s.add_argument("--listen", default="127.0.0.1:8820")
    s.add_argument("--tls-cert")
    s.add_argument("--tls-key")
    args = ap.parse_args(argv)

    if args.cmd == "new-token":
        token, digest = new_token()
        print(f"token:  {token}\nsha256: {digest}")
        print("Give the token to the client; put only the sha256 in the config.", file=sys.stderr)
        return 0
    try:
        cfg = load_config(args.config)
    except (ConfigError, OSError, ValueError) as exc:
        print(f"taintward-control: bad config: {exc}", file=sys.stderr)
        return 2
    if args.cmd == "check":
        for t in cfg.tenants.values():
            roles = sorted(p.role for p in cfg.tokens.values() if p.tenant == t.name)
            print(f"{t.name}: home={','.join(t.home) or '-'} tokens={','.join(roles)}")
        return 0
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    host, _, port = args.listen.rpartition(":")
    app = App(cfg, config_path=args.config)
    httpd = serve(app, host.strip("[]") or "127.0.0.1", int(port),
                  tls_cert=args.tls_cert, tls_key=args.tls_key)
    log.info("taintward-control: %d tenant(s), data in %s, listening on %s%s",
             len(cfg.tenants), cfg.data_dir, args.listen, " (TLS)" if args.tls_cert else "")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        httpd.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
