"""The control plane (taintward/control) and the multi-tenant pieces around
it: tenant isolation, roles, policy versions, span upload with raw value
masking, reports, audits, evidence proofs, the SDK client and the tenant
vault."""

from __future__ import annotations

import gzip
import json
import time
import urllib.error
import urllib.request

import pytest

from taintward.control import ingest
from taintward.control.app import App, serve
from taintward.control.config import ConfigError, hash_token, new_token, parse_config
from taintward.evidence.merkle import InclusionProof, _hash_leaf, verify_inclusion
from taintward.evidence.spans import span_tenant, spans_from_otlp
from tests.test_report import T0, _doc, _tool

TOK = {name: f"tok-{name}" for name in ("acme-app", "acme-dpo", "acme-ops", "globex-ops")}
SSN = "234-12-1234"


def _config(tmp_path, **extra):
    return parse_config({
        "data_dir": str(tmp_path / "data"),
        "tenants": {
            "acme": {"home": ["eu"], "tokens": [
                {"name": "app", "role": "agent", "sha256": hash_token(TOK["acme-app"])},
                {"name": "dpo", "role": "reader", "sha256": hash_token(TOK["acme-dpo"])},
                {"name": "ops", "role": "admin", "sha256": hash_token(TOK["acme-ops"])}]},
            "globex": {"tokens": [
                {"name": "ops", "role": "admin", "sha256": hash_token(TOK["globex-ops"])}]},
        }, **extra})


@pytest.fixture
def app(tmp_path):
    return App(_config(tmp_path))


def call(app, method, target, who=None, body=b"", **headers):
    if who:
        headers["Authorization"] = f"Bearer {TOK[who]}"
    if isinstance(body, (dict, list)):
        body = json.dumps(body).encode()
        headers.setdefault("Content-Type", "application/json")
    return app.handle(method, target, headers, body)


def js(r):
    return json.loads(r.body)


def violation_doc(trace="a" * 32, args=None, **resource):
    doc = _doc([
        _tool(trace, "1" * 16, "get_customer", "internal", 1),
        _tool(trace, "2" * 16, "send_email", "external", 2, juris="us", violation=True,
              reasons="pii_egress", redacted=True,
              **({"args": args} if args is not None else {})),
    ])
    for k, v in resource.items():
        doc["resourceSpans"][0]["resource"]["attributes"].append(
            {"key": k, "value": {"stringValue": v}})
    return doc


# --- config -----------------------------------------------------------------------

def test_config_errors(tmp_path):
    good = {"name": "a", "role": "agent", "sha256": hash_token("x")}
    for tenants, msg in [
        ({"bad/name": {"tokens": [good]}}, "invalid tenant"),
        ({"t": {"tokens": [dict(good, role="root")]}}, "role must be"),
        ({"t": {"tokens": [dict(good, sha256="x")]}}, "64 hex"),
        ({"t": {"tokens": [good]}, "u": {"tokens": [good]}}, "listed twice"),
        ({"t": {"tokens": []}}, "non-empty 'tokens'"),
    ]:
        with pytest.raises(ConfigError, match=msg):
            parse_config({"data_dir": str(tmp_path), "tenants": tenants})
    token, digest = new_token()
    assert token.startswith("twc_") and digest == hash_token(token) and len(digest) == 64


# --- auth and roles ------------------------------------------------------------------

def test_auth_and_roles(app):
    assert call(app, "GET", "/healthz").status == 200
    assert call(app, "GET", "/v1/policy").status == 401
    r = app.handle("GET", "/v1/policy", {"Authorization": "Bearer nope"})
    assert r.status == 401 and r.headers["WWW-Authenticate"] == "Bearer"
    assert call(app, "GET", "/v1/policy", "acme-app").status == 200
    # the agent token of an app cannot change the policy or read reports
    assert call(app, "PUT", "/v1/policy", "acme-app", {"destinations": {}}).status == 403
    assert call(app, "GET", "/v1/report", "acme-app").status == 403
    # a reader (data protection officer) reads but cannot upload or change
    assert call(app, "GET", "/v1/report?format=json", "acme-dpo").status == 200
    assert call(app, "POST", "/v1/traces", "acme-dpo", violation_doc()).status == 403
    assert call(app, "PUT", "/v1/policy", "acme-dpo", {}).status == 403
    assert call(app, "DELETE", "/v1/policy", "acme-ops").status == 405
    assert call(app, "GET", "/v1/nothing", "acme-ops").status == 404


def test_config_reload_revokes_a_token(tmp_path):
    path = tmp_path / "control.json"
    cfg = json.loads(json.dumps({"data_dir": "data", "tenants": {"acme": {"tokens": [
        {"name": "app", "role": "agent", "sha256": hash_token(TOK["acme-app"])}]}}}))
    path.write_text(json.dumps(cfg))
    app = App(config_path=path)
    assert call(app, "GET", "/v1/policy", "acme-app").status == 200
    cfg["tenants"]["acme"]["tokens"][0]["sha256"] = hash_token("another")
    path.write_text(json.dumps(cfg))
    import os
    os.utime(path, ns=(time.time_ns() + 10**9, time.time_ns() + 10**9))
    assert call(app, "GET", "/v1/policy", "acme-app").status == 401
    path.write_text("{not json")  # a broken edit keeps the last good config
    os.utime(path, ns=(time.time_ns() + 2 * 10**9, time.time_ns() + 2 * 10**9))
    assert call(app, "GET", "/v1/policy", "acme-app").status == 401
    assert app.config.tenants["acme"]


# --- policy ------------------------------------------------------------------------

def test_policy_versions_etags_and_isolation(app):
    r = call(app, "GET", "/v1/policy", "acme-app")
    assert js(r)["version"] == 0 and js(r)["policy"]["destinations"] == {}
    pol = {"destinations": {"get_customer": "internal", "send_email": ["external", "US"],
                            "post": {"destination": "external", "allow": ["channel"]}},
           "llm_jurisdiction": "us"}
    r = call(app, "PUT", "/v1/policy", "acme-ops", pol)
    assert r.status == 200 and js(r)["version"] == 1
    etag = r.headers["ETag"]
    got = js(call(app, "GET", "/v1/policy", "acme-app"))
    assert got["policy"]["destinations"]["send_email"] == {
        "destination": "external", "jurisdiction": "us", "allow": []}
    assert got["policy"]["destinations"]["post"]["allow"] == ["channel"]
    # unchanged: 304, and the same policy again is not a new version
    assert call(app, "GET", "/v1/policy", "acme-app", **{"If-None-Match": etag}).status == 304
    assert js(call(app, "PUT", "/v1/policy", "acme-ops", pol))["version"] == 1
    # a stale writer gets 412 instead of overwriting a newer version
    r2 = call(app, "PUT", "/v1/policy", "acme-ops", {"destinations": {"a": "log"}},
              **{"If-Match": etag})
    assert r2.status == 200 and js(r2)["version"] == 2
    r3 = call(app, "PUT", "/v1/policy", "acme-ops", {"destinations": {"b": "log"}},
              **{"If-Match": etag})
    assert r3.status == 412 and r3.headers["ETag"] == r2.headers["ETag"]
    hist = js(call(app, "GET", "/v1/policy/history", "acme-dpo"))["versions"]
    assert [v["version"] for v in hist] == [2, 1] and hist[0]["by"] == "ops"
    # bad documents are refused and change nothing
    for bad in ({"destinations": {"x": "nowhere"}}, {"rules": []},
                {"destinations": {"x": ["external", "u s"]}}, [1]):
        assert call(app, "PUT", "/v1/policy", "acme-ops", bad).status == 400
    assert js(call(app, "GET", "/v1/policy", "acme-app"))["version"] == 2
    # the other tenant sees none of it
    other = js(call(app, "GET", "/v1/policy", "globex-ops"))
    assert other["tenant"] == "globex" and other["version"] == 0
    assert other["policy"]["destinations"] == {}


# --- span upload -------------------------------------------------------------------

def test_upload_sets_the_tenant_from_the_token(app, tmp_path):
    # the client claims to be globex; the token says acme
    r = call(app, "POST", "/v1/traces", "acme-app", violation_doc(**{"taintward.tenant": "globex"}))
    assert r.status == 200 and r.headers["X-Taintward-Spans"] == "2"
    acme = app.store("acme").spans(T0 - 10**9, T0 + 10**9)
    assert len(acme) == 2 and {span_tenant(s) for s in acme} == {"acme"}
    assert app.store("globex").spans(T0 - 10**9, T0 + 10**9) == []
    assert not (tmp_path / "data" / "tenants" / "globex" / "spans").exists()
    stored = b"".join(p.read_bytes() for p in (tmp_path / "data").rglob("*.jsonl"))
    assert b"globex" not in stored  # the claimed tenant is dropped, not just outvoted
    # globex's report and evidence are empty
    rep = js(call(app, "GET", f"/v1/report?format=json&start={_iso(T0 - 10**9)}"
                              f"&end={_iso(T0 + 10**9)}", "globex-ops"))
    assert rep["totals"]["tool_calls"] == 0
    assert js(call(app, "GET", "/v1/evidence", "globex-ops"))["shards"] == []


def test_violations_reach_the_tenant_evidence_log_once(app):
    doc = violation_doc()
    for _ in range(2):  # an exporter retry sends the same batch again
        assert call(app, "POST", "/v1/traces", "acme-app", doc).status == 200
    shards = js(call(app, "GET", "/v1/evidence", "acme-dpo"))["shards"]
    assert [(s["tenant"], s["size"]) for s in shards] == [("acme", 1)]
    r = call(app, "GET", f"/v1/evidence/proof?trace_id={'a' * 32}&span_id={'2' * 16}", "acme-dpo")
    p = js(r)
    proof = InclusionProof.from_dict(p["proof"])
    assert verify_inclusion(_hash_leaf(p["record"]), proof, bytes.fromhex(p["root"]), p["size"])
    # a changed record does not verify
    assert not verify_inclusion(_hash_leaf(dict(p["record"], tool="x")), proof,
                                bytes.fromhex(p["root"]), p["size"])
    assert p["record"]["tool"] == "send_email"
    # the other tenant cannot get acme's proof
    assert call(app, "GET", f"/v1/evidence/proof?trace_id={'a' * 32}&span_id={'2' * 16}",
                "globex-ops").status == 404


def test_raw_values_are_masked_before_storing_and_still_reported(app, tmp_path):
    args = json.dumps({"to": "a@b.example", "body": f"ssn {SSN}"})
    r = call(app, "POST", "/v1/traces", "acme-app",
             violation_doc(args=args, **{"host.note": f"call 555-123-4567 ({SSN})"}))
    assert r.status == 200 and r.headers["X-Taintward-Raw-Masked"] == "4"
    stored = b"".join(p.read_bytes() for p in (tmp_path / "data").rglob("*.jsonl"))
    assert SSN.encode() not in stored and b"a@b.example" not in stored
    assert b"555-123-4567" not in stored and b"[US_SSN]" in stored
    rep = js(call(app, "GET", f"/v1/report?format=json&start={_iso(T0 - 10**9)}"
                              f"&end={_iso(T0 + 10**9)}", "acme-dpo"))
    ext = rep["raw_check"]["by_destination"]["external"]
    assert ext["calls_with_raw"] == 1 and ext["raw_values"] == 2
    assert rep["raw_check"]["claim"]["status"] != "holds"
    finding = rep["raw_check"]["findings"][0]
    assert finding["types"] == ["EMAIL_ADDRESS", "US_SSN"]
    # fingerprints use the tenant's key: the same value gives the same one
    from taintward.evidence.report import _fp
    key = app.store("acme").fingerprint_key()
    assert _fp(SSN, key) in finding["fingerprints"]


def test_upload_formats_and_limits(tmp_path):
    from google.protobuf.json_format import ParseDict
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
        ExportTraceServiceRequest,
    )

    app = App(_config(tmp_path, max_body_bytes=4000))
    doc = violation_doc()
    # protobuf, as the OpenTelemetry exporters send it (ids are bytes)
    pb = json.loads(json.dumps(doc))
    for s in pb["resourceSpans"][0]["scopeSpans"][0]["spans"]:
        import base64
        s["traceId"] = base64.b64encode(bytes.fromhex(s["traceId"])).decode()
        s["spanId"] = base64.b64encode(bytes.fromhex(s["spanId"])).decode()
    body = ParseDict(pb, ExportTraceServiceRequest()).SerializeToString()
    r = call(app, "POST", "/v1/traces", "acme-app", body,
             **{"Content-Type": "application/x-protobuf"})
    assert r.status == 200 and r.headers["Content-Type"] == "application/x-protobuf"
    spans = app.store("acme").spans(T0 - 10**9, T0 + 10**9)
    assert {s.trace_id for s in spans} == {"a" * 32}  # stored as hex
    # gzip
    gz = gzip.compress(json.dumps(violation_doc("b" * 32)).encode())
    r = call(app, "POST", "/v1/traces", "acme-app", gz,
             **{"Content-Type": "application/json", "Content-Encoding": "gzip"})
    assert r.status == 200
    # a small body that inflates past the limit
    bomb = gzip.compress(b"{" + b" " * 100_000 + b"}")
    assert call(app, "POST", "/v1/traces", "acme-app", bomb, **{
        "Content-Type": "application/json", "Content-Encoding": "gzip"}).status == 413
    for ctype, body, status in [("text/plain", b"{}", 415), ("application/json", b"[1]", 400),
                                ("application/json", b"{", 400),
                                ("application/x-protobuf", b"\xff\xff\xff", 400),
                                ("application/json", b"{}", 400)]:
        assert call(app, "POST", "/v1/traces", "acme-app", body,
                    **{"Content-Type": ctype}).status == status, (ctype, body)


def test_mask_string_keeps_the_longest_overlapping_match():
    text, hits = ingest.mask_string("card 4111 1111 1111 1111 and 555-123-4567")
    assert text == "card [CREDIT_CARD] and [PHONE_NUMBER]"
    assert [k for k, _ in hits] == ["CREDIT_CARD", "PHONE_NUMBER"]
    # a phone number inside an email address: one replacement, not two that collide
    text, hits = ingest.mask_string("mail 555-123-4567@x.example now")
    assert text == "mail [EMAIL_ADDRESS] now" and [k for k, _ in hits] == ["EMAIL_ADDRESS"]


# --- report and audit -----------------------------------------------------------------

def _iso(ns):
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ns / 1e9, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def test_report_endpoint(app):
    call(app, "POST", "/v1/traces", "acme-app", violation_doc())
    win = f"start={_iso(T0 - 10**9)}&end={_iso(T0 + 10**9)}"
    r = call(app, "GET", f"/v1/report?{win}&frameworks=gdpr", "acme-dpo")
    assert r.status == 200 and r.headers["Content-Type"].startswith("text/html")
    assert b"acme" in r.body and b"GDPR" in r.body
    data = js(call(app, "GET", f"/v1/report?{win}&format=json", "acme-dpo"))
    assert data["totals"]["tool_calls"] == 2 and data["totals"]["violations"] == 1
    ev = data["evidence_log"]
    assert ev["violations_in_window"] == ev["violations_found_in_log"] == 1
    assert ev["path"] == "control plane, tenant acme" and "tenants" not in json.dumps(ev)
    assert call(app, "GET", "/v1/report?since=forever", "acme-dpo").status == 400
    assert call(app, "GET", "/v1/report?format=pdf", "acme-dpo").status == 400


def test_audit_endpoint_uses_the_tenant_policy_and_home(app):
    tools = {"tools": [
        {"name": "get_customer", "outputSchema": {"properties": {"email": {"type": "string"}}}},
        {"name": "send_email", "inputSchema": {"properties": {"to": {"type": "string"}}}},
    ]}
    call(app, "PUT", "/v1/policy", "acme-ops",
         {"destinations": {"get_customer": "internal", "send_email": ["external", "us"]}})
    call(app, "POST", "/v1/traces", "acme-app", violation_doc())
    res = js(call(app, "POST", "/v1/audit", "acme-dpo", {"tools": tools, "since": "100000d"}))
    assert res["policy_version"] == 1 and res["unmapped"] == []
    row = res["paths"][0]
    assert row["path"] == ["get_customer", "send_email"] and row["cross_border"] is True
    assert row["observed"]["runs"] == 1
    # globex has no policy: both tools unmapped, no traces
    res2 = js(call(app, "POST", "/v1/audit", "globex-ops", {"tools": tools}))
    assert res2["unmapped"] == ["get_customer", "send_email"] and res2["summary"]["observed"] == 0
    assert call(app, "POST", "/v1/audit", "acme-dpo", {"tool": []}).status == 400
    r = call(app, "POST", "/v1/audit?format=md", "acme-dpo", {"tools": tools})
    assert r.body.startswith(b"# Data over-exposure audit")


# --- over a real socket, with the SDK's own exporter and client -------------------------

@pytest.fixture
def server(tmp_path):
    app = App(_config(tmp_path))
    httpd = serve(app, "127.0.0.1", 0)
    url = f"http://127.0.0.1:{httpd.server_address[1]}"
    yield app, url
    httpd.shutdown()
    httpd.server_close()


def test_http_server_with_the_otlp_exporter(server):
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor

    app, url = server
    provider = TracerProvider(resource=Resource.create({"service.name": "bot"}))
    provider.add_span_processor(SimpleSpanProcessor(OTLPSpanExporter(
        endpoint=url + "/v1/traces", headers={"Authorization": f"Bearer {TOK['acme-app']}"})))
    with provider.get_tracer("t").start_as_current_span("send_email") as sp:
        sp.set_attribute("taintward.destination", "external")
        sp.set_attribute("gen_ai.tool.call.arguments", f'{{"body": "{SSN}"}}')
    provider.shutdown()
    spans = app.store("acme").spans(0, time.time_ns() + 10**9)
    assert len(spans) == 1 and span_tenant(spans[0]) == "acme"
    assert SSN not in json.dumps(spans[0].attrs)
    # body limits are checked before the body is read
    req = urllib.request.Request(url + "/v1/traces", data=b"x", method="POST", headers={
        "Authorization": f"Bearer {TOK['acme-app']}", "Content-Type": "application/json",
        "Content-Length": str(10**9)})
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req, timeout=5)
    assert e.value.code == 413


def test_sdk_client_cache_and_refresh(server, tmp_path, monkeypatch):
    from taintward.sdk.control import ControlError, refresh_ward, ward_from_control

    app, url = server
    call(app, "PUT", "/v1/policy", "acme-ops",
         {"destinations": {"lookup": "internal", "send": ["external", "us"]},
          "default_destination": "log"})
    cache = tmp_path / "policy-cache.json"
    ward = ward_from_control(url, TOK["acme-app"], cache=cache)
    assert ward.policy_for("lookup").destination == "internal"
    assert ward.policy_for("send").jurisdiction == "us"
    assert ward.policy_for("other").destination == "log" and ward.policy_version == 1
    # a new version is applied by refresh; an unchanged one costs a 304
    assert refresh_ward(ward) is False
    call(app, "PUT", "/v1/policy", "acme-ops", {"destinations": {"lookup": "external"}})
    assert refresh_ward(ward) is True
    assert ward.policy_for("lookup").destination == "external" and ward.policy_version == 2
    assert ward.policy_for("other").destination == "external"
    # control plane down: the cached policy is used
    dead = "http://127.0.0.1:9"
    w2 = ward_from_control(dead, TOK["acme-app"], cache=cache)
    assert w2.policy_version == 2 and w2.policy_for("lookup").destination == "external"
    # down and no cache: every tool is external
    w3 = ward_from_control(dead, TOK["acme-app"], cache=tmp_path / "none.json")
    assert w3.policy_version is None and w3.policy_for("lookup").destination == "external"
    # a wrong token is an error, not an empty policy
    from taintward.sdk.control import ControlClient
    with pytest.raises(ControlError, match="401"):
        ControlClient(url, "wrong").fetch()
    with pytest.raises(ControlError):
        ControlClient("ftp://x", "t")
    monkeypatch.delenv("TAINTWARD_CONTROL_URL", raising=False)
    with pytest.raises(ControlError):
        ControlClient(None, "t")


def test_apply_policy_keeps_the_old_policy_on_a_bad_document():
    from taintward.sdk.integrations import Ward
    ward = Ward({"a": "internal"})
    with pytest.raises(ValueError):
        ward.apply_policy({"destinations": {"a": "external", "b": "nowhere"}})
    assert ward.policy_for("a").destination == "internal"


# --- tenant on spans, report filter, tenant vault --------------------------------------

def test_tenant_on_every_span_and_report_filter(tmp_path, monkeypatch):
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    from taintward.sdk import instrumentation as ins

    provider, mem = TracerProvider(), InMemorySpanExporter()
    provider.add_span_processor(ins._TenantSpanProcessor("acme"))
    provider.add_span_processor(SimpleSpanProcessor(mem))
    provider.get_tracer("t").start_span("x").end()
    assert mem.get_finished_spans()[0].attributes["taintward.tenant"] == "acme"
    monkeypatch.setenv("TAINTWARD_TENANT", "../etc")
    with pytest.raises(ValueError):
        ins.tenant_from_env()

    from taintward.evidence.report import main as report_main
    f = tmp_path / "spans.jsonl"
    a, b = violation_doc("a" * 32, **{"taintward.tenant": "acme"}), violation_doc("b" * 32)
    for s in b["resourceSpans"][0]["scopeSpans"][0]["spans"]:
        s["attributes"].append({"key": "taintward.tenant", "value": {"stringValue": "globex"}})
    f.write_text(json.dumps(a) + "\n" + json.dumps(b) + "\n")
    assert {span_tenant(s) for s in spans_from_otlp(a) + spans_from_otlp(b)} == {"acme", "globex"}
    out = tmp_path / "r.json"
    report_main(["--source", "otlp-file", "--otlp-file", str(f), "--tenant", "globex",
                 "--start", _iso(T0 - 10**9), "--end", _iso(T0 + 10**9),
                 "--format", "json", "--out", str(out)])
    data = json.loads(out.read_text())
    assert data["totals"]["tool_calls"] == 2 and data["totals"]["runs"] == 1


KEY_A = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
KEY_B = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"


def test_tenant_vault_keeps_tenants_apart(tmp_path, monkeypatch):
    monkeypatch.setenv("TAINTWARD_VAULT_KEY", KEY_A)
    from taintward.sdk.vault import SQLiteVault, TenantVault, get_vault

    db = str(tmp_path / "shared.db")
    a = TenantVault(SQLiteVault(db, KEY_A), "acme")
    b = TenantVault(SQLiteVault(db, KEY_B), "globex")
    a.put("TOK1", "alice@acme.example", subject="alice")
    b.put("TOK1", "bob@globex.example", subject="alice")  # same token and subject
    assert a.get("TOK1") == "alice@acme.example"
    assert b.get("TOK1") == "bob@globex.example"
    assert TenantVault(SQLiteVault(db, KEY_A), "other").get("TOK1") is None
    assert a.forget_subject("alice") == 1
    assert a.get("TOK1") is None and b.get("TOK1") == "bob@globex.example"
    # resealing one tenant's rows does not touch (or fail on) the other's
    a.put("TOK2", "x", subject="s")
    a2 = TenantVault(SQLiteVault(db, KEY_B.replace("f", "e", 1)), "acme")
    with pytest.raises(Exception):
        a2.get("TOK2")  # new key only: old rows need the old key in the ring
    assert b.reseal() == 0 and a.reseal() == 0
    # get_vault wraps shared backends only
    assert isinstance(get_vault(f"sqlite://{db}", tenant="acme"), TenantVault)
    assert not isinstance(get_vault("memory", tenant="acme"), TenantVault)
    with pytest.raises(ValueError):
        TenantVault(SQLiteVault(db, KEY_A), "a/b")


def test_init_with_the_control_plane(server, monkeypatch):
    from taintward.sdk import instrumentation as ins
    from taintward.sdk import integrations as tw

    app, url = server
    call(app, "PUT", "/v1/policy", "acme-ops", {"destinations": {"lookup": "internal"}})
    monkeypatch.setenv("TAINTWARD_CONTROL_URL", url)
    monkeypatch.setenv("TAINTWARD_CONTROL_TOKEN", TOK["acme-app"])
    seen = {}

    def fake_tracing(service, **kw):
        seen.update(kw, service=service)
        return None
    monkeypatch.setattr(ins, "configure_tracing", fake_tracing)
    try:
        ward = tw.init("bot", tenant="acme")
        assert ward.policy_for("lookup").destination == "internal" and ward.policy_version == 1
        # spans go to the control plane, with the token
        assert seen["endpoint"] == url + "/v1/traces"
        assert seen["headers"] == {"Authorization": f"Bearer {TOK['acme-app']}"}
        assert seen["tenant"] == "acme"
        # an explicit endpoint (your own collector) is kept, without the token
        tw.init("bot", endpoint="http://collector:4318/v1/traces")
        assert seen["endpoint"] == "http://collector:4318/v1/traces" and seen["headers"] is None
        with pytest.raises(ValueError, match="pass no destinations"):
            tw.init("bot", destinations={"x": "internal"})
        # off: the local map is used
        assert tw.init("bot", destinations={"x": "internal"}, control=False).policy_for(
            "lookup").destination == "external"
    finally:
        tw._GLOBAL = None
