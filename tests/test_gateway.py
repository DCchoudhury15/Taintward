"""Tests for the Taintward MCP gateway (taintward/gateway/).

Offline: the example HR upstream runs in process (mcp in-memory transport)
or as a stdio subprocess; nothing talks to the network.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import anyio
import pytest

mcp = pytest.importorskip("mcp")

from mcp import Client, StdioServerParameters  # noqa: E402
from mcp.shared.exceptions import MCPError  # noqa: E402
from opentelemetry.sdk.trace import TracerProvider  # noqa: E402
from opentelemetry.sdk.trace.export import SimpleSpanProcessor  # noqa: E402
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (  # noqa: E402
    InMemorySpanExporter,
)

from taintward.gateway import BLOCKED_ERROR_CODE, Gateway, parse_config  # noqa: E402
from taintward.gateway.config import ConfigError, load_config  # noqa: E402
from taintward.gateway.examples import hr_server  # noqa: E402
from taintward.gateway.policy import (  # noqa: E402
    NON_ADEQUATE_JURISDICTIONS,
    RULE_NAMES,
    SENSITIVE_SINKS,
    PolicyInput,
    evaluate,
)
from taintward.sdk.instrumentation import (  # noqa: E402
    ATTR_DEST,
    ATTR_JURISDICTION,
    ATTR_VIOLATION,
)
from taintward.sdk.taint import ATTR_CLASSES, ATTR_SENSITIVE  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
REGO = REPO / "collector" / "policy" / "pii_egress.rego"
SSN = hr_server.SSN
AWS_KEY = hr_server.AWS_KEY
RAW_BODY = f"Employee SSN is {SSN} and the key is {AWS_KEY}"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _config(send_email_mode: str = "redact", **extra):
    cfg = parse_config({
        "upstreams": [{"name": "hr", "command": "python",
                       "args": ["-m", "taintward.gateway.examples.hr_server"]}],
        "defaults": {"destination": "external", "mode": "redact"},
        "tools": [
            {"match": "get_*", "destination": "internal"},
            {"match": "list_*", "destination": "internal"},
            {"match": "send_email", "destination": "external", "mode": send_email_mode,
             **extra},
        ],
    })
    # Run the upstream in process so tests can inspect hr_server.OUTBOX.
    cfg.upstreams[0].server_object = hr_server.mcp
    return cfg


def _tracer():
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return provider.get_tracer("test"), exporter


def _gateway_spans(exporter, tool=None):
    spans = [s for s in exporter.get_finished_spans()
             if s.name.startswith("taintward.gateway ")]
    if tool is not None:
        spans = [s for s in spans if s.attributes.get("gen_ai.tool.name") == tool]
    return spans


def _run(cfg, body):
    """Run ``await body(client)`` against a gateway built from cfg; return
    the span exporter."""
    tracer, exporter = _tracer()
    server = Gateway(cfg, tracer=tracer).build_server()

    async def main():
        async with Client(server) as client:
            await body(client)

    anyio.run(main)
    return exporter


def _text(result) -> str:
    return "\n".join(getattr(b, "text", "") for b in result.content) + json.dumps(
        result.structured_content, default=str)


@pytest.fixture(autouse=True)
def _clear_outbox():
    hr_server.OUTBOX.clear()
    yield
    hr_server.OUTBOX.clear()


# ---------------------------------------------------------------------------
# policy: Python mirror of pii_egress.rego
# ---------------------------------------------------------------------------

def _rego_set(name: str) -> set[str]:
    src = REGO.read_text()
    m = re.search(rf"^{name}\s*:=\s*\{{([^}}]*)\}}", src, re.M)
    assert m, f"set {name} not found in {REGO}"
    return set(re.findall(r'"([^"]+)"', m.group(1)))


def test_policy_sets_match_rego():
    assert _rego_set("sensitive_sinks") == set(SENSITIVE_SINKS)
    assert _rego_set("non_adequate_jurisdictions") == set(NON_ADEQUATE_JURISDICTIONS)


def test_policy_rule_names_match_rego():
    src = REGO.read_text()
    assert set(re.findall(r'"rule":\s*"([^"]+)"', src)) == set(RULE_NAMES)
    # The rule heads the Python module mirrors. A new rule in the Rego file
    # must be mirrored in taintward/gateway/policy.py (and added here).
    heads = set(re.findall(r"^([a-z_]+)(?:\([^)]*\))?\s+(?:contains|if)\b", src, re.M))
    assert heads == {"has_class", "violation", "transfer_violation", "redact", "deny"}


def _grid():
    for sensitive in (True, False):
        for classes in ("", "pii", "secret", "pii,secret"):
            for dest in ("internal", "external", "llm", "log", "rag"):
                for jur in ("", "us", "eu"):
                    yield PolicyInput(sensitive=sensitive, classes=classes,
                                      destination=dest, jurisdiction=jur, tool="t")


def test_policy_rules():
    d = evaluate(PolicyInput(True, "pii", "external", "us"))
    assert d.redact and d.rules() == ["pii_egress", "transfer"]
    assert not evaluate(PolicyInput(True, "secret", "internal", "")).is_violation
    assert evaluate(PolicyInput(True, "secret", "log", "")).rules() == ["pii_egress"]
    assert evaluate(PolicyInput(True, "pii", "rag", "us")).rules() == ["transfer"]
    assert evaluate(PolicyInput(False, "", "external", "")).violations == []


@pytest.mark.skipif(shutil.which("opa") is None, reason="opa binary not on PATH")
def test_policy_matches_opa_eval():
    for inp in _grid():
        out = subprocess.run(
            ["opa", "eval", "-f", "json", "-d", str(REGO), "--stdin-input",
             "data.taintward.decision"],
            input=json.dumps(inp.as_dict()), capture_output=True, text=True, check=True,
        )
        val = json.loads(out.stdout)["result"][0]["expressions"][0]["value"]
        ours = evaluate(inp)
        key = lambda v: json.dumps(v, sort_keys=True)  # noqa: E731
        assert sorted(val["violations"], key=key) == sorted(ours.violations, key=key), inp
        assert val["redact"] == ours.redact, inp


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------

def test_config_globs_defaults_and_validation():
    cfg = _config("block")
    assert cfg.policy_for("get_employee").destination == "internal"
    assert cfg.policy_for("send_email").mode == "block"
    unknown = cfg.policy_for("upload_file")
    assert unknown.destination == "external" and unknown.mode == "redact"

    cfg2 = parse_config({
        "upstreams": [{"name": "a", "url": "http://localhost:1/mcp"}],
        "tools": [{"match": "x_*", "upstream": "b", "destination": "internal"}],
    })
    assert cfg2.policy_for("x_1", "a").destination == "external"  # upstream filter
    assert cfg2.policy_for("x_1", "b").destination == "internal"

    with pytest.raises(ConfigError):
        parse_config({"upstreams": [{"name": "a", "command": "x"}],
                      "tools": [{"match": "*", "mode": "explode"}]})
    with pytest.raises(ConfigError):
        parse_config({"upstreams": [{"name": "a", "command": "x", "url": "http://x"}]})
    with pytest.raises(ConfigError):
        parse_config({"upstreams": [{"name": "a", "command": "x"}],
                      "tools": [{"match": "*", "destination": "moon"}]})


def test_example_config_loads():
    cfg = load_config(REPO / "taintward" / "gateway" / "example-config.yaml")
    assert cfg.upstreams[0].command == sys.executable
    assert cfg.upstreams[0].cwd == str(REPO)
    assert cfg.policy_for("send_email").mode == "block"
    assert cfg.policy_for("get_employee").destination == "internal"
    assert cfg.policy_for("whatever").destination == "external"


# ---------------------------------------------------------------------------
# gateway behavior (in-memory upstream)
# ---------------------------------------------------------------------------

def test_tools_reexposed_with_same_names_and_schemas():
    upstream_tools = {}
    gateway_tools = {}

    async def direct():
        async with Client(hr_server.mcp) as c:
            upstream_tools.update({t.name: t.input_schema for t in (await c.list_tools()).tools})

    anyio.run(direct)

    async def body(client):
        gateway_tools.update({t.name: t.input_schema for t in (await client.list_tools()).tools})

    _run(_config(), body)
    assert gateway_tools == upstream_tools
    assert {"get_employee", "send_email", "list_departments"} <= set(gateway_tools)


def test_redact_mode_raw_values_never_reach_send_email():
    results = {}

    async def body(client):
        results["emp"] = await client.call_tool("get_employee", {"employee_id": "E100"})
        # The agent tries to mail the raw values (as if it had them in context).
        results["mail"] = await client.call_tool(
            "send_email", {"to": "x@example.org", "subject": "record", "body": RAW_BODY})

    exporter = _run(_config("redact"), body)

    # Nothing raw reached the external tool.
    assert len(hr_server.OUTBOX) == 1
    sent = json.dumps(hr_server.OUTBOX)
    assert SSN not in sent and AWS_KEY not in sent
    assert "[PII]" in hr_server.OUTBOX[0]["body"]
    assert "[SECRET]" in hr_server.OUTBOX[0]["body"]

    # The result the agent saw was masked too.
    emp_text = _text(results["emp"])
    assert SSN not in emp_text and AWS_KEY not in emp_text

    # Spans: same attribute names as the SDK.
    (emp_span,) = _gateway_spans(exporter, "get_employee")
    assert emp_span.attributes[ATTR_DEST] == "internal"
    assert emp_span.attributes[ATTR_SENSITIVE] is True
    assert emp_span.attributes[ATTR_CLASSES] == "pii,secret"
    assert emp_span.attributes[ATTR_VIOLATION] is False
    assert emp_span.attributes["taintward.result.redacted"] is True

    (mail_span,) = _gateway_spans(exporter, "send_email")
    a = mail_span.attributes
    assert a[ATTR_DEST] == "external"
    assert a[ATTR_JURISDICTION] == ""
    assert a[ATTR_VIOLATION] is True
    assert a["taintward.policy.rules"] == "pii_egress"
    assert a["taintward.mode"] == "redact"
    assert a["taintward.blocked"] is False
    assert a["taintward.args.redacted"] is True
    assert a["gen_ai.operation.name"] == "execute_tool"
    for span in (emp_span, mail_span):
        for v in span.attributes.values():
            assert SSN not in str(v) and AWS_KEY not in str(v)


def test_session_taint_flags_later_clean_calls():
    async def body(client):
        await client.call_tool("send_email", {"to": "a@b.c", "subject": "s", "body": "hi"})
        await client.call_tool("get_employee", {"employee_id": "E100"})
        await client.call_tool("send_email", {"to": "a@b.c", "subject": "s", "body": "hi"})

    exporter = _run(_config("redact"), body)
    first, second = _gateway_spans(exporter, "send_email")
    assert first.attributes[ATTR_SENSITIVE] is False
    assert first.attributes[ATTR_VIOLATION] is False
    # Clean args, but the session read sensitive data earlier: tainted.
    assert second.attributes[ATTR_SENSITIVE] is True
    assert second.attributes[ATTR_VIOLATION] is True


def test_block_mode_returns_error_and_sends_nothing():
    errors = []

    async def body(client):
        with pytest.raises(MCPError) as ei:
            await client.call_tool("send_email",
                                   {"to": "x@example.org", "subject": "s", "body": RAW_BODY})
        errors.append(ei.value)
        # Session taint: after a sensitive read, even a clean call is blocked.
        await client.call_tool("get_employee", {"employee_id": "E100"})
        with pytest.raises(MCPError) as ei2:
            await client.call_tool("send_email", {"to": "a@b.c", "subject": "s", "body": "hi"})
        errors.append(ei2.value)

    exporter = _run(_config("block"), body)
    assert hr_server.OUTBOX == []
    assert all(e.code == BLOCKED_ERROR_CODE for e in errors)
    assert "pii_egress" in errors[0].message
    spans = _gateway_spans(exporter, "send_email")
    assert len(spans) == 2
    for s in spans:
        assert s.attributes["taintward.blocked"] is True
        assert s.attributes[ATTR_VIOLATION] is True
        assert SSN not in s.attributes["gen_ai.tool.call.arguments"]


def test_block_mode_allows_clean_call_in_clean_session():
    async def body(client):
        r = await client.call_tool("send_email", {"to": "a@b.c", "subject": "s", "body": "hi"})
        assert not r.is_error

    exporter = _run(_config("block"), body)
    assert hr_server.OUTBOX == [{"to": "a@b.c", "subject": "s", "body": "hi"}]
    (s,) = _gateway_spans(exporter, "send_email")
    assert s.attributes["taintward.blocked"] is False


def test_audit_mode_passes_through_but_records_violation():
    async def body(client):
        await client.call_tool("send_email",
                               {"to": "x@example.org", "subject": "s", "body": RAW_BODY})

    exporter = _run(_config("audit"), body)
    # Raw value passed through (dry run).
    assert hr_server.OUTBOX[0]["body"] == RAW_BODY
    (s,) = _gateway_spans(exporter, "send_email")
    assert s.attributes[ATTR_VIOLATION] is True
    assert s.attributes["taintward.dry_run"] is True
    assert s.attributes["taintward.mode"] == "audit"
    # The span itself never stores the raw value.
    assert SSN not in s.attributes["gen_ai.tool.call.arguments"]
    assert AWS_KEY not in s.attributes["gen_ai.tool.call.arguments"]


def test_transfer_rule_and_passthrough_args():
    async def body(client):
        await client.call_tool("send_email",
                               {"to": "alice@example.com", "subject": "s", "body": RAW_BODY})

    exporter = _run(_config("redact", jurisdiction="us", passthrough_args=["to"]), body)
    msg = hr_server.OUTBOX[0]
    assert msg["to"] == "alice@example.com"  # passthrough: not redacted
    assert SSN not in msg["body"]
    (s,) = _gateway_spans(exporter, "send_email")
    assert s.attributes["taintward.policy.rules"] == "pii_egress,transfer"
    assert s.attributes[ATTR_JURISDICTION] == "us"
    assert "alice@example.com" not in s.attributes["gen_ai.tool.call.arguments"]


def test_internal_destination_gets_reversible_token_not_raw():
    from taintward.sdk.redact import get_redactor

    cfg = _config()
    cfg.rules.insert(0, type(cfg.rules[0])(match="send_email", destination="internal"))

    async def body(client):
        await client.call_tool("send_email", {"to": "a@b.c", "subject": "s", "body": SSN})

    _run(cfg, body)
    token = hr_server.OUTBOX[0]["body"]
    assert token != SSN and len(token) == len(SSN)
    assert get_redactor().reverse(token) == SSN


def test_unknown_tool_is_error():
    async def body(client):
        with pytest.raises(MCPError):
            await client.call_tool("no_such_tool", {})

    _run(_config(), body)


def test_prefix_renames_tools():
    cfg = _config()
    cfg.upstreams[0].prefix = "hr_"
    seen = {}

    async def body(client):
        seen["names"] = {t.name for t in (await client.list_tools()).tools}
        await client.call_tool("hr_list_departments", {})

    exporter = _run(cfg, body)
    assert "hr_get_employee" in seen["names"] and "get_employee" not in seen["names"]
    (s,) = _gateway_spans(exporter, "hr_list_departments")
    # hr_list_departments does not match "list_*": the safe default applies.
    assert s.attributes[ATTR_DEST] == "external"


# ---------------------------------------------------------------------------
# end to end over stdio: client -> `python -m taintward.gateway` -> stdio HR upstream
# ---------------------------------------------------------------------------

def test_cli_stdio_end_to_end(tmp_path):
    outbox = tmp_path / "outbox.jsonl"
    cfg_path = tmp_path / "gw.yaml"
    cfg_path.write_text(
        "upstreams:\n"
        "  - name: hr\n"
        "    command: python\n"
        "    args: [\"-m\", \"taintward.gateway.examples.hr_server\"]\n"
        f"    cwd: {REPO}\n"
        "    env:\n"
        f"      TAINTWARD_HR_OUTBOX: {outbox}\n"
        "tools:\n"
        "  - match: \"get_*\"\n"
        "    destination: internal\n"
        "  - match: send_email\n"
        "    destination: external\n"
        "    mode: redact\n"
        "  - match: \"list_*\"\n"
        "    destination: external\n"
        "    mode: block\n"
    )
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "taintward.gateway", "--config", str(cfg_path)],
        cwd=str(REPO),
    )
    seen = {}

    async def main():
        with anyio.fail_after(180):
            await _session()

    async def _session():
        async with Client(params, read_timeout_seconds=120) as client:
            seen["tools"] = {t.name for t in (await client.list_tools()).tools}
            emp = await client.call_tool("get_employee", {"employee_id": "E100"})
            seen["emp"] = _text(emp)
            await client.call_tool("send_email",
                                   {"to": "x@example.org", "subject": "s", "body": RAW_BODY})
            with pytest.raises(MCPError) as ei:
                await client.call_tool("list_departments", {})
            seen["code"] = ei.value.code

    anyio.run(main)

    assert {"get_employee", "send_email", "list_departments"} <= seen["tools"]
    assert SSN not in seen["emp"] and AWS_KEY not in seen["emp"]
    sent = outbox.read_text()
    assert SSN not in sent and AWS_KEY not in sent
    assert "[PII]" in sent
    assert seen["code"] == BLOCKED_ERROR_CODE
