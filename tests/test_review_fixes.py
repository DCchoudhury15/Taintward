"""Regression tests for the SDK security review findings.

Each block names the finding it covers. The rule for all of them: a raw
sensitive value must never reach a non-internal sink or a span attribute.
"""

from __future__ import annotations

import asyncio
import collections
import json
import logging
from decimal import Decimal

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from taintward.sdk import detect
from taintward.sdk import instrumentation as instr
from taintward.sdk.detect import detect_mapping, mask_value
from taintward.sdk.redact import redact_payload

SSN = "234-12-1234"
SSN_PLAIN = 234121234
AWS = "AKIAIOSFODNN7EXAMPLE"


def _tracer():
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return provider.get_tracer("test"), exporter


def _no_raw(spans, *raws):
    for s in spans:
        for k, v in (s.attributes or {}).items():
            for raw in raws:
                assert str(raw) not in str(v), f"raw value in span attribute {k}"
        for ev in s.events:
            for k, v in (ev.attributes or {}).items():
                for raw in raws:
                    assert str(raw) not in str(v), f"raw value in event attribute {k}"
        desc = s.status.description or ""
        for raw in raws:
            assert str(raw) not in desc


@pytest.fixture(autouse=True)
def _clean_runs():
    instr.end_run()
    yield
    instr.end_run()


# ---------------------------------------------------------------------------
# 2. non-string leaves
# ---------------------------------------------------------------------------

class _Card:
    def __str__(self) -> str:
        return f"customer ssn {SSN}"


def test_int_leaf_with_key_context_is_redacted():
    out = redact_payload({"ssn": SSN_PLAIN}, "external")
    assert out["ssn"] != SSN_PLAIN
    assert str(SSN_PLAIN) not in json.dumps(out)


def test_int_leaf_internal_gets_token_string():
    out = redact_payload({"ssn": SSN_PLAIN}, "internal")
    assert isinstance(out["ssn"], str)
    assert out["ssn"] != str(SSN_PLAIN)


def test_object_leaf_is_redacted():
    out = redact_payload({"card": _Card()}, "external")
    assert isinstance(out["card"], str)
    assert SSN not in out["card"]
    assert "[PII]" in out["card"]


def test_decimal_and_float_leaves_kept_when_clean():
    out = redact_payload({"amount": Decimal("12.50"), "ratio": 0.5, "n": 3, "ok": True}, "external")
    assert out == {"amount": Decimal("12.50"), "ratio": 0.5, "n": 3, "ok": True}


def test_mask_value_masks_non_string_leaves():
    out = mask_value({"ssn": SSN_PLAIN, "card": _Card(), "n": 7})
    assert str(SSN_PLAIN) not in json.dumps(out, default=str)
    assert SSN not in json.dumps(out, default=str)
    assert out["n"] == 7


def test_object_arg_never_reaches_tool_or_span_raw():
    tracer, exporter = _tracer()
    got = {}

    @instr.instrument_tool("send", destination=instr.DEST_EXTERNAL, tracer=tracer)
    def send(card, ssn):
        got["card"], got["ssn"] = card, ssn
        return "ok"

    send(_Card(), ssn=SSN_PLAIN)
    assert SSN not in str(got["card"])
    assert str(SSN_PLAIN) not in str(got["ssn"])
    _no_raw(exporter.get_finished_spans(), SSN, SSN_PLAIN)


def test_jsonable_masks_unknown_objects():
    s = instr._jsonable({"x": _Card()})
    assert SSN not in s
    assert "[PII]" in s


# ---------------------------------------------------------------------------
# 4. boolean env flags
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("1", True), ("true", True), ("TRUE", True), ("yes", True), ("On", True),
    ("0", False), ("false", False), ("False", False), ("no", False), ("off", False),
    ("", False), ("  ", False),
])
def test_env_flag_default_false(monkeypatch, raw, expected):
    from taintward.sdk.envflags import env_flag
    monkeypatch.setenv("TAINTWARD_TEST_FLAG", raw)
    assert env_flag("TAINTWARD_TEST_FLAG", False) is expected


def test_env_flag_unset_and_default_true(monkeypatch):
    from taintward.sdk.envflags import env_flag
    monkeypatch.delenv("TAINTWARD_TEST_FLAG", raising=False)
    assert env_flag("TAINTWARD_TEST_FLAG", False) is False
    assert env_flag("TAINTWARD_TEST_FLAG", True) is True
    monkeypatch.setenv("TAINTWARD_TEST_FLAG", "false")
    assert env_flag("TAINTWARD_TEST_FLAG", True) is False
    # An unknown value keeps the default (safe for a default-on flag).
    monkeypatch.setenv("TAINTWARD_TEST_FLAG", "maybe")
    assert env_flag("TAINTWARD_TEST_FLAG", True) is True
    assert env_flag("TAINTWARD_TEST_FLAG", False) is False


@pytest.mark.parametrize("raw,expected", [("0", False), ("false", False), ("1", True)])
def test_dry_run_env_is_parsed(monkeypatch, raw, expected):
    import importlib
    monkeypatch.setenv("TAINTWARD_DRY_RUN", raw)
    monkeypatch.setenv("TAINTWARD_MASK_IN_SDK", "false")
    mod = importlib.reload(instr)
    try:
        assert mod.DRY_RUN is expected
        assert mod.MASK_IN_PROCESS is False
    finally:
        monkeypatch.delenv("TAINTWARD_DRY_RUN")
        monkeypatch.delenv("TAINTWARD_MASK_IN_SDK")
        importlib.reload(instr)


# ---------------------------------------------------------------------------
# 5. nested taint
# ---------------------------------------------------------------------------

def _nested_tools(tracer):
    @instr.instrument_tool("lookup", destination=instr.DEST_INTERNAL, tracer=tracer)
    def lookup():
        return {"ssn": SSN}

    @instr.instrument_tool("summarize", destination=instr.DEST_INTERNAL, tracer=tracer)
    def summarize():
        lookup()
        return "one record found"

    @instr.instrument_tool("send", destination=instr.DEST_EXTERNAL, tracer=tracer)
    def send(text):
        return "sent"

    return summarize, send


def _span(exporter, name):
    return [s for s in exporter.get_finished_spans() if s.name == name][-1]


def test_nested_taint_inside_run():
    tracer, exporter = _tracer()
    summarize, send = _nested_tools(tracer)
    instr.begin_run("r", tracer=tracer)
    try:
        summarize()
        send("hello")
    finally:
        instr.end_run()
    assert _span(exporter, "send").attributes.get(instr.ATTR_VIOLATION) is True
    assert _span(exporter, "summarize").attributes.get("taintward.sensitive") is True


def test_nested_taint_outside_run():
    tracer, exporter = _tracer()
    summarize, send = _nested_tools(tracer)
    summarize()
    assert instr.current_taint() is not None
    send("hello")
    assert _span(exporter, "send").attributes.get(instr.ATTR_VIOLATION) is True
    assert _span(exporter, "summarize").attributes.get("taintward.sensitive") is True


def test_nested_taint_outside_run_through_asyncio_task():
    tracer, exporter = _tracer()

    @instr.instrument_tool("lookup", destination=instr.DEST_INTERNAL, tracer=tracer)
    async def lookup():
        return {"ssn": SSN}

    @instr.instrument_tool("summarize", destination=instr.DEST_INTERNAL, tracer=tracer)
    async def summarize():
        await asyncio.gather(asyncio.create_task(lookup()))
        return "done"

    @instr.instrument_tool("send", destination=instr.DEST_EXTERNAL, tracer=tracer)
    async def send(text):
        return "sent"

    async def main():
        await summarize()
        await send("hi")

    asyncio.run(main())
    assert _span(exporter, "send").attributes.get(instr.ATTR_VIOLATION) is True


# ---------------------------------------------------------------------------
# 9. degraded detection
# ---------------------------------------------------------------------------

@pytest.fixture
def broken_model(monkeypatch):
    """Simulate a spaCy / Presidio model that fails to load."""
    def boom():
        raise OSError("can't find model 'en_core_web_sm'")
    monkeypatch.setattr(detect, "_get_analyzer", boom)
    detect._reset_engine()
    yield
    monkeypatch.undo()
    detect._reset_engine()


def test_health_ok_normally():
    h = detect.health()
    assert h["ok"] is True
    assert h["mode"] == "full"


def test_degraded_falls_back_to_regex(broken_model, caplog):
    with caplog.at_level(logging.ERROR, logger="taintward.detect"):
        dets = detect.detect_text(f"ssn {SSN}, key {AWS}, mail a.b@example.com")
        detect.detect_text("again 345-23-4567")
    types = {d.entity_type for d in dets}
    assert "AWS_ACCESS_KEY" in types
    assert any("SSN" in t for t in types)
    assert "EMAIL_ADDRESS" in types
    h = detect.health()
    assert h["ok"] is False
    assert h["mode"] == "regex_only"
    assert "en_core_web_sm" in h["error"]
    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(errors) == 1  # logged once
    assert redact_payload({"x": f"ssn {SSN}"}, "external") == {"x": "ssn [PII]"}
    # Key context recognizers still work without NER.
    assert redact_payload({"ssn": "234121234"}, "external") == {"ssn": "[PII]"}


def test_degraded_without_presidio_uses_stdlib_regex(monkeypatch):
    monkeypatch.setattr(detect, "_PRESIDIO_OK", False)
    detect._reset_engine()
    try:
        dets = detect.detect_text(f"ssn {SSN} key {AWS} card 4111 1111 1111 1111 a@b.io")
        types = {d.entity_type for d in dets}
        assert {"AWS_ACCESS_KEY", "CREDIT_CARD", "EMAIL_ADDRESS"} <= types
        assert any("SSN" in t for t in types)
        assert detect.health()["mode"] == "regex_only"
    finally:
        monkeypatch.undo()
        detect._reset_engine()


def test_fail_closed_blocks_non_internal_calls(broken_model, monkeypatch):
    monkeypatch.setattr(instr, "FAIL_CLOSED", True)
    tracer, _ = _tracer()
    ran = []

    @instr.instrument_tool("send", destination=instr.DEST_EXTERNAL, tracer=tracer)
    def send(x):
        ran.append(x)

    @instr.instrument_tool("store", destination=instr.DEST_INTERNAL, tracer=tracer)
    def store(x):
        ran.append(x)

    with pytest.raises(detect.DetectionDegradedError):
        send("hi")
    store("hi")
    assert ran == ["hi"]


def test_fail_closed_off_by_default(broken_model):
    tracer, _ = _tracer()

    @instr.instrument_tool("send", destination=instr.DEST_EXTERNAL, tracer=tracer)
    def send(x):
        return x

    assert send("hi") == "hi"


# ---------------------------------------------------------------------------
# 10. dict keys
# ---------------------------------------------------------------------------

def test_detect_mapping_scans_keys():
    assert detect_mapping({SSN: "x"})


def test_redact_payload_redacts_keys():
    out = redact_payload({SSN: "x", "plain": 1}, "external")
    assert SSN not in json.dumps(out)
    assert out["plain"] == 1
    assert "x" in out.values()


def test_redacted_keys_stay_unique():
    out = redact_payload({SSN: 1, "345-23-4567": 2, "[PII]": 3}, "external")
    assert len(out) == 3
    assert sorted(out.values()) == [1, 2, 3]
    assert out["[PII]"] == 3
    assert SSN not in json.dumps(out)


def test_mask_value_masks_keys():
    out = mask_value({SSN: {"inner " + AWS: 1}})
    s = json.dumps(out)
    assert SSN not in s and AWS not in s


def test_structure_walker_redacts_keys():
    from taintward.sdk.integrations._payload import redact_structure
    out = redact_structure({"role": "user", "meta": {SSN: "x"}}, "llm")
    assert SSN not in json.dumps(out)
    assert out["role"] == "user"


def test_tool_span_has_no_raw_key():
    tracer, exporter = _tracer()

    @instr.instrument_tool("send", destination=instr.DEST_EXTERNAL, tracer=tracer)
    def send(data):
        assert SSN not in json.dumps(data)
        return {SSN: "echo"}

    send({SSN: "x"})
    _no_raw(exporter.get_finished_spans(), SSN)


# ---------------------------------------------------------------------------
# 11. namedtuple, sets and other containers
# ---------------------------------------------------------------------------

Person = collections.namedtuple("Person", "name ssn")


def test_namedtuple_kept():
    p = Person("x", SSN)
    out = redact_payload(p, "external")
    assert isinstance(out, Person)
    assert out.ssn == "[PII]"
    m = mask_value(p)
    assert isinstance(m, Person)
    assert m.ssn == "[PII]"


def test_sets_and_ordered_dict():
    out = redact_payload({"s": {SSN, "a"}, "f": frozenset({SSN})}, "external")
    assert isinstance(out["s"], set) and SSN not in out["s"]
    assert isinstance(out["f"], frozenset) and SSN not in out["f"]
    od = collections.OrderedDict([("a", SSN), ("b", "c")])
    r = redact_payload(od, "external")
    assert isinstance(r, collections.OrderedDict)
    assert list(r) == ["a", "b"] and r["a"] == "[PII]"
    dd = collections.defaultdict(list, {"a": [SSN]})
    r = mask_value(dd)
    assert isinstance(r, collections.defaultdict) and r["a"] == ["[PII]"]
    assert r.default_factory is list
    m = mask_value({"s": {SSN}})
    assert m == {"s": {"[PII]"}}


# ---------------------------------------------------------------------------
# 12. a tool that raises
# ---------------------------------------------------------------------------

def test_raising_tool_records_violation_and_no_raw_exception():
    tracer, exporter = _tracer()

    @instr.instrument_tool("send", destination=instr.DEST_EXTERNAL, tracer=tracer)
    def send(body):
        raise ValueError(f"could not send to {SSN}")

    with pytest.raises(ValueError):
        send(f"ssn {SSN}")
    s = _span(exporter, "send")
    assert s.attributes.get(instr.ATTR_VIOLATION) is True
    assert s.attributes.get(instr.ATTR_DEST) == "external"
    assert s.attributes.get("taintward.sensitive") is True
    assert any(ev.name == "exception" for ev in s.events)
    assert "[PII]" in s.attributes.get("taintward.tool.error", "")
    _no_raw([s], SSN)


def test_raising_async_tool_records_violation():
    tracer, exporter = _tracer()

    @instr.instrument_tool("send", destination=instr.DEST_EXTERNAL, tracer=tracer)
    async def send(body):
        raise RuntimeError(f"bad {SSN}")

    with pytest.raises(RuntimeError):
        asyncio.run(send(f"ssn {SSN}"))
    s = _span(exporter, "send")
    assert s.attributes.get(instr.ATTR_VIOLATION) is True
    _no_raw([s], SSN)


# ---------------------------------------------------------------------------
# 16. minor
# ---------------------------------------------------------------------------

def test_taint_source_span_is_set():
    tracer, exporter = _tracer()

    @instr.instrument_tool("lookup", destination=instr.DEST_INTERNAL, tracer=tracer)
    def lookup():
        return {"ssn": SSN}

    @instr.instrument_tool("send", destination=instr.DEST_EXTERNAL, tracer=tracer)
    def send(x):
        return "ok"

    instr.begin_run("r", tracer=tracer)
    try:
        lookup()
        send("x")
    finally:
        instr.end_run()
    src = format(_span(exporter, "lookup").context.span_id, "016x")
    assert _span(exporter, "send").attributes.get(instr.ATTR_TaintSource) == src


def test_taint_source_survives_baggage():
    from taintward.sdk import taint as tnt
    label = tnt.TaintLabel.of({detect.Sensitivity.PII}, source_span_id="00000000000000ab")
    back = tnt.TaintLabel.from_baggage(label.to_baggage())
    assert back.source_span_id == "00000000000000ab"


def test_no_thread_local_run_state():
    assert not hasattr(instr, "_run_state")


def test_runs_in_concurrent_asyncio_tasks_do_not_clobber():
    tracer, exporter = _tracer()

    @instr.instrument_tool("lookup", destination=instr.DEST_INTERNAL, tracer=tracer)
    async def lookup(n):
        await asyncio.sleep(0)
        return {"ssn": SSN} if n == 0 else {"n": n}

    @instr.instrument_tool("send", destination=instr.DEST_EXTERNAL, tracer=tracer)
    async def send(n):
        await asyncio.sleep(0)
        return "ok"

    async def one(n):
        instr.begin_run(f"run{n}", tracer=tracer)
        try:
            await lookup(n)
            await asyncio.sleep(0)
            await send(n)
        finally:
            instr.end_run()

    async def main():
        await asyncio.gather(one(0), one(1), one(2))

    asyncio.run(main())
    roots = [s for s in exporter.get_finished_spans() if s.name.startswith("run")]
    assert len(roots) == 3
    sends = [s for s in exporter.get_finished_spans() if s.name == "send"]
    flagged = sorted(bool(s.attributes.get(instr.ATTR_VIOLATION)) for s in sends)
    assert flagged == [False, False, True]


def test_nested_begin_run_keeps_outer_run():
    tracer, exporter = _tracer()
    instr.begin_run("outer", tracer=tracer)
    instr.begin_run("inner", tracer=tracer)
    instr.end_run()
    instr.end_run()
    names = sorted(s.name for s in exporter.get_finished_spans())
    assert names == ["inner", "outer"]


# ---------------------------------------------------------------------------
# 3. taintward.args_redacted marker
# ---------------------------------------------------------------------------

def test_args_redacted_marker_set():
    tracer, exporter = _tracer()

    @instr.instrument_tool("send", destination=instr.DEST_EXTERNAL, tracer=tracer)
    def send(x):
        return "ok"

    send(f"ssn {SSN}")
    s = _span(exporter, "send")
    assert s.attributes.get(instr.ATTR_ARGS_REDACTED) is True


def test_args_redacted_marker_absent_in_dry_run(monkeypatch):
    monkeypatch.setattr(instr, "DRY_RUN", True)
    tracer, exporter = _tracer()
    got = []

    @instr.instrument_tool("send", destination=instr.DEST_EXTERNAL, tracer=tracer)
    def send(x):
        got.append(x)

    send(f"ssn {SSN}")
    s = _span(exporter, "send")
    assert instr.ATTR_ARGS_REDACTED not in s.attributes
    assert got == [f"ssn {SSN}"]  # dry run: the tool gets the raw value
    _no_raw([s], SSN)  # but the span never does


def test_args_redacted_marker_absent_without_sdk_masking(monkeypatch):
    monkeypatch.setattr(instr, "MASK_IN_PROCESS", False)
    tracer, exporter = _tracer()

    @instr.instrument_tool("send", destination=instr.DEST_EXTERNAL, tracer=tracer)
    def send(x):
        return "ok"

    send(f"ssn {SSN}")
    assert instr.ATTR_ARGS_REDACTED not in _span(exporter, "send").attributes


def test_output_masked_without_sdk_masking(monkeypatch):
    # gap G5: the collector only knows regex types, so a name in a tool
    # output must be masked in the process even with TAINTWARD_MASK_IN_SDK=0
    monkeypatch.setattr(instr, "MASK_IN_PROCESS", False)
    tracer, exporter = _tracer()

    @instr.instrument_tool("lookup", destination=instr.DEST_INTERNAL, tracer=tracer)
    def lookup(x):
        return f"Employee Alice Lee, ssn {SSN}"

    lookup("1")
    _no_raw([_span(exporter, "lookup")], SSN)
    assert "Alice Lee" not in str(dict(_span(exporter, "lookup").attributes))


def test_args_redacted_marker_not_on_llm_message_spans():
    tracer, exporter = _tracer()
    with instr.GuardedCall("chat m", destination=instr.DEST_LLM, tracer=tracer,
                           kwargs={"messages": [{"role": "user", "content": "hi"}]},
                           input_attr="gen_ai.input.messages") as call:
        call.record_result("ok")
    assert instr.ATTR_ARGS_REDACTED not in _span(exporter, "chat m").attributes


def test_guarded_call_passthrough_not_raw_on_span():
    tracer, exporter = _tracer()
    with instr.GuardedCall("send", destination=instr.DEST_EXTERNAL, tracer=tracer,
                           kwargs={"to": "alice@example.com", "body": f"ssn {SSN}"},
                           passthrough={"to"}) as call:
        assert call.kwargs["to"] == "alice@example.com"
        call.record_result("ok")
    s = _span(exporter, "send")
    assert "alice@example.com" not in s.attributes["gen_ai.tool.call.arguments"]
    assert s.attributes.get(instr.ATTR_ARGS_REDACTED) is True


def test_gateway_sets_args_redacted_marker():
    pytest.importorskip("mcp")
    import anyio
    from mcp import Client

    from taintward.gateway import Gateway, parse_config
    from taintward.gateway.examples import hr_server

    def cfg(mode):
        c = parse_config({
            "upstreams": [{"name": "hr", "command": "python",
                           "args": ["-m", "taintward.gateway.examples.hr_server"]}],
            "defaults": {"destination": "external", "mode": mode},
            "tools": [{"match": "send_email", "destination": "external", "mode": mode}],
        })
        c.upstreams[0].server_object = hr_server.mcp
        return c

    def run(mode):
        tracer, exporter = _tracer()
        server = Gateway(cfg(mode), tracer=tracer).build_server()

        async def main():
            async with Client(server) as client:
                await client.call_tool("send_email",
                                       {"to": "a@b.c", "subject": "s", "body": f"ssn {SSN}"})
        anyio.run(main)
        hr_server.OUTBOX.clear()
        (s,) = [x for x in exporter.get_finished_spans() if x.name.startswith("taintward.gateway")]
        return s

    assert run("redact").attributes.get("taintward.args_redacted") is True
    assert "taintward.args_redacted" not in run("audit").attributes


def test_langchain_tool_sets_marker():
    pytest.importorskip("langchain_core")
    from langchain_core.tools import tool

    from taintward.sdk.integrations import Ward

    tracer, exporter = _tracer()

    @tool
    def send_email(body: str) -> str:
        """Send an email."""
        return "sent"

    ward = Ward({"send_email": "external"}, tracer=tracer, placeholders=False)
    (wrapped,) = ward.wrap_langchain_tools([send_email])
    wrapped.invoke({"body": f"ssn {SSN}"})
    s = _span(exporter, "send_email")
    assert s.attributes.get(instr.ATTR_ARGS_REDACTED) is True
    _no_raw([s], SSN)


def test_nested_taint_inside_ward_run():
    from taintward.sdk.integrations import Ward

    tracer, exporter = _tracer()
    summarize, send = _nested_tools(tracer)
    ward = Ward({}, tracer=tracer, placeholders=False)
    with ward.run("r"):
        summarize()
        send("hello")
    assert _span(exporter, "send").attributes.get(instr.ATTR_VIOLATION) is True


def test_nested_call_then_egress_inside_same_outer_call():
    tracer, exporter = _tracer()

    @instr.instrument_tool("lookup", destination=instr.DEST_INTERNAL, tracer=tracer)
    def lookup():
        return {"ssn": SSN}

    @instr.instrument_tool("send", destination=instr.DEST_EXTERNAL, tracer=tracer)
    def send(text):
        return "sent"

    @instr.instrument_tool("agent_step", destination=instr.DEST_INTERNAL, tracer=tracer)
    def agent_step():
        lookup()
        send("summary only")
        return "done"

    agent_step()
    assert _span(exporter, "send").attributes.get(instr.ATTR_VIOLATION) is True


def test_gateway_fail_closed(broken_model, monkeypatch):
    pytest.importorskip("mcp")
    import anyio
    from mcp import Client, MCPError

    from taintward.gateway import Gateway, parse_config
    from taintward.gateway.examples import hr_server

    monkeypatch.setattr(instr, "FAIL_CLOSED", True)
    c = parse_config({
        "upstreams": [{"name": "hr", "command": "python",
                       "args": ["-m", "taintward.gateway.examples.hr_server"]}],
        "tools": [{"match": "send_email", "destination": "external", "mode": "redact"}],
    })
    c.upstreams[0].server_object = hr_server.mcp
    tracer, _ = _tracer()
    server = Gateway(c, tracer=tracer).build_server()

    async def main():
        async with Client(server) as client:
            with pytest.raises(MCPError, match="degraded"):
                await client.call_tool("send_email",
                                       {"to": "a@b.c", "subject": "s", "body": "hi"})
    anyio.run(main)
    assert hr_server.OUTBOX == []
