"""Tests for what the second read-through found.

* A value that makes a recognizer raise must not switch detection off for
  the payload it is in: the value is masked whole, the rest is scanned.
* The evidence CLI ``record`` uses its ClickHouse flags and every service
  for the single-file log too, and prints one line when the source fails.
* The compliance table does not call an unchecked log "verification failed".
* ``taintward-fix`` sees ``client.chat.completions.create`` style calls and
  knows a client wrapped with ``protect_openai``.
* ``taintward-audit`` reads a saved JSON-RPC ``tools/list`` response.
"""

from __future__ import annotations

import ast
import json
import textwrap
import time

import pytest

from taintward.sdk import detect, recognizers_intl
from taintward.sdk.destinations import DEST_EXTERNAL, DEST_INTERNAL, DEST_LLM
from taintward.sdk.integrations._payload import redact_structure
from taintward.sdk.placeholders import PlaceholderMap
from taintward.sdk.redact import redact_payload

SSN = "234-12-1234"
EMAIL = "jo.fox@example.com"
# Shaped like an Italian fiscal code, with Arabic-Indic digits. The pattern's
# \d matches them; the check digit table did not have them (KeyError).
ODD_DIGITS = "ABCDEF٣٣A٣٣A٣٣٣A"


@pytest.fixture(autouse=True)
def _fresh_cache():
    detect.clear_cache()
    yield
    detect.clear_cache()


# ---------------------------------------------------------------------------
# a recognizer that raises
# ---------------------------------------------------------------------------

def test_fiscal_code_check_takes_digits_of_other_scripts():
    assert recognizers_intl.codice_fiscale_ok(ODD_DIGITS) is False
    assert recognizers_intl.national_id("code " + ODD_DIGITS, "") == []
    # a real one is still found
    assert recognizers_intl.codice_fiscale_ok("RSSMRA85T10A562S") is True


def test_odd_digits_do_not_switch_redaction_off():
    """This exact payload went out unchanged: the recognizer raised, and the
    whole payload was treated as clean."""
    payload = {"note": f"my ssn is {SSN}, mail {EMAIL}, ref {ODD_DIGITS}"}
    out = redact_payload(payload, DEST_EXTERNAL)
    assert SSN not in json.dumps(out) and EMAIL not in json.dumps(out)
    assert detect.health()["mode"] != "broken"


TRIGGER = "zz-break-the-recognizer-zz"


def _raises_on_trigger(text: str, key_words: str) -> list:
    if TRIGGER in text:
        raise KeyError("boom")
    return []


def test_context_recognizer_that_raises_masks_only_that_value(monkeypatch, caplog):
    monkeypatch.setattr(detect, "CONTEXT_RECOGNIZERS",
                        detect.CONTEXT_RECOGNIZERS + (_raises_on_trigger,))
    bad = f"ssn {SSN} {TRIGGER}"
    payload = {"bad": bad, "good": f"ssn {SSN} is on file", "clean": "nothing here"}
    with caplog.at_level("ERROR", logger="taintward.detect"):
        out = redact_payload(payload, DEST_EXTERNAL)
    assert out["bad"] == "[SECRET]"                  # masked whole
    assert SSN not in json.dumps(out)                # the other value is still scanned
    assert out["good"].startswith("ssn [PII]")
    assert out["clean"] == "nothing here"
    # the log names the recognizer, never the text
    assert "_raises_on_trigger" in caplog.text and SSN not in caplog.text
    # one bad value is not "detection is broken" for the process
    assert detect.health()["mode"] != "broken"


def test_unscanned_value_for_the_llm_and_for_internal_sinks(monkeypatch):
    monkeypatch.setattr(detect, "CONTEXT_RECOGNIZERS",
                        detect.CONTEXT_RECOGNIZERS + (_raises_on_trigger,))
    bad = f"ssn {SSN} {TRIGGER}"
    dets = detect.detect_text(bad)
    assert [(d.entity_type, d.start, d.end) for d in dets] == [(detect.UNSCANNED, 0, len(bad))]
    pmap = PlaceholderMap()
    assert redact_structure({"doc": bad}, DEST_LLM, placeholders=pmap) == {"doc": "<UNSCANNED_1>"}
    # never an FF1 token over the whole value
    assert redact_payload({"doc": bad}, DEST_INTERNAL) == {"doc": "[SECRET]"}


def test_unscanned_result_is_not_cached(monkeypatch):
    bad = f"ssn {SSN} {TRIGGER}"
    monkeypatch.setattr(detect, "CONTEXT_RECOGNIZERS",
                        detect.CONTEXT_RECOGNIZERS + (_raises_on_trigger,))
    assert detect.detect_text(bad)[0].entity_type == detect.UNSCANNED
    monkeypatch.undo()
    # the recognizer is gone (fixed): the value is scanned again, not served
    # from the cache as "unscanned"
    assert "US_SSN" in {d.entity_type for d in detect.detect_text(bad)}


def test_pattern_recognizer_that_raises_does_not_skip_the_other_values(monkeypatch):
    """A pattern recognizer that raised on the joined text was skipped for
    every value in the payload, silently."""
    engine = detect._get_engine()
    real = type(engine)._match

    def match(rec, text):
        if TRIGGER in text:
            raise ValueError("boom")
        return real(rec, text)

    monkeypatch.setattr(type(engine), "_match", staticmethod(match))
    payload = {"bad": f"mail {EMAIL} {TRIGGER}", "good": f"mail {EMAIL} and ssn {SSN}"}
    out = redact_payload(payload, DEST_EXTERNAL)
    assert out["bad"] == "[SECRET]"
    assert EMAIL not in json.dumps(out) and SSN not in json.dumps(out)
    assert out["good"] == "mail [PII] and ssn [PII]"


# ---------------------------------------------------------------------------
# evidence CLI and report
# ---------------------------------------------------------------------------

def _ch_row(span_id: str, service: str, *, sdk_flag: bool = False) -> str:
    bools = {"taintward.violation": True} if sdk_flag else {"taintward.policy.violation": True}
    return json.dumps({
        "trace_id": "t1", "span_id": span_id, "parent_span_id": "", "name": "send_email",
        "service": service, "start_ns": time.time_ns() - 5_000_000_000,
        "attributes_string": {"taintward.destination": "external",
                              "taintward.taint.classes": "pii"},
        "attributes_bool": bools, "attributes_number": {},
    })


def test_record_single_file_uses_clickhouse_flags_and_every_service(tmp_path, monkeypatch, capsys):
    from taintward.evidence import spans
    from taintward.evidence.log import main
    from taintward.evidence.merkle import MerkleLog

    seen = {}

    def run(self, query):
        seen.update(url=self.http_url, user=self.user, query=query)
        return _ch_row("s1", "agent-a") + "\n" + _ch_row("s2", "agent-b", sdk_flag=True) + "\n"

    monkeypatch.setattr(spans.ClickHouseSource, "_run", run)
    log_file = tmp_path / "v.logl"
    args = ["--log-file", str(log_file), "record", "--service", "agent-a", "--service", "agent-b",
            "--clickhouse-url", "http://ch.internal:8123", "--clickhouse-user", "reader"]
    assert main(args) == 0
    # the flags were ignored before: docker exec, first service only
    assert seen["url"] == "http://ch.internal:8123" and seen["user"] == "reader"
    assert "'agent-a'" in seen["query"] and "'agent-b'" in seen["query"]
    # both violations are in the log, the SDK-flagged one too
    assert {r["span_id"] for r in MerkleLog(log_file).records()} == {"s1", "s2"}
    assert main(args) == 0 and len(MerkleLog(log_file)) == 2   # no duplicates


def test_record_prints_one_line_when_the_source_fails(tmp_path, monkeypatch, capsys):
    from taintward.evidence import spans
    from taintward.evidence.log import main

    def run(self, query):
        raise RuntimeError("clickhouse-client failed: connection refused")

    monkeypatch.setattr(spans.ClickHouseSource, "_run", run)
    assert main(["--log-file", str(tmp_path / "v.logl"), "record"]) == 1
    assert "error: clickhouse-client failed" in capsys.readouterr().err


def test_record_checkpoint_needs_the_sharded_log(tmp_path, capsys):
    from taintward.evidence.log import main

    rc = main(["--log-file", str(tmp_path / "v.logl"), "record", "--source", "otlp-file",
               "--otlp-file", str(tmp_path), "--checkpoint"])
    assert rc == 1 and "--evidence-dir" in capsys.readouterr().err


def test_compliance_does_not_call_an_unchecked_log_failed():
    from taintward.evidence.compliance import _evidence

    unchecked = _evidence("evidence_log", {"evidence_log": {"records": 3, "verification": None}})
    assert "not verified" in unchecked and "failed" not in unchecked
    ok = _evidence("evidence_log", {"evidence_log": {"records": 3, "verification": {"ok": True}}})
    assert ok.endswith("3 record(s), verified")
    bad = _evidence("evidence_log", {"evidence_log": {"records": None,
                                                      "verification": {"ok": False}}})
    assert "could not be read" in bad and bad.endswith("verification failed")


def test_report_bad_window_is_an_error_line(tmp_path, capsys):
    from taintward.evidence.report import main

    f = tmp_path / "t.json"
    f.write_text("{}")
    assert main(["--source", "otlp-file", "--otlp-file", str(f), "--since", "soon"]) == 1
    assert "error:" in capsys.readouterr().err
    f.write_text("{not json")
    assert main(["--source", "otlp-file", "--otlp-file", str(f)]) == 1


# ---------------------------------------------------------------------------
# taintward-fix
# ---------------------------------------------------------------------------

def _findings(src: str) -> list:
    from taintward.fix_suggester.suggest import analyze_tree

    return analyze_tree(ast.parse(textwrap.dedent(src)), "<test>")


def test_fix_sees_client_style_llm_calls():
    found = _findings("""
        from openai import OpenAI
        from anthropic import Anthropic
        client = OpenAI()
        claude = Anthropic()

        def ask(q):
            return client.chat.completions.create(model="m", messages=[{"role": "user", "content": q}])

        def ask2(q):
            return claude.messages.create(model="m", messages=[])
    """)
    assert [(f.call, f.destination, f.enclosing) for f in found] == [
        ("client.chat.completions.create", "llm", "ask"),
        ("claude.messages.create", "llm", "ask2"),
    ]
    assert "protect_openai" in found[0].fix


def test_fix_knows_a_protected_client():
    found = _findings("""
        import taintward as tw
        from openai import OpenAI
        client = tw.protect_openai(OpenAI())
        raw = OpenAI()

        class Bot:
            def __init__(self, ward):
                self.llm = ward.protect_anthropic(make())

            def ask(self, q):
                return self.llm.messages.create(model="m", messages=[])

        def ask(q):
            return client.chat.completions.create(model="m", messages=[])

        def chained(q):
            return tw.protect_openai(OpenAI()).responses.create(model="m", input=q)

        def leaky(q):
            return raw.chat.completions.create(model="m", messages=[])
    """)
    assert [(f.call, f.enclosing) for f in found] == [("raw.chat.completions.create", "leaky")]


def test_fix_missing_file_is_exit_2(monkeypatch, capsys, tmp_path):
    from taintward.fix_suggester import suggest

    monkeypatch.setattr("sys.argv", ["taintward-fix", str(tmp_path / "nope.py")])
    assert suggest.main() == 2
    assert "cannot analyze" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# taintward-audit
# ---------------------------------------------------------------------------

def test_audit_reads_a_saved_json_rpc_response(tmp_path, capsys):
    from taintward.analysis.audit import main
    from taintward.analysis.fcg import load_tools

    tools = [{"name": "get_customer", "inputSchema": {"properties": {"id": {"type": "string"}}},
              "outputSchema": {"properties": {"email": {"type": "string"}}}},
             {"name": "send_email", "inputSchema": {"properties": {"to": {"type": "string"}}}}]
    doc = {"jsonrpc": "2.0", "id": 1, "result": {"tools": tools}}
    names = [t.name for t in load_tools(doc, lambda n: ("external", "", False))]
    assert names == ["get_customer", "send_email"]     # was [] : no tools, an empty audit

    assert main(["--tools", str(tmp_path / "missing.json")]) == 1
    assert "error:" in capsys.readouterr().err


def test_jaeger_needs_a_service_name(tmp_path, capsys):
    """With no --service the demo service was asked for, so the report or
    the log looked clean for a system it never read."""
    from taintward.evidence.log import main as log_main
    from taintward.evidence.report import main as report_main

    assert report_main(["--source", "jaeger"]) == 1
    assert "--service is required" in capsys.readouterr().err
    assert log_main(["--log-file", str(tmp_path / "v.logl"), "record", "--source", "jaeger"]) == 1
    assert "--service is required" in capsys.readouterr().err


def test_record_without_a_service_reads_every_service(tmp_path, monkeypatch):
    from taintward.evidence import spans
    from taintward.evidence.log import main

    seen = {}

    def run(self, query):
        seen["query"] = query
        return _ch_row("s1", "my-agent") + "\n"

    monkeypatch.setattr(spans.ClickHouseSource, "_run", run)
    assert main(["--log-file", str(tmp_path / "v.logl"), "record"]) == 0
    assert "serviceName IN" not in seen["query"]     # was: only 'taintward-hr-bot'


# ---------------------------------------------------------------------------
# phone numbers are looked for only where they can count
# ---------------------------------------------------------------------------

PHONE = "212-736-5000"


def _phones(text: str, key: str = "") -> list[str]:
    found = detect.detect_leaves({key: text} if key else text)
    return [t[d.start:d.end] for t, ds in found for d in ds if d.entity_type == "PHONE_NUMBER"]


def test_phone_is_found_after_a_phone_word_anywhere_in_a_long_value(monkeypatch):
    filler = "4155552671,9876543210,2024-03-02\n" * 400      # numbers, no phone word
    # "number" is a context word only for the recognizer that is cut into
    # pieces; the other phone rules do not know it
    text = filler + f"the number {PHONE} today\n" + filler + f"Number: {PHONE}"
    got = _phones(text)
    assert got.count(PHONE) == 2
    # the same hits as scanning the whole value (how it was done before)
    detect.clear_cache()
    monkeypatch.setattr(detect, "_context_pieces", lambda seg, ctx: [seg])
    assert _phones(text) == got


def test_phone_under_a_phone_key_needs_no_word():
    assert _phones(PHONE, key="phone") == [PHONE]
    assert _phones(f"x {PHONE} y", key="number") == [PHONE]   # only the cut-up recognizer
    assert _phones(f"x {PHONE} y", key="note") == []        # no word, no key: as before


def test_phone_far_after_its_word_is_still_not_counted():
    # 64 characters is how far back a context word is looked for
    assert _phones("phone " + "x" * 80 + " " + PHONE) == []
    assert _phones("phone " + "x" * 40 + " " + PHONE) == [PHONE]


def test_context_pieces_cover_what_the_context_check_can_see():
    seg = detect._Segment("a" * 300 + " phone " + "9" * 10 + " " + "b" * 300, "")
    pieces = detect._context_pieces(seg, ("phone",))
    assert len(pieces) == 1
    p = pieces[0]
    assert p.owner is seg and seg.norm[p.off:p.off + 5] == "phone"
    assert "9" * 10 in p.norm and len(p.norm) < 250
    p.add("PHONE_NUMBER", 6, 16, 0.4, ("phone",))
    assert seg.results == [("PHONE_NUMBER", p.off + 6, p.off + 16, 0.4, ("phone",))]
    # a context key: the whole value
    whole = detect._Segment("9" * 10, "phone")
    assert detect._context_pieces(whole, ("phone",)) == [whole]
    # no word and no key: nothing to scan
    assert detect._context_pieces(detect._Segment("1 2 3 4 5 6 7 8", ""), ("phone",)) == []


def test_a_table_of_numbers_is_not_slow():
    text = "1 " * 60_000          # 120 KB, took about 3 seconds
    detect.detect_text("warm up 123")
    t = time.perf_counter()
    assert detect.detect_text(text) == []
    assert time.perf_counter() - t < 1.5
