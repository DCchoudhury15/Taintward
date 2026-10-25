"""Tests for the evidence report (evidence/report.py, evidence/spans.py)."""

from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from evidence.report import build_report, main, render_html, scan_text
from evidence.spans import (
    OtlpFileSource,
    spans_from_clickhouse_rows,
    spans_from_otlp,
)

T0 = 1_792_800_000_000_000_000  # 2026-10-24 UTC, in ns
WINDOW = dict(start_ns=T0 - 10**12, end_ns=T0 + 10**13)
MASKED = "{\"args\": [\"employee: {'ssn': '[PII]', 'key': '[SECRET]'}\"], \"kwargs\": {}}"


def _v(value):
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    return {"stringValue": value}


def _span(trace, span, name, offset, **attrs):
    return {
        "traceId": trace, "spanId": span, "name": name,
        "startTimeUnixNano": str(T0 + offset), "endTimeUnixNano": str(T0 + offset + 1000),
        "attributes": [{"key": k, "value": _v(v)} for k, v in attrs.items()],
    }


def _tool(trace, span, tool, dest, offset, *, juris="", sensitive=True, classes="pii,secret",
          violation=False, transfer=False, reasons="", redacted=False, args=MASKED, **extra):
    a = {
        "gen_ai.tool.name": tool, "agentward.destination": dest,
        "agentward.jurisdiction": juris, "agentward.sensitive": sensitive,
        "agentward.policy.violation": violation,
        "agentward.policy.transfer_violation": transfer,
        "agentward.policy.reasons": reasons, "agentward.policy.decision_engine": "rego",
        "agentward.redacted": redacted,
    }
    if sensitive:
        a["agentward.taint.classes"] = classes
    if args is not None:
        a["gen_ai.tool.call.arguments"] = args
    a.update(extra)
    return _span(trace, span, tool, offset, **a)


def _doc(spans, service="hr-bot"):
    return {"resourceSpans": [{
        "resource": {"attributes": [{"key": "service.name", "value": _v(service)}]},
        "scopeSpans": [{"scope": {"name": "agentward"}, "spans": spans}],
    }]}


TRACE_A = "a" * 32
TRACE_B = "b" * 32


def clean_spans():
    """Two runs that look like the demo: all egress inputs masked."""
    spans = []
    for i, tr in enumerate((TRACE_A, TRACE_B)):
        base = i * 10**9
        spans += [
            _span(tr, f"{i}000000000000000", "hr_bot.run", base),
            _tool(tr, f"{i}000000000000001", "query_db", "internal", base + 1,
                  args='{"args": ["alice"]}'),
            _tool(tr, f"{i}000000000000002", "internal_store", "internal", base + 2,
                  args='{"args": [{"ssn": "866-13-7965"}]}', redacted=True),
            _tool(tr, f"{i}000000000000003", "ask_llm", "llm", base + 3, juris="us",
                  violation=True, transfer=True, reasons="transfer,pii_egress", redacted=True),
            _tool(tr, f"{i}000000000000004", "rag_retrieve", "rag", base + 4,
                  args='{"args": ["policy for alice"]}'),
            _tool(tr, f"{i}000000000000005", "call_external_api", "external", base + 5,
                  juris="us", violation=True, transfer=True, reasons="transfer,pii_egress"),
            _tool(tr, f"{i}000000000000006", "write_log", "log", base + 6,
                  violation=True, reasons="pii_egress"),
        ]
    return spans_from_otlp(_doc(spans))


def report(spans, **kw):
    return build_report(spans, source="test fixtures", generated_ns=T0, **WINDOW, **kw)


class TestParsing(unittest.TestCase):
    def test_otlp_and_jaeger_wrapper(self):
        doc = _doc([_tool(TRACE_A, "1" * 16, "ask_llm", "llm", 0, violation=True)])
        a = spans_from_otlp(doc)
        b = spans_from_otlp({"result": doc})
        self.assertEqual(len(a), 1)
        self.assertEqual(a, b)
        s = a[0]
        self.assertEqual(s.service, "hr-bot")
        self.assertEqual(s.attrs["agentward.destination"], "llm")
        self.assertIs(s.attrs["agentward.policy.violation"], True)
        self.assertEqual(s.start_ns, T0)

    def test_file_source_jsonl_window_and_dedupe(self):
        d1 = _doc([_tool(TRACE_A, "1" * 16, "ask_llm", "llm", 0)])
        d2 = _doc([_tool(TRACE_A, "1" * 16, "ask_llm", "llm", 0),       # duplicate
                   _tool(TRACE_B, "2" * 16, "write_log", "log", 5),
                   _tool(TRACE_B, "3" * 16, "late", "log", 10**15)])   # outside window
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "traces.json"
            p.write_text(json.dumps(d1) + "\n" + json.dumps(d2) + "\n")
            spans = OtlpFileSource([td]).fetch(T0 - 1, T0 + 10**9)
            self.assertEqual(sorted(s.name for s in spans), ["ask_llm", "write_log"])
            self.assertEqual(OtlpFileSource([p], services=["other"]).fetch(0, 2 * T0), [])

    def test_clickhouse_rows(self):
        rows = [{"trace_id": TRACE_A, "span_id": "1" * 16, "parent_span_id": "",
                 "name": "ask_llm", "service": "hr-bot", "start_ns": T0,
                 "attributes_string": {"agentward.destination": "llm"},
                 "attributes_bool": {"agentward.policy.violation": 1},
                 "attributes_number": {}}]
        s = spans_from_clickhouse_rows(rows)[0]
        self.assertIs(s.attrs["agentward.policy.violation"], True)
        self.assertEqual(s.attrs["agentward.destination"], "llm")


class TestNumbers(unittest.TestCase):
    def setUp(self):
        self.data = report(clean_spans())

    def test_totals(self):
        t = self.data["totals"]
        self.assertEqual(t["runs"], 2)
        self.assertEqual(t["tool_calls"], 12)       # root spans are not tool calls
        self.assertEqual(t["sensitive_calls"], 12)
        self.assertEqual(t["violations"], 6)
        self.assertEqual(t["transfers"], 4)

    def test_classes_and_destinations(self):
        self.assertEqual(self.data["sensitive_by_class"], {"pii": 12, "secret": 12})
        d = self.data["destinations"]
        self.assertEqual(d["internal"]["calls"], 4)
        self.assertEqual(d["llm"], {"calls": 2, "sensitive_calls": 2, "violations": 2})
        self.assertEqual(d["rag"]["violations"], 0)

    def test_outcomes_and_rules(self):
        v = self.data["violations"]
        self.assertEqual(v["by_outcome"]["redacted"], 2)            # ask_llm
        self.assertEqual(v["by_outcome"]["nothing_to_redact"], 4)
        self.assertEqual(v["by_outcome"]["blocked"], 0)
        self.assertEqual(v["by_rule"], {"pii_egress": 6, "transfer": 4})

    def test_transfers_by_jurisdiction(self):
        us = self.data["transfers"]["by_jurisdiction"]["us"]
        self.assertEqual(us["calls"], 4)
        self.assertEqual(us["transfer_flags"], 4)
        self.assertEqual(list(self.data["transfers"]["by_jurisdiction"]), ["us"])

    def test_recipients(self):
        rows = {(r["tool"], r["destination"]): r for r in self.data["recipients"]}
        self.assertEqual(len(rows), 6)
        self.assertEqual(rows[("ask_llm", "llm")]["jurisdiction"], "us")
        self.assertEqual(rows[("ask_llm", "llm")]["calls"], 2)
        self.assertEqual(rows[("write_log", "log")]["violations"], 2)
        # internal destinations come first
        self.assertEqual(self.data["recipients"][0]["destination"], "internal")

    def test_claim_supported_when_clean(self):
        claim = self.data["raw_check"]["claim"]
        self.assertEqual(claim["status"], "supported")
        self.assertTrue(claim["statement"].startswith("0 raw sensitive values"))
        self.assertIn("4 call(s) checked", claim["statement"])

    def test_internal_tokens_not_flagged(self):
        # internal_store holds an SSN-shaped token; internal is not scanned
        self.assertEqual(self.data["raw_check"]["findings"], [])


class TestNeverOverclaims(unittest.TestCase):
    RAW_SSN = "234-12-1234"
    RAW_KEY = "AKIAIOSFODNN7EXAMPLE"

    def _with(self, extra):
        return report(clean_spans() + spans_from_otlp(_doc([extra])))

    def test_raw_value_to_llm_blocks_claim(self):
        leak = _tool(TRACE_A, "9" * 16, "ask_llm", "llm", 50, violation=True,
                     reasons="pii_egress",
                     args=json.dumps({"args": [f"ssn {self.RAW_SSN} key {self.RAW_KEY}"]}))
        data = self._with(leak)
        claim = data["raw_check"]["claim"]
        self.assertEqual(claim["status"], "raw_found")
        self.assertNotIn("0 raw sensitive values", claim["statement"])
        f = data["raw_check"]["findings"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["types"], ["AWS_ACCESS_KEY", "US_SSN"])
        page = render_html(data)
        self.assertNotIn("0 raw sensitive values were sent", page)
        # the report itself never contains the raw values
        self.assertNotIn(self.RAW_SSN, page)
        self.assertNotIn(self.RAW_KEY, page)
        self.assertNotIn(self.RAW_SSN, json.dumps(data))

    def test_raw_value_to_external_via_messages_attr(self):
        leak = _tool(TRACE_B, "8" * 16, "chat", "external", 60, args=None,
                     **{"gen_ai.input.messages": "mail alice@example.com"})
        self.assertEqual(self._with(leak)["raw_check"]["claim"]["status"], "raw_found")

    def test_unrecorded_input_is_not_confirmed(self):
        blind = _tool(TRACE_A, "7" * 16, "send", "external", 70, args=None)
        claim = self._with(blind)["raw_check"]["claim"]
        self.assertEqual(claim["status"], "not_confirmed")
        self.assertTrue(any("no recorded input" in r for r in claim["reasons"]))

    def test_audit_mode_is_not_confirmed(self):
        audit = _tool(TRACE_A, "6" * 16, "send", "llm", 80, violation=True,
                      reasons="pii_egress", **{"agentward.dry_run": True})
        data = self._with(audit)
        self.assertEqual(data["raw_check"]["claim"]["status"], "not_confirmed")
        self.assertEqual(data["violations"]["by_outcome"]["audit_only"], 1)

    def test_blocked_call_is_not_sent(self):
        blocked = _tool(TRACE_A, "5" * 16, "send", "external", 90, violation=True,
                        reasons="pii_egress", args=None, **{"agentward.blocked": True})
        data = self._with(blocked)
        self.assertEqual(data["raw_check"]["claim"]["status"], "supported")
        self.assertEqual(data["violations"]["by_outcome"]["blocked"], 1)

    def test_no_calls(self):
        data = report([])
        self.assertEqual(data["raw_check"]["claim"]["status"], "no_calls")
        self.assertIn("No AgentWard tool call spans", " ".join(data["warnings"]))

    def test_luhn_and_masks(self):
        self.assertEqual(scan_text("[PII] [SECRET] 1234"), [])
        self.assertEqual(scan_text("card 4111 1111 1111 1112"), [])     # fails Luhn
        self.assertEqual(scan_text("card 4111 1111 1111 1111")[0]["type"], "CREDIT_CARD")


class TestOutput(unittest.TestCase):
    def test_html_is_self_contained_and_embeds_data(self):
        page = render_html(report(clean_spans()))
        self.assertTrue(page.startswith("<!doctype html>"))
        self.assertIn("@media print", page)
        self.assertNotRegex(page, r"<(script|link)[^>]+(src|href)=")
        self.assertNotIn(chr(0x2014), page)  # no em dash
        m = re.search(r"id='agentward-report-data'>(.*?)</script>", page, re.S)
        data = json.loads(m.group(1))
        self.assertEqual(data["totals"]["violations"], 6)

    def test_digest_matches_data(self):
        import hashlib

        data = report(clean_spans())
        body = {k: v for k, v in data.items() if k != "digest"}
        want = hashlib.sha256(json.dumps(body, sort_keys=True,
                                         separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(data["digest"], want)

    def test_cli_json_from_file(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "t.jsonl"
            src.write_text(json.dumps(_doc([_tool(TRACE_A, "1" * 16, "ask_llm", "llm",
                                                  0, violation=True)])) + "\n")
            out = Path(td) / "r.json"
            rc = main(["--source", "otlp-file", "--otlp-file", str(src),
                       "--start", "2026-10-01T00:00:00Z", "--end", "2026-11-01T00:00:00Z",
                       "--format", "json", "--out", str(out)])
            self.assertEqual(rc, 0)
            data = json.loads(out.read_text())
            self.assertEqual(data["totals"]["violations"], 1)
            self.assertEqual(data["raw_check"]["claim"]["status"], "supported")

    def test_evidence_section_coverage(self):
        from evidence.checkpoint import keygen
        from evidence.report import span_violation_record
        from evidence.shards import ShardedLog

        spans = clean_spans()
        with tempfile.TemporaryDirectory() as td:
            keygen(Path(td) / "k", Path(td) / "k.pub")
            from evidence.checkpoint import load_private_key

            log = ShardedLog(Path(td) / "ev")
            viol = [s for s in spans if s.attrs.get("agentward.policy.violation")]
            for s in viol[:4]:
                log.append(span_violation_record(s), tenant="acme")
            log.checkpoint(load_private_key(Path(td) / "k"))
            log.append(span_violation_record(viol[4]), tenant="acme")
            data = report(spans, evidence_dir=str(Path(td) / "ev"),
                          public_key=str(Path(td) / "k.pub"))
            ev = data["evidence_log"]
            self.assertEqual(ev["violations_in_window"], 6)
            self.assertEqual(ev["violations_found_in_log"], 5)
            self.assertEqual(ev["violations_covered_by_checkpoint"], 4)
            self.assertTrue(ev["verification"]["ok"])
            self.assertEqual(ev["checkpoint"]["seq"], 1)


if __name__ == "__main__":
    unittest.main()
