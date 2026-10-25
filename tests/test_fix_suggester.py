"""Tests for the AST fix-suggester."""

from __future__ import annotations

import ast
import textwrap
import unittest
from pathlib import Path

from taintward.fix_suggester.suggest import analyze_file, analyze_tree, narrate
from taintward.sdk.destinations import DEST_EXTERNAL, DEST_LLM

SAMPLE = Path(__file__).resolve().parents[1] / "taintward" / "fix_suggester" / "sample_buggy_agent.py"


class TestFixSuggester(unittest.TestCase):
    def setUp(self):
        self.findings = analyze_file(SAMPLE)

    def test_finds_external_post(self):
        f = next((x for x in self.findings if x.call == "requests.post"), None)
        self.assertIsNotNone(f, "requests.post not flagged")
        self.assertEqual(f.destination, DEST_EXTERNAL)
        self.assertEqual(f.enclosing, "send_to_auditor")

    def test_finds_llm_create(self):
        f = next((x for x in self.findings if x.call == "openai.ChatCompletion.create"), None)
        self.assertIsNotNone(f, "openai create not flagged")
        self.assertEqual(f.destination, DEST_LLM)
        self.assertEqual(f.enclosing, "summarize_with_llm")

    def test_finds_module_level_put(self):
        f = next((x for x in self.findings if x.call == "requests.put"), None)
        self.assertIsNotNone(f)
        self.assertEqual(f.enclosing, "<module>")

    def test_does_not_flag_safe_internal(self):
        # safe_internal_lookup has no egress sink -> no finding references it
        self.assertFalse(any(x.enclosing == "safe_internal_lookup" for x in self.findings))

    def test_fix_mentions_redact_payload(self):
        for f in self.findings:
            self.assertIn("redact_payload", f.fix)
            self.assertIn(f.destination.upper(), f.fix)

    def test_narrate_is_grounded(self):
        f = self.findings[0]
        text = narrate(f)
        self.assertIn(f.call, text)
        self.assertIn(f.destination, text)
        self.assertIn("redact_payload", text)


def _findings_for(src: str) -> list:
    tree = ast.parse(textwrap.dedent(src), filename="<test>")
    return analyze_tree(tree, "<test>")


class TestGuardDecoratorAliasing(unittest.TestCase):
    """Regression tests for _is_instrumented seeing through `import ... as`
    aliasing of the instrument_tool decorator, and NOT being fooled by an
    unrelated decorator whose name merely ends with "instrument_tool"."""

    def test_aliased_instrument_tool_is_recognized_as_guarded(self):
        # `from taintward.sdk.instrumentation import instrument_tool as it` -- the real
        # guard, just imported under a different local name. Must NOT be
        # flagged: aliasing doesn't change what the decorator does at runtime.
        findings = _findings_for(
            """
            import requests
            from taintward.sdk.instrumentation import instrument_tool as it

            @it(destination="external")
            def do_thing():
                requests.post("https://x.example.com", json={"ssn": "123"})
            """
        )
        self.assertEqual(findings, [], "aliased @instrument_tool import wrongly flagged as unguarded")

    def test_aliased_module_import_is_recognized_as_guarded(self):
        # `import taintward.sdk.instrumentation as instr` then `@instr.instrument_tool`.
        findings = _findings_for(
            """
            import requests
            import taintward.sdk.instrumentation as instr

            @instr.instrument_tool(destination="external")
            def do_thing():
                requests.post("https://x.example.com", json={"ssn": "123"})
            """
        )
        self.assertEqual(findings, [], "aliased module @instr.instrument_tool wrongly flagged as unguarded")

    def test_lookalike_decorator_name_is_not_treated_as_guard(self):
        # A decorator that merely *ends with* "instrument_tool" in its name
        # (but isn't the real decorator) must still be flagged as unguarded --
        # otherwise a substring endswith() match would let real leaks through.
        findings = _findings_for(
            """
            import requests

            def fake_instrument_tool(fn):
                return fn

            @fake_instrument_tool
            def do_thing():
                requests.post("https://x.example.com", json={"ssn": "123"})
            """
        )
        self.assertEqual(len(findings), 1, "lookalike decorator name suppressed a real finding")
        self.assertEqual(findings[0].enclosing, "do_thing")


if __name__ == "__main__":
    unittest.main()