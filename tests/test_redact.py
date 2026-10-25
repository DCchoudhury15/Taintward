"""Tests for taintward/sdk/redact.py: destination-aware reversible redaction."""

from __future__ import annotations

import unittest

from taintward.core.doe import Sensitivity
from taintward.sdk import instrumentation as instr
from taintward.sdk.redact import Redactor, redact_payload

SSN = "234-12-1234"
AWS = "AKIAIOSFODNN7EXAMPLE"


class TestRedaction(unittest.TestCase):
    def setUp(self):
        self.r = Redactor()

    def test_internal_ssn_is_reversible_format_preserving_token(self):
        tok = self.r.redact_value(SSN, Sensitivity.PII, instr.DEST_INTERNAL)
        self.assertNotEqual(tok, SSN)
        self.assertEqual(len(tok), len(SSN))           # format-preserving
        self.assertEqual(tok.count("-"), 2)             # ###-##-#### shape kept
        self.assertTrue(tok.replace("-", "").isdigit()) # still all digits
        self.assertEqual(self.r.reverse(tok), SSN)      # round-trips exactly

    def test_internal_aws_key_is_reversible(self):
        tok = self.r.redact_value(AWS, Sensitivity.SECRET, instr.DEST_INTERNAL)
        self.assertEqual(len(tok), len(AWS))            # length preserved
        self.assertEqual(self.r.reverse(tok), AWS)

    def test_external_is_non_reversible_mask(self):
        self.assertEqual(
            self.r.redact_value(SSN, Sensitivity.PII, instr.DEST_EXTERNAL), "[PII]"
        )
        self.assertEqual(
            self.r.redact_value(AWS, Sensitivity.SECRET, instr.DEST_LLM), "[SECRET]"
        )
        self.assertIsNone(self.r.reverse("[PII]"))
        self.assertIsNone(self.r.reverse("[SECRET]"))

    def test_rag_is_masked_not_reversible(self):
        # embeddings are invertible -> rag gets a mask, not a reversible token
        tok = self.r.redact_value(SSN, Sensitivity.PII, instr.DEST_RAG)
        self.assertEqual(tok, "[PII]")
        self.assertIsNone(self.r.reverse(tok))

    def test_same_value_different_treatment_by_destination(self):
        """The headline Phase 4 property: same SSN, internal vs external."""
        internal = self.r.redact_value(SSN, Sensitivity.PII, instr.DEST_INTERNAL)
        external = self.r.redact_value(SSN, Sensitivity.PII, instr.DEST_EXTERNAL)
        self.assertNotEqual(internal, external)
        self.assertEqual(self.r.reverse(internal), SSN)
        self.assertIsNone(self.r.reverse(external))

    def test_clean_value_unchanged(self):
        # redact_payload detects first; a clean string is left alone.
        self.assertEqual(
            redact_payload("nothing sensitive", instr.DEST_INTERNAL),
            "nothing sensitive",
        )
        # redact_value with a CLEAN sensitivity is a no-op (low-level API trusts
        # the caller's classification; detection is redact_payload's job).
        self.assertEqual(
            self.r.redact_value("anything", Sensitivity.CLEAN, instr.DEST_INTERNAL),
            "anything",
        )

    def test_redact_payload_recurses_dict(self):
        # "engineering" is not detected as PII; "Alice" would be (PERSON),
        # names are PII, so we use a non-name clean field here. Pass our own
        # redactor so the vault used for redaction is the one we reverse with.
        payload = {"ssn": SSN, "dept": "engineering", "key": AWS, "nested": {"ssn": SSN}}
        out = redact_payload(payload, instr.DEST_INTERNAL, redactor=self.r)
        self.assertEqual(out["dept"], "engineering")
        self.assertNotEqual(out["ssn"], SSN)
        self.assertEqual(self.r.reverse(out["ssn"]), SSN)
        self.assertEqual(self.r.reverse(out["nested"]["ssn"]), SSN)
        self.assertEqual(self.r.reverse(out["key"]), AWS)

    def test_redact_payload_external_masks_all(self):
        payload = {"ssn": SSN, "key": AWS}
        out = redact_payload(payload, instr.DEST_EXTERNAL)
        self.assertEqual(out["ssn"], "[PII]")
        self.assertEqual(out["key"], "[SECRET]")

    def test_non_sensitive_destination_for_secret_is_mask(self):
        # SECRET to an external sink is a mask, not reversible
        tok = self.r.redact_value(AWS, Sensitivity.SECRET, instr.DEST_LOG)
        self.assertEqual(tok, "[SECRET]")

    def test_cross_process_digit_only_token_reverses_correctly(self):
        # Two independent Redactor instances (e.g. two worker processes) with
        # no shared vault: FF1 is deterministic, so a digit-only (radix 10)
        # token from process A can be structurally decrypted by process B's
        # _fpe_decrypt fallback with no case-loss risk (digits have no case).
        proc_a = Redactor()
        tok = proc_a.redact_value(SSN, Sensitivity.PII, instr.DEST_INTERNAL)
        proc_b = Redactor()  # fresh instance, empty vault
        self.assertEqual(proc_b.reverse(tok), SSN)

    def test_cross_process_alnum_token_fails_closed_not_case_mangled(self):
        # Regression for a real gap: _fpe_encrypt lowercases the alphabet
        # before running FF1 (radix 36), so an alnum token's original letter
        # case only lives in the vault, never in the token's own characters.
        # Before the fix, the vault-miss fallback (_fpe_decrypt) still tried
        # to structurally decrypt radix-36 tokens and silently returned a
        # case-mangled value (e.g. "EMP4521XQ" -> "emp4521xq") that looked
        # like a valid reversal but was NOT the exact original -- a silent
        # violation of the "reversal is exact" guarantee. It must now fail
        # closed (None) instead of returning a wrong-but-plausible value.
        alnum = "EMP4521XQ"
        proc_a = Redactor()
        tok = proc_a.redact_value(alnum, Sensitivity.SECRET, instr.DEST_INTERNAL)
        self.assertNotEqual(tok, alnum.lower())  # sanity: token really differs
        proc_b = Redactor()  # fresh instance, empty vault -> vault miss
        result = proc_b.reverse(tok)
        self.assertIsNone(result)  # fail closed, not a case-mangled guess
        self.assertNotEqual(result, alnum.lower())

    def test_same_process_alnum_reversal_still_exact(self):
        # The fix only restricts the cross-process *fallback*; same-process
        # reversal (vault hit) must still be exact, case included.
        alnum = "EMP4521XQ"
        tok = self.r.redact_value(alnum, Sensitivity.SECRET, instr.DEST_INTERNAL)
        self.assertEqual(self.r.reverse(tok), alnum)


if __name__ == "__main__":
    unittest.main()