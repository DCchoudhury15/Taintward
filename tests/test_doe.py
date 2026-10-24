"""Tests for core/doe.py against AgentRaft's worked examples and edge cases.

Runnable with stdlib alone: ``python3 -m unittest discover tests``
or ``python3 -m pytest tests`` (if pytest is installed).
"""

from __future__ import annotations

import unittest

from core.doe import (
    DOESets,
    Field,
    Sensitivity,
    classify,
    sensitive_fields,
)

# Sensitivity shorthands for readable test data.
PII = Sensitivity.PII
SECRET = Sensitivity.SECRET
CLEAN = Sensitivity.CLEAN


def _f(name: str, sensitivity: Sensitivity = CLEAN, value: object = None) -> Field:
    return Field(name=name, sensitivity=sensitivity, value=value)


class TestFieldIdentity(unittest.TestCase):
    """A Field is identified by name only; value/sensitivity are metadata."""

    def test_same_name_different_value_are_equal(self):
        self.assertEqual(
            _f("ssn", PII, value="111-22-3333"),
            _f("ssn", PII, value="999-88-7777"),
        )

    def test_same_name_hashes_equal(self):
        s = {_f("ssn", PII), _f("ssn", PII)}
        self.assertEqual(len(s), 1)

    def test_different_names_not_equal(self):
        self.assertNotEqual(_f("a"), _f("b"))


class TestDOEFormula(unittest.TestCase):
    """D_OE = (D_trans \\ (D_nec ∪ D_int)) ∩ D_total, verified on cases."""

    def test_paper_email_to_auditor_example(self):
        """The motivating example from AgentRaft §1.

        User: "extract the payment date from a transaction log and email it
        to an auditor." ``read_file`` returns a full schema; the LLM passes
        everything to ``send_email``. Only the date was intended/necessary.
        """
        # read_file returned: payment_date (clean), card_number (PII), cvv (SECRET)
        d_total = {
            _f("payment_date", CLEAN),
            _f("card_number", PII),
            _f("cvv", SECRET),
        }
        # LLM transmitted the whole schema to send_email
        d_trans = {
            _f("payment_date", CLEAN),
            _f("card_number", PII),
            _f("cvv", SECRET),
        }
        # User only intended the date
        d_int = {_f("payment_date", CLEAN)}
        # send_email strictly needs the date (the body), not the card/cvv
        d_nec = {_f("payment_date", CLEAN)}

        result = classify(DOESets.of(d_total, d_trans, d_int, d_nec))

        self.assertTrue(result.is_violation)
        self.assertEqual(result.over_exposed_names, ("card_number", "cvv"))
        # Sensitive over-exposure is the enforceable subset.
        sensitive = result.sensitive_over_exposure()
        self.assertEqual(
            sorted(f.name for f in sensitive), ["card_number", "cvv"]
        )

    def test_clean_field_over_exposed_is_d_oe_but_not_sensitive(self):
        """DOE is sensitivity-agnostic; enforcement only fires on sensitive."""
        d_total = {_f("notes", CLEAN), _f("ssn", PII)}
        d_trans = {_f("notes", CLEAN), _f("ssn", PII)}
        d_int: set[Field] = set()
        d_nec: set[Field] = set()

        result = classify(DOESets.of(d_total, d_trans, d_int, d_nec))

        self.assertEqual(result.over_exposed_names, ("notes", "ssn"))
        self.assertEqual(
            sorted(f.name for f in result.sensitive_over_exposure()), ["ssn"]
        )

    def test_nothing_transmitted_no_violation(self):
        d_total = {_f("ssn", PII)}
        result = classify(DOESets.of(d_total, set(), set(), set()))
        self.assertFalse(result.is_violation)
        self.assertEqual(result.over_exposed_names, ())

    def test_necessary_field_not_over_exposed(self):
        """A field in D_nec is allowed even if transmitted."""
        d_total = {_f("ssn", PII)}
        d_trans = {_f("ssn", PII)}
        d_nec = {_f("ssn", PII)}
        result = classify(DOESets.of(d_total, d_trans, set(), d_nec))
        self.assertFalse(result.is_violation)

    def test_intended_field_not_over_exposed(self):
        """A field in D_int is allowed even if transmitted and not necessary."""
        d_total = {_f("ssn", PII)}
        d_trans = {_f("ssn", PII)}
        d_int = {_f("ssn", PII)}
        result = classify(DOESets.of(d_total, d_trans, d_int, set()))
        self.assertFalse(result.is_violation)

    def test_nec_superset_of_trans_no_violation(self):
        d_total = {_f("ssn", PII)}
        d_trans = {_f("ssn", PII)}
        d_nec = {_f("ssn", PII), _f("extra", CLEAN)}  # extra not in D_total
        result = classify(DOESets.of(d_total, d_trans, set(), d_nec))
        self.assertFalse(result.is_violation)

    def test_trans_excludes_source_is_not_over_exposed(self):
        """D_OE is intersected with D_total: sink-internal fields are safe."""
        d_total = {_f("ssn", PII)}
        # 'server_generated_id' was not retrieved at the source
        d_trans = {_f("server_generated_id", CLEAN)}
        result = classify(DOESets.of(d_total, d_trans, set(), set()))
        self.assertFalse(result.is_violation)

    def test_partial_transmission(self):
        """Only the transmitted-and-not-allowed-and-sourced subset is D_OE."""
        d_total = {_f("a", PII), _f("b", PII), _f("c", CLEAN)}
        d_trans = {_f("a", PII), _f("b", PII)}  # c not transmitted
        d_int = {_f("a", PII)}  # a intended
        d_nec: set[Field] = set()
        result = classify(DOESets.of(d_total, d_trans, d_int, d_nec))
        self.assertEqual(result.over_exposed_names, ("b",))


class TestSensitivityFilter(unittest.TestCase):
    def test_sensitive_fields_filters_clean(self):
        fields = [_f("a", PII), _f("b", SECRET), _f("c", CLEAN)]
        sensitive = sensitive_fields(fields)
        self.assertEqual(sorted(f.name for f in sensitive), ["a", "b"])

    def test_clean_is_not_sensitive(self):
        self.assertFalse(Sensitivity.CLEAN.is_sensitive)
        self.assertTrue(Sensitivity.PII.is_sensitive)
        self.assertTrue(Sensitivity.SECRET.is_sensitive)


class TestDOEResultIteration(unittest.TestCase):
    def test_iterating_result_yields_d_oe(self):
        d_total = {_f("ssn", PII)}
        result = classify(DOESets.of(d_total, d_total, set(), set()))
        self.assertEqual([f.name for f in result], ["ssn"])


if __name__ == "__main__":
    unittest.main()