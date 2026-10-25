"""Tests for the fast detection path in taintward.sdk.detect.

Covers the new recognizers (plain SSN by key, fine-grained GitHub tokens,
temporary AWS keys, spaced-out digits, street addresses), the noisy types
that no longer count as PII, the per-value cache, the per-call detection
scope, and offset mapping on long or non-ASCII text.
"""

from __future__ import annotations

import json
import unittest

from taintward.sdk import detect


def _analyzer_available() -> bool:
    try:
        detect._get_analyzer()
        return True
    except Exception:
        return False


def _types(dets) -> set[str]:
    return {d.entity_type for d in dets if d.is_sensitive}


@unittest.skipUnless(_analyzer_available(), "Presidio / spaCy model not installed")
class TestNewRecognizers(unittest.TestCase):
    def setUp(self):
        detect.clear_cache()

    def test_plain_ssn_needs_key_or_context(self):
        self.assertIn("US_SSN", _types(detect.detect_mapping({"ssn": "536228491"})))
        self.assertIn("US_SSN", _types(detect.detect_mapping({"customer": {"social_security": 536228491}})))
        self.assertIn("US_SSN", _types(detect.detect_text("level=warn ssn=811309005 retry=0")))
        self.assertIn("US_SSN", _types(detect.detect_text("Her social security number is 855330879.")))
        # The same number with no SSN context is a tracking number, not PII.
        self.assertEqual(_types(detect.detect_mapping({"tracking_number": "536228491"})), set())
        self.assertEqual(_types(detect.detect_text("Parcel number 536228491 is out for delivery.")), set())

    def test_plain_ssn_rejects_invalid_numbers(self):
        for bad in ("000228491", "666228491", "936228491", "536008491", "536220000"):
            self.assertEqual(_types(detect.detect_mapping({"ssn": bad})) - {"GENERIC_API_KEY"}, set(), bad)

    def test_github_fine_grained_token(self):
        tok = "github_pat_" + "A1b2C3d4E5f6G7h8I9j0K1" + "_" + "x" * 30 + "Y7" * 15
        dets = detect.detect_text(f"Token for CI: {tok} thanks")
        self.assertIn("GITHUB_TOKEN", _types(dets))
        self.assertNotIn("GENERIC_API_KEY", _types(dets))

    def test_temporary_aws_key(self):
        self.assertIn("AWS_ACCESS_KEY", _types(detect.detect_text("key ASIAEXAMPLEEXAMPLEE1 used")))

    def test_spaced_out_digits(self):
        self.assertIn("US_SSN", _types(detect.detect_text("SSN is 7 2 4 - 6 8 - 6 9 6 6.")))
        self.assertIn("CREDIT_CARD", _types(detect.detect_text("Card: 4 1 4 6 8 6 1 9 5 2 8 5 1 5 6 8")))
        self.assertIn("PHONE_NUMBER", _types(detect.detect_text('mobile: "+ 1   6 4 6   8 6 7   0 7 3 9"')))
        # A list of single digits is not a card, SSN or phone.
        self.assertEqual(_types(detect.detect_text("steps 1 2 3 4 5 6 7 8 9 done")), set())

    def test_street_address(self):
        text = "Ship it to 6124 Maple Blvd, Salem, OR 46319 please"
        dets = [d for d in detect.detect_text(text) if d.entity_type == "STREET_ADDRESS"]
        self.assertEqual(len(dets), 1)
        self.assertEqual(text[dets[0].start:dets[0].end], "6124 Maple Blvd, Salem, OR 46319")

    def test_keyed_secret(self):
        self.assertIn("GENERIC_API_KEY",
                      _types(detect.detect_mapping({"api_key": "cleck8n6-t4jwblo9-lfce7g49-m90itpgi"})))
        self.assertIn("GENERIC_API_KEY", _types(detect.detect_mapping({"password": "hunter22"})))
        self.assertEqual(_types(detect.detect_mapping({"token_count": 12345})), set())
        self.assertEqual(_types(detect.detect_mapping({"password": "****"})), set())


@unittest.skipUnless(_analyzer_available(), "Presidio / spaCy model not installed")
class TestNoiseTypes(unittest.TestCase):
    def setUp(self):
        detect.clear_cache()

    def tearDown(self):
        detect.set_pii_types(disable=detect.NOISE_TYPES_DEFAULT)

    def test_ids_dates_and_urls_do_not_taint(self):
        payload = {"id": 96930, "created": "2026-02-07T11:42:43Z", "zip": "94107",
                   "link": "https://example.com/a", "trace": "3f1c9a2e-7b4d-4e0a-9c11-5d2e8f6a0b47"}
        self.assertEqual(detect.detect_mapping(payload), [])
        self.assertFalse(detect.taint_for(detect.detect_mapping(payload)).is_tainted)

    def test_noise_types_can_be_turned_back_on(self):
        text = "see https://example.com/docs for details"
        self.assertNotIn("URL", _types(detect.detect_text(text)))
        detect.set_pii_types(enable=["URL"])
        self.assertIn("URL", _types(detect.detect_text(text)))
        self.assertNotIn("URL", detect.ignored_types())

    def test_email_still_found_without_url_noise(self):
        dets = detect.detect_text("mail maria.garcia@example.com now")
        self.assertEqual(_types(dets), {"EMAIL_ADDRESS"})


@unittest.skipUnless(_analyzer_available(), "Presidio / spaCy model not installed")
class TestCacheAndScope(unittest.TestCase):
    def setUp(self):
        detect.clear_cache()

    def test_cache_keys_hold_no_raw_text(self):
        detect.detect_text("My SSN is 536-22-8491")
        self.assertGreaterEqual(detect.cache_info()["size"], 1)
        for key in list(detect._cache):
            self.assertNotIn("536-22-8491", repr(key))

    def test_cached_result_matches_fresh_result(self):
        text = "Maria Garcia (maria@example.com) SSN 536-22-8491"
        first = [(d.entity_type, d.start, d.end) for d in detect.detect_text(text)]
        second = [(d.entity_type, d.start, d.end) for d in detect.detect_text(text)]
        detect.clear_cache()
        third = [(d.entity_type, d.start, d.end) for d in detect.detect_text(text)]
        self.assertEqual(first, second)
        self.assertEqual(first, third)

    def test_scope_shares_key_context_with_detect_text(self):
        # Outside a scope a bare 9-digit string has no context.
        self.assertEqual(detect.detect_text("536228491"), [])
        with detect.detection_scope():
            detect.detect_mapping({"ssn": "536228491"})
            self.assertIn("US_SSN", _types(detect.detect_text("536228491")))
        self.assertEqual(detect.detect_text("536228491"), [])

    def test_mapping_offsets_are_per_leaf(self):
        payload = {"a": "hello", "b": "write to wchen@corp.example.org today"}
        for text, dets in detect.detect_leaves(payload):
            for d in dets:
                self.assertEqual(text[d.start:d.end], "wchen@corp.example.org")

    def test_match_that_crosses_values_is_redone_per_value(self):
        # The PEM regex could run from the first value's BEGIN line to the
        # second value's END line once the values are joined. The truncated
        # key in the first value must still be found on its own.
        leaves = detect.detect_leaves(["-----BEGIN RSA PRIVATE KEY-----", "x -----END RSA PRIVATE KEY-----"])
        self.assertIn("PRIVATE_KEY", _types(leaves[0][1]))
        for text, dets in leaves:
            for d in dets:
                self.assertLessEqual(d.end, len(text))


@unittest.skipUnless(_analyzer_available(), "Presidio / spaCy model not installed")
class TestOffsets(unittest.TestCase):
    def setUp(self):
        detect.clear_cache()

    def test_long_text_offsets(self):
        filler = "the quick brown fox jumps over the lazy dog. " * 300  # about 13.5 KB
        text = filler + "Contact Maria Garcia at maria.garcia@example.com today. " + filler
        dets = detect.detect_text(text)
        spans = {text[d.start:d.end] for d in dets}
        self.assertIn("maria.garcia@example.com", spans)
        self.assertIn("Maria Garcia", spans)

    def test_ligature_and_zero_width_offsets(self):
        text = "\ufb01le owner SSN 61\u200b2-30-\u200c5518 ok"
        dets = [d for d in detect.detect_text(text) if d.entity_type == "US_SSN"]
        self.assertEqual(len(dets), 1)
        self.assertEqual(text[dets[0].start:dets[0].end], "61\u200b2-30-\u200c5518")

    def test_mask_value_on_payload(self):
        masked = detect.mask_value({"name": "Maria Garcia", "ssn": "536-22-8491", "id": 7})
        self.assertEqual(masked, {"name": "[PII]", "ssn": "[PII]", "id": 7})
        json.dumps(masked)


if __name__ == "__main__":
    unittest.main()
