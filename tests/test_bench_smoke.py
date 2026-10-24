"""Detection-quality smoke test (a tiny slice of bench/run_detection.py).

Runs sdk.detect on fixed, synthetic examples and fails if recall on key
classes drops below the baseline measured when this test was written. The
full benchmark lives in bench/ and docs/benchmark.md.
"""

from __future__ import annotations

import unittest

from sdk import detect

# (text, class, value) - value must occur exactly once in text.
POSITIVES = [
    ("My SSN is 536-22-8491, please update it.", "US_SSN", "536-22-8491"),
    ('{"customer": {"id": 4411, "ssn": "412-73-1955"}}', "US_SSN", "412-73-1955"),
    ("level=info svc=billing lookup ok ssn=233-41-6702", "US_SSN", "233-41-6702"),
    ("ID number: 701-18-4420", "US_SSN", "701-18-4420"),
    ("Her social security number is ５３６-２２-８４９１.",
     "US_SSN", "５３６-２２-８４９１"),
    ("SSN on file 61​2-30-‌5518", "US_SSN", "61​2-30-‌5518"),
    ("Here is the key AKIAEXAMPLEEXAMPLEE5 for the bucket", "AWS_ACCESS_KEY", "AKIAEXAMPLEEXAMPLEE5"),
    ('{"aws_access_key_id": "AKIAEXAMPLEEXAMPLEE3"}', "AWS_ACCESS_KEY", "AKIAEXAMPLEEXAMPLEE3"),
    ("AWS_ACCESS_KEY_ID=AKIAEXAMPLEEXAMPLEE4\n", "AWS_ACCESS_KEY", "AKIAEXAMPLEEXAMPLEE4"),
    ("2025-03-01T10:00:00Z WARN [auth] leaked key AKIAEXAMPLEEXAMPLEE2",
     "AWS_ACCESS_KEY", "AKIAEXAMPLEEXAMPLEE2"),
    ("rotated: AK​IA6PLQ2WZ3XR7MTB4NVE", "AWS_ACCESS_KEY", "AK​IA6PLQ2WZ3XR7MTB4NVE"),
    ("You can reach me at maria.garcia@example.com", "EMAIL", "maria.garcia@example.com"),
    ('{"email": "wchen@corp.example.org", "plan": "pro"}', "EMAIL", "wchen@corp.example.org"),
    ("user=priya.sharma@example.net request_id=42", "EMAIL", "priya.sharma@example.net"),
    ("Subject: Invoice\n\nSend the invoice to okafor.aisha@example.com\n", "EMAIL",
     "okafor.aisha@example.com"),
    ("cc lukas7@mail.example.com", "EMAIL", "lukas7@mail.example.com"),
    ("Session token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3OCJ9.c2lnbmF0dXJlLXNpZ25hdHVyZQ",
     "JWT", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3OCJ9.c2lnbmF0dXJlLXNpZ25hdHVyZQ"),
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAsyntheticbodyonly\n-----END RSA PRIVATE KEY-----",
     "PRIVATE_KEY",
     "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAsyntheticbodyonly\n-----END RSA PRIVATE KEY-----"),
]

# Hard negatives: none of these may be flagged as an SSN or a secret.
NEGATIVES = [
    "Trace 3f1c9a2e-7b4d-4e0a-9c11-5d2e8f6a0b47 completed",
    "Deployed commit 9c4b1e2f7a3d5e6f8a9b0c1d2e3f4a5b6c7d8e9f to staging",
    "Upgraded the agent to v2.14.3",
]

# Baseline recall measured on the examples above (2026-10-24). Raise these
# when detection improves; never lower them to make a regression pass.
BASELINE_RECALL = {"US_SSN": 1.0, "AWS_ACCESS_KEY": 1.0, "EMAIL": 1.0, "JWT": 1.0, "PRIVATE_KEY": 1.0}

TYPE_MAP = {"US_SSN": "US_SSN", "USA_SSN": "US_SSN", "EMAIL_ADDRESS": "EMAIL"}


def _analyzer_available() -> bool:
    try:
        detect._get_analyzer()
        return True
    except Exception:
        return False


@unittest.skipUnless(_analyzer_available(), "Presidio / spaCy model not installed")
class TestDetectionSmoke(unittest.TestCase):
    def test_recall_not_below_baseline(self):
        hits: dict[str, list[bool]] = {}
        for text, cls, value in POSITIVES:
            start = text.index(value)
            end = start + len(value)
            found = any(
                TYPE_MAP.get(d.entity_type, d.entity_type) == cls and d.start < end and start < d.end
                for d in detect.detect_text(text)
            )
            hits.setdefault(cls, []).append(found)
        for cls, floor in BASELINE_RECALL.items():
            recall = sum(hits[cls]) / len(hits[cls])
            self.assertGreaterEqual(recall, floor, f"{cls} recall {recall:.2f} < baseline {floor}")

    def test_hard_negatives_not_flagged_as_ssn_or_secret(self):
        for text in NEGATIVES:
            bad = [d.entity_type for d in detect.detect_text(text)
                   if d.entity_type in {"US_SSN", "USA_SSN"} or d.sensitivity.value == "secret"]
            self.assertEqual(bad, [], text)


if __name__ == "__main__":
    unittest.main()
