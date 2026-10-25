"""Detection-quality smoke test (a tiny slice of bench/run_detection.py).

Runs taintward.sdk.detect on fixed, synthetic examples and fails if recall on key
classes drops below the baseline measured when this test was written. The
full benchmark lives in bench/ and docs/benchmark.md.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

from taintward.sdk import detect

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
    # Added with the fast detection path (2026-10-24).
    ("level=warn svc=auth lookup ok ssn=811309005 retry=0", "US_SSN", "811309005"),
    ("Her social security number is 855330879, can you check it?", "US_SSN", "855330879"),
    ("agent: Her social security number is 7 2 4 - 6 8 - 6 9 6 6.", "US_SSN", "7 2 4 - 6 8 - 6 9 6 6"),
    ("Token for CI: github_pat_EXAMPLEEXAMPLEEXAMPLE7_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEX7",
     "GITHUB_TOKEN",
     "github_pat_EXAMPLEEXAMPLEEXAMPLE7_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEX7"),
    ("temporary key ASIAEXAMPLEEXAMPLEE1 from STS", "AWS_ACCESS_KEY", "ASIAEXAMPLEEXAMPLEE1"),
    ("Ship it to 6124 Maple Blvd, Salem, OR 46319", "ADDRESS", "6124 Maple Blvd, Salem, OR 46319"),
    ("Card: 4 1 4 6 8 6 1 9 5 2 8 5 1 5 6 8", "CREDIT_CARD", "4 1 4 6 8 6 1 9 5 2 8 5 1 5 6 8"),
]

# Hard negatives: none of these may be flagged as anything sensitive.
NEGATIVES = [
    "Trace 3f1c9a2e-7b4d-4e0a-9c11-5d2e8f6a0b47 completed",
    "Deployed commit 9c4b1e2f7a3d5e6f8a9b0c1d2e3f4a5b6c7d8e9f to staging",
    "Upgraded the agent to v2.14.3",
    '{"ok": true, "tracking_number": "219703564", "items": 8}',
    '{"id": 96930, "created": "2026-02-07T11:42:43Z", "zip": "94107"}',
    "Parcel number 940186481 is out for delivery.",
    "sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
]

# Baseline recall measured on the examples above (2026-10-24). Raise these
# when detection improves; never lower them to make a regression pass.
BASELINE_RECALL = {"US_SSN": 1.0, "AWS_ACCESS_KEY": 1.0, "EMAIL": 1.0, "JWT": 1.0, "PRIVATE_KEY": 1.0,
                   "GITHUB_TOKEN": 1.0, "ADDRESS": 1.0, "CREDIT_CARD": 1.0}

# Measured on the full benchmark (bench/results/detection_after_fast_path.md),
# rounded down. Checked by test_full_benchmark_floors when bench/data exists.
FULL_BENCH_FLOORS = {"example_recall_payload": 0.94, "example_precision_payload": 1.0,
                     "strict_precision": 0.96, "strict_recall": 0.94}
FULL_BENCH_MAX_FALSE_ALARM = 0.0

TYPE_MAP = {"US_SSN": "US_SSN", "USA_SSN": "US_SSN", "EMAIL_ADDRESS": "EMAIL",
            "STREET_ADDRESS": "ADDRESS", "LOCATION": "ADDRESS"}


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

    def test_hard_negatives_not_flagged(self):
        for text in NEGATIVES:
            bad = [d.entity_type for d in detect.detect_text(text) if d.is_sensitive]
            self.assertEqual(bad, [], text)

    def test_full_benchmark_floors(self):
        data = Path(__file__).resolve().parent.parent / "bench" / "data" / "detection.jsonl"
        if not data.exists():
            self.skipTest("bench/data/detection.jsonl not present")
        sys.path.insert(0, str(data.parent.parent))
        import run_detection

        res = run_detection.evaluate(run_detection.load(data))
        payload = res["binary"]["payload"]
        got = {"example_recall_payload": payload["recall"],
               "example_precision_payload": payload["precision"],
               "strict_precision": res["overall_strict"]["precision"],
               "strict_recall": res["overall_strict"]["recall"]}
        for name, floor in FULL_BENCH_FLOORS.items():
            self.assertGreaterEqual(got[name], floor - 0.005, f"{name} {got[name]:.3f} < {floor}")
        self.assertLessEqual(payload["false_alarm_rate"], FULL_BENCH_MAX_FALSE_ALARM)


if __name__ == "__main__":
    unittest.main()
