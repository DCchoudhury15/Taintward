"""Checks for the outside-data benchmark helpers (bench/external/run_external.py).

These do not need the datasets. They check that result files can only hold
value shapes, never values, and that the scoring helpers behave.
"""

from __future__ import annotations

import importlib.util
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "bench" / "external" / "run_external.py"
RESULTS = ROOT / "bench" / "results"


def _load():
    spec = importlib.util.spec_from_file_location("run_external", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ext = _load()


class ShapeTest(unittest.TestCase):
    def test_examples(self):
        self.assertEqual(ext.shape("Anna-Lena 042"), "Aa-Aa d3")
        self.assertEqual(ext.shape("alice.lee@example.com"), "a.a@a.a")
        self.assertEqual(ext.shape("000-00-0000"), "d3-d2-d4")
        self.assertEqual(ext.shape("Иван Петров"), "X X")

    def test_shape_never_spells_the_value(self):
        for value in ["Johnathan Smithers", "DE89370400440532013000",
                      "ExampleKeyValue12345", "4111 1111 1111 1111"]:
            s = re.sub(r"d\d+", "", ext.shape(value))
            self.assertRegex(s, r"^[AaX \W]*$", f"{value!r} -> {s!r}")

    def test_shape_is_capped(self):
        self.assertLessEqual(len(ext.shape("a1 " * 100)), 40)


class ChecksumTest(unittest.TestCase):
    def test_card(self):
        self.assertTrue(ext.checksum_valid("CREDIT_CARD", "4111 1111 1111 1111"))
        self.assertFalse(ext.checksum_valid("CREDIT_CARD", "4111 1111 1111 1112"))

    def test_iban(self):
        self.assertTrue(ext.checksum_valid("IBAN", "DE89 3704 0044 0532 0130 00"))
        self.assertFalse(ext.checksum_valid("IBAN", "DE88 3704 0044 0532 0130 00"))

    def test_other_class(self):
        self.assertIsNone(ext.checksum_valid("PERSON", "Anna"))


class SampleTest(unittest.TestCase):
    def test_same_seed_same_sample(self):
        rows = [{"id": str(i), "lang": "en" if i % 2 else "de"} for i in range(50)]
        a = [r["id"] for r in ext.sample(rows, 5, 1337)]
        b = [r["id"] for r in ext.sample(rows, 5, 1337)]
        self.assertEqual(a, b)
        self.assertEqual(len(a), 10)

    def test_bad_offsets_dropped(self):
        rows = [{"text": "abc", "entities": [
            {"start": 0, "end": 2, "label": "NAME"},
            {"start": 2, "end": 9, "label": "NAME"}]}]
        stats = ext.clean_entities(rows, {"NAME": "PERSON"})
        self.assertEqual(stats["bad_offsets"], 1)
        self.assertEqual(rows[0]["entities"][0]["cls"], "PERSON")


class DevSplitTest(unittest.TestCase):
    """Rules are tuned on the dev rows; they must never overlap the test rows."""

    def test_dev_rows_are_not_in_the_test_sample(self):
        rows = [{"id": str(i), "lang": ("en", "de", "fr")[i % 3]} for i in range(300)]
        test = ext.sample(rows, 40, 1337)
        dev = ext.dev_sample(rows, test, 40, 1337)
        self.assertEqual(len(dev), 120)
        self.assertFalse({r["id"] for r in dev} & {r["id"] for r in test})


class FloorsTest(unittest.TestCase):
    """--check fails the CI job when a score drops under its floor."""

    @staticmethod
    def _res(recall=0.9, precision=0.9, ex_recall=0.99, fa=0.0, cls_recall=0.99):
        return {"overall_strict": {"recall": recall, "precision": precision},
                "binary": {"text": {"recall": ex_recall, "false_alarm_rate": fa}},
                "per_class": {c: {"recall": cls_recall} for c in ext.CLASSES}}

    def test_good_scores_pass(self):
        for name in ext.FLOORS:
            self.assertEqual(ext.check_floors(name, self._res()), [])

    def test_each_kind_of_drop_fails(self):
        self.assertTrue(ext.check_floors("gretel", self._res(recall=0.1)))
        self.assertTrue(ext.check_floors("gretel", self._res(precision=0.1)))
        self.assertTrue(ext.check_floors("gretel", self._res(ex_recall=0.1)))
        self.assertTrue(ext.check_floors("gretel", self._res(fa=0.99)))
        self.assertTrue(ext.check_floors("ai4privacy", self._res(cls_recall=0.1)))

    def test_floors_only_name_known_classes(self):
        for f in ext.FLOORS.values():
            self.assertLessEqual(set(f["class_recall"]), set(ext.CLASSES))


class CommittedResultsTest(unittest.TestCase):
    """The committed result files must not hold anything that looks like a value."""

    PATTERNS = [
        r"\b\d{3}-\d{2}-\d{4}\b",
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z]{2,}",
        r"\bAKIA[A-Z0-9]{12,}",
        r"\b[A-Z]{2}\d{2}[A-Z0-9]{12,30}\b",
        r"(?<![.\d])(?:\d[ -]?){13,19}\b",
    ]

    def test_no_value_like_strings(self):
        files = sorted(RESULTS.glob("external_*"))
        if not files:
            self.skipTest("no outside-data results committed")
        for f in files:
            text = f.read_text(encoding="utf-8")
            for p in self.PATTERNS:
                m = re.search(p, text)
                self.assertIsNone(m, f"{f.name}: {m and m.group(0)!r}")


if __name__ == "__main__":
    unittest.main()
