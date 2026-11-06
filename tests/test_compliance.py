"""Compliance mappings (taintward/evidence/compliance.py) and their report
section. The mapping must stay consistent (every control it names exists),
honest (nothing claims more than "supports"; the gaps are listed), and the
docs page must be what the code generates."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from taintward.evidence import compliance as C
from taintward.evidence.report import main, render_html
from tests.test_report import clean_spans, report

ROOT = Path(__file__).resolve().parents[1]


def test_every_named_control_exists_and_levels_are_known():
    for r in C.REQUIREMENTS:
        assert r.framework in C.FRAMEWORKS, r
        assert r.level in C.LEVELS, r
        assert all(c in C.CONTROLS for c in r.controls), r
        assert r.limits, f"{r.ref} needs its limits"
        if r.level == C.NOT_COVERED:
            assert r.how == "-", r
        else:
            assert r.controls and r.how != "-", r


def test_each_framework_lists_gaps_and_is_not_all_supports():
    for fid in C.FRAMEWORKS:
        levels = [r.level for r in C.REQUIREMENTS if r.framework == fid]
        assert len(levels) >= 4
        assert set(levels) != {C.SUPPORTS}, f"{fid}: every row says supports"
    gaps = {(r.framework, r.ref) for r in C.REQUIREMENTS if r.level == C.NOT_COVERED}
    assert ("hipaa", "§164.514(b)") in gaps  # redaction is not Safe Harbor de-identification
    assert ("eu-ai-act", "Art. 10") in gaps   # training data
    assert ("hipaa", "§164.308(b)") in gaps   # a BAA is still needed


def test_no_row_promises_compliance():
    text = C.markdown().lower()
    for word in ("compliant ", "guarantee", "ensures compliance", "certified"):
        assert word not in text.replace("not by itself make a system compliant", ""), word


def test_docs_page_is_generated_from_the_code():
    page = (ROOT / "docs" / "compliance.md").read_text()
    assert page == C.markdown(), "run: python -m taintward.evidence.compliance > docs/compliance.md"
    nav = (ROOT / "mkdocs.yml").read_text()
    assert "compliance.md" in nav


def test_parse_frameworks():
    assert C.parse_frameworks("") == ()
    assert C.parse_frameworks("all") == tuple(C.FRAMEWORKS)
    assert C.parse_frameworks("HIPAA, gdpr,gdpr") == ("hipaa", "gdpr")
    with pytest.raises(ValueError, match="unknown framework pci"):
        C.parse_frameworks("gdpr,pci")


def test_report_rows_use_the_reports_own_numbers():
    data = report(clean_spans(), frameworks=("gdpr", "soc2"))
    rows = {(r["framework"], r["ref"]): r for r in data["compliance"]["rows"]}
    assert {f for f, _ in rows} == {"gdpr", "soc2"}
    assert rows[("gdpr", "Art. 44")]["evidence"] == "Section 5: 4 transfer(s) (us: 4)"
    assert rows[("gdpr", "Art. 30")]["evidence"].startswith("Section 6: ")
    assert "6 recipient(s)" in rows[("gdpr", "Art. 30")]["evidence"]
    v = data["violations"]["total"]
    assert rows[("soc2", "CC7.3")]["evidence"].startswith(f"Section 4: {v} violation(s)")
    assert rows[("gdpr", "Art. 5(1)(c)")]["evidence"] == (
        "Section 7: " + data["raw_check"]["claim"]["statement"])
    assert rows[("gdpr", "Art. 5(2)")]["evidence"] == (
        "Section 8: no evidence log was given for this report")
    assert rows[("gdpr", "Art. 17")]["evidence"] == ""  # nothing in a report shows it


def test_section_only_with_frameworks_and_part_of_the_digest():
    plain = report(clean_spans())
    assert "compliance" not in plain
    assert "Compliance mapping" not in render_html(plain)
    mapped = report(clean_spans(), frameworks=("hipaa",))
    page = render_html(mapped)
    assert "11. Compliance mapping" in page and "§164.514(b)" in page
    assert "not legal advice" in page
    assert mapped["digest"] != plain["digest"]


def test_cli_frameworks(tmp_path, capsys):
    from tests.test_report import _doc, _tool
    f = tmp_path / "t.json"
    f.write_text(json.dumps(_doc([_tool("c" * 32, "1" * 16, "ask_llm", "llm", 1)])))
    args = ["--source", "otlp-file", "--otlp-file", str(f), "--since", "3650d",
            "--format", "json", "--out", str(tmp_path / "r.json")]
    assert main(args + ["--frameworks", "eu-ai-act"]) == 0
    data = json.loads((tmp_path / "r.json").read_text())
    assert {r["framework"] for r in data["compliance"]["rows"]} == {"eu-ai-act"}
    with pytest.raises(SystemExit):
        main(args + ["--frameworks", "nope"])
    assert "unknown framework nope" in capsys.readouterr().err
