"""Markdown tables from saved placeholder evaluation results."""

from __future__ import annotations

import json
from pathlib import Path

COLS = [
    ("restore ok", lambda s: f"{s['restore_ok']}/{s['tasks']}"),
    ("placeholders back", lambda s: f"{s['placeholders_survived']}/{s['placeholders_needed']}"),
    ("copied exactly", lambda s: f"{s['placeholders_exact']}/{s['placeholders_needed']}"),
    ("rewritten, not restored", lambda s: str(s["rewritten"])),
    ("dropped", lambda s: str(s["dropped"])),
    ("tool args ok", lambda s: f"{s['tool_args_ok']}/{s['tool_tasks']}"),
    ("tool called", lambda s: f"{s['tool_called']}/{s['tool_tasks']}"),
    ("wrong restore", lambda s: str(s["wrong_restore"])),
    ("model mix-up", lambda s: str(s["mixups"])),
    ("leftover", lambda s: str(s["leftover_tasks"])),
    ("raw value sent", lambda s: str(s["leak_known"])),
    ("failures flagged", lambda s: s["failed_flagged"]),
]


def load(results_dir: Path) -> list[dict]:
    runs = []
    for p in sorted(Path(results_dir).glob("*.json")):
        if "__partial" in p.name:
            continue
        runs.append(json.loads(p.read_text()))
    return runs


def render(results_dir: Path) -> str:
    runs = load(results_dir)
    if not runs:
        return "no results yet"
    head = "| model | mode | " + " | ".join(c for c, _ in COLS) + " |"
    sep = "|" + "---|" * (len(COLS) + 2)
    rows = [head, sep]
    order = {"baseline": 0, "replay": 1, "hardened": 2}
    label = {"replay": "baseline answers + tolerant restore (offline)"}
    for r in sorted(runs, key=lambda r: (r["provider"], r["model"], order.get(r["mode"], 9))):
        name = r["model"] if r["provider"] == "ollama" else f"{r['model']} ({r['provider']})"
        rows.append(f"| {name} | {label.get(r['mode'], r['mode'])} | "
                    + " | ".join(f(r["summary"]) for _, f in COLS) + " |")
    cats = list(runs[0]["summary"]["by_category"])
    rows += ["", "| model | mode | " + " | ".join(cats) + " |", "|" + "---|" * (len(cats) + 2)]
    for r in sorted(runs, key=lambda r: (r["provider"], r["model"], order.get(r["mode"], 9))):
        name = r["model"] if r["provider"] == "ollama" else f"{r['model']} ({r['provider']})"
        rows.append(f"| {name} | {label.get(r['mode'], r['mode'])} | "
                    + " | ".join(r["summary"]["by_category"].get(c, "-") for c in cats) + " |")
    return "\n".join(rows)
