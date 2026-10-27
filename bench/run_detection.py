"""Detection-quality benchmark for taintward.sdk.detect.

Runs ``taintward.sdk.detect.detect_text`` over every example in the labeled dataset and
reports:

* span-level precision / recall / F1 per entity class and overall. A
  prediction matches a labeled entity when their character spans overlap and
  the predicted type maps to the labeled class ("strict"). A second, "any
  type" view counts an overlap with any labeled entity as a hit, because for
  taint purposes an SSN flagged as a bank number still taints the chain.
* an example-level binary metric: "was any sensitive data detected in this
  example?" This is what actually drives taint in instrument_tool. It is
  measured two ways: on the raw text, and in "payload" mode where JSON
  examples are parsed and walked with ``detect_mapping`` exactly like the SDK
  does for a tool that returns a dict.
* recall on evasion examples and false-alarm rate on hard negatives, per tag.
* the worst false negatives and false positives.

Writes ``bench/results/detection<suffix>.json`` and ``.md``.

Usage:  python bench/run_detection.py [--data bench/data/detection.jsonl] [--label baseline]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from taintward.sdk import detect  # noqa: E402

CLASSES = [
    "US_SSN", "EMAIL", "PHONE", "CREDIT_CARD", "IBAN", "PERSON", "ADDRESS",
    "AWS_ACCESS_KEY", "GITHUB_TOKEN", "GENERIC_API_KEY", "JWT", "PRIVATE_KEY",
]

# Detector entity type -> benchmark class. Anything not listed is reported as
# "OTHER:<type>" (it still taints, so it matters for false alarms).
TYPE_MAP = {
    "US_SSN": "US_SSN", "USA_SSN": "US_SSN",
    "EMAIL_ADDRESS": "EMAIL", "EMAIL": "EMAIL",
    "PHONE_NUMBER": "PHONE",
    "CREDIT_CARD": "CREDIT_CARD",
    "IBAN_CODE": "IBAN",
    "PERSON": "PERSON",
    "LOCATION": "ADDRESS",
    "STREET_ADDRESS": "ADDRESS",
    "AWS_ACCESS_KEY": "AWS_ACCESS_KEY",
    "GITHUB_TOKEN": "GITHUB_TOKEN",
    "GENERIC_API_KEY": "GENERIC_API_KEY",
    "JWT": "JWT",
    "PRIVATE_KEY": "PRIVATE_KEY",
}


def map_type(t: str) -> str:
    return TYPE_MAP.get(t, f"OTHER:{t}")


def overlaps(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    return a_start < b_end and b_start < a_end


def mask(value: str) -> str:
    # Reports are committed, so never write a full secret into them.
    return value if len(value) <= 8 else f"{value[:8]}...({len(value)} chars)"


def prf(tp_p: int, n_pred: int, tp_g: int, n_gold: int) -> dict:
    p = tp_p / n_pred if n_pred else None
    r = tp_g / n_gold if n_gold else None
    f = (2 * p * r / (p + r)) if (p is not None and r is not None and p + r) else (0.0 if n_gold else None)
    return {"precision": p, "recall": r, "f1": f, "n_pred": n_pred, "n_gold": n_gold,
            "tp_pred": tp_p, "tp_gold": tp_g}


def load(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def payload_detect(ex: dict) -> list:
    if ex["format"] == "json":
        try:
            return detect.detect_mapping(json.loads(ex["text"]))
        except ValueError:
            pass
    return detect.detect_text(ex["text"])


def evaluate(examples: list[dict]) -> dict:
    gold_n = Counter()
    gold_hit_strict = Counter()
    gold_hit_any = Counter()
    pred_n = Counter()
    pred_ok_strict = Counter()
    pred_ok_any = Counter()
    false_negatives: list[dict] = []
    false_positives: list[dict] = []
    per_tag = defaultdict(lambda: {"examples": 0, "flagged": 0, "gold": 0, "gold_hit": 0})
    binary = {"text": Counter(), "payload": Counter(), "correct_span": Counter()}

    t0 = time.perf_counter()
    for ex in examples:
        golds = ex["entities"]
        preds = [d for d in detect.detect_text(ex["text"]) if d.is_sensitive]
        pmapped = [(map_type(d.entity_type), d) for d in preds]

        for g in golds:
            gold_n[g["type"]] += 1
            strict = any(c == g["type"] and overlaps(d.start, d.end, g["start"], g["end"])
                         for c, d in pmapped)
            anyt = any(overlaps(d.start, d.end, g["start"], g["end"]) for _, d in pmapped)
            gold_hit_strict[g["type"]] += strict
            gold_hit_any[g["type"]] += anyt
            if not strict:
                false_negatives.append({
                    "id": ex["id"], "class": g["type"], "tag": ex["tag"], "format": ex["format"],
                    "value": mask(g["value"]),
                    "found_as": sorted({c for c, d in pmapped
                                        if overlaps(d.start, d.end, g["start"], g["end"])}),
                })

        for c, d in pmapped:
            pred_n[c] += 1
            ok_s = any(c == g["type"] and overlaps(d.start, d.end, g["start"], g["end"]) for g in golds)
            ok_a = any(overlaps(d.start, d.end, g["start"], g["end"]) for g in golds)
            pred_ok_strict[c] += ok_s
            pred_ok_any[c] += ok_a
            if not ok_a:
                false_positives.append({
                    "id": ex["id"], "predicted": c, "score": round(d.score, 2), "tag": ex["tag"],
                    "format": ex["format"], "matched_text": ex["text"][d.start:d.end][:80],
                })

        # Example-level "is this tainted?"
        truth = bool(golds)
        flagged_text = bool(preds)
        flagged_payload = any(d.is_sensitive for d in payload_detect(ex))
        flagged_correct = any(overlaps(d.start, d.end, g["start"], g["end"])
                              for d in preds for g in golds)
        for mode, flag in (("text", flagged_text), ("payload", flagged_payload),
                           ("correct_span", flagged_correct if truth else flagged_text)):
            key = ("tp" if flag else "fn") if truth else ("fp" if flag else "tn")
            binary[mode][key] += 1

        t = per_tag[ex["tag"]]
        t["examples"] += 1
        t["flagged"] += flagged_text
        t["gold"] += len(golds)
        t["gold_hit"] += sum(1 for g in golds if any(
            overlaps(d.start, d.end, g["start"], g["end"]) for d in preds))
    elapsed = time.perf_counter() - t0

    per_class = {}
    for c in CLASSES:
        per_class[c] = prf(pred_ok_strict[c], pred_n[c], gold_hit_strict[c], gold_n[c])
        per_class[c]["recall_any_type"] = gold_hit_any[c] / gold_n[c] if gold_n[c] else None
    other_preds = {c: {"n_pred": pred_n[c], "overlapping_a_label": pred_ok_any[c]}
                   for c in sorted(pred_n) if c.startswith("OTHER:")}

    # Overall micro-averaged. Strict: predictions of non-benchmark types count
    # against precision (they are false alarms unless they overlap a label).
    all_pred = sum(pred_n.values())
    overall_strict = prf(sum(pred_ok_strict.values()), all_pred,
                         sum(gold_hit_strict.values()), sum(gold_n.values()))
    overall_any = prf(sum(pred_ok_any.values()), all_pred,
                      sum(gold_hit_any.values()), sum(gold_n.values()))

    def bin_metrics(cnt: Counter) -> dict:
        tp, fp, fn, tn = cnt["tp"], cnt["fp"], cnt["fn"], cnt["tn"]
        p = tp / (tp + fp) if tp + fp else None
        r = tp / (tp + fn) if tp + fn else None
        f = 2 * p * r / (p + r) if p and r else 0.0
        return {"precision": p, "recall": r, "f1": f, "false_alarm_rate": fp / (fp + tn) if fp + tn else None,
                "tp": tp, "fp": fp, "fn": fn, "tn": tn}

    fn_rank = {c: per_class[c]["recall"] or 0 for c in CLASSES}
    false_negatives.sort(key=lambda x: (fn_rank.get(x["class"], 0), x["class"], x["id"]))
    false_positives.sort(key=lambda x: (-x["score"], x["predicted"], x["id"]))

    return {
        "n_examples": len(examples),
        "n_entities": sum(gold_n.values()),
        "seconds": round(elapsed, 2),
        "per_class": per_class,
        "other_detector_types": other_preds,
        "overall_strict": overall_strict,
        "overall_any_type": overall_any,
        "binary": {m: bin_metrics(c) for m, c in binary.items()},
        "per_tag": dict(sorted(per_tag.items())),
        "false_negatives": false_negatives,
        "false_positives": false_positives,
    }


def spread(items: list[dict], key: str, per_group: int, limit: int) -> list[dict]:
    """Take up to ``per_group`` items from each group (in order), so one noisy
    class does not fill the whole "worst" list."""
    seen: Counter = Counter()
    out = []
    for x in items:
        if seen[x[key]] < per_group:
            seen[x[key]] += 1
            out.append(x)
    return out[:limit]


def fmt(x) -> str:
    return "-" if x is None else f"{x:.2f}"


def to_markdown(res: dict, label: str) -> str:
    L = [f"# Detection benchmark ({label})", "",
         f"{res['n_examples']} examples, {res['n_entities']} labeled entities, "
         f"{res['seconds']}s total.", "",
         "## Per class (span overlap, type must match)", "",
         "| class | gold | pred | precision | recall | F1 | recall (any type) |",
         "|---|---:|---:|---:|---:|---:|---:|"]
    for c, m in res["per_class"].items():
        L.append(f"| {c} | {m['n_gold']} | {m['n_pred']} | {fmt(m['precision'])} | "
                 f"{fmt(m['recall'])} | {fmt(m['f1'])} | {fmt(m['recall_any_type'])} |")
    for name, key in (("overall, strict", "overall_strict"), ("overall, any type", "overall_any_type")):
        m = res[key]
        L.append(f"| **{name}** | {m['n_gold']} | {m['n_pred']} | {fmt(m['precision'])} | "
                 f"{fmt(m['recall'])} | {fmt(m['f1'])} | |")
    L += ["", "## Detector types outside the benchmark classes", "",
          "| detector type | predictions | overlapping a real label |", "|---|---:|---:|"]
    for c, m in res["other_detector_types"].items():
        L.append(f"| {c[6:]} | {m['n_pred']} | {m['overlapping_a_label']} |")
    L += ["", "## Example level: was anything sensitive detected?", "",
          "| mode | precision | recall | F1 | false alarm rate on negatives | TP | FP | FN | TN |",
          "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for mode, m in res["binary"].items():
        L.append(f"| {mode} | {fmt(m['precision'])} | {fmt(m['recall'])} | {fmt(m['f1'])} | "
                 f"{fmt(m['false_alarm_rate'])} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} |")
    L += ["", "`text` = detect_text on the raw string. `payload` = JSON examples parsed and "
          "walked with detect_mapping, like instrument_tool does. `correct_span` = a positive "
          "only counts if some detection overlaps a real label.", "",
          "## Per tag", "", "| tag | examples | flagged | labeled entities hit (any type) |",
          "|---|---:|---:|---:|"]
    for tag, t in res["per_tag"].items():
        hit = f"{t['gold_hit']}/{t['gold']}" if t["gold"] else "-"
        L.append(f"| {tag} | {t['examples']} | {t['flagged']} | {hit} |")
    L += ["", "## Worst false negatives (up to 3 per class, lowest-recall classes first)", "", "| id | class | tag | format | value | found as |",
          "|---|---|---|---|---|---|"]
    for x in spread(res["false_negatives"], "class", 3, 36):
        v = x["value"].replace("\n", "\\n").replace("|", "\\|")
        L.append(f"| {x['id']} | {x['class']} | {x['tag']} | {x['format']} | `{v}` | "
                 f"{', '.join(x['found_as']) or '-'} |")
    L += ["", "## Worst false positives (up to 5 per detector type, highest score first)", "",
          "| id | predicted | score | tag | format | matched text |", "|---|---|---:|---|---|---|"]
    for x in spread(res["false_positives"], "predicted", 5, 40):
        v = x["matched_text"].replace("\n", "\\n").replace("|", "\\|")
        L.append(f"| {x['id']} | {x['predicted']} | {x['score']} | {x['tag']} | {x['format']} | `{v}` |")
    return "\n".join(L) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description="Detection-quality benchmark for taintward.sdk.detect")
    ap.add_argument("--data", default=str(ROOT / "bench" / "data" / "detection.jsonl"))
    ap.add_argument("--out-dir", default=str(ROOT / "bench" / "results"))
    ap.add_argument("--label", default="current", help="name for this run, used in file names")
    args = ap.parse_args()

    examples = load(Path(args.data))
    detect.detect_text("warm up")  # build Presidio once, outside the timing
    res = evaluate(examples)
    res["label"] = args.label
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"detection_{args.label}.json").write_text(json.dumps(res, indent=2) + "\n")
    md = to_markdown(res, args.label)
    (out / f"detection_{args.label}.md").write_text(md)
    print(md)


if __name__ == "__main__":
    main()
