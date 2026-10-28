"""Detection quality and latency on outside, publicly labeled PII data.

The synthetic benchmark in bench/ was written together with the detection
rules, so it flatters them. This script runs the same detector, scored the
same way as bench/run_detection.py, on labeled data written by other people:

* ai4privacy/open-pii-masking-500k-ai4privacy, validation split
  (CC-BY-4.0 plus the Llama 3.1 / 3.3 community license; built with Llama).
  Short texts in en, fr, de, es, it, nl, hi, te.
* gretelai/synthetic_pii_finance_multilingual, test split (Apache-2.0).
  Full-length financial documents (emails, statements, XML / JSON formats)
  in English, Spanish, Swedish, German, Italian, Dutch and French.

Both are themselves synthetic (written by LLMs), but neither was seen while
the rules were written, and they use their own label sets and formats.

Run bench/external/download.py first (it caches the files outside git).
No detection rule was changed for this evaluation.

What is measured, per dataset:

* span level precision / recall / F1 per Taintward class, strict (the
  detector type must fit the class) and "any type" (any detection that
  overlaps counts, because for taint any hit taints the chain), overall and
  per language,
* recall per source label, including labels with no Taintward class,
* example level "was anything sensitive detected?" on the raw text and in
  payload mode (texts that parse as JSON are walked with detect_mapping),
* time of detect_text per example (cache cleared before each call) and of
  a wrapped echo tool for a subset,
* the most common shapes of missed values and of false alarms, so the
  results can drive the next rule changes.

Committed result files never contain dataset text: values are shown only as
their shape (``Aa Aa``, ``dd.dd.dd``), with the dataset row id.

Usage:
    python bench/external/download.py
    python bench/external/run_external.py                 # both datasets
    python bench/external/run_external.py --source gretel --per-language 100
"""

from __future__ import annotations

import argparse
import ast
import json
import random
import re
import statistics
import sys
import time
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "bench"))

import download  # noqa: E402
from run_detection import fmt, overlaps, prf  # noqa: E402

from taintward.sdk import detect  # noqa: E402

# ---------------------------------------------------------------------------
# Label mapping
# ---------------------------------------------------------------------------

# Taintward class -> detector entity types that count as the right type.
ACCEPT = {
    "PERSON": {"PERSON"},
    "EMAIL": {"EMAIL_ADDRESS"},
    "PHONE": {"PHONE_NUMBER"},
    "CREDIT_CARD": {"CREDIT_CARD"},
    "IBAN": {"IBAN_CODE"},
    # Social security / national insurance numbers. Taintward only has US
    # (and two Presidio extras) formats for this.
    "SSN": {"US_SSN", "USA_SSN", "UK_NHS", "US_ITIN", "IN_AADHAAR"},
    # Other government ids: passport, driver license, id card, tax number.
    "GOV_ID": {"US_DRIVER_LICENSE", "US_PASSPORT", "US_ITIN", "IN_PAN", "IN_AADHAAR",
               "UK_NHS", "US_SSN"},
    "ADDRESS": {"LOCATION", "STREET_ADDRESS"},
    "IP_ADDRESS": {"IP_ADDRESS"},
    "SECRET": {"AWS_ACCESS_KEY", "GITHUB_TOKEN", "GENERIC_API_KEY", "JWT", "PRIVATE_KEY"},
}
CLASSES = list(ACCEPT)

# Detector type -> the class its predictions are counted under (for the
# per class precision column). Types not listed are "OTHER:<type>".
PRIMARY = {
    "PERSON": "PERSON", "EMAIL_ADDRESS": "EMAIL", "PHONE_NUMBER": "PHONE",
    "CREDIT_CARD": "CREDIT_CARD", "IBAN_CODE": "IBAN",
    "US_SSN": "SSN", "USA_SSN": "SSN", "UK_NHS": "SSN", "IN_AADHAAR": "SSN",
    "US_DRIVER_LICENSE": "GOV_ID", "US_PASSPORT": "GOV_ID", "US_ITIN": "GOV_ID",
    "IN_PAN": "GOV_ID",
    "LOCATION": "ADDRESS", "STREET_ADDRESS": "ADDRESS",
    "IP_ADDRESS": "IP_ADDRESS",
    "AWS_ACCESS_KEY": "SECRET", "GITHUB_TOKEN": "SECRET", "GENERIC_API_KEY": "SECRET",
    "JWT": "SECRET", "PRIVATE_KEY": "SECRET",
}

# Source label -> Taintward class, or None when Taintward has no class for it.
LABEL_MAP = {
    "ai4privacy": {
        "GIVENNAME": "PERSON", "SURNAME": "PERSON",
        "EMAIL": "EMAIL",
        "TELEPHONENUM": "PHONE",
        "CREDITCARDNUMBER": "CREDIT_CARD",
        "SOCIALNUM": "SSN",
        "IDCARDNUM": "GOV_ID", "PASSPORTNUM": "GOV_ID", "DRIVERLICENSENUM": "GOV_ID",
        "TAXNUM": "GOV_ID",
        "STREET": "ADDRESS", "BUILDINGNUM": "ADDRESS", "CITY": "ADDRESS", "ZIPCODE": "ADDRESS",
        # no Taintward class
        "DATE": None, "TIME": None, "AGE": None, "SEX": None, "GENDER": None,
        "TITLE": None, "USERNAME": None,
    },
    "gretel": {
        "name": "PERSON", "first_name": "PERSON", "last_name": "PERSON",
        "email": "EMAIL",
        "phone_number": "PHONE",
        "credit_card_number": "CREDIT_CARD",
        "iban": "IBAN",
        "ssn": "SSN",
        "driver_license_number": "GOV_ID", "passport_number": "GOV_ID",
        "street_address": "ADDRESS",
        "ipv4": "IP_ADDRESS", "ipv6": "IP_ADDRESS",
        "api_key": "SECRET", "password": "SECRET",
        # no Taintward class
        "company": None, "date": None, "date_of_birth": None, "date_time": None,
        "time": None, "customer_id": None, "employee_id": None, "account_pin": None,
        "bank_routing_number": None, "bban": None, "swift_bic_code": None,
        "credit_card_security_code": None, "local_latlng": None, "user_name": None,
    },
}

GRETEL_LANG = {"English": "en", "Spanish": "es", "Swedish": "sv", "German": "de",
               "Italian": "it", "Dutch": "nl", "French": "fr", "France": "fr"}

# ---------------------------------------------------------------------------
# Loading and sampling
# ---------------------------------------------------------------------------


def _parse_list(raw):
    if isinstance(raw, list):
        return raw
    if raw is None:
        return []
    try:
        return json.loads(raw)
    except ValueError:
        return ast.literal_eval(raw)


def load_ai4privacy(path: Path) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            r = json.loads(line)
            ents = [{"start": int(e["start"]), "end": int(e["end"]), "label": e["label"]}
                    for e in _parse_list(r["privacy_mask"])]
            rows.append({"id": str(r.get("uid") or r.get("id")), "lang": r["language"],
                         "text": r["source_text"], "entities": ents, "kind": "text"})
    return rows


def load_gretel(path: Path) -> list[dict]:
    import pyarrow.parquet as pq

    table = pq.read_table(path)
    cols = table.column_names
    text_col = "generated_text" if "generated_text" in cols else "text"
    data = table.to_pydict()
    rows = []
    for i in range(table.num_rows):
        ents = [{"start": int(e["start"]), "end": int(e["end"]), "label": e["label"]}
                for e in _parse_list(data["pii_spans"][i])]
        lang = data["language"][i]
        rows.append({"id": str(data["index"][i]) if "index" in cols else str(i),
                     "lang": GRETEL_LANG.get(lang, lang), "text": data[text_col][i],
                     "entities": ents, "kind": data.get("document_type", [""] * table.num_rows)[i]})
    return rows


def sample(rows: list[dict], per_language: int, seed: int) -> list[dict]:
    by_lang = defaultdict(list)
    for r in rows:
        by_lang[r["lang"]].append(r)
    rng = random.Random(seed)
    out = []
    for lang in sorted(by_lang):
        group = by_lang[lang]
        out.extend(rng.sample(group, min(per_language, len(group))))
    return out


def clean_entities(rows: list[dict], label_map: dict) -> dict:
    """Drop labels whose offsets are outside the text. Returns counts."""
    stats = Counter()
    for r in rows:
        kept = []
        for e in r["entities"]:
            if not (0 <= e["start"] < e["end"] <= len(r["text"])):
                stats["bad_offsets"] += 1
                continue
            if e["label"] not in label_map:
                stats[f"unknown_label:{e['label']}"] += 1
            e["cls"] = label_map.get(e["label"])
            kept.append(e)
        r["entities"] = kept
    return dict(stats)


# ---------------------------------------------------------------------------
# Shapes (so result files never hold dataset text)
# ---------------------------------------------------------------------------


def shape(value: str) -> str:
    """``Anna-Lena 042`` -> ``Aa-Aa d3``. Letters: A (capital) / a (lower),
    other scripts: X, a run of digits: d plus its length. Letter runs are
    collapsed, so the shape never spells out the value."""
    out: list[str] = []
    digits = 0

    def flush() -> None:
        nonlocal digits
        if digits:
            out.append(f"d{digits}")
            digits = 0

    for ch in value:
        if ch.isdigit():
            digits += 1
            continue
        flush()
        if ch.isalpha():
            if ch.isascii() or unicodedata.name(ch, "").startswith("LATIN"):
                c = "A" if ch.isupper() else "a"
            else:
                c = "X"
        elif ch.isspace():
            c = " "
        else:
            c = ch
        if out and out[-1] == c:
            continue
        out.append(c)
    flush()
    return "".join(out)[:40]


def script_of(value: str) -> str:
    for ch in value:
        if ch.isalpha() and not ch.isascii():
            name = unicodedata.name(ch, "")
            if not name.startswith("LATIN"):
                return name.split(" ")[0].lower()
    return "latin"


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


def _iban_ok(value: str) -> bool:
    v = re.sub(r"\s", "", value).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{8,30}", v):
        return False
    moved = v[4:] + v[:4]
    return int("".join(str(int(c, 36)) for c in moved)) % 97 == 1


def checksum_valid(cls: str, value: str) -> bool | None:
    """Whether a card / IBAN label passes its checksum (None for other classes).
    Taintward rejects numbers that fail it, on purpose."""
    if cls == "CREDIT_CARD":
        d = re.sub(r"\D", "", value)
        return 12 <= len(d) <= 19 and _luhn_ok(d)
    if cls == "IBAN":
        return _iban_ok(value)
    return None


def fn_reason(text: str, g: dict, found_as: list[str]) -> str:
    """A rough reason bucket for a missed label, for the improvement list."""
    v = text[g["start"]:g["end"]]
    cls = g["cls"]
    if found_as:
        return "found as another type: " + ",".join(found_as)
    if checksum_valid(cls, v) is False:
        return f"{cls} fails its checksum (rejected on purpose)"
    if script_of(v) != "latin":
        return "non-Latin script"
    if cls == "PERSON":
        if not re.search(r"[A-ZÀ-Þ]", v):
            return "name not capitalized"
        return "capitalized name missed by NER"
    if cls == "ADDRESS":
        return f"address part: {g['label']}"
    if cls in ("PHONE", "SSN", "GOV_ID", "CREDIT_CARD", "IBAN", "IP_ADDRESS"):
        return f"{cls} format {shape(v)}"
    return f"{cls} {shape(v)}"


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def payload_detect(text: str) -> list:
    s = text.strip()
    if s[:1] in "{[":
        try:
            return detect.detect_mapping(json.loads(s))
        except ValueError:
            pass
    return detect.detect_text(text)


def percentile(xs: list[float], q: float) -> float | None:
    if not xs:
        return None
    xs = sorted(xs)
    k = (len(xs) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def size_bucket(n: int) -> str:
    if n < 200:
        return "<200 chars"
    if n < 1000:
        return "200-999 chars"
    if n < 5000:
        return "1k-5k chars"
    return ">=5k chars"


def evaluate(rows: list[dict]) -> dict:
    gold_n, hit_s, hit_a = Counter(), Counter(), Counter()
    pred_n, pred_ok_s, pred_ok_a, pred_ok_mapped = Counter(), Counter(), Counter(), Counter()
    by_label = defaultdict(lambda: {"n": 0, "hit_strict": 0, "hit_any": 0, "as": Counter()})
    lang_c = defaultdict(lambda: {"gold": Counter(), "hit_s": Counter(), "hit_a": Counter(),
                                  "pred": 0, "pred_ok_s": 0, "pred_ok_a": 0,
                                  "bin": Counter(), "examples": 0})
    binary = {"text": Counter(), "payload": Counter(), "correct_span": Counter()}
    fn_reasons = defaultdict(Counter)
    fn_examples = defaultdict(list)
    fp_types = defaultdict(Counter)
    fp_examples = defaultdict(list)
    times_text = defaultdict(list)
    checksum = defaultdict(Counter)
    chars_total = 0
    secs_total = 0.0

    for ex in rows:
        text = ex["text"]
        golds = ex["entities"]
        mapped = [g for g in golds if g["cls"]]
        lc = lang_c[ex["lang"]]
        lc["examples"] += 1

        detect.clear_cache()
        t0 = time.perf_counter()
        dets = detect.detect_text(text)
        dt = time.perf_counter() - t0
        times_text[size_bucket(len(text))].append(dt)
        chars_total += len(text)
        secs_total += dt
        preds = [d for d in dets if d.is_sensitive]

        for g in golds:
            ov = [d for d in preds if overlaps(d.start, d.end, g["start"], g["end"])]
            any_hit = bool(ov)
            strict = bool(g["cls"]) and any(d.entity_type in ACCEPT[g["cls"]] for d in ov)
            bl = by_label[g["label"]]
            bl["n"] += 1
            bl["hit_strict"] += strict
            bl["hit_any"] += any_hit
            for t in {d.entity_type for d in ov}:
                bl["as"][t] += 1
            if not g["cls"]:
                continue
            c = g["cls"]
            gold_n[c] += 1
            hit_s[c] += strict
            hit_a[c] += any_hit
            lc["gold"][c] += 1
            lc["hit_s"][c] += strict
            lc["hit_a"][c] += any_hit
            ok = checksum_valid(c, text[g["start"]:g["end"]])
            if ok is not None:
                k = "valid" if ok else "invalid"
                checksum[c][k] += 1
                checksum[c][k + "_hit"] += strict
            if not strict:
                found_as = sorted({d.entity_type for d in ov})
                reason = fn_reason(text, g, found_as)
                fn_reasons[c][reason] += 1
                if len(fn_examples[(c, reason)]) < 3:
                    fn_examples[(c, reason)].append(
                        {"id": ex["id"], "lang": ex["lang"], "label": g["label"],
                         "shape": shape(text[g["start"]:g["end"]])})

        for d in preds:
            c = PRIMARY.get(d.entity_type, f"OTHER:{d.entity_type}")
            ov = [g for g in golds if overlaps(d.start, d.end, g["start"], g["end"])]
            ok_s = any(g["cls"] and d.entity_type in ACCEPT[g["cls"]] for g in ov)
            ok_a = bool(ov)
            pred_n[c] += 1
            pred_ok_s[c] += ok_s
            pred_ok_a[c] += ok_a
            pred_ok_mapped[c] += any(g["cls"] for g in ov)
            lc["pred"] += 1
            lc["pred_ok_s"] += ok_s
            lc["pred_ok_a"] += ok_a
            if not ok_s:
                over = sorted({g["label"] for g in ov}) or ["no label"]
                key = f"{d.entity_type} on {'/'.join(over)}"
                fp_types[d.entity_type][key] += 1
                if len(fp_examples[key]) < 3:
                    fp_examples[key].append({"id": ex["id"], "lang": ex["lang"],
                                             "shape": shape(text[d.start:d.end])})

        truth = bool(mapped)
        flagged_text = bool(preds)
        flagged_payload = any(d.is_sensitive for d in payload_detect(text))
        flagged_correct = any(overlaps(d.start, d.end, g["start"], g["end"])
                              for d in preds for g in mapped)
        for mode, flag in (("text", flagged_text), ("payload", flagged_payload),
                           ("correct_span", flagged_correct if truth else flagged_text)):
            key = ("tp" if flag else "fn") if truth else ("fp" if flag else "tn")
            binary[mode][key] += 1
            if mode == "text":
                lc["bin"][key] += 1

    def bin_metrics(cnt: Counter) -> dict:
        tp, fp, fn, tn = cnt["tp"], cnt["fp"], cnt["fn"], cnt["tn"]
        p = tp / (tp + fp) if tp + fp else None
        r = tp / (tp + fn) if tp + fn else None
        f = 2 * p * r / (p + r) if p and r else 0.0
        return {"precision": p, "recall": r, "f1": f,
                "false_alarm_rate": fp / (fp + tn) if fp + tn else None,
                "tp": tp, "fp": fp, "fn": fn, "tn": tn}

    per_class = {}
    for c in CLASSES:
        m = prf(pred_ok_s[c], pred_n[c], hit_s[c], gold_n[c])
        m["recall_any_type"] = hit_a[c] / gold_n[c] if gold_n[c] else None
        per_class[c] = m
    all_pred = sum(pred_n.values())
    overall_strict = prf(sum(pred_ok_s.values()), all_pred, sum(hit_s.values()), sum(gold_n.values()))
    overall_any = prf(sum(pred_ok_a.values()), all_pred, sum(hit_a.values()), sum(gold_n.values()))

    per_language = {}
    for lang, lc in sorted(lang_c.items()):
        per_language[lang] = {
            "examples": lc["examples"],
            "strict": prf(lc["pred_ok_s"], lc["pred"], sum(lc["hit_s"].values()),
                          sum(lc["gold"].values())),
            "any_type": prf(lc["pred_ok_a"], lc["pred"], sum(lc["hit_a"].values()),
                            sum(lc["gold"].values())),
            "recall_by_class": {c: (lc["hit_s"][c] / lc["gold"][c] if lc["gold"][c] else None)
                                for c in CLASSES},
            "gold_by_class": {c: lc["gold"][c] for c in CLASSES},
            "binary_text": bin_metrics(lc["bin"]),
        }

    labels = {}
    for lab, b in sorted(by_label.items(), key=lambda kv: -kv[1]["n"]):
        labels[lab] = {"n": b["n"], "class": None,
                       "recall_strict": b["hit_strict"] / b["n"] if b["n"] else None,
                       "recall_any_type": b["hit_any"] / b["n"] if b["n"] else None,
                       "found_as": dict(b["as"].most_common(4))}
    for r in rows:
        for g in r["entities"]:
            labels[g["label"]]["class"] = g["cls"]

    other = {c: {"n_pred": pred_n[c], "overlapping_a_label": pred_ok_a[c],
                 "overlapping_a_mapped_label": pred_ok_mapped[c]}
             for c in sorted(pred_n) if c.startswith("OTHER:")}

    latency = {"detect_text_ms": {}, "chars_per_second": chars_total / secs_total if secs_total else None,
               "ms_per_kb_mean": 1000 * secs_total / (chars_total / 1000) if chars_total else None}
    for b, xs in sorted(times_text.items()):
        latency["detect_text_ms"][b] = {
            "n": len(xs), "p50": 1000 * percentile(xs, 0.5), "p95": 1000 * percentile(xs, 0.95),
            "p99": 1000 * percentile(xs, 0.99), "mean": 1000 * statistics.fmean(xs)}

    return {
        "n_examples": len(rows),
        "n_entities_mapped": sum(gold_n.values()),
        "n_entities_all": sum(b["n"] for b in by_label.values()),
        "per_class": per_class,
        "overall_strict": overall_strict,
        "overall_any_type": overall_any,
        "other_detector_types": other,
        "binary": {m: bin_metrics(c) for m, c in binary.items()},
        "per_language": per_language,
        "per_source_label": labels,
        "false_negative_reasons": {c: dict(v.most_common(12)) for c, v in fn_reasons.items()},
        "false_negative_examples": {f"{c} | {r}": v for (c, r), v in fn_examples.items()},
        "false_positive_types": {t: dict(v.most_common(8)) for t, v in fp_types.items()},
        "false_positive_examples": dict(fp_examples),
        "checksum": {c: dict(v) for c, v in checksum.items()},
        "latency": latency,
    }


def wrapped_latency(rows: list[dict], n: int) -> dict:
    """p50 / p95 / p99 of an echo tool under @instrument_tool(external) with
    the payload {"text": <example>}, cache cleared before each call."""
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    from taintward.sdk import instrumentation as instr

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("taintward-bench-external")

    def echo(payload):
        return payload

    wrapped = instr.instrument_tool("bench.echo", destination=instr.DEST_EXTERNAL,
                                    tracer=tracer)(echo)
    wrapped({"text": "warm up"})
    by_bucket = defaultdict(list)
    for ex in rows[:n]:
        exporter.clear()
        instr.end_run()
        detect.clear_cache()
        t0 = time.perf_counter()
        wrapped({"text": ex["text"]})
        by_bucket[size_bucket(len(ex["text"]))].append(time.perf_counter() - t0)
    exporter.clear()
    instr.end_run()
    out = {}
    for b, xs in sorted(by_bucket.items()):
        out[b] = {"n": len(xs), "p50": 1000 * percentile(xs, 0.5),
                  "p95": 1000 * percentile(xs, 0.95), "p99": 1000 * percentile(xs, 0.99)}
    allx = [x for xs in by_bucket.values() for x in xs]
    out["all"] = {"n": len(allx), "p50": 1000 * percentile(allx, 0.5),
                  "p95": 1000 * percentile(allx, 0.95), "p99": 1000 * percentile(allx, 0.99)}
    return out


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def _ms(x) -> str:
    return "-" if x is None else f"{x:.1f}"


def to_markdown(res: dict, synthetic: dict | None) -> str:
    src = res["source"]
    L = [f"# Detection on outside data: {src['repo']}", "",
         f"Split `{src['split']}`, revision `{src['revision'][:12]}`, license {src['license']}. "
         f"{res['n_examples']} examples sampled ({res['per_language_sample']} per language, "
         f"seed {res['seed']}), {res['n_entities_all']} labeled values, "
         f"{res['n_entities_mapped']} of them in a Taintward class.", "",
         "Generated by `bench/external/run_external.py`. No detection rule was changed for "
         "this run. Values are shown only as shapes (A = capitalized word, a = lower case, "
         "d3 = three digits, X = non-Latin letters).", "",
         "## Per class (span overlap)", "",
         "| class | gold | pred | precision | recall | F1 | recall (any type) | synthetic recall |",
         "|---|---:|---:|---:|---:|---:|---:|---:|"]
    syn_map = {"PERSON": "PERSON", "EMAIL": "EMAIL", "PHONE": "PHONE", "CREDIT_CARD": "CREDIT_CARD",
               "IBAN": "IBAN", "SSN": "US_SSN", "ADDRESS": "ADDRESS"}
    for c, m in res["per_class"].items():
        syn = "-"
        if synthetic:
            if c in syn_map:
                syn = fmt(synthetic["per_class"][syn_map[c]]["recall"])
            elif c == "SECRET":
                keys = ["AWS_ACCESS_KEY", "GITHUB_TOKEN", "GENERIC_API_KEY", "JWT", "PRIVATE_KEY"]
                g = sum(synthetic["per_class"][k]["n_gold"] for k in keys)
                h = sum(synthetic["per_class"][k]["tp_gold"] for k in keys)
                syn = fmt(h / g)
        if not m["n_gold"] and not m["n_pred"]:
            continue
        L.append(f"| {c} | {m['n_gold']} | {m['n_pred']} | {fmt(m['precision'])} | "
                 f"{fmt(m['recall'])} | {fmt(m['f1'])} | {fmt(m['recall_any_type'])} | {syn} |")
    for name, key in (("overall, strict", "overall_strict"), ("overall, any type", "overall_any_type")):
        m = res[key]
        syn = fmt(synthetic[key]["recall"]) if synthetic else "-"
        L.append(f"| **{name}** | {m['n_gold']} | {m['n_pred']} | {fmt(m['precision'])} | "
                 f"{fmt(m['recall'])} | {fmt(m['f1'])} | | {syn} |")
    for c, m in res.get("checksum", {}).items():
        v, iv = m.get("valid", 0), m.get("invalid", 0)
        L += ["", f"{c}: {v} labels pass the checksum, {iv} fail it. Recall on the valid ones: "
              f"{fmt(m.get('valid_hit', 0) / v if v else None)}; on the invalid ones: "
              f"{fmt(m.get('invalid_hit', 0) / iv if iv else None)}. Taintward rejects "
              "numbers that fail the checksum on purpose, to avoid false alarms."]
    L += ["", "Precision counts a detection as right when it overlaps a labeled value of a "
          "class it fits (strict) or any labeled value at all, including labels with no "
          "Taintward class (any type). Real PII the dataset did not label counts against "
          "precision, so precision is a lower bound.", "",
          "## Example level: was anything sensitive detected?", "",
          "Positive = the example has at least one value in a Taintward class.", "",
          "| mode | precision | recall | F1 | false alarm rate | TP | FP | FN | TN | synthetic recall |",
          "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for mode, m in res["binary"].items():
        syn = fmt(synthetic["binary"][mode]["recall"]) if synthetic else "-"
        L.append(f"| {mode} | {fmt(m['precision'])} | {fmt(m['recall'])} | {fmt(m['f1'])} | "
                 f"{fmt(m['false_alarm_rate'])} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} | {syn} |")
    L += ["", "## Per language", "",
          "| lang | examples | strict P | strict R | strict F1 | any-type R | example recall | example false alarms |",
          "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for lang, m in res["per_language"].items():
        b = m["binary_text"]
        fa = f"{b['fp']}/{b['fp'] + b['tn']}" if b["fp"] + b["tn"] else "-"
        L.append(f"| {lang} | {m['examples']} | {fmt(m['strict']['precision'])} | "
                 f"{fmt(m['strict']['recall'])} | {fmt(m['strict']['f1'])} | "
                 f"{fmt(m['any_type']['recall'])} | {fmt(b['recall'])} | {fa} |")
    present = [c for c in CLASSES if res["per_class"][c]["n_gold"]]
    L += ["", "Strict recall per language and class:", "",
          "| lang | " + " | ".join(present) + " |", "|---|" + "---:|" * len(present)]
    for lang, m in res["per_language"].items():
        L.append(f"| {lang} | " + " | ".join(
            fmt(m["recall_by_class"][c]) if m["gold_by_class"][c] else "-" for c in present) + " |")
    L += ["", "## Per source label", "",
          "| label | Taintward class | count | recall (strict) | recall (any type) | most often found as |",
          "|---|---|---:|---:|---:|---|"]
    for lab, m in res["per_source_label"].items():
        fa = ", ".join(f"{t} {n}" for t, n in m["found_as"].items()) or "-"
        L.append(f"| {lab} | {m['class'] or 'none'} | {m['n']} | "
                 f"{fmt(m['recall_strict']) if m['class'] else '-'} | {fmt(m['recall_any_type'])} | {fa} |")
    L += ["", "## Why values were missed (top reasons per class)", "",
          "| class | reason | count | example rows (id, lang, shape) |", "|---|---|---:|---|"]
    for c, reasons in res["false_negative_reasons"].items():
        for r, n in list(reasons.items())[:6]:
            exs = res["false_negative_examples"].get(f"{c} | {r}", [])
            e = "; ".join(f"{x['id']} {x['lang']} `{x['shape']}`" for x in exs)
            L.append(f"| {c} | {r.replace('|', '/')} | {n} | {e} |")
    L += ["", "## False alarms (detections that fit no labeled value of their class)", "",
          "| detector type | overlapping label | count | example rows (id, lang, shape) |",
          "|---|---|---:|---|"]
    for t, keys in sorted(res["false_positive_types"].items(), key=lambda kv: -sum(kv[1].values())):
        for k, n in list(keys.items())[:5]:
            exs = res["false_positive_examples"].get(k, [])
            e = "; ".join(f"{x['id']} {x['lang']} `{x['shape']}`" for x in exs)
            L.append(f"| {t} | {k.split(' on ', 1)[1]} | {n} | {e} |")
    lat = res["latency"]
    L += ["", "## Latency", "",
          f"`detect_text` per example, cache cleared before each call. Mean cost "
          f"{_ms(lat['ms_per_kb_mean'])} ms per 1,000 characters.", "",
          "| text size | n | p50 ms | p95 ms | p99 ms | mean ms |", "|---|---:|---:|---:|---:|---:|"]
    for b, m in lat["detect_text_ms"].items():
        L.append(f"| {b} | {m['n']} | {_ms(m['p50'])} | {_ms(m['p95'])} | {_ms(m['p99'])} | {_ms(m['mean'])} |")
    if res.get("wrapped_latency"):
        L += ["", "Wrapped echo tool (`@instrument_tool`, external), payload `{\"text\": example}`, "
              "cache cleared before each call:", "",
              "| text size | n | p50 ms | p95 ms | p99 ms |", "|---|---:|---:|---:|---:|"]
        for b, m in res["wrapped_latency"].items():
            L.append(f"| {b} | {m['n']} | {_ms(m['p50'])} | {_ms(m['p95'])} | {_ms(m['p99'])} |")
    if res.get("clean_stats"):
        L += ["", f"Label clean-up: {res['clean_stats']}"]
    return "\n".join(L) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="Detection on outside labeled PII data")
    ap.add_argument("--source", choices=["ai4privacy", "gretel", "all"], default="all")
    ap.add_argument("--per-language", type=int, default=None,
                    help="examples per language (default 500 for ai4privacy, 250 for gretel)")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--wrapped", type=int, default=300,
                    help="examples to time through a wrapped tool (0 = skip)")
    ap.add_argument("--out-dir", default=str(ROOT / "bench" / "results"))
    args = ap.parse_args()

    syn_path = ROOT / "bench" / "results" / "detection_after_fast_path.json"
    synthetic = json.loads(syn_path.read_text()) if syn_path.exists() else None
    detect.detect_text("warm up")

    sources = ["ai4privacy", "gretel"] if args.source == "all" else [args.source]
    for name in sources:
        path = download.path_for(name)
        if not path.exists():
            print(f"{name}: {path} missing, run bench/external/download.py first", file=sys.stderr)
            return 2
        per_lang = args.per_language or (500 if name == "ai4privacy" else 250)
        rows = load_ai4privacy(path) if name == "ai4privacy" else load_gretel(path)
        rows = sample(rows, per_lang, args.seed)
        stats = clean_entities(rows, LABEL_MAP[name])
        print(f"{name}: {len(rows)} examples, evaluating ...", flush=True)
        t0 = time.perf_counter()
        res = evaluate(rows)
        res["seconds"] = round(time.perf_counter() - t0, 1)
        if args.wrapped:
            res["wrapped_latency"] = wrapped_latency(rows, args.wrapped)
        src = download.SOURCES[name]
        res["source"] = {"name": name, "repo": src["repo"], "revision": src["revision"],
                         "split": src["path"], "license": src["license"]}
        res["per_language_sample"] = per_lang
        res["seed"] = args.seed
        res["clean_stats"] = stats
        res["label_map"] = LABEL_MAP[name]
        res["accept"] = {c: sorted(v) for c, v in ACCEPT.items()}
        out = Path(args.out_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / f"external_{name}.json").write_text(json.dumps(res, indent=2, sort_keys=False) + "\n")
        md = to_markdown(res, synthetic)
        (out / f"external_{name}.md").write_text(md)
        print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
