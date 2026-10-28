"""Run the Python SDK detector on the shared fixture file.

Usage (from the repository root, with the Python SDK installed):

    .venv/bin/python packages/taintward-js/scripts/python-detect.py \
        packages/taintward-js/test/fixtures/detect-cases.json \
        packages/taintward-js/test/fixtures/python-expected.json

For each case it writes the spans the Python detector finds, with offsets
converted to UTF-16 units (what JavaScript string indexes use). Case texts are
stored base64-encoded (``text_b64``) and the output holds fingerprints, not
values, so fake secrets in the fixtures do not trip secret scanners. Entity
types the TypeScript SDK does not detect (names and places from NER, and a few
Presidio-only types) are listed separately under "out_of_scope".
"""

import base64
import json
import sys

from taintward.sdk import detect

JS_TYPES = {
    "US_SSN", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "IBAN_CODE",
    "AWS_ACCESS_KEY", "GITHUB_TOKEN", "GENERIC_API_KEY", "JWT", "PRIVATE_KEY",
    "STREET_ADDRESS",
}


def u16(text: str, i: int) -> int:
    return len(text[:i].encode("utf-16-le")) // 2


def main() -> None:
    src, dst = sys.argv[1], sys.argv[2]
    with open(src, encoding="utf-8") as f:
        cases = json.load(f)
    health = detect.health()
    out = {"python_detector_mode": health["mode"], "cases": {}}
    for case in cases:
        text, key = base64.b64decode(case["text_b64"]).decode("utf-8"), case.get("key", "")
        dets = detect._analyze([(text, key)], 0.5)[0] if text else []
        spans, other = [], []
        for d in dets:
            item = {
                "type": d.entity_type,
                "start": u16(text, d.start),
                "end": u16(text, d.end),
                "fingerprint": d.fingerprint,
            }
            (spans if d.entity_type in JS_TYPES else other).append(item)
        out["cases"][case["id"]] = {"spans": spans, "out_of_scope": other}
    with open(dst, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1, ensure_ascii=False)
        f.write("\n")
    print(f"python detector mode: {health['mode']}; wrote {len(cases)} cases to {dst}")


if __name__ == "__main__":
    main()
