"""Download the outside PII datasets used by bench/external/run_external.py.

The files are cached outside the repository (they are not ours to
redistribute, and they are large). Default cache folder:
``~/.cache/taintward-bench/external``, or set ``TAINTWARD_BENCH_CACHE``.

Each file is pinned to a dataset commit, so a later change on the hub does
not silently change the benchmark.

| dataset | split used | license |
|---|---|---|
| ai4privacy/open-pii-masking-500k-ai4privacy | validation (test.jsonl) | CC-BY-4.0, plus the Llama 3.1 / 3.3 community license |
| gretelai/synthetic_pii_finance_multilingual | test | Apache-2.0 |

Usage:  python bench/external/download.py [--force] [--only NAME]
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import urllib.request
from pathlib import Path

SOURCES = {
    "ai4privacy": {
        "repo": "ai4privacy/open-pii-masking-500k-ai4privacy",
        "revision": "506996d625ed970a0063432daf6007cf4a3a48e3",
        "path": "data/validation/test.jsonl",
        "file": "ai4privacy_open_pii_500k_validation.jsonl",
        "license": "CC-BY-4.0 + Llama 3.1/3.3 community license",
    },
    "gretel": {
        "repo": "gretelai/synthetic_pii_finance_multilingual",
        "revision": "7b844d16738527a04264f50214cb426a4cea0897",
        "path": "data/test-00000-of-00001.parquet",
        "file": "gretel_pii_finance_multilingual_test.parquet",
        "license": "Apache-2.0",
    },
}


def cache_dir() -> Path:
    base = os.environ.get("TAINTWARD_BENCH_CACHE")
    root = Path(base) if base else Path.home() / ".cache" / "taintward-bench"
    return root / "external"


def path_for(name: str) -> Path:
    return cache_dir() / SOURCES[name]["file"]


def url_for(src: dict) -> str:
    return (f"https://huggingface.co/datasets/{src['repo']}/resolve/"
            f"{src['revision']}/{src['path']}")


def fetch(name: str, force: bool = False) -> Path:
    src = SOURCES[name]
    out = path_for(name)
    if out.exists() and not force:
        print(f"{name}: cached at {out}")
        return out
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".part")
    print(f"{name}: downloading {url_for(src)}")
    h = hashlib.sha256()
    with urllib.request.urlopen(url_for(src), timeout=60) as r, tmp.open("wb") as f:
        while chunk := r.read(1 << 20):
            f.write(chunk)
            h.update(chunk)
    tmp.replace(out)
    print(f"{name}: {out.stat().st_size} bytes, sha256 {h.hexdigest()}")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Download the outside PII datasets (cached outside git).")
    ap.add_argument("--force", action="store_true", help="download again even if cached")
    ap.add_argument("--only", choices=sorted(SOURCES), help="download one dataset")
    args = ap.parse_args()
    for name in ([args.only] if args.only else SOURCES):
        fetch(name, args.force)
    return 0


if __name__ == "__main__":
    sys.exit(main())
