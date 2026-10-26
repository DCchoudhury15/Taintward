"""Run the placeholder evaluation against a real model.

    python bench/placeholders/run.py --provider ollama --model qwen2.5:3b --mode baseline
    python bench/placeholders/run.py --provider ollama --model qwen2.5:3b --mode hardened
    python bench/placeholders/run.py --provider openai --model gpt-4o-mini --mode hardened
    python bench/placeholders/run.py --provider anthropic --model claude-haiku-4-5 --mode hardened
    python bench/placeholders/run.py --provider langchain --model qwen2.5:3b --mode hardened
    python bench/placeholders/run.py --replay      # offline: baseline answers + tolerant restore
    python bench/placeholders/run.py --report      # tables from all saved results

Results go to bench/placeholders/results/<provider>__<model>__<mode>.json.
A provider without its API key (or without a running Ollama) is skipped with
a message, it is not an error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))  # the repo root, for `taintward`
sys.path.insert(0, str(HERE))

os.environ.setdefault("TAINTWARD_FPE_KEY", "EF4359D8D580AA4F7F036D6F04FB771B")  # fake, fixed

import harness  # noqa: E402
import report  # noqa: E402

RESULTS = HERE / "results"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--provider", default="ollama",
                    choices=["ollama", "openai", "anthropic", "langchain"])
    ap.add_argument("--model", default="qwen2.5:3b")
    ap.add_argument("--mode", default="hardened", choices=["baseline", "hardened"])
    ap.add_argument("--tasks", help="comma separated task ids (default: all)")
    ap.add_argument("--max-tokens", type=int, default=400)
    ap.add_argument("--report", action="store_true", help="print tables from saved results")
    ap.add_argument("--replay", action="store_true",
                    help="offline: restore saved baseline answers with tolerant restore")
    ap.add_argument("--rescore", action="store_true",
                    help="offline: score saved runs again with the current rules")
    args = ap.parse_args(argv)

    if args.rescore:
        for p in sorted(RESULTS.glob("*.json")):
            if p.name.endswith("__replay.json"):
                continue
            out = harness.rescore(json.loads(p.read_text()))
            p.write_text(json.dumps(out, indent=1, ensure_ascii=False))
            print(f"rescored {p.name}: {out['summary']['restore_ok']}/{out['summary']['tasks']}")
        return 0

    if args.replay:
        for p in sorted(RESULTS.glob("*__baseline.json")):
            run = json.loads(p.read_text())
            if sum("known" in r for r in run["results"]) < len(run["results"]):
                print(f"skip {p.name}: saved before answers were kept for replay")
                continue
            out = harness.replay_tolerant(run)
            dest = p.with_name(p.name.replace("__baseline.json", "__replay.json"))
            dest.write_text(json.dumps(out, indent=1, ensure_ascii=False))
            print(f"saved {dest}")
        return 0

    if args.report:
        print(report.render(RESULTS))
        return 0

    reason = harness.provider_available(args.provider)
    if reason:
        print(f"skip {args.provider}: {reason}")
        return 0

    ids = args.tasks.split(",") if args.tasks else None

    def progress(r):
        mark = "ok  " if r["restore_ok"] else "FAIL"
        extra = "" if r["restore_ok"] else "  " + "; ".join(r["problems"][:3])
        if r["error"]:
            extra += f"  error={r['error'][:80]}"
        print(f"{mark} {r['id']:<24} {r['seconds']:>6}s{extra}", flush=True)

    out = harness.run_model(args.provider, args.model, args.mode, ids, progress=progress,
                            max_tokens=args.max_tokens)
    RESULTS.mkdir(exist_ok=True)
    safe = args.model.replace("/", "_").replace(":", "-")
    suffix = "" if ids is None else "__partial"
    path = RESULTS / f"{args.provider}__{safe}__{args.mode}{suffix}.json"
    path.write_text(json.dumps(out, indent=1, ensure_ascii=False))
    print(json.dumps(out["summary"], indent=1))
    print(f"saved {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
