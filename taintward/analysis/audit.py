"""Offline data over-exposure audit (AgentRaft, without an LLM).

Static: from your tool definitions and destination map, every path by which
sensitive data could go from a source tool to an outside sink (fcg.py).
Dynamic: from recorded spans (an OTLP file), which of those paths really
ran: a run where the source returned sensitive data and the sink was called
later, with the outcome of the sink call. A path that never ran is untested;
the prompts written by ``--prompts`` are a test corpus for exactly those.

    python -m taintward.analysis.audit --tools tools.json \\
        --destinations destinations.json --otlp-file traces.jsonl \\
        --home eu --prompts untested.jsonl --out audit.md

``tools.json`` is an MCP ``tools/list`` result. ``destinations.json`` is the
SDK destination map (``{"get_customer": "internal", "send_email":
["external", "us"]}``); ``--gateway-config`` reads the gateway's rules
instead. Tools in neither are ``external``, the same default as the SDK, and
are listed as unmapped.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from taintward.analysis.fcg import FCG, Policy, build_fcg, load_tools, paths
from taintward.analysis.prompt_synth import synthesize, to_jsonl


def policy_from_destinations(mapping: dict[str, Any], *, default_destination: str = "external",
                             default_jurisdiction: str = "") -> Policy:
    """The SDK destination map, read the same way as ``Ward`` reads it
    (without loading the detectors)."""
    from taintward.sdk.destinations import ToolPolicy, _to_policy
    policies = {str(name): _to_policy(v) for name, v in mapping.items()}
    default = ToolPolicy(default_destination, default_jurisdiction)

    def policy(name: str) -> tuple[str, str, bool]:
        p = policies.get(name, default)
        return p.destination, p.jurisdiction, name in policies
    return policy


def _upstream_of(cfg: Any, name: str) -> str:
    """The upstream an exposed tool name comes from. The gateway exposes
    ``prefix + tool``, so the longest matching prefix wins; with several
    upstreams and no prefix to tell them apart the answer is unknown ("")
    and only rules without ``upstream:`` apply."""
    hits = [u for u in cfg.upstreams if name.startswith(u.prefix)]
    if not hits:
        return ""
    longest = max(len(u.prefix) for u in hits)
    hits = [u for u in hits if len(u.prefix) == longest]
    return hits[0].name if len(hits) == 1 else ""


def policy_from_gateway(path: str) -> Policy:
    from taintward.gateway.config import load_config
    cfg = load_config(path)

    def policy(name: str) -> tuple[str, str, bool]:
        upstream = _upstream_of(cfg, name)
        p = cfg.policy_for(name, upstream)
        return (p.destination, p.jurisdiction,
                any(r.matches(name, upstream) for r in cfg.rules))
    return policy


def observed_flows(spans: Iterable[Any]) -> dict[tuple[str, str], dict]:
    """(source tool, sink tool) -> runs where the source returned sensitive data
    and the sink ran later, with the outcome of every such sink call (each
    call counted once, even after several sensitive source calls)."""
    from taintward.evidence import report as R
    by_trace: dict[str, list] = defaultdict(list)
    for s in spans:
        if R.is_tool_call(s):
            by_trace[s.trace_id].append(s)
    flows: dict[tuple[str, str], dict] = {}
    for trace_id, calls in by_trace.items():
        calls.sort(key=lambda s: (s.start_ns, s.span_id))
        for i, a in enumerate(calls):
            if not R.is_sensitive(a):
                continue
            for b in calls[i + 1:]:
                if R.destination(b) not in ("external", "llm", "log", "rag"):
                    continue
                f = flows.setdefault((R.tool_name(a), R.tool_name(b)),
                                     {"runs": set(), "calls": set(), "violations": 0,
                                      "outcomes": Counter()})
                f["runs"].add(trace_id)
                if (trace_id, b.span_id) not in f["calls"]:
                    f["calls"].add((trace_id, b.span_id))
                    f["violations"] += int(R.is_violation(b))
                    f["outcomes"][R.outcome(b)] += 1
    return flows


def audit(tools_doc: Any, policy: Policy, *, spans: Iterable[Any] | None = None,
          max_hops: int = 3, home: Iterable[str] = ()) -> tuple[dict, FCG]:
    g = build_fcg(load_tools(tools_doc, policy))
    found = paths(g, max_hops=max_hops)
    flows = observed_flows(spans) if spans is not None else {}
    home_set = {h.lower() for h in home}
    rows = []
    for p in found:
        sink = g.tools[p[-1]]
        seen = flows.get((p[0], p[-1]))
        juris = sink.jurisdiction
        rows.append({
            "path": list(p),
            "destination": sink.destination,
            "jurisdiction": juris,
            "cross_border": bool(juris) and juris.lower() not in home_set,
            "source_fields": g.tools[p[0]].sensitive_outputs,
            "last_edge": [list(x) for x in g.edges[(p[-2], p[-1])].fields],
            "observed": None if seen is None else {
                "runs": len(seen["runs"]), "violations": seen["violations"],
                "outcomes": dict(sorted(seen["outcomes"].items()))},
        })
    result = {
        "tools": len(g.tools),
        "sources": sorted(n for n, t in g.tools.items() if t.is_source),
        "sinks": [{"tool": t.name, "destination": t.destination, "jurisdiction": t.jurisdiction}
                  for t in sorted(g.tools.values(), key=lambda t: t.name) if t.is_sink],
        "unmapped": sorted(n for n, t in g.tools.items() if not t.mapped),
        "edges": len(g.edges),
        "traces_given": spans is not None,
        "paths": rows,
        "summary": {
            "paths": len(rows),
            "observed": sum(1 for r in rows if r["observed"]),
            "untested": sum(1 for r in rows if not r["observed"]),
            "cross_border": sum(1 for r in rows if r["cross_border"]),
            "observed_with_raw_outcome": sum(
                1 for r in rows if r["observed"] and r["observed"]["outcomes"].get("audit_only")),
        },
    }
    return result, g


def render_markdown(res: dict) -> str:
    s = res["summary"]
    out = ["# Data over-exposure audit", "",
           f"{res['tools']} tool(s), {len(res['sources'])} source(s), {len(res['sinks'])} sink(s), "
           f"{res['edges']} edge(s). **{s['paths']} path(s)** from a source to a sink"
           + (f": {s['observed']} seen in the traces, {s['untested']} never ran."
              if res["traces_given"] else " (no traces given, so none is marked as seen)."),
           ""]
    if s["cross_border"]:
        out.append(f"{s['cross_border']} path(s) end at a sink outside the home jurisdictions.")
        out.append("")
    if s["observed_with_raw_outcome"]:
        out.append(f"**{s['observed_with_raw_outcome']} path(s) ran in audit-only mode**: "
                   "data went out without redaction.")
        out.append("")
    if res["unmapped"]:
        out += ["Unmapped tools (treated as `external`): "
                + ", ".join(f"`{n}`" for n in res["unmapped"]), ""]
    out += ["| path | sink | jurisdiction | fields into the sink | seen in traces |",
            "|---|---|---|---|---|"]
    for r in res["paths"]:
        seen = r["observed"]
        seen_txt = ("-" if not res["traces_given"] else "never ran" if not seen else
                    f"{seen['runs']} run(s), " + ", ".join(f"{k} {v}" for k, v in seen["outcomes"].items()))
        fields = ", ".join(f"{o} -> {i} ({why})" for o, i, why in r["last_edge"][:4])
        if len(r["last_edge"]) > 4:
            fields += ", ..."
        out.append(f"| {' -> '.join(r['path'])} | {r['destination']} | "
                   f"{r['jurisdiction'] or '-'}{' (cross-border)' if r['cross_border'] else ''} | "
                   f"{fields} | {seen_txt} |")
    out += ["", "Paths come from tool definitions: a field matches another when their names "
            "mean the same thing, and any value can go into a free-text field. A path that "
            "never ran is not safe, only untested: run the prompts from `--prompts` with "
            "Taintward on to test it."]
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="taintward-audit",
                                 description="Offline data over-exposure audit of an agent's tools.")
    ap.add_argument("--tools", required=True, help="MCP tools/list JSON")
    m = ap.add_mutually_exclusive_group()
    m.add_argument("--destinations", help="SDK destination map JSON")
    m.add_argument("--gateway-config", help="gateway YAML (its tool rules)")
    ap.add_argument("--otlp-file", action="append", default=[],
                    help="recorded spans (OTLP JSON lines); may be given more than once")
    ap.add_argument("--home", default="", help="comma list of home jurisdictions, e.g. eu")
    ap.add_argument("--max-hops", type=int, default=3)
    ap.add_argument("--format", choices=("md", "json"), default="md")
    ap.add_argument("--out", default="-")
    ap.add_argument("--prompts", help="write test prompts for the paths that never ran (JSONL)")
    args = ap.parse_args(argv)

    tools_doc = json.loads(Path(args.tools).read_text())
    if args.gateway_config:
        policy = policy_from_gateway(args.gateway_config)
    else:
        mapping = json.loads(Path(args.destinations).read_text()) if args.destinations else {}
        policy = policy_from_destinations(mapping)
    spans = None
    if args.otlp_file:
        from taintward.evidence.spans import OtlpFileSource
        spans = OtlpFileSource(args.otlp_file).fetch(0, 2**63 - 1)
    res, g = audit(tools_doc, policy, spans=spans, max_hops=args.max_hops,
                   home=[h for h in args.home.split(",") if h.strip()])
    text = json.dumps(res, indent=2, sort_keys=True) if args.format == "json" else render_markdown(res)
    if args.out == "-":
        sys.stdout.write(text if text.endswith("\n") else text + "\n")
    else:
        Path(args.out).write_text(text if text.endswith("\n") else text + "\n")
    if args.prompts:
        untested = [tuple(r["path"]) for r in res["paths"] if not r["observed"]]
        Path(args.prompts).write_text(to_jsonl(synthesize(g, untested)))
        print(f"wrote {len(untested)} prompt(s) to {args.prompts}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
