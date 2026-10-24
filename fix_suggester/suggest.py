"""AST fix-suggester: grounded, one-line fixes for unguarded egress sinks.

The "recover" pillar. Walks agent tool-call code, finds calls to external / LLM
sinks whose arguments are NOT routed through the SDK's redaction (i.e. not
wrapped by an ``@instrument_tool``-decorated tool), and emits the exact
one-line fix. An LLM *narrates* the finding, but the suggestion itself is
grounded in the AST, not a free-form LLM patch, which is more defensible (and
cheaper) than asking a model to propose a fix.

The SigNoz MCP read path (``signoz_search_traces`` for similar past
violations, to prioritize fixes by which leak shape actually fires in prod)
is a hook, activated when the MCP server and a model key are configured.
Without them, ``narrate`` produces a deterministic, AST-grounded explanation.

Sink detection (configurable): dotted call names matching
  external: ``*.post`` / ``*.put`` / ``*.patch`` / ``*.delete`` / ``*.urlopen``
  llm:      dotted name containing ``openai`` or ``anthropic`` and ending ``.create``
A call is UNGUARDED if its enclosing function is not decorated with
``@instrument_tool`` (those tools auto-redact their args via the Phase 4 gate).
"""

from __future__ import annotations

import ast
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sdk.destinations import DEST_EXTERNAL, DEST_LLM

_EXTERNAL_SUFFIXES = (".post", ".put", ".patch", ".delete", ".urlopen")
_LLM_TOKENS = ("openai", "anthropic")


def _dotted_name(node: ast.AST) -> str:
    """Reconstruct the dotted name of a called function, e.g. requests.post or
    openai.ChatCompletion.create."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_dotted_name(node.value)}.{node.attr}"
    return ""


def _classify_sink(dotted: str) -> str | None:
    low = dotted.lower()
    if any(low.endswith(s) for s in _EXTERNAL_SUFFIXES):
        return DEST_EXTERNAL
    if low.endswith(".create") and any(tok in low for tok in _LLM_TOKENS):
        return DEST_LLM
    return None


def _import_aliases(tree: ast.AST) -> dict[str, str]:
    """Map local names introduced by `import x as y` / `from m import x as y`
    to the real name they refer to, so decorator matching sees through import
    aliasing, e.g. `from sdk.instrumentation import instrument_tool as it`."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
    return aliases


def _is_instrumented(fn: ast.FunctionDef | ast.AsyncFunctionDef, aliases: dict[str, str]) -> bool:
    for dec in fn.decorator_list:
        name = _dotted_name(dec.func) if isinstance(dec, ast.Call) else _dotted_name(dec)
        # Resolve import aliasing before matching: either the whole decorator
        # name (`it` -> `instrument_tool`) or its leading dotted component
        # (`instr.instrument_tool` where `instr` aliases the module).
        head, _, rest = name.partition(".")
        resolved = aliases.get(name, name)
        if head in aliases and rest:
            resolved = f"{aliases[head]}.{rest}"
        # Exact match on the (dotted) decorator name only -- a substring
        # `endswith("instrument_tool")` check would wrongly treat an unrelated
        # decorator like `fake_instrument_tool` as the real guard.
        if resolved.split(".")[-1] == "instrument_tool":
            return True
    return False


@dataclass
class Finding:
    file: str
    lineno: int
    col: int
    call: str          # the dotted sink name
    destination: str   # external | llm
    enclosing: str     # enclosing function (or "<module>")
    fix: str           # the one-line fix

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


def analyze_tree(tree: ast.AST, filename: str) -> list[Finding]:
    findings: list[Finding] = []

    # Parent map so each Call can find its true enclosing function (no double
    # counting, correct enclosing name even when calls nest).
    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent

    aliases = _import_aliases(tree)

    def enclosing_fn(call: ast.Call):
        p = parents.get(call)
        while p is not None:
            if isinstance(p, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return p
            p = parents.get(p)
        return None

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        dotted = _dotted_name(node.func)
        dest = _classify_sink(dotted)
        if dest is None:
            continue
        enc = enclosing_fn(node)
        enclosing_name = enc.name if enc else "<module>"
        guarded = _is_instrumented(enc, aliases) if enc else False
        if guarded:
            continue
        arg_hint = "payload" if dest == DEST_EXTERNAL else "prompt/record"
        findings.append(Finding(
            file=filename,
            lineno=node.lineno,
            col=node.col_offset,
            call=dotted,
            destination=dest,
            enclosing=enclosing_name,
            fix=f"redact = redact_payload({arg_hint}, instr.DEST_{dest.upper()})  # before {dotted}(...)  [Phase 4 egress gate; or wrap fn with @instrument_tool(destination=instr.DEST_{dest.upper()})]",
        ))
    return findings


def analyze_file(path: str | Path) -> list[Finding]:
    path = Path(path)
    tree = ast.parse(path.read_text(), filename=str(path))
    return analyze_tree(tree, str(path))


def narrate(finding: Finding) -> str:
    """Grounded narration of a finding. With a model + the SigNoz MCP, this
    would pull similar past violations (signoz_search_traces) to prioritize;
    here it's a deterministic, AST-grounded explanation."""
    return (
        f"{finding.file}:{finding.lineno}: `{finding.call}` is an unguarded "
        f"{finding.destination} sink inside `{finding.enclosing}`. Its argument "
        f"reaches the sink without the Phase 4 egress gate, so raw PII could "
        f"leave the system. Suggested fix:\n    {finding.fix}"
    )


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: suggest.py <agent_source.py> [...]", file=sys.stderr)
        return 2
    any_finding = False
    for path in sys.argv[1:]:
        for f in analyze_file(path):
            any_finding = True
            print(narrate(f))
            print()
    if not any_finding:
        print("no unguarded egress sinks found")
    return 1 if any_finding else 0


if __name__ == "__main__":
    raise SystemExit(main())