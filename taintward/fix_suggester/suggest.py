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

Sink detection: dotted call names matching
  external: ``*.post`` / ``*.put`` / ``*.patch`` / ``*.delete`` / ``*.urlopen``
  llm:      a dotted name containing ``openai`` or ``anthropic`` and ending
            ``.create``, or a client call such as
            ``client.chat.completions.create`` / ``client.responses.create`` /
            ``client.messages.create`` (also ``.parse``, ``.stream`` and
            ``.embeddings.create``)
A call is UNGUARDED unless its enclosing function is decorated with
``@instrument_tool`` (those tools redact their arguments), or it is made on a
client that this file wrapped with ``protect_openai`` / ``protect_anthropic``
(``client = tw.protect_openai(OpenAI())``).
"""

from __future__ import annotations

import ast
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from taintward.sdk.destinations import DEST_EXTERNAL, DEST_LLM

_EXTERNAL_SUFFIXES = (".post", ".put", ".patch", ".delete", ".urlopen")
_LLM_TOKENS = ("openai", "anthropic")
# How the OpenAI and Anthropic clients are really called: on a client object
# of any name, so the dotted name has no "openai" in it.
_LLM_CLIENT_SUFFIXES = (
    ".chat.completions.create", ".chat.completions.parse", ".responses.create",
    ".responses.parse", ".messages.create", ".messages.stream", ".messages.parse",
    ".embeddings.create",
)
# Wrappers that make every call on the client they return go through the gate.
_PROTECT_FUNCS = ("protect_openai", "protect_anthropic")


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
    if any(low.endswith(s) for s in _LLM_CLIENT_SUFFIXES):
        return DEST_LLM
    return None


def _attr_chain(node: ast.AST) -> tuple[ast.AST, str]:
    """(root node, ".a.b.c") for ``root.a.b.c``."""
    tail = ""
    while isinstance(node, ast.Attribute):
        tail = f".{node.attr}{tail}"
        node = node.value
    return node, tail


def _is_protect_call(node: ast.AST) -> bool:
    return (isinstance(node, ast.Call)
            and _dotted_name(node.func).split(".")[-1] in _PROTECT_FUNCS)


def _protected_clients(tree: ast.AST) -> set[str]:
    """Names this file binds to a protected client:
    ``client = tw.protect_openai(OpenAI())``, ``self.llm = protect_anthropic(c)``."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and _is_protect_call(node.value):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign) and node.value and _is_protect_call(node.value):
            targets = [node.target]
        else:
            continue
        names.update(n for n in map(_dotted_name, targets) if n)
    return names


def _import_aliases(tree: ast.AST) -> dict[str, str]:
    """Map local names introduced by `import x as y` / `from m import x as y`
    to the real name they refer to, so decorator matching sees through import
    aliasing, e.g. `from taintward.sdk.instrumentation import instrument_tool as it`."""
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
    protected = _protected_clients(tree)

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
        root, tail = _attr_chain(node.func)
        # tw.protect_openai(OpenAI()).chat.completions.create(...): the root is a call
        dotted = _dotted_name(node.func) if not isinstance(root, ast.Call) else tail
        dest = _classify_sink(dotted)
        if dest is None:
            continue
        if dest == DEST_LLM and (
                _is_protect_call(root)
                or any(dotted == p or dotted.startswith(p + ".") for p in protected)):
            continue  # a protected client redacts what it sends
        enc = enclosing_fn(node)
        enclosing_name = enc.name if enc else "<module>"
        guarded = _is_instrumented(enc, aliases) if enc else False
        if guarded:
            continue
        call_name = dotted.lstrip(".")
        if dest == DEST_EXTERNAL:
            fix = (f"payload = redact_payload(payload, DEST_EXTERNAL)  # before {call_name}(...); "
                   f"or decorate {enclosing_name if enc else 'the function'} with "
                   f"@instrument_tool(destination=DEST_EXTERNAL)")
        else:
            fix = (f"client = tw.protect_openai(client)  # or tw.protect_anthropic(client), "
                   f"once, where the client is made; "
                   f"or prompt = redact_payload(prompt, DEST_LLM) before {call_name}(...)")
        findings.append(Finding(
            file=filename,
            lineno=node.lineno,
            col=node.col_offset,
            call=call_name,
            destination=dest,
            enclosing=enclosing_name,
            fix=fix,
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
        f"reaches the sink without Taintward's redaction, so raw personal data or "
        f"secrets could leave the system. Suggested fix:\n    {finding.fix}"
    )


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("usage: taintward-fix <agent_source.py> [...]", file=sys.stderr)
        return 0 if len(sys.argv) >= 2 else 2
    any_finding = False
    for path in sys.argv[1:]:
        try:
            findings = analyze_file(path)
        except (OSError, SyntaxError, ValueError) as exc:
            # a missing file or one that is not Python: say so, exit 2
            print(f"error: cannot analyze {path}: {exc}", file=sys.stderr)
            return 2
        for f in findings:
            any_finding = True
            print(narrate(f))
            print()
    if not any_finding:
        print("no unguarded egress sinks found")
    return 1 if any_finding else 0


if __name__ == "__main__":
    raise SystemExit(main())