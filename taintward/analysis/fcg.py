"""Cross-tool function call graph (AgentRaft section B), without an LLM.

AgentRaft builds a graph of "the output of tool A can become the input of
tool B" with type pruning plus an LLM that judges whether the two fields
mean the same thing. Here the second step is deterministic: two fields are
related when their names share a meaning group (email / mail / recipient,
ssn / social_security / tax_id, ...) or a word, and any string can flow
into a free-text input (body, message, text, query, prompt, ...), because
that is how an agent moves data it was not asked to move.

Input: tool definitions in the MCP ``tools/list`` shape (``name``,
``description``, ``inputSchema``, optional ``outputSchema``) and a policy
that gives each tool its destination class and jurisdiction (the same
destination map as the SDK, or the gateway config).

* a **source** is a tool whose output can hold sensitive data: an
  ``internal`` or ``rag`` tool, or one with an output field named like
  personal data,
* a **sink** is an ``external``, ``llm``, ``log`` or ``rag`` tool with inputs,
* an **edge** A -> B lists the (output field, input field) pairs that match.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping

EGRESS = ("external", "llm", "log", "rag")
# Worst first: used to rank paths.
SINK_RANK = {"external": 0, "llm": 1, "log": 2, "rag": 3}

# Field names that mean "free text": anything can be written into them.
FREE_TEXT = frozenset({
    "body", "text", "message", "content", "msg", "note", "notes", "comment", "comments",
    "description", "summary", "query", "prompt", "input", "question", "payload", "data",
    "details", "html", "markdown", "subject", "title", "caption", "reply", "answer",
})

# Words that mean the same kind of value.
GROUPS: tuple[frozenset[str], ...] = tuple(frozenset(g.split()) for g in (
    "email mail e_mail recipient to cc bcc sender from address_email",
    "phone tel telephone mobile cell fax msisdn",
    "name fullname full_name first last firstname lastname surname customer person "
    "patient employee user contact owner holder",
    "ssn social_security tax_id taxid tin national_id nationalid passport license "
    "licence id_number",
    "address street city zip zipcode postal postcode country location",
    "dob birthdate birth_date birthday date_of_birth",
    "card card_number pan iban account account_number bank routing",
    "password secret token api_key apikey key credential",
))

# Output fields named like these make a tool a source even if it is not internal.
SENSITIVE_WORDS = frozenset().union(*GROUPS) - {"to", "from", "key", "user"}

_SPLIT = re.compile(r"[^a-z0-9]+")
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def words(name: str) -> frozenset[str]:
    """'customerEmail' -> {'customer', 'email', 'customer_email'}."""
    flat = _CAMEL.sub("_", name).lower()
    parts = [p for p in _SPLIT.split(flat) if p]
    out = set(parts)
    if len(parts) > 1:
        out.add("_".join(parts))
    return frozenset(out)


def _group(ws: frozenset[str]) -> set[int]:
    return {i for i, g in enumerate(GROUPS) if ws & g}


@dataclass(frozen=True)
class Tool:
    name: str
    description: str = ""
    inputs: Mapping[str, str] = field(default_factory=dict)    # field -> JSON type
    outputs: Mapping[str, str] = field(default_factory=dict)   # empty: not declared
    destination: str = "external"
    jurisdiction: str = ""
    mapped: bool = False

    @property
    def is_sink(self) -> bool:
        return self.destination in EGRESS and bool(self.inputs)

    @property
    def sensitive_outputs(self) -> list[str]:
        return [f for f in self.outputs if words(f) & SENSITIVE_WORDS]

    @property
    def is_source(self) -> bool:
        return self.destination in ("internal", "rag") or bool(self.sensitive_outputs)


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    # (output field or "*" for an undeclared output, input field, why)
    fields: tuple[tuple[str, str, str], ...]


def _props(schema: Any) -> dict[str, str]:
    if not isinstance(schema, Mapping):
        return {}
    props = schema.get("properties")
    if not isinstance(props, Mapping):
        return {}
    out = {}
    for k, v in props.items():
        t = v.get("type", "string") if isinstance(v, Mapping) else "string"
        out[str(k)] = t if isinstance(t, str) else "string"
    return out


Policy = Callable[[str], tuple[str, str, bool]]


def load_tools(doc: Any, policy: Policy) -> list[Tool]:
    """Tools from an MCP tools/list result (``{"tools": [...]}`` or a list).
    ``policy(name) -> (destination, jurisdiction, mapped)``."""
    if isinstance(doc, Mapping) and isinstance(doc.get("result"), Mapping):
        doc = doc["result"]  # a saved JSON-RPC response: {"result": {"tools": [...]}}
    items = doc.get("tools", []) if isinstance(doc, Mapping) else doc
    tools = []
    for t in items or []:
        if not isinstance(t, Mapping) or not t.get("name"):
            continue
        name = str(t["name"])
        dest, juris, mapped = policy(name)
        tools.append(Tool(name, str(t.get("description") or ""),
                          _props(t.get("inputSchema") or t.get("input_schema")),
                          _props(t.get("outputSchema") or t.get("output_schema")),
                          dest, juris, mapped))
    return tools


def _compatible(out_type: str, in_type: str) -> bool:
    if in_type == "string":
        return True  # anything can be written as text
    return out_type == in_type or (out_type, in_type) in (("integer", "number"),)


def match_fields(a: Tool, b: Tool) -> tuple[tuple[str, str, str], ...]:
    """The (output, input, why) pairs that let A's output reach B's input."""
    pairs = []
    outs = list(a.outputs.items()) or [("*", "string")]
    for i_name, i_type in b.inputs.items():
        iw = words(i_name)
        free = bool(iw & FREE_TEXT)
        for o_name, o_type in outs:
            if not _compatible(o_type, i_type):
                continue
            if o_name != "*":
                ow = words(o_name)
                if ow & iw - {"id"} or _group(ow) & _group(iw):
                    pairs.append((o_name, i_name, "same meaning"))
                    continue
            if free and i_type == "string":
                pairs.append((o_name, i_name, "free text"))
    return tuple(dict.fromkeys(pairs))


@dataclass
class FCG:
    tools: dict[str, Tool]
    edges: dict[tuple[str, str], Edge]

    def out(self, name: str) -> list[Edge]:
        return [e for (s, _), e in self.edges.items() if s == name]


def build_fcg(tools: Iterable[Tool]) -> FCG:
    by_name = {t.name: t for t in tools}
    edges = {}
    for a in by_name.values():
        for b in by_name.values():
            if a.name == b.name or not b.inputs:
                continue
            pairs = match_fields(a, b)
            if pairs:
                edges[(a.name, b.name)] = Edge(a.name, b.name, pairs)
    return FCG(by_name, edges)


def paths(g: FCG, *, max_hops: int = 3) -> list[tuple[str, ...]]:
    """Acyclic paths from each source to each sink, at most ``max_hops`` edges
    (AgentRaft's BFS over the graph), shortest first."""
    found: list[tuple[str, ...]] = []
    for src in sorted(n for n, t in g.tools.items() if t.is_source):
        queue = deque([(src,)])
        while queue:
            path = queue.popleft()
            if len(path) > 1 and g.tools[path[-1]].is_sink:
                found.append(path)
            if len(path) - 1 >= max_hops:
                continue
            for e in sorted(g.out(path[-1]), key=lambda e: e.dst):
                if e.dst not in path:
                    queue.append(path + (e.dst,))
    found.sort(key=lambda p: (len(p), SINK_RANK.get(g.tools[p[-1]].destination, 9), p))
    return found
