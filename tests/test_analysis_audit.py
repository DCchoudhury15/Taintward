"""The offline data over-exposure audit (taintward/analysis): graph edges,
source -> sink paths, which of them ran in recorded spans, and the test
prompts for the ones that never ran. No LLM, so every result is fixed."""

from __future__ import annotations

import json

from taintward.analysis import fcg
from taintward.analysis.audit import (
    audit,
    main,
    policy_from_destinations,
    render_markdown,
)
from taintward.analysis.prompt_synth import synthesize
from taintward.evidence.spans import spans_from_otlp
from tests.test_report import _doc, _span, _tool


def schema(**props):
    return {"type": "object", "properties": {k: {"type": v} for k, v in props.items()}}


TOOLS = {"tools": [
    {"name": "get_customer", "description": "Look up a customer",
     "inputSchema": schema(customer_id="string"),
     "outputSchema": schema(full_name="string", email="string", ssn="string", tier="integer",
                            account="string")},
    {"name": "search_kb", "inputSchema": schema(query="string")},           # rag, no output schema
    {"name": "send_email", "inputSchema": schema(to="string", subject="string", body="string")},
    {"name": "post_slack", "inputSchema": schema(channel="string", text="string")},
    {"name": "set_priority", "inputSchema": schema(level="integer")},
    {"name": "audit_log", "inputSchema": schema(entry="string")},           # no free text input
    {"name": "list_regions", "inputSchema": schema()},                      # no inputs
    {"name": "charge", "inputSchema": schema(account_number="integer")},
]}
DESTS = {"get_customer": "internal", "search_kb": "rag", "send_email": ["external", "us"],
         "post_slack": ["external", "eu"], "audit_log": "log", "list_regions": "internal",
         "charge": "external"}


def run(spans=None, **kw):
    return audit(TOOLS, policy_from_destinations(DESTS), spans=spans, **kw)


def test_field_matching_is_by_meaning_and_free_text():
    tools = {t.name: t for t in fcg.load_tools(TOOLS, policy_from_destinations(DESTS))}
    pairs = fcg.match_fields(tools["get_customer"], tools["send_email"])
    assert ("email", "to", "same meaning") in pairs
    assert ("ssn", "body", "free text") in pairs
    assert not any(i == "channel" for _, i, _ in fcg.match_fields(tools["get_customer"], tools["post_slack"]))
    # strings cannot become an integer, and "tier" does not mean "level"
    assert fcg.match_fields(tools["get_customer"], tools["set_priority"]) == ()
    assert fcg.match_fields(tools["get_customer"], tools["audit_log"]) == ()  # "entry" is not free text
    # "account" means the same as "account_number", but a string is not an integer
    assert fcg.match_fields(tools["get_customer"], tools["charge"]) == ()
    assert fcg.words("customerEmail") == {"customer", "email", "customer_email"}


def test_sources_sinks_and_unmapped():
    res, _ = run()
    assert res["sources"] == ["get_customer", "list_regions", "search_kb"]
    sinks = {s["tool"]: s["destination"] for s in res["sinks"]}
    assert sinks == {"send_email": "external", "post_slack": "external", "search_kb": "rag",
                     "set_priority": "external", "audit_log": "log", "charge": "external"}
    assert res["unmapped"] == ["set_priority"]  # defaults to external, and is listed


def test_paths_are_ranked_and_marked_cross_border():
    res, _ = run(home=["eu"])
    by_path = {tuple(r["path"]): r for r in res["paths"]}
    assert ("get_customer", "send_email") in by_path
    assert ("get_customer", "post_slack") in by_path
    assert by_path[("get_customer", "send_email")]["cross_border"] is True   # us
    assert by_path[("get_customer", "post_slack")]["cross_border"] is False  # eu = home
    assert by_path[("get_customer", "send_email")]["source_fields"] == [
        "full_name", "email", "ssn", "account"]
    assert ("get_customer", "audit_log") not in by_path
    # a path through another sink: customer data goes into the knowledge base search,
    # and its (undeclared) output into an email
    assert ("get_customer", "search_kb", "send_email") in by_path
    lengths = [len(r["path"]) for r in res["paths"]]
    assert lengths == sorted(lengths)
    assert all(len(p) <= 4 for p in by_path)  # max 3 hops
    assert all(len(set(p)) == len(p) for p in by_path)  # no tool twice
    short, _ = run(max_hops=1)
    assert all(len(r["path"]) == 2 for r in short["paths"])


def test_observed_paths_come_from_the_traces():
    tr, other = "c" * 32, "d" * 32
    spans = spans_from_otlp(_doc([
        _span(tr, "0" * 16, "agent.run", 0),
        _tool(tr, "1" * 16, "get_customer", "internal", 1),
        _tool(tr, "2" * 16, "send_email", "external", 2, juris="us", violation=True,
              reasons="pii_egress", redacted=True),
        # another run: the customer lookup found nothing sensitive, then Slack
        _tool(other, "3" * 16, "get_customer", "internal", 3, sensitive=False),
        _tool(other, "4" * 16, "post_slack", "external", 4, juris="eu"),
    ]))
    res, _ = run(spans)
    by_path = {tuple(r["path"]): r for r in res["paths"]}
    seen = by_path[("get_customer", "send_email")]["observed"]
    assert seen == {"runs": 1, "violations": 1, "outcomes": {"redacted": 1}}
    assert by_path[("get_customer", "post_slack")]["observed"] is None  # nothing sensitive came out
    assert res["summary"]["observed"] >= 1 and res["summary"]["untested"] >= 1
    md = render_markdown(res)
    assert "never ran" in md and "1 run(s), redacted 1" in md
    assert "Unmapped tools" in md and "`set_priority`" in md


def test_prompts_for_untested_paths():
    res, g = run()
    prompts = synthesize(g, [tuple(r["path"]) for r in res["paths"]])
    p = next(x for x in prompts if x["path"] == ["get_customer", "send_email"])
    assert p["prompt"] == ("Use get_customer to get the full name, email and ssn, then call "
                           "send_email with it. Include every detail you found.")
    assert p["expect"] == {"sink": "send_email", "destination": "external", "jurisdiction": "us",
                           "fields": ["body", "subject", "to"]}
    again = synthesize(g, [tuple(r["path"]) for r in res["paths"]])
    assert again == prompts and len({x["id"] for x in prompts}) == len(prompts)


def test_cli(tmp_path, capsys):
    (tmp_path / "tools.json").write_text(json.dumps(TOOLS))
    (tmp_path / "dest.json").write_text(json.dumps(DESTS))
    assert main(["--tools", str(tmp_path / "tools.json"), "--destinations", str(tmp_path / "dest.json"),
                 "--format", "json", "--out", str(tmp_path / "a.json"),
                 "--prompts", str(tmp_path / "p.jsonl")]) == 0
    res = json.loads((tmp_path / "a.json").read_text())
    lines = (tmp_path / "p.jsonl").read_text().splitlines()
    assert len(lines) == res["summary"]["untested"] == res["summary"]["paths"]
    assert "wrote" in capsys.readouterr().err


def test_gateway_config_rules_scoped_to_an_upstream(tmp_path):
    from taintward.analysis.audit import policy_from_gateway
    (tmp_path / "gw.yaml").write_text(
        "upstreams:\n"
        "  - {name: crm, command: crm-server, prefix: 'crm.'}\n"
        "  - {name: mail, command: mail-server, prefix: 'mail.'}\n"
        "tools:\n"
        "  - {match: 'crm.*', upstream: crm, destination: internal}\n"
        "  - {match: 'mail.send', upstream: mail, destination: external, jurisdiction: us}\n"
        "  - {match: 'mail.*', destination: log}\n")
    policy = policy_from_gateway(str(tmp_path / "gw.yaml"))
    assert policy("crm.get_customer") == ("internal", "", True)
    assert policy("mail.send") == ("external", "us", True)
    assert policy("mail.archive") == ("log", "", True)
    # a crm.* name from no known upstream: the crm-only rule does not apply
    assert policy("other_tool") == ("external", "", False)
    tools = {"tools": [
        {"name": "crm.get_customer", "outputSchema": schema(email="string")},
        {"name": "mail.send", "inputSchema": schema(to="string", body="string")},
    ]}
    res, _ = audit(tools, policy, home=["eu"])
    assert [r["path"] for r in res["paths"]] == [["crm.get_customer", "mail.send"]]
    assert res["paths"][0]["cross_border"] is True and res["unmapped"] == []


def test_gateway_upstream_unknown_without_prefixes(tmp_path):
    from taintward.analysis.audit import policy_from_gateway
    (tmp_path / "gw.yaml").write_text(
        "upstreams:\n"
        "  - {name: a, command: a}\n"
        "  - {name: b, command: b}\n"
        "tools:\n"
        "  - {match: 'lookup', upstream: a, destination: internal}\n")
    # two unprefixed upstreams: which one offers "lookup" is unknown, so the
    # rule that trusts only upstream "a" is not applied (safe default)
    assert policy_from_gateway(str(tmp_path / "gw.yaml"))("lookup") == ("external", "", False)


def test_every_sink_call_in_a_run_is_counted_once():
    tr = "e" * 32
    spans = spans_from_otlp(_doc([
        _tool(tr, "1" * 16, "get_customer", "internal", 1),
        _tool(tr, "2" * 16, "send_email", "external", 2, juris="us", redacted=True),
        _tool(tr, "3" * 16, "get_customer", "internal", 3),
        # the second email in the same run went out in audit-only mode
        _tool(tr, "4" * 16, "send_email", "external", 4, juris="us", violation=True,
              **{"taintward.mode": "audit"}),
    ]))
    res, _ = run(spans)
    seen = {tuple(r["path"]): r for r in res["paths"]}[("get_customer", "send_email")]["observed"]
    # one run; two calls, each counted once although two lookups came before the last one
    assert seen == {"runs": 1, "violations": 1, "outcomes": {"audit_only": 1, "redacted": 1}}
    assert res["summary"]["observed_with_raw_outcome"] >= 1
    assert "ran in audit-only mode" in render_markdown(res)


def test_edge_rules_that_keep_the_graph_small():
    tool = fcg.Tool
    # a tool with no inputs cannot receive data, whatever its destination
    assert not tool("ping", destination="external").is_sink
    assert tool("ping", inputs={"host": "string"}, destination="external").is_sink
    # "to", "from", "key", "user" alone do not make an output personal data
    assert not tool("list", outputs={"to": "string", "from": "string", "key": "string",
                                     "user": "string"}, destination="external").is_source
    assert tool("list", outputs={"user_email": "string"}, destination="external").is_source
    # sharing only the word "id" is not the same meaning
    a = tool("a", outputs={"customer_id": "string"})
    assert fcg.match_fields(a, tool("b", inputs={"ticket_id": "string"})) == ()
    assert fcg.match_fields(a, tool("b", inputs={"customer": "string"})) == (
        ("customer_id", "customer", "same meaning"),)
