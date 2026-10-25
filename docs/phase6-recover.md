# Phase 6: recover, AST fix-suggester + DLP simulation + polish

**Status:** done (local, 2026-09-05). 6 fix-suggester unit tests green.

The "recover" pillar: when the policy fires, suggest the exact fix. The
fix-suggester walks the agent's tool-call code with Python's `ast`, finds
calls to external / LLM sinks whose arguments are not routed through the
SDK's Phase 4 egress gate (i.e. not wrapped by an `@instrument_tool`-decorated
tool), and emits the **exact one-line fix**. An LLM *narrates* the finding,
but the **suggestion is grounded in the AST**, which is more defensible (and
cheaper) than asking a model to propose a free-form patch.

## Pieces

- `taintward/fix_suggester/suggest.py`
  - `_dotted_name` reconstructs the called function (`requests.post`,
    `openai.ChatCompletion.create`, and so on).
  - `_classify_sink`: external (`*.post`/`*.put`/`*.patch`/`*.delete`/`*.urlopen`)
    or LLM (dotted name containing `openai`/`anthropic` and ending `.create`).
  - a parent map assigns each `Call` its true enclosing function (no double
    counting); a call is UNGUARDED if its enclosing function isn't decorated
    with `@instrument_tool`.
  - `Finding` feeds `narrate`, which produces a grounded explanation. The
    SigNoz MCP read (`signoz_search_traces` for similar past violations, to
    prioritize fixes) is a hook for when the MCP server plus a model key are
    configured.
  - CLI: `python taintward/fix_suggester/suggest.py <agent_source.py> [...]`.
- `taintward/fix_suggester/sample_buggy_agent.py`: a deliberately-leaky agent (raw
  `requests.post`, `openai.ChatCompletion.create`, a module-level
  `requests.put`, plus a safe internal helper) for the suggester to analyze.
- **DLP simulation mode**: `TAINTWARD_DRY_RUN=1` makes the SDK log the
  violation (`taintward.dry_run=true`) WITHOUT redacting args, an audit/dry-run
  mode for safe rollout (see what would be flagged before enforcing).
- **RAG**: `rag_retrieve` is already masked at the SDK egress gate (Phase 4:
  rag goes to `[PII]`/`[SECRET]`, since embeddings are invertible, OWASP
  LLM08:2025). No separate redact-before-embed step is needed because the gate
  already redacts before the tool runs.

## Verified

```
$ python taintward/fix_suggester/suggest.py taintward/fix_suggester/sample_buggy_agent.py
sample_buggy_agent.py:15: `requests.post` is an unguarded external sink inside `send_to_auditor`. ... fix: redact = redact_payload(payload, instr.DEST_EXTERNAL) ...
sample_buggy_agent.py:20: `openai.ChatCompletion.create` is an unguarded llm sink inside `summarize_with_llm`. ... fix: redact = redact_payload(prompt/record, instr.DEST_LLM) ...
sample_buggy_agent.py:29: `requests.put` is an unguarded external sink inside `<module>`. ...
```

The safe internal helper is not flagged.

## Tests + project

- `tests/test_fix_suggester.py`: 6 green (external POST, LLM create,
  module-level PUT, safe-internal ignored, fix mentions `redact_payload`,
  narration grounded). Full suite **45 python green**.
- README updated with the full 6-phase pipeline and how to run it.

## The full arc (detect → propagate → decide → redact → record → recover)

| phase | does | replaces |
|---|---|---|
| 1 | formal DOE model + SigNoz substrate | (foundation) |
| 2 | runtime taint on OTel (baggage + re-detection) | AgentRaft's Φ (LLM-judged propagation) |
| 3 | Rego policy in the collector | AgentRaft's D_nec 3-LLM committee |
| 4 | reversible context-aware redaction | static field-name masking |
| 5 | tamper-evident Merkle evidence + lineage/SLO dashboards | metrics turned into verifiable Art. 30/15 records |
| 6 | AST-grounded fix-suggester + DLP dry-run | (AgentRaft has no recovery step) |
