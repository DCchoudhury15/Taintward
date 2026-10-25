# Handoff: work left on branch product-v0.2

Read this first. Delete this file in the final commit before merging to main.

## State (2026-10-25)

Branch `product-v0.2` holds everything below on top of `main` (92be654).
`python -m pytest -q`: 309 passed, 1 skipped (the skip needs the `opa`
binary). `ruff check .` clean. `go test ./...` in
`collector/processor/taintpolicy` passes. `helm lint deploy/helm/agentward` passes.

Done on this branch:

- packaging (all runtime packages ship), CI for GitLab and GitHub
- FF1 (NIST vectors), encrypted vault: memory, SQLite, Postgres, Redis; GDPR erasure
- MCP gateway: stdio and HTTP (`--listen`), redact / block / audit, Redis sessions
- framework adapters: LangChain, LangGraph, OpenAI Agents SDK, OpenAI and Anthropic clients
- LLM placeholders and restore (`<PERSON_1>` to the model, real values back to the user)
- fast detection: 1 KB call 518 ms to 8.4 ms, false alarms 48% to 0% (`docs/benchmark.md`)
- compliance report (`evidence/report.py`), sharded evidence log with Ed25519 checkpoints,
  RFC 9162 inclusion and consistency proofs, crash repair
- collector hardening: fails closed, scans all span data, more patterns, decision cache
- Docker compose quickstart, Helm chart (verified on kind), load tests (`docs/scaling.md`)
- landing page in `site/` already says Taintward

## Task 1: finish the SDK review fixes

Partial work is on branch `wip-sdk-review-fixes` (one WIP commit on top of an
older product-v0.2). It adds `sdk/envflags.py`, `sdk/regex_fallback.py`,
`sdk/_walk.py` and `tests/test_review_fixes.py`, and starts changes in
`sdk/detect.py`, `sdk/redact.py` and `sdk/recognizers_extra.py`. Unfinished
and untested. Merge or rebase it onto product-v0.2 first, then finish it.

Each item below needs a failing test first, then the fix:

2. Non-string leaves: `redact_payload({"ssn": 234121234}, "external")` returns
   the raw int. Objects whose `__str__` contains an SSN reach tools raw and
   reach spans raw via `_jsonable(default=str)`. Detect on the str form and
   replace detected values with the redacted string.
4. `AGENTWARD_DRY_RUN=0` turns dry run ON (`!= ""` check in
   `sdk/instrumentation.py`). One helper for all boolean env flags: true only
   for 1/true/yes/on, case-insensitive.
5. Nested taint: an inner wrapped tool returns an SSN, the outer returns a
   clean summary, then an external send may record no violation. Check inside
   and outside `Ward.run()` / `begin_run`.
9. Detection silently returns nothing if spaCy or Presidio fail to load (this
   really happened with bad dependency versions). Log an ERROR once, expose a
   health function, fall back to regex-only detection, and add
   `AGENTWARD_FAIL_CLOSED=1` to refuse non-internal calls while degraded.
10. Dict keys are never scanned: `{"234-12-1234": "x"}` passes raw. Scan and
    redact keys, keep them unique.
11. `redact_payload` turns namedtuples into tuples, and `mask_value` raises on
    them. Use `t(*items)` when the value has `_fields`.
12. A tool that raises records no violation. Set the attributes before the
    call or in a finally, and redact exception messages.
16. Minor: unused `span_attrs`; `ATTR_TaintSource` is always empty; `begin_run`
    clears context tokens without detaching; `threading.local` run state is
    shared across asyncio tasks (check whether the contextvar run box replaces it).
3. SDK side of a collector change. The collector now redacts
   `gen_ai.tool.call.arguments` unless the span has bool
   `agentward.args_redacted = true`. Set it in `GuardedCall.__enter__`
   (`sdk/instrumentation.py`) next to `ATTR_REDACTED`:
   `not DRY_RUN and not (self._passthrough & self._raw_kwargs.keys())`, and in
   `gateway/server.py` where it stores redacted args. Until then the collector
   masks the SDK's reversible tokens in stored args (safe, but loses them).

Keep `tests/test_detect_latency.py` and the bench smoke floors passing.

## Task 2: rename AgentWard to Taintward

Reason: the PyPI name `agentward` belongs to agentward.ai, a company in the
same market. `taintward` is free on PyPI and GitHub (checked 2026-10-24).

- Move `sdk/`, `core/`, `evidence/`, `fix_suggester/`, `gateway/` into one
  package `taintward/` and rewrite imports. Add `taintward/__init__.py` that
  re-exports the integrations API (`init`, `run`, `wrap_langchain_tools`,
  `protect_langchain_model`, `wrap_function_tools`, `protect_openai`,
  `protect_anthropic`, `restore`), so users write `import taintward as tw`.
- PyPI name `taintward`. Console scripts `taintward-report`,
  `taintward-gateway`, `taintward-evidence`, `taintward-fix`.
- Env vars `AGENTWARD_*` to `TAINTWARD_*`. Span attributes `agentward.*` to
  `taintward.*` in the SDK, the gateway, the Go processor, the Rego package,
  the report, the dashboards and the Helm chart. No compatibility shims are
  needed: there are no outside users yet.
- Go module path and collector name, Dockerfiles, compose, Helm chart dir
  (`deploy/helm/taintward`), CI paths, all docs, README.
- Links: GitLab becomes `gitlab.com/divyanshuchoudhury51/taintward` and GitHub
  `github.com/DCchoudhury15/taintward`. The owner renames both repos by hand.
- Afterwards, `grep -ri agentward` should only hit history notes (for example
  "renamed from AgentWard").

## Task 3: finish and ship

- README: real numbers from `docs/benchmark.md` and `docs/scaling.md`; links
  to the report, Helm and scaling docs; `import taintward as tw` examples.
- `CHANGELOG.md` for 0.2.0.
- Rebuild and run `docker compose up --build`. Check in Jaeger
  (localhost:16686) that violations show and the raw SSN `234-12-1234` and
  key `AKIAIOSFODNN7EXAMPLE` appear nowhere.
- Full checks: pytest, ruff, go test, go vet, helm lint.
- Merge to `main` and push once (GitLab is the main remote; GitHub is
  flagged, push there too if it works). Keep the number of pushes small:
  each push starts a GitLab pipeline.
- Site: `site/index.html` is static. The owner deploys it on Vercel.

## Rules for this repo (from the owner)

- Never mention AI tools or assistants anywhere: code, docs, commit messages,
  merge requests. No Co-Authored-By lines.
- Never use the em dash character anywhere.
- Docs in plain, simple English. Technical, no metaphors.
- Commit as DCchoudhury15. Use fake data only in tests and examples.
