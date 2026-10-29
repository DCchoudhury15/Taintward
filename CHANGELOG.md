# Changelog

## Unreleased

### Added

- Adapters for CrewAI (`wrap_crewai_tools`, `protect_crewai_llm`),
  LlamaIndex (`wrap_llamaindex_tools`, `protect_llamaindex_llm`), Pydantic AI
  (`wrap_pydantic_ai_tools`, `wrap_pydantic_ai_toolset`,
  `protect_pydantic_ai_model`), Google ADK (`wrap_adk_tools`,
  `protect_adk_model`) and LiteLLM (`protect_litellm` for the SDK,
  `TaintwardGuardrail` for the proxy). Same gate as the other adapters:
  tools get what their destination allows, the model gets placeholders and
  its answer is restored. Extras `crewai`, `llamaindex`, `pydantic-ai`,
  `google-adk`, `litellm`; tests run each framework's own agent loop with a
  scripted model, in a new `adapter-tests` CI job pinned by
  `constraints-adapters.txt`.
- Key rings and rotation (`taintward/sdk/keys.py`, `docs/key-management.md`):
  `TAINTWARD_KEYS` loads FPE and vault keys from a JSON file or HashiCorp
  Vault KV, with keys optionally wrapped by AWS KMS, GCP KMS or Vault
  Transit. Vault rows now name the key that sealed them; old rows still
  open. New `taintward-keys` command: `rotate`, `reseal` (re-encrypt vault
  rows under the active key, SQLite, Postgres and Redis), `retire`,
  `generate`, `show`. Erasure finds rows under every key in the ring.
  New extras `aws` and `gcp`. Tested against real Vault and LocalStack.
- TypeScript SDK in `packages/taintward-js` (npm name `taintward`):
  `taintwardMiddleware()` for the Vercel AI SDK sends placeholders to the
  model and restores real values in text, reasoning and tool call
  arguments, also when streamed. Same detector rules as Python (checked
  case by case against it), tolerant restore of rewritten placeholders,
  the placeholder instruction line and strict mode. No name detection.

- `docs/threat-model.md`: trust boundaries, assets, what is prevented,
  detected or not handled for each attacker, known detection bypasses,
  STRIDE per component, 11 open gaps (G1 to G11) and a deployment hardening
  checklist. Every claim points to the code and test behind it.
- `bench/external/`: detection measured on two public labeled PII datasets
  (ai4privacy, gretel finance multilingual). Results in
  `bench/results/external_*` show value shapes only, never dataset text.
  Summary in "Results on outside data" in `docs/benchmark.md`.
- Documentation site (mkdocs-material, `mkdocs.yml`): concepts, guides,
  recipes, configuration, span attribute, command line and Python API
  reference, operations and security pages. `mkdocs build --strict` runs in
  CI, and `.github/workflows/docs.yml` publishes it to GitHub Pages from
  main.

### Changed

- The README is shorter, with the key numbers at the top.

- README and SECURITY.md say that the 0% false alarm and 0.94 recall numbers
  are from the synthetic benchmark, and link the outside-data results and
  the threat model.
- Links on the site, quickstart, SECURITY.md and CONTRIBUTING.md point to
  the GitHub repo. Security reports go to GitHub private advisories, with the
  GitLab confidential issue as a fallback.

## 0.2.0

First release under the name Taintward. The project was called AgentWard
before; the PyPI name `agentward` belongs to another company, so everything
was renamed.

### Renamed

- One Python package, `taintward`, holds `sdk`, `core`, `evidence`,
  `fix_suggester` and `gateway`. `import taintward as tw` gives the
  integrations API: `tw.init`, `tw.run`, `tw.wrap_langchain_tools`,
  `tw.protect_langchain_model`, `tw.wrap_function_tools`, `tw.protect_openai`,
  `tw.protect_anthropic`, `tw.restore`, `tw.health`.
- PyPI name `taintward`. Commands: `taintward-report`, `taintward-gateway`,
  `taintward-evidence`, `taintward-fix`.
- Environment variables `AGENTWARD_*` are now `TAINTWARD_*`.
- Span attributes `agentward.*` are now `taintward.*` in the SDK, the
  gateway, the collector processor, the Rego package (`package taintward`),
  the report, the dashboards and the Helm chart.
- Go module `github.com/DCchoudhury15/taintward/...`, collector binary and
  images `taintward-collector`, `taintward-gateway`, `taintward-demo`.
- Helm chart in `deploy/helm/taintward`. The gateway Dockerfile moved to
  `deploy/gateway.Dockerfile`.
- There are no compatibility aliases for the old names.

### Added

- Packaging: every runtime package ships; extras `mcp`, `langchain`,
  `openai-agents`, `llm`, `postgres`, `redis`. CI for GitLab and GitHub.
- FF1 format-preserving encryption, checked against the NIST sample vectors.
- Token vault with AES-256-GCM encryption at rest: memory, SQLite, Postgres
  and Redis backends, with per-subject erasure for GDPR.
- MCP gateway over stdio and HTTP (`--listen`) with redact, block and audit
  modes per tool, and Redis session storage for several replicas.
- Framework adapters for LangChain, LangGraph, the OpenAI Agents SDK and the
  OpenAI and Anthropic clients.
- Placeholders for the LLM: the model gets `<PERSON_1>`, `<SSN_1>` and the
  caller gets the real values back.
- Compliance report (`taintward-report`), a sharded evidence log with
  Ed25519 signed checkpoints, RFC 9162 inclusion and consistency proofs, and
  repair after a crash.
- Docker compose quickstart with Jaeger, a Helm chart (tested on kind) and
  load tests for the collector, the SDK and the gateway.
- Detection health: `tw.health()` reports `full`, `regex_only` or `broken`.
- `TAINTWARD_FAIL_CLOSED=1`: refuse calls to non-internal sinks while
  detection is degraded (SDK and gateway).
- `taintward.args_redacted` span attribute: the stored tool arguments are
  already redacted, so the collector keeps them (and their reversible
  tokens) as they are.
- `taintward.taint.source_span` now names the span that first found the
  data, and the source span rides in baggage.

### Changed

- Detection is much faster: a wrapped 1 KB tool call went from 518 ms to
  8.4 ms (p50), and false alarms on clean payloads went from 48% to 0% on
  the benchmark. See `docs/benchmark.md`.
- Collector processor: fails closed, scans all span data, has more secret
  patterns and caches policy decisions.
- If spaCy or Presidio fail to load, detection logs one ERROR and falls back
  to regex-only detection instead of finding nothing.
- Run state (`begin_run` / `end_run`, `tw.run`) lives in context variables:
  runs in concurrent asyncio tasks no longer mix, and nested runs work.

### Fixed

- Numbers and other non-string values (an SSN stored as an int, an object
  whose `str()` holds an SSN) reached tools and spans raw. They are now
  checked in their string form and redacted.
- Dict keys were never scanned. They are now scanned and redacted, and
  redacted keys are kept unique.
- namedtuples became plain tuples, and masking one raised an error. They
  keep their type now; sets, frozensets and dict subclasses too.
- `AGENTWARD_DRY_RUN=0` turned dry run on. All on/off settings now use one
  parser: on for `1`, `true`, `yes`, `on`, off for `0`, `false`, `no`, `off`.
- Taint from a wrapped tool called inside another wrapped tool could be
  lost, so a later external call recorded no violation.
- A tool that raised recorded no violation, and the exception message
  reached the span raw. The violation is recorded now and the exception
  message and stack trace are masked.
- The Helm chart shipped an older copy of the Rego policy.
