# Phase 3: the Rego policy processor (collector-side decide + redact)

**Status:** done (local, 2026-09-04). Verified end-to-end in SigNoz and with Go unit tests.

AgentRaft judges "strictly necessary" (D_nec) with a 3-LLM voting committee
(GPT-4.1 / Qwen3-Plus / DeepSeek-V3.2, majority vote). Phase 3 replaces that
with a **deterministic Rego policy evaluated per span in an OpenTelemetry
collector processor**, auditable, no LLM calls, editable without a rebuild.
This is the second headline trade of the project thesis.

## Architecture: sidecar collector

Rather than rebuild SigNoz's forked collector, a minimal **sidecar collector**
sits between the SDK and SigNoz:

```
SDK  --OTLP/HTTP :4319-->  taintward-collector
                             [otlp receiver]
                                    |
                             [taint_policy processor]  <-- Rego eval + redact
                                    |
                             [batch]
                                    |
                          --OTLP/gRPC :4317-->  SigNoz ingester
```

- SDK `configure_tracing(endpoint=http://localhost:4319/v1/traces)`.
- `TAINTWARD_MASK_IN_SDK=0` makes the SDK send **raw** tool inputs to the
  trusted local sidecar, and the **collector** applies Rego and redacts
  before SigNoz stores anything. Tool outputs are masked in the SDK either
  way, because the collector only has regex patterns. (With the flag on, the
  SDK masks inputs in-process too, which is the Phase 2 backstop for when no
  sidecar is present.)
- The collector exports to SigNoz via gRPC `:4317` (the `otlpexporter` is gRPC;
  `:4318` is SigNoz's HTTP port).

## Pieces

- `collector/policy/pii_egress.rego`, the **source of truth**. Rules:
  - `violation` (pii_egress): sensitive + sink in {external, llm, log}.
  - `transfer_violation`: PII + jurisdiction in the non-adequate set {us}
    (GDPR Art. 44). Fires *in addition* to egress when the sink is abroad.
  - `redact`: sensitive, so redact raw values from stored attrs.
  - `decision = { redact, violations }` is the aggregate the processor reads.
  - Rego v1 (`import rego.v1`); admins edit this file and restart, no rebuild
    needed.
- `collector/processor/taintpolicy/` (Go module, processor v1.66.0 + OPA):
  - embeds the policy (`//go:embed`), runs `rego.PrepareForEval` at startup
    (compile once, eval many), calls `EvalInput(spanAttrs)` per span.
  - writes collector-authoritative `taintward.policy.*` attrs:
    `redacted`, `violation`, `transfer_violation`, `violations` (JSON),
    `reasons`, `decision_engine=rego`.
  - redacts raw PII and secrets (regexes go to `[PII]` / `[SECRET]`) on
    **every** span, whatever the policy decides. See "Hardening" below.
  - forwards to the next consumer (the `next consumer.Traces` from the factory).
  - `MutatesData=true`; runs before `batch`.
- `collector/builder.yaml` (ocb manifest) + `collector/config.yaml` (runtime).
  Built with `ocb` (builder v0.160.0) into `collector/bin/taintward-collector`.

## Verified in SigNoz (breach run, SDK mask off)

| span | dest | jurisdiction | violation | transfer | redacted | reasons |
|---|---|---|---|---|---|---|
| query_db | internal | (none) | false | false | true | (none) |
| ask_llm | llm | us | **true** | **true** | true | transfer,pii_egress |
| rag_retrieve | rag | (none) | false | false | true | (none) |
| call_external_api | external | us | **true** | **true** | true | transfer,pii_egress |
| write_log | log | (none) | **true** | false | true | pii_egress |
| agent.decide / hr_bot.run | (none) | (none) | false | false | false | (none) |

**Redaction proof:** the SDK sent `ask_llm`'s output with raw `"ssn":
"234-12-1234"`; the collector masked it to `"ssn": "[PII]"` before storage
(`taintward.policy.decision_engine=rego`, `redacted=true`). `query_db` shows
both `"ssn": "[PII]"` and `"deploy_key": "[SECRET]"`. **Zero raw SSN/AWS
values anywhere** in the stored hr_bot spans.

## Tests

- `collector/processor/taintpolicy/processor_test.go`: 3 Go tests, offline
  (no SigNoz needed): egress+transfer+redact on a tainted external-us span;
  internal sink redacts but doesn't violate; clean span stays untouched.
- `hardening_test.go`: the hardening cases below (nested values, events,
  span name, resource attrs, fullwidth and zero-width SSNs, cards, keys,
  Rego errors, string "true", missing `sensitive`, "US", the args marker,
  startup checks, and a byte-for-byte check that the two rego files match).
- `bench_test.go`: `BenchmarkProcessSpan`.
- Run: `cd collector/processor/taintpolicy && go test ./... && go test -bench . -run x`

## Hardening (2026-10)

A security review found ways raw PII could still reach SigNoz. What changed:

**1. Tool arguments.** The processor used to skip `gen_ai.tool.call.arguments`
always, so the SDK's reversible tokens would not be masked again. But then raw
arguments got through in SDK dry-run mode, for non-string arguments, and from
any other OTel producer. Now the processor skips that attribute only when the
span has `taintward.args_redacted = true` (a real bool). Anything else (missing,
the string "true", false) means the arguments are scanned like every other
value. The older `taintward.redacted` flag is not used for this: it only says
"the gate changed what the sink got", so it is false when nothing was found and
true even when a passthrough kwarg stayed raw.

**2. Everything is scanned.** The backstop now walks:

- span attributes, including values nested in maps and lists, and UTF-8 bytes
- the span name and the status message
- event names and event attributes (for example `exception.message`)
- link attributes
- resource attributes and scope attributes

Values nested deeper than 32 levels are replaced with `[REDACTED]`, since they
were not scanned.

Before matching, text that is not plain ASCII is normalized: zero-width and
other invisible format characters are removed, NFKC is applied (so fullwidth
`２３４` becomes `234`), and Unicode dashes, spaces and digits become ASCII.
If the normalized text has a match, the whole value is stored in its
normalized, masked form. Mapping positions back to the original text through
NFKC is easy to get wrong, and the only cost of storing the normalized form is
that some harmless characters look different in a value that held PII anyway.

New patterns:

- SSN with spaces or dots (`234 12 1234`), not only dashes.
- SSN as 9 bare digits, but **only next to an SSN keyword** (`ssn`, `social
  security number`). Without a keyword, 9 digits are far more often an order
  ID, a count, a ZIP+4 code or a timestamp part, and masking all of them would
  make traces useless.
- Payment cards: 13 to 19 digits with optional spaces or dashes, a known
  issuer prefix and length (Visa, Mastercard, Amex, Discover, JCB, Diners,
  UnionPay) and a passing Luhn check. The prefix check matters: Luhn alone
  passes 1 in 10 random numbers, and millisecond timestamps (13 digits
  starting with 1) would be masked.
- API keys: OpenAI/Anthropic style `sk-...`, Stripe, Slack `xox?-`, Google
  `AIza...`, GitHub fine-grained `github_pat_`, GitLab `glpat-`, AWS `ASIA`,
  JWTs, PEM private keys, `Bearer <token>`, and `password=...`, `api_key: ...`,
  `token: ...` style assignments (only the value is masked, 8+ characters).

**3. Fail closed.**

- The regex backstop runs on every span, whatever the policy says. The policy
  decides violations; the backstop decides redaction.
- If Rego evaluation fails or the decision is undefined or has the wrong
  shape, the span is still redacted, `taintward.policy.redacted = true` and
  `taintward.policy.error` holds the reason.
- `taintward.sensitive` also accepts the strings "true" and "1" (any case)
  and a non-zero int.
- Any `taintward.policy.*` attributes the producer sent are removed first, so
  a fake `violation = false` cannot survive.
- The policy now has `default redact := false`. Before, `decision` was
  undefined for every span that was not sensitive, so no transfer violation
  was ever reported for those spans. (`violation`, `transfer_violation` and
  `deny` are multi-value rules: they are already the empty set when nothing
  matches, and Rego does not allow a default on them.)
- At startup the processor checks that the policy is `package taintward`,
  defines `decision` and `redact`, and gives a well formed decision for two
  sample inputs. If not, the collector does not start and says why.

**4. Case.** Jurisdiction, destination and taint classes are compared in lower
case, both in the policy and in Go before evaluation, so "US" triggers the
transfer rule. A Go test checks that `collector/policy/pii_egress.rego` and the
embedded copy are byte-for-byte the same.

**5. Speed.** Regexes are compiled once. Each string gets one cheap byte pass
first (digit count, `@`, `:` or `=`, keyword checks), and a regex runs only if
it could match, so a clean ASCII string costs no allocations. Policy decisions
are cached by their input (five short strings, few distinct values). Set
`decision_cache_size: 0` if a custom policy depends on anything other than
its input, such as time.

| BenchmarkProcessSpan | before | after |
|---|---|---|
| clean span | ~105 us, 390 allocs | ~4 us, 14 allocs |
| span with SSN + email | ~100 us, 399 allocs | ~13 us, 24 allocs |
| no cache (Rego every span) | n/a | ~92 us, 517 allocs |

## Gotchas (for future me)

- Collector submodules are **decoupled** from core: `processor` is at
  **v1.66.0**, not v0.160.0, while `otlpreceiver`/`batchprocessor`/`otlpexporter`
  are at v0.160.0. `go mod tidy` resolves this; ocb's manifest pins per-module.
- `processor.CreateTracesFunc` in v1.66 takes **4 args**: `(ctx, Settings,
  Config, next consumer.Traces)`. The processor MUST store `next` and call
  `next.ConsumeTraces`, or data just stops at the processor.
- `processor.Traces` embeds `component.Component`, so implement no-op
  `Start(ctx, component.Host)` and `Shutdown(ctx)`.
- `Capabilities` lives in `consumer`, not `component`. `NewFactory` wants
  `component.MustNewType(str)`.
- `healthcheckextension` isn't at v0.160.0 (it's on a separate version line),
  so I dropped it.
- `otlpexporter` is **gRPC**, point it at `:4317`, not `:4318` (that's HTTP).
- ocb generates to a temp dir before the binary; `replaces:` need an
  **absolute** local path (relative paths break from the temp dir). Set
  `dist.output_path: ./build` to persist the generated tree.
- `//go:embed` can't reach above the package dir, so the policy is copied into
  `collector/processor/taintpolicy/pii_egress.rego`. The `policy_path` config
  lets the canonical `collector/policy/pii_egress.rego` override at runtime
  (edit without rebuild). Keep the two in sync.
