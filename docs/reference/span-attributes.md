# Span attributes

Every attribute Taintward writes, by who writes it. Names follow the
OpenTelemetry GenAI semantic conventions (`gen_ai.*`) where one exists, and
use the `taintward.*` prefix otherwise. The names are part of the public API
(see [Stability and versioning](../operations/versioning.md)): dashboards,
alerts, the collector policy and the report depend on them.

Values are never raw sensitive data. Inputs and outputs are stored redacted
or masked.

## Resource

| attribute | value |
|---|---|
| `service.name` | the name given to `tw.init()` / `configure_tracing()`, or the gateway's `service_name` |
| `service.namespace` | `taintward` (set by `configure_tracing`) |

## Taint (SDK and gateway)

| attribute | type | meaning |
|---|---|---|
| `taintward.sensitive` | bool | the call, or the run or session it belongs to, touched sensitive data |
| `taintward.taint.classes` | string | comma list of classes, sorted: `pii`, `secret` |
| `taintward.taint.level` | string | `low`, `medium` (PII) or `high` (a secret) |
| `taintward.taint.id` | string | random id of the taint label, the same across the run |
| `taintward.taint.source_span` | string | span id (16 hex chars) of the call that first found the data (SDK) |

The same label travels in OTel baggage as `taint.id`, `taint.classes`,
`taint.level` and `taint.source`. Baggage from outside is not trusted for
anything but lineage.

## Call (SDK and gateway)

| attribute | type | written by | meaning |
|---|---|---|---|
| `taintward.destination` | string | both | `internal`, `external`, `llm`, `log` or `rag` |
| `taintward.jurisdiction` | string | both | from the tool map, or `llm_jurisdiction` for LLM spans; empty when not set |
| `taintward.violation` | bool | both | a tainted run or session reached an `external`, `llm` or `log` sink |
| `taintward.violation.reason` | string | both | short reason, for example `tainted chain reached llm sink` |
| `taintward.redacted` | bool | SDK | the gate changed what the sink received |
| `taintward.args_redacted` | bool | both | the stored `gen_ai.tool.call.arguments` are already redacted for the destination; the collector keeps them as they are (so internal tokens survive) |
| `taintward.dry_run` | bool | both | audit mode: the sink received raw input (SDK `TAINTWARD_DRY_RUN`, gateway `mode: audit`) |
| `taintward.tool.error` | string or bool | both | the sink raised (SDK: the message with sensitive data masked) or returned an MCP error (gateway: `true`) |
| `taintward.framework` | string | SDK adapters | `langchain`, `openai-agents`, `openai.chat`, `openai.responses`, `anthropic` |

## Gateway only

Span name: `taintward.gateway <tool>`.

| attribute | type | meaning |
|---|---|---|
| `taintward.mode` | string | `redact`, `block` or `audit` |
| `taintward.blocked` | bool | the call was refused and not forwarded |
| `taintward.policy.rules` | string | rules that fired, for example `pii_egress,transfer` |
| `taintward.args.redacted` | bool | the forwarded arguments differ from what the agent sent |
| `taintward.result.redacted` | bool | the result was masked before the agent saw it |
| `taintward.gateway.upstream` | string | upstream name from the config |
| `mcp.method.name` | string | `tools/call` |

## Collector (`taint_policy` processor)

The collector removes any of the attributes it owns that a sender set
itself, then writes them from its own decision.

| attribute | type | meaning |
|---|---|---|
| `taintward.policy.violation` | bool | the `pii_egress` rule fired |
| `taintward.policy.transfer_violation` | bool | the `transfer` rule fired |
| `taintward.policy.violations` | string | the violations as JSON, for example `[{"rule":"pii_egress","sink":"llm"}]` |
| `taintward.policy.reasons` | string | comma list of rule names |
| `taintward.policy.redacted` | bool | the policy asked for redaction (every sensitive span), or the policy failed |
| `taintward.policy.decision_engine` | string | `rego` |
| `taintward.policy.masked_values` | int | how many values the collector masked on this span (only when more than 0) |
| `taintward.policy.error` | string | the policy could not be evaluated; the span was masked anyway |

## GenAI semantic conventions

| attribute | written on | meaning |
|---|---|---|
| `gen_ai.operation.name` | all | `execute_tool` for tools, `chat` for model calls |
| `gen_ai.tool.name` | tool spans | the tool name (the exposed name in the gateway) |
| `gen_ai.tool.call.arguments` | tool spans | input after redaction (masked in audit mode) |
| `gen_ai.tool.call.result` | tool spans | output, masked |
| `gen_ai.input.messages` | model spans | request after redaction (placeholders or masks) |
| `gen_ai.output.messages` | model spans | response as the provider sent it (placeholders, not restored), masked |
| `gen_ai.provider.name` | model spans | `openai`, `anthropic`, ... |
| `gen_ai.request.model` | model spans | the requested model |
| `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens` | model spans | token usage when the provider reports it |
| `taintward.placeholders.instruction` | model spans | `true` when the placeholder system line was added |
| `taintward.placeholders.repaired` | model spans | placeholders the model wrote in another form (`[PERSON_1]`, `Person 1`) that were still restored |
| `taintward.placeholders.lost` | model spans | placeholders the model broke so they could not be restored |
| `taintward.placeholders.unknown` | model spans | placeholder-like text that matches nothing in the run |

## Useful filters

| question | filter |
|---|---|
| all leaks the collector confirmed | `taintward.policy.violation = true` |
| cross-border transfers | `taintward.policy.transfer_violation = true` |
| calls the gateway refused | `taintward.blocked = true` |
| anything still in audit mode | `taintward.dry_run = true` |
| model calls that carried personal data | `gen_ai.operation.name = chat AND taintward.sensitive = true` |
| policy failures | `taintward.policy.error EXISTS` |
