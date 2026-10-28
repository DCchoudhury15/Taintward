# Policy

The policy decides whether a call is a **violation**. It is a Rego file,
`collector/policy/pii_egress.rego`, and it is the source of truth: the
collector evaluates it on every span. The MCP gateway implements the same
rules in Python (a test fails if the Python copy and the Rego file drift
apart), and the SDK sets its own `taintward.violation` flag for the egress
rule before the span leaves the process.

## The rules

Input for one call:

```json
{"sensitive": true, "classes": "pii,secret", "destination": "llm",
 "jurisdiction": "us", "tool": "ask_llm"}
```

| rule | fires when | span attribute |
|---|---|---|
| `pii_egress` | `sensitive` is true and `destination` is `external`, `llm` or `log` | `taintward.policy.violation=true` |
| `transfer` | `classes` has `pii` and `jurisdiction` is in `non_adequate_jurisdictions` (default `{"us"}`) | `taintward.policy.transfer_violation=true` |

`internal` and `rag` are not violation sinks. They are still redacted
(tokens and masks), but sending sensitive data there is allowed.

The output is `data.taintward.decision = {"redact": bool, "violations": [...]}`.
`redact` is true for every sensitive span, so raw values are removed from
stored spans whether or not the call was a violation.

## Who evaluates it

| where | when | what it does with the decision |
|---|---|---|
| SDK (`GuardedCall`, adapters) | before the call | redacts the input for the destination, sets `taintward.violation` for the egress rule (the transfer rule is left to the collector) |
| MCP gateway | before and after the upstream call | redacts, blocks or only records, per tool `mode` |
| collector (`taint_policy` processor) | when the span arrives | writes `taintward.policy.*`, removes raw values still on the span |

The collector's answer is the authoritative one in the evidence report
(`decided_by: collector`). It also drops the `taintward.policy.*` attributes it owns if
a sender set them, so a forged `violation=false` does not survive. If the
policy fails to evaluate, the collector fails closed: it masks everything it
can and writes `taintward.policy.error`.

## Modes

The decision is the same everywhere. What happens next depends on the mode:

| mode | where | sink receives | violation recorded |
|---|---|---|---|
| redact (default) | SDK, gateway | redacted values | yes |
| block | gateway | nothing, the call is refused with MCP error `-32001` | yes, `taintward.blocked=true` |
| audit | gateway `mode: audit`, SDK `TAINTWARD_DRY_RUN=1` | raw values | yes, `taintward.dry_run=true` |

Audit mode is for rollout only. See
[Audit mode first, then enforce](../recipes/audit-then-enforce.md).

## Changing the policy

Edit the Rego file and restart the collector (no rebuild), or pass your own
file to the Helm chart with `--set-file collector.policy.rego=my.rego`. Keep
these parts, which the processor checks at startup:

- `package taintward`
- a `decision` rule and `default redact := false`

Common changes:

- add a jurisdiction to `non_adequate_jurisdictions`;
- add `rag` to `sensitive_sinks` if your vector store is run by a third
  party;
- add a rule on `input.tool` for a tool that must never see `secret` data.

If you change the sink set, the jurisdiction set or the rule names, the
gateway copy in `taintward/gateway/policy.py` must change too (the SDK's own
egress set is `_EGRESS_SINKS` in `taintward/sdk/instrumentation.py`). The
test in `tests/test_gateway.py` tells you when they differ.

## No LLM in the decision

The research model Taintward is based on (AgentRaft) asks a committee of
three LLMs whether each data flow was necessary. Taintward replaces that with
this deterministic policy: the same input always gives the same decision, it
costs far less than one LLM call, and an auditor can read it. See
[AgentRaft mapping](../agentraft-mapping.md) for the full comparison.
