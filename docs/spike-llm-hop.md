# Spike: does a taint tag survive an LLM hop?

**Date:** 2026-09-01. **Status:** answered, the thesis holds.

This is the make-or-break experiment flagged in `PLAN.md` section 4, risk #1:
if the agent reads an SSN and then calls an LLM that *regenerates* the value
into a new surface form, does structural OTel-baggage propagation keep the
taint alive, or do we need AgentRaft's Φ (LLM-judged semantic dependency) as a
fall-back?

## Setup

Minimal flow, run via `spike/llm_hop.py`:

```
read_file  ->  llm_rephrase  ->  external_api
(internal)    (LLM sink)       (external sink)
```

A deterministic stub LLM runs three modes so each transformation case is
tested deterministically (the real OpenAI/Anthropic path is one env var away):

| mode | LLM output | PII still detectable in output? |
|---|---|---|
| passthrough | `"Employee record for Alice Lee; SSN 234-12-1234."` | yes |
| reformat | `"Employee record; SSN 234121234."` (dashes stripped) | **no** (US_SSN regex needs dashes) |
| summarize | `"The employee's record has been processed."` (value dropped) | **no** |

## Result

The chain-level taint (OTel baggage) persists into the `external_api` sink in
**all three modes**, including `summarize`, where the value is gone from the
output text entirely. Verified in SigNoz / ClickHouse:

```
taintward.violation=true  on  external_api (dest=external, classes=pii,secret)
taintward.violation=true  on  llm_rephrase (dest=llm,      classes=pii,secret)
```

The stored `gen_ai.tool.call.result` shows the **masked** output
(`'Employee record; [PII] [PII].'`); raw PII never reaches SigNoz, while the
taint *classes* persist on the span regardless of masking.

## Why it works: the two-layer model

1. **Call-chain taint (baggage)** is value-independent. It doesn't depend on
   the secret's surface form, so it survives *any* transformation, reformat,
   abbreviate, paraphrase, drop, by construction. This is the propagation that
   AgentRaft would need Φ (per-step LLM semantic judgment) to achieve, and
   Taintward gets it for free from OTel baggage.

2. **Field-level taint (detection re-fire)** catches the PII *additionally*
   when it stays detectable (passthrough, and partially reformat). It doesn't
   survive non-detectable transformations (reformat-without-dashes, summarize).

The chain-level tag is a **safe over-approximation**: a PII-touched chain
reaching an external/LLM sink is flagged as a violation even when the specific
field can't be pinpointed after the transformation. For enforcement, flagging
the sink is the right call, it's better to flag than to leak.

## The residual gap (where Φ would still help)

There's one case structural propagation can't resolve on its own: PII
transformed into a *non-detectable* form that still travels **semantically**,
for example the LLM outputs "the last four digits are 1234" instead of the
full SSN. The chain is still flagged (over-approximation), so nothing is
missed, but the lineage map can't say *which field* leaked.

Closing that gap, pinpointing the transformed field, is exactly where
AgentRaft's Φ (LLM-judged semantic dependency) would slot in as an **optional
Phase 6 fall-back**, run only on chains already flagged as tainted and only at
audit time (not per-step). It's **not** required for the runtime enforcement
thesis, which is the headline result of this spike.

## Conclusion

The core architectural bet holds: **baggage propagation plus per-I/O
re-detection is sufficient for runtime enforcement.** Φ is demoted from "core
mechanism" (as in AgentRaft) to "optional audit-grade refinement", exactly the
trade the project thesis claimed. Phase 2 can proceed to the full
`demo/hr_bot` on this foundation.
