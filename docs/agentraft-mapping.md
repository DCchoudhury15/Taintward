# AgentRaft to Taintward: Section-by-Section Mapping

This document is the **citation defense** for Taintward. It maps each module of
AgentRaft (arXiv:2603.07557, Lin et al., March 2026) to its Taintward
counterpart and states the transformation. Anyone reading this should be able to
answer *"what did you actually change vs the paper?"* per section.

## The paper, in one paragraph

AgentRaft defines **Data Over-Exposure (DOE)** as the risk that an LLM agent
transmits sensitive data beyond **user intent** and **functional necessity**
during cross-tool interactions. Formally:

```
D_OE = (D_trans \ (D_nec ∪ D_int)) ∩ D_total

D_total : all data retrieved at the source
D_trans : data payload delivered to the sink
D_int   : data the user intended to transmit
D_nec   : data strictly necessary for the sink
D_OE    : over-exposed data
```

It detects DOE offline via (1) a cross-tool Function Call Graph built by
static type-pruning plus LLM semantic validation, (2) BFS prompt synthesis over
the FCG, and (3) runtime taint tracking (LA-DTP) where taint propagation uses an
LLM-judged semantic-dependency function **Φ(a,f)** and D_nec is decided by a
multi-LLM voting committee (GPT-4.1, Qwen3-Plus, DeepSeek-V3.2) grounded in
GDPR/CCPA/PIPL. Evaluated on AgentDojo with 6,675 MCP.so tools; DOE shows up in
57.07% of call chains; judge F1 is 97.86%.

## Section map

### A. DOE formal model
- **Paper:** the `D_OE` set expression above, the mathematical definition of the
  risk.
- **Taintward:** `taintward/core/doe.py` implements exactly this expression as typed set
  operations over `Field` identifiers.
- **Transformation:** kept verbatim. This is the formal anchor that makes the
  "same model, different substrate" claim defensible. Unit-tested against the
  paper's worked examples.

### B. Cross-Tool Function Call Graph (FCG)
- **Paper:** directed graph of tool-to-tool edges, hybrid static type-pruning
  (type equivalence/subset/conversion) plus LLM validation of semantic
  relevance; call-edge template uses extracted Verb+Object. F1 95.10%.
- **Taintward:** `analysis/fcg.py`, deferred to Phase 5. Runtime traces
  *are* the call graph; the FCG is only needed for offline audit/fuzz.
- **Transformation:** dropped for MVP, reintroduced as an offline audit mode
  that also generates the integration-test prompt corpus.

### C. User Prompt Synthesis
- **Paper:** BFS over the FCG for acyclic source-to-sink paths, instantiate
  templates with concrete user assets, partition into D_int and
  over-exposure candidates. 93.74% trigger coverage.
- **Taintward:** `analysis/prompt_synth.py`, a **test-harness/fuzzer** for our
  own demo bot, not a general attack generator.
- **Transformation:** reframed. Synthesized prompts become the integration
  test corpus that proves the enforcement pipeline fires.

### D. Runtime Taint Tracking (LA-DTP)
- **Paper:** maintains a dynamic Taint Table 𝒯 (field to label), labels at
  source, propagates through three observation points: `source_function`,
  `tool_function`, `sink_function`.
- **Taintward:** `taintward/sdk/taint.py` (Taint Table materialized as OTel span
  attributes) plus `taintward/sdk/instrumentation.py` (the three observation points
  become span start/end hooks). Taint rides in **OTel baggage** within a
  process and **span links** across fan-out/fan-in.
- **Transformation:** replaced Φ with structural propagation. This is the
  core novelty, propagation is real-time and LLM-free.

### E. Φ(a,f), LLM-judged semantic dependency
- **Paper:** "is field *a* semantically derived from/associated with field *f*?"
  The expensive, offline, per-step LLM call that drives propagation.
- **Taintward:** eliminated in the runtime path (baggage carries the tag
  structurally). Optionally reintroduced in Phase 6 as a **fall-back** for
  untagged cross-process flows where the LLM regenerated a value.
- **Transformation:** the headline trade. Deterministic structural
  propagation instead of per-step LLM judgment.

### F. D_nec, the multi-LLM voting committee
- **Paper:** GPT-4.1, Qwen3-Plus, DeepSeek-V3.2 majority vote, prompted with
  GDPR/CCPA/PIPL data-minimization plus least-privilege. F1 97.92% vs ~83%
  single-model.
- **Taintward:** `collector/policy/*.rego`, a deterministic, editable Rego
  bundle evaluated per span in the collector processor. Per-sink-class rules
  encode "strictly necessary" statically.
- **Transformation:** the second headline trade. Auditable, no 3 LLM calls
  per step, admins edit rules without a rebuild. The trade-off is losing the
  committee's nuance on novel sinks, which is acceptable for a product you can
  ship.

### G. Substrate, the AgentDojo custom trace
- **Paper:** custom "Agent Trace" log format (function names, args, return
  values per step). Built on AgentDojo. Target agent GPT-5.1.
- **Taintward:** **OpenTelemetry `gen_ai.*` semantic conventions** ingested by
  **SigNoz**. `genainormalizer` unifies OpenInference/OpenLLMetry into
  `gen_ai.*` for LangChain/LangGraph/CrewAI.
- **Transformation:** the platform trade. Standard, ubiquitous, the format
  agents already speak.

### H. Enforcement, not in the paper
- **Paper:** AgentRaft only **detects** DOE; it does not prevent it.
- **Taintward:** `taintward/sdk/redact.py` (FF1 format-preserving reversible token for
  internal sinks, non-reversible mask for external/LLM) plus an SDK-side
  egress gate and collector-side redact, so raw PII is never stored.
- **Transformation:** Taintward's addition. Detect becomes enforce.

### I. Evidence, not in the paper
- **Paper:** produces aggregate metrics (57.07%, F1, etc.).
- **Taintward:** lineage map plus blast-radius as SigNoz dashboards, plus a
  tamper-evident Merkle/history-tree log (Crosby-Wallach, O(log n) inclusion
  and consistency proofs), giving cryptographically verifiable GDPR Art. 30/15
  evidence.
- **Transformation:** Taintward's addition. Metrics become verifiable records.

## The one-sentence pitch

*"AgentRaft proved you can track sensitive data through an agent, but it's just
a paper, on a format nobody uses. Taintward puts its formal model on
OpenTelemetry, replaces the LLM committee with deterministic policy, adds
runtime redaction so the leak never happens, and turns the trail into GDPR
evidence, shipped as a real product on SigNoz."*

## Verified facts (re-checked 2026-09-01)

- arXiv:2603.07557, "AgentRaft: Automated Detection of Data Over-Exposure in
  LLM Agents", Lin/Wu/Nan/Zhang/Zheng (Sun Yat-sen Univ.) + Wang (UCF),
  8 March 2026.
- DOE in 57.07% of call chains (347/608); 65.42% of transmitted fields
  over-exposed (1803/2756).
- Judge F1 97.86% (data-field granularity); multi-LLM +~14% F1 vs single-model.
- 6,675 tools from MCP.so; implemented on AgentDojo.
- FCG F1 95.10%; prompt trigger coverage 93.74%.
