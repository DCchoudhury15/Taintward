# Taintward: Project Plan

## 0. Thesis

AgentRaft (arXiv:2603.07557) proved you can *detect* Data Over-Exposure (DOE) in
LLM agents, but it's offline, on AgentDojo's custom trace format, and its two
core mechanisms (Φ = LLM-judged semantic dependency for taint propagation;
D_nec = 3-LLM voting committee for necessity) are expensive and
non-deterministic. Taintward takes AgentRaft's formal DOE model and puts it
on OpenTelemetry + SigNoz as a runtime enforcement product: replace Φ with
structural baggage/span-link propagation (real-time, LLM-free), replace the
D_nec committee with deterministic Rego policy (auditable), and add the thing
AgentRaft explicitly *doesn't* do, **redact-before-egress** so the leak never
happens, plus lineage/blast-radius as live GDPR Art. 30 evidence.

**Goal (decided 2026-09-01):** portfolio centerpiece, a deep, demoable end-to-end
story with a write-up/talk. Favor a tight, compelling vertical over exhaustive
coverage. FCG/audit-mode (Phase 5) and the 3-LLM committee stay *optional*.

## 1. AgentRaft to Taintward section map

| # | AgentRaft section | Taintward counterpart | Transformation |
|---|---|---|---|
| A | DOE formal model `D_OE = (D_trans \ (D_nec ∪ D_int)) ∩ D_total` | `taintward/core/doe.py` | **Keep verbatim**, this is the formal anchor |
| B | FCG generation (type-pruning + LLM validation) | `analysis/fcg.py` | **Defer to Phase 5** (offline audit) |
| C | Prompt synthesis (BFS over FCG) | `analysis/prompt_synth.py` | **Reframe** as integration-test prompt generator |
| D | Runtime taint tracking (LA-DTP), Taint Table 𝒯 | `taintward/sdk/taint.py` + `taintward/sdk/instrumentation.py` | **Replace Φ with baggage + span-links**, this is the core novelty |
| E | Φ(a,f) LLM semantic dependency | *(eliminated in runtime path)* | **Headline trade**, kept as optional Phase 6 fall-back |
| F | D_nec multi-LLM committee | `collector/policy/*.rego` | **Replace with Rego**, second headline trade |
| G | AgentDojo custom trace | OTel `gen_ai.*` semconv → SigNoz | **Platform trade** |
| H | *(not in paper)* enforcement | `taintward/sdk/redact.py` (FF1) + egress gate | **Taintward addition** |
| I | *(not in paper)* evidence | lineage/blast-radius + Merkle log | **Taintward addition (GDPR)** |

**Defensible-novelty sentence:** same DOE math (A), runtime not offline (D),
deterministic not LLM (E→baggage, F→Rego), standard not custom (G),
enforce not just detect (H), evidence not just metrics (I).

## 2. Architecture

```
detect → propagate → decide → redact → record → recover
(Presidio+secrets) (baggage+span-links) (Rego+jurisdiction) (FF1/mask) (lineage+Merkle) (AST fix-suggester)

Demo Agent ──spans──▶ OTel Collector
                        │
                  [Policy Processor]   ← reads taint attrs, evals Rego
                        │
                  [flow-aware redact]  ← strips raw PII before storage
                        │
                  SigNoz (ClickHouse) ──▶ dashboards / alerts / SLO
                        │
                  [Merkle-evident log] ← Art. 30 evidence
                        │
                  [Fix-suggester]      ← reads via SigNoz MCP
```

The **SDK-side egress gate** is the primary enforcement point (block/redact
before the external/LLM call, in-process); the collector gate is the backstop.

## 3. Phases (each one ends demoable)

### Phase 1: Foundation & formal core
- [x] Repo scaffold (this plan, mapping doc, layout)
- [ ] `taintward/core/doe.py`: formal DOE model, pure, unit-tested against paper examples
- [ ] Local SigNoz (Foundry/docker-compose) standing; one hand-crafted trace visible
- **Demoable:** DOE formula + tests matching the paper; one trace in SigNoz.

### Phase 2: Detect + propagate (runtime taint, on OTel)
- `taintward/sdk/detect.py`: Presidio (regex + spaCy NER) + pii-protector secret recognizers
- `taintward/sdk/taint.py`: compact baggage tag (`taint.id/classes/level`, never the secret); respects W3C limits
- `taintward/sdk/instrumentation.py`: wraps tool calls into `gen_ai.*` spans; sets taint attrs + baggage; uses **span links** for fan-out/fan-in
- `demo/hr_bot`: 5 tools, internal DB, external API, LLM, log, RAG
- **Make-or-break spike:** does a taint tag survive an LLM hop into regenerated output? Attack this first.
- **Demoable:** injected SSN's taint visible on every downstream span in SigNoz (no enforcement yet).

### Phase 3: Decide (Rego policy processor)
- `collector/` Go processor via `ocb`, `MutatesData=true`, runs **before `batch`**
- `policy/pii_egress.rego`: `PII + external/llm ⇒ VIOLATION`; **jurisdiction tags** add `PII → non-adequate-jurisdiction ⇒ TRANSFER_VIOLATION` (Art. 44)
- Emit violation span; redact span attrs so SigNoz never stores raw PII
- **Demoable:** SSN reaches external API, violation span fires, raw value absent from ClickHouse.

### Phase 4: Enforce (reversible, context-aware redaction), the standout
- `taintward/sdk/redact.py`: **FF1 FPE** reversible token for *internal* sinks, non-reversible `[SSN]` mask for *external/LLM*
- SDK-side egress gate (block/redact before the call); collector is the backstop
- FPE caveat: NIST withdrew FF3 (Feb 2025), FF1 libs are low-maturity, so label this "demo-grade, swap to Vault Transform for prod"
- **Demoable:** internal sink gets a reversible token (round-trips), external gets `[SSN]`.

### Phase 5: Record (lineage, blast-radius, SLO, evidence)
- `dashboards/`: SigNoz JSON, imported via SigNoz MCP
- `taintward/evidence/`: Merkle/history-tree log, O(log n) inclusion + consistency proofs
- `analysis/fcg.py` + `prompt_synth.py`: offline audit/fuzz mode; synthesized prompts become the integration-test corpus
- **Demoable:** lineage DAG in SigNoz + CLI proving a violation is in the Merkle log.

### Phase 6: Recover + polish
- `fix-suggester/`: AST-walk finds an unguarded external/LLM arg, emits a one-line fix; LLM narrates via `signoz_search_traces`/`signoz_get_trace_details` MCP
- DLP simulation mode (dry-run: log, don't block); RAG checks (redact-before-embed, retrieval-time authz)
- README, architecture diagram, demo script, AgentRaft-vs-Taintward write-up
- **Demoable:** breach-simulator button triggers the full pipeline, fix-suggester proposes the patch.

## 4. Tech choices & risks

| Decision | Choice | Note |
|---|---|---|
| SDK lang | Python on OTel | matches LangChain/LangGraph/CrewAI; `genainormalizer` → `gen_ai.*` |
| Collector | Go, custom processor via `ocb` | must run before `batch` |
| Policy | OPA/Rego (not Cedar) | Rego has regex; editable without rebuild |
| Redaction | FF1 FPE reversible + mask | demo-grade libs; prod → Vault Transform |
| Baggage | compact tag only; strip at egress | plaintext, no integrity, crosses trust boundaries |
| Fix-suggester LLM | small, grounded by AST + MCP | never free-form patches |

**Top risks:**
1. **Baggage across the LLM hop.** The tag must survive into the LLM's *output* args, not just the request. If the LLM regenerates the value, structural propagation breaks and we'd need a Φ-style semantic check (Phase 6 fall-back). **Attack this in Phase 2.**
2. **FF1 library maturity.** Fine for a demo, don't claim it's prod-grade.
3. **`ocb` build into the SigNoz distro.** Budget a day for this.

## 5. Out of scope (discipline)

- Not a general agent framework, just instrument one demo bot well.
- Not a new trace format, use `gen_ai.*` or lose the "standard" argument.
- Not the 3-LLM D_nec committee (contradicts the deterministic thesis; optional later).
- Not FCG before Phase 5 (it's offline audit, not runtime).

## 6. Success criteria

- **P1:** `doe.py` tests green vs paper examples; one trace in SigNoz.
- **P2:** taint tag visible on every downstream span.
- **P3:** violation span emitted; raw PII absent from ClickHouse (grep it).
- **P4:** internal sink round-trips a reversible token; external gets `[SSN]`.
- **P5:** lineage DAG renders; Merkle inclusion proof verifies; SLO burn rate visible.
- **P6:** fix-suggester emits the correct one-line wrap for an unguarded external call.
