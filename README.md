# AgentWard

> A GPS tracker for sensitive data inside AI agents: runtime **enforcement** of
> the Data Over-Exposure (DOE) model on OpenTelemetry + SigNoz.

## The problem

AI agents chain tool calls together: read from a database, hand the result to
an LLM, call an external API, write a log line. Somewhere in that chain, a
field that should never have left the building (an SSN, an API key, a
customer's address) can slip through, because nobody is tracking where the
data actually *goes* once it enters the chain.

[AgentRaft](https://arxiv.org/abs/2603.07557) (Lin et al., March 2026) proved
this is measurable: it found this kind of over-exposure in 57% of the call
chains it analyzed. But AgentRaft is a research pipeline, not something you
can run in production. It works offline, on a custom trace format from the
AgentDojo benchmark, and it decides "was this data strictly necessary?" by
polling three different LLMs and taking a majority vote.

AgentWard takes AgentRaft's formal model and turns it into something that
runs live, on infrastructure you already have (OpenTelemetry + SigNoz), with
no LLM in the hot path:

| AgentRaft | AgentWard |
|---|---|
| Φ = LLM-judged semantic dependency (taint propagation) | structural OTel **baggage + span-link** propagation, real-time and LLM-free |
| D_nec = GPT-4.1 / Qwen3-Plus / DeepSeek-V3.2 voting committee | deterministic **Rego** policy, auditable, no 3 LLM calls per step |
| AgentDojo custom trace format | standard OTel `gen_ai.*` semconv into **SigNoz** |
| offline **detection** | runtime **enforcement** (redact-before-egress) |
| metrics | **lineage / blast-radius** as GDPR Art. 30 evidence |

The underlying math (`D_OE = (D_trans \ (D_nec ∪ D_int)) ∩ D_total`) is kept
exactly as AgentRaft defined it, see [`core/doe.py`](core/doe.py) and
[`docs/agentraft-mapping.md`](docs/agentraft-mapping.md) for the full
section-by-section mapping. The build plan is in [`PLAN.md`](PLAN.md).

## How it works

Six stages, each replacing one piece of AgentRaft with something that runs
in real time:

```mermaid
flowchart LR
    A["1. Detect<br/>Presidio + secret regexes"] --> B["2. Propagate<br/>OTel baggage + span links"]
    B --> C["3. Decide<br/>Rego policy, sidecar collector"]
    C --> D["4. Redact<br/>reversible token (internal) /<br/>one-way mask (egress)"]
    D --> E["5. Record<br/>Merkle log + SigNoz dashboards"]
    E --> F["6. Recover<br/>AST-grounded fix-suggester"]
```

And here is the actual runtime shape of it, an agent process instrumented
with the AgentWard SDK, talking to a sidecar collector that makes the
policy decision before anything reaches storage:

```mermaid
flowchart TD
    subgraph AP["Agent process (the HR bot demo)"]
        SDK["AgentWard SDK<br/>detect · taint · redact"]
        T1["query_db (internal)"]
        T2["ask_llm (llm)"]
        T3["call_external_api (external)"]
        T4["write_log (log)"]
        T5["rag_retrieve (rag)"]
        SDK -. instrument_tool .-> T1
        SDK -. instrument_tool .-> T2
        SDK -. instrument_tool .-> T3
        SDK -. instrument_tool .-> T4
        SDK -. instrument_tool .-> T5
    end

    AP -->|"OTLP/HTTP spans, :4319"| RCV

    subgraph SC["agentward-collector (sidecar)"]
        RCV["otlp receiver"]
        POL["taint_policy processor<br/>Rego eval + redact"]
        RCV --> POL
    end

    SC -->|"OTLP/gRPC, :4317"| SNZ

    subgraph SNZ["SigNoz"]
        CH[("ClickHouse")]
        UI["React UI, :8080"]
        CH --> UI
    end

    CH --> EV["Merkle evidence log<br/>tamper-evident, GDPR Art. 30"]
    CH --> DASH["Dashboards<br/>lineage / blast-radius / SLO"]
    DASH -. prioritizes .-> FIX
    AP -. source code .-> FIX["Fix-suggester<br/>walks the AST for unguarded sinks"]
    FIX -. one-line patch .-> AP
```

Two propagation layers do the actual tracking, which is the part that has
to survive an LLM rewriting the data beyond recognition:

1. **Chain-level (baggage)**: the moment a tool call touches sensitive data,
   a compact tag (`taint.id`, `taint.classes`, never the value itself) rides
   along in OTel baggage to every downstream span in that trace. This
   doesn't care what the LLM does to the data. Even if summarizing or
   translating destroys the original bytes, the taint tag survives because
   it's attached to the *call chain*, not the *value*.
2. **Field-level (re-detection)**: every tool's input and output is
   re-scanned on the way through, so brand-new sensitive data introduced
   mid-chain (an LLM inventing a plausible-looking SSN, say) still gets
   caught.

At the sink, the collector's Rego policy is what actually decides:
`sensitive data + destination in {external, llm, log} ⇒ violation`, plus a
second rule for cross-border transfers (`PII + non-adequate jurisdiction ⇒
transfer_violation`, the GDPR Art. 44 case). Whatever the policy flags gets
redacted before it's ever written to SigNoz's storage.

## See it in action

Running the breach simulator (injects a fake SSN and AWS key into the HR
bot's database, then lets the agent's normal `query_db → internal_store →
ask_llm → rag_retrieve → call_external_api → write_log` chain run) produces
this, verified against a live SigNoz instance:

| tool | destination | stored value | violation | transfer |
|---|---|---|---|---|
| `query_db` | internal | `"ssn": "[PII]"` | no | no |
| `internal_store` | internal | `"ssn": "103-48-0677"` (reversible token, same shape as a real SSN, round-trips to the original) | no | no |
| `ask_llm` | llm | `"ssn": "[PII]"` | **yes** | **yes** |
| `rag_retrieve` | rag | `[PII]` (embeddings are invertible, so RAG is treated as egress too) | no | no |
| `call_external_api` | external | `[PII]` | **yes** | **yes** |
| `write_log` | log | `[PII]` | **yes** | no |

The real SSN and the real AWS key never appear anywhere in ClickHouse, not
even in the spans for tools that legitimately need the data internally.
That's the "context-aware" part: the same field gets a reversible token in
one tool and an irreversible mask two hops later, because the system tracked
*where the data was actually headed*, not just what field it came from.

## Quickstart

```bash
docker compose up --build
```

This starts the AgentWard collector, a demo HR agent that leaks an SSN and an
AWS key, and a Jaeger trace viewer. Open http://localhost:16686, pick the
service `agentward-hr-bot`, and you will see `ask_llm`, `call_external_api`
and `write_log` flagged as violations, with no raw SSN or key anywhere. Full
walkthrough, and how to send traces to SigNoz instead: [`docs/quickstart.md`](docs/quickstart.md).

## Use it in your agent

```bash
pip install "agentward[langchain]"      # or [openai-agents], [mcp], [llm]
python -m spacy download en_core_web_sm
```

**LangChain / LangGraph / OpenAI Agents SDK.** One `init()` call, then wrap
your tools and model (`aw.wrap_function_tools` for the OpenAI Agents SDK). Tools not in the map are treated as `external`, so a
forgotten tool gets masked data, never raw data.

```python
from sdk import integrations as aw

ward = aw.init("my-agent", destinations={
    "search_db": "internal",
    "send_email": ("external", "us"),
})
tools = aw.wrap_langchain_tools(tools)       # keeps names and schemas
model = aw.protect_langchain_model(model)    # redacts every request to the LLM
with ward.run():
    agent.invoke(...)
```

Plain OpenAI and Anthropic clients: `aw.protect_openai(client)` /
`aw.protect_anthropic(client)`. Details and limits: [`docs/integrations.md`](docs/integrations.md).

**MCP gateway, no code changes.** Put `agentward-gateway --config gateway.yaml`
in your MCP client config in place of the real server. Every tool call is
scanned and, per tool, redacted, blocked or only recorded (audit mode).
See [`docs/mcp-gateway.md`](docs/mcp-gateway.md).

## Status

All six phases are built and verified, each landed as its own stacked PR:

| phase | does | replaces |
|---|---|---|
| 1 | formal DOE model + local SigNoz substrate | (foundation) |
| 2 | runtime taint on OTel (baggage + per-I/O re-detection) | AgentRaft's Φ (LLM-judged propagation) |
| 3 | Rego policy in a sidecar collector | AgentRaft's D_nec 3-LLM committee |
| 4 | reversible, context-aware redaction (FF1 FPE for internal, mask for egress) | static field-name masking |
| 5 | tamper-evident Merkle log + lineage / blast-radius / SLO dashboards | metrics turned into verifiable Art. 30/15 records |
| 6 | AST-grounded fix-suggester + DLP dry-run | (AgentRaft has no recovery step) |

On top of that, v0.2 adds what is needed to use it for real:

- one-command Docker quickstart ([`docs/quickstart.md`](docs/quickstart.md))
- framework adapters for LangChain, LangGraph, the OpenAI Agents SDK and the OpenAI / Anthropic clients ([`docs/integrations.md`](docs/integrations.md))
- an MCP gateway with redact / block / audit modes ([`docs/mcp-gateway.md`](docs/mcp-gateway.md))
- FF1 encryption checked against the NIST sample vectors, and a token vault (in memory, or SQLite encrypted at rest) with per-subject erasure for GDPR ([`docs/redaction-crypto.md`](docs/redaction-crypto.md))
- CI for GitLab and GitHub

Per-phase writeups live in `docs/phase{3,4,5,6}-*.md` and `docs/spike-llm-hop.md`.

## Run it yourself

```bash
# unit tests, no SigNoz needed
python3 -m pytest -q                                   # Python tests
cd collector/processor/taintpolicy && go test ./...   # Go processor tests

# end-to-end against your own SigNoz
cd signoz && foundryctl cast -f casting.yaml                              # start SigNoz
cd collector && ./bin/agentward-collector --config file:./config.yaml &  # sidecar, :4319
python3 demo/hr_bot/breach_simulator.py --endpoint http://localhost:4319/v1/traces
python3 demo/phase5_evidence_demo.py                    # Merkle inclusion + tamper check
agentward-fix fix_suggester/sample_buggy_agent.py       # exits 1 when it finds unguarded sinks
```

Then open `http://localhost:8080`, filter on `agentward.violation=true`, and
you'll see the flagged spans from the run above.

**Keys.** Set `AGENTWARD_FPE_KEY` (hex AES key) for stable tokens. Without it
a random key is made per process and a warning is printed. The public demo
key is only used when `AGENTWARD_ALLOW_DEMO_KEY=1`. The FF1 code has not had
an outside audit yet; see [`docs/redaction-crypto.md`](docs/redaction-crypto.md)
for the limits.

## Layout

```
core/           formal DOE model (pure, the mathematical anchor)
sdk/            Python: detect / taint / redact / vault / instrumentation
sdk/integrations/  LangChain, LangGraph, OpenAI Agents, LLM client adapters
gateway/        MCP gateway (redact / block / audit per tool)
collector/      Go: custom OTel processor + Rego policy             (Phase 3+)
demo/hr_bot/    the instrumented demo bot + breach simulator
dashboards/     SigNoz JSON: lineage / blast-radius / SLO / alerts
fix_suggester/  AST-walk patch proposer                             (Phase 6)
evidence/       tamper-evident Merkle log (Art. 30 evidence)        (Phase 5)
tests/          unit + e2e
```

## References

- AgentRaft: Automated Detection of Data Over-Exposure in LLM Agents, Lin et al.,
  arXiv:2603.07557, March 2026.
- OpenTelemetry GenAI semantic conventions (`gen_ai.*`).
- SigNoz, OTel-native observability.
