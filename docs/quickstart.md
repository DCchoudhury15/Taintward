# Quickstart

Two parts, about 5 minutes each:

1. [Run the demo with Docker](#part-1-the-docker-demo): see the collector
   flag and redact a leak, with nothing installed but Docker.
2. [Protect your own agent](#part-2-protect-your-own-agent): `pip install`
   and about 10 lines of code for a LangGraph agent or an OpenAI client.

All data in the demo is fake.

## Part 1: the Docker demo

A small HR bot reads an employee record that holds a fake SSN and a fake
AWS key, then sends that data to an LLM, an external API and a log. The
Taintward collector checks every span against the Rego policy, marks the
leaks as violations and removes the raw values before the spans are stored.

You need Docker with the Compose plugin. Nothing else.

### Run it

From the repo root:

```bash
git clone https://github.com/DCchoudhury15/Taintward.git
cd Taintward
docker compose up --build
```

The first build takes about 4 minutes (the collector is compiled from source
and the demo installs Presidio and spaCy). After that, `docker compose up`
starts in a few seconds.

What starts:

| service | what it does | host port |
|---|---|---|
| `jaeger` | trace viewer | 16686 (UI) |
| `taintward-collector` | OTLP receiver + `taint_policy` processor | 14319 (OTLP/HTTP) |
| `demo` | runs the breach simulator once, then exits | none |

Both host ports are published on `127.0.0.1` only: the collector receiver
has no auth, and the UI shows span data.

The demo prints `external API ack: ...` and exits with code 0. That is
expected. The collector and Jaeger keep running.

### What you should see

Open <http://localhost:16686>, pick the service `taintward-hr-bot` and click
**Find Traces**. Open the `hr_bot.run` trace. It has these spans:

| span | destination | `taintward.policy.violation` |
|---|---|---|
| `query_db` | internal | false |
| `internal_store` | internal | false |
| `ask_llm` | llm | **true** (pii_egress + transfer) |
| `rag_retrieve` | rag | false |
| `call_external_api` | external | **true** (pii_egress + transfer) |
| `write_log` | log | **true** (pii_egress) |

To list only the leaks, put `taintward.policy.violation=true` in the **Tags**
box and search again. You get the three spans above.

Click any span and look at `gen_ai.tool.call.arguments` and
`gen_ai.tool.call.result`:

- On the egress spans (`ask_llm`, `call_external_api`, `write_log`) the SSN
  shows as `[PII]` and the AWS key as `[SECRET]`.
- On `internal_store` the SSN shows as a token like `103-48-0677`. It has the
  same shape as an SSN and can be turned back into the real value by the
  key holder, but it is not the real value.
- The fake SSN `234-12-1234` and the fake key `AKIAIOSFODNN7EXAMPLE` appear
  nowhere.

You can check that last point from the command line too:

```bash
curl -s -G http://localhost:16686/api/v3/traces \
  --data-urlencode query.service_name=taintward-hr-bot \
  --data-urlencode query.start_time_min=$(date -u -d '-1 hour' +%FT%TZ) \
  --data-urlencode query.start_time_max=$(date -u -d '+1 min' +%FT%TZ) \
  | grep -c -E '234-12-1234|AKIAIOSFODNN7EXAMPLE'
```

It prints `0`.

### Run the demo again

```bash
docker compose run --rm demo
```

Each run adds one new trace.

### Change the policy

The policy file `collector/policy/pii_egress.rego` is mounted into the
collector. Edit it, then:

```bash
docker compose restart taintward-collector
```

No rebuild needed. What the policy says is explained in
[Policy](concepts/policy.md).

### Send your own agent's spans

Point your OTLP/HTTP exporter at `http://localhost:14319/v1/traces`. The
collector runs the same policy on your spans. Part 2 below does exactly
that.

### Use SigNoz (or any OTLP backend) instead of Jaeger

The collector sends spans to whatever `OTLP_EXPORT_ENDPOINT` says, as an
OTLP gRPC `host:port`. The default is `jaeger:4317`.

If SigNoz runs on the same machine and listens on port 4317:

```bash
OTLP_EXPORT_ENDPOINT=host.docker.internal:4317 \
  docker compose up --build --no-deps taintward-collector demo
```

`--no-deps` skips Jaeger. Then open SigNoz, go to Traces and filter on
`service.name = taintward-hr-bot` and `taintward.policy.violation = true`.

For a remote SigNoz, use its address, for example
`OTLP_EXPORT_ENDPOINT=signoz.example.com:4317`. The exporter uses plain gRPC
without TLS. If your backend needs TLS, edit `collector/config.docker.yaml`.
More backends (Grafana Tempo, Jaeger, SigNoz Cloud) are in
[Send traces to SigNoz, Tempo or Jaeger](recipes/trace-backends.md).

### Also write spans to a file

The collector can also write every checked span as OTLP JSON, one object
per line:

```bash
TAINTWARD_TRACE_EXPORTERS='[otlp_grpc/backend, file]' docker compose up
```

The file is `/var/lib/taintward/spans.jsonl` in the `taintward-spans`
volume. To copy it out:

```bash
docker compose cp taintward-collector:/var/lib/taintward/spans.jsonl .
```

This file is one of the inputs of the [compliance report](evidence-report.md).

### Ports

The quickstart does not use host ports 4317, 4318 or 8080, so it can run next
to a local SigNoz.

## Part 2: protect your own agent

Keep the Docker stack from part 1 running: your agent will send its spans to
the same collector and you will see them in the same Jaeger.

### Install

Python 3.11 or newer.

```bash
python -m venv .venv && . .venv/bin/activate
pip install "taintward[langchain]"      # or [openai-agents], [llm], [mcp]
python -m spacy download en_core_web_sm
```

The spaCy model is needed for name detection. Without it Taintward still
runs, logs one ERROR and falls back to regex-only detection (see
[Detection health](integrations.md#detection-health)).

Set a key so reversible tokens are stable across restarts (any 64 hex
characters; this one is for the quickstart only):

```bash
export TAINTWARD_FPE_KEY=$(python -c "import os; print(os.urandom(32).hex())")
```

### LangGraph or LangChain

```python
import taintward as tw
from langchain.agents import create_agent        # or langgraph.prebuilt.create_react_agent
from langchain_openai import ChatOpenAI          # pip install langchain-openai

tw.init("support-bot", endpoint="http://localhost:14319/v1/traces",
        destinations={"lookup_customer": "internal",
                      "send_email": {"destination": "external", "allow": ["to"]}})
tools = tw.wrap_langchain_tools([lookup_customer, send_email])   # your @tool functions
model = tw.protect_langchain_model(ChatOpenAI(model="gpt-4.1-mini"))
agent = create_agent(model, tools)
with tw.run("support-bot.run"):
    agent.invoke({"messages": [("user", "Email Alice Lee about her refund")]})
```

What happens:

- the model sees `<PERSON_1>` instead of `Alice Lee`, and the reply your code
  gets has the real name again;
- `lookup_customer` is `internal`, so it gets reversible tokens;
- `send_email` is `external`, so its body gets `[PII]` masks, but the `to`
  argument is on its `allow` list and reaches the tool as is;
- any tool you forgot to list is treated as `external`.

No API key at hand? The repo has an offline version of this agent with a
scripted model:

```bash
python demo/langgraph_example.py --console --endpoint http://localhost:14319/v1/traces
```

### Plain OpenAI (or Anthropic) client

```python
import taintward as tw
from openai import OpenAI

tw.init("support-bot", endpoint="http://localhost:14319/v1/traces")
client = tw.protect_openai(OpenAI())           # or tw.protect_anthropic(Anthropic())
messages = [{"role": "user", "content": "Summarize: Alice Lee, SSN 234-12-1234, wants a refund."}]
with tw.run("summarize"):
    reply = client.chat.completions.create(model="gpt-4.1-mini", messages=messages)
print(reply.choices[0].message.content)        # real values restored
```

The request that reaches OpenAI says `<PERSON_1>, SSN <SSN_1>`.

### See it

In Jaeger, pick the service `support-bot`. The `chat` span holds the
redacted request in `gen_ai.input.messages`, and spans that sent sensitive
data to an `llm`, `external` or `log` destination have
`taintward.violation=true` (set by the SDK) and
`taintward.policy.violation=true` (set by the collector).

## Next steps

- [Concepts](concepts/destinations.md): destinations, taint, placeholders,
  policy and evidence in a few pages.
- [Audit mode first, then enforce](recipes/audit-then-enforce.md): how to
  roll this out on a real agent without breaking it.
- [Kubernetes and Helm](deploy-kubernetes.md) and [Scaling](scaling.md).

## Stop

```bash
docker compose down
```
