# Quickstart

This runs the whole AgentWard demo with one command. A small HR bot reads an
employee record that holds a fake SSN and a fake AWS key, then sends that data
to an LLM, an external API and a log. The AgentWard collector checks every
span against the Rego policy, marks the leaks as violations and removes the
raw values before the spans are stored.

You need Docker with the Compose plugin. Nothing else.

## Run it

From the repo root:

```bash
docker compose up --build
```

The first build takes about 4 minutes (the collector is compiled from source
and the demo installs Presidio and spaCy). After that, `docker compose up`
starts in a few seconds.

What starts:

| service | what it does | host port |
|---|---|---|
| `jaeger` | trace viewer | 16686 (UI) |
| `agentward-collector` | OTLP receiver + `taint_policy` processor | 14319 (OTLP/HTTP) |
| `demo` | runs the breach simulator once, then exits | none |

The demo prints `external API ack: ...` and exits with code 0. That is
expected. The collector and Jaeger keep running.

## What you should see

Open http://localhost:16686, pick the service `agentward-hr-bot` and click
**Find Traces**. Open the `hr_bot.run` trace. It has these spans:

| span | destination | `agentward.policy.violation` |
|---|---|---|
| `query_db` | internal | false |
| `internal_store` | internal | false |
| `ask_llm` | llm | **true** (pii_egress + transfer) |
| `rag_retrieve` | rag | false |
| `call_external_api` | external | **true** (pii_egress + transfer) |
| `write_log` | log | **true** (pii_egress) |

To list only the leaks, put `agentward.policy.violation=true` in the **Tags**
box and search again. You get the three spans above.

Click any span and look at `gen_ai.tool.call.arguments` and
`gen_ai.tool.call.result`:

- On the egress spans (`ask_llm`, `call_external_api`, `write_log`) the SSN
  shows as `[PII]` and the AWS key as `[SECRET]`.
- On `internal_store` the SSN shows as a token like `103-48-0677`. It has the
  same shape as an SSN and can be turned back into the real value by the
  key holder, but it is not the real value.
- The real SSN `234-12-1234` and the real key `AKIAIOSFODNN7EXAMPLE` appear
  nowhere.

You can check that last point from the command line too:

```bash
curl -s -G http://localhost:16686/api/v3/traces \
  --data-urlencode query.service_name=agentward-hr-bot \
  --data-urlencode query.start_time_min=$(date -u -d '-1 hour' +%FT%TZ) \
  --data-urlencode query.start_time_max=$(date -u -d '+1 min' +%FT%TZ) \
  | grep -c -E '234-12-1234|AKIAIOSFODNN7EXAMPLE'
```

It prints `0`.

## Run the demo again

```bash
docker compose run --rm demo
```

Each run adds one new trace.

## Change the policy

The policy file `collector/policy/pii_egress.rego` is mounted into the
collector. Edit it, then:

```bash
docker compose restart agentward-collector
```

No rebuild needed.

## Send your own agent's spans

Point your OTLP/HTTP exporter at `http://localhost:14319/v1/traces`. The
collector runs the same policy on your spans.

## Use SigNoz (or any OTLP backend) instead of Jaeger

The collector sends spans to whatever `OTLP_EXPORT_ENDPOINT` says, as an
OTLP gRPC `host:port`. The default is `jaeger:4317`.

If SigNoz runs on the same machine and listens on port 4317:

```bash
OTLP_EXPORT_ENDPOINT=host.docker.internal:4317 \
  docker compose up --build --no-deps agentward-collector demo
```

`--no-deps` skips Jaeger. Then open SigNoz, go to Traces and filter on
`service.name = agentward-hr-bot` and `agentward.policy.violation = true`.

For a remote SigNoz, use its address, for example
`OTLP_EXPORT_ENDPOINT=signoz.example.com:4317`. The exporter uses plain gRPC
without TLS. If your backend needs TLS, edit `collector/config.docker.yaml`.

## Stop

```bash
docker compose down
```

## Ports

The quickstart does not use host ports 4317, 4318 or 8080, so it can run next
to a local SigNoz.
