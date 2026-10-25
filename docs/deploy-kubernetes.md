# Deploy on Kubernetes

This guide installs AgentWard on a Kubernetes cluster with the Helm chart in
`deploy/helm/agentward`. You get:

* the **policy collector**: an OTLP endpoint for your agents. It runs the
  Rego policy on every span, marks violations, removes raw PII and secrets,
  and sends the result to your trace backend (SigNoz, Jaeger, Tempo, or any
  OTLP backend). It has an HPA, a PodDisruptionBudget and health probes.
* optionally the **routing tier**: a small collector in front of the policy
  tier that sends all spans of one trace to the same policy pod.
* optionally the **MCP gateway**: the AgentWard gateway over HTTP, with an
  HPA and a shared Redis for sessions.

How to size it is in [scaling.md](scaling.md).

## What you need

* A Kubernetes cluster (1.27 or newer) and `kubectl` pointed at it.
* Helm 3.
* The images. There is no public registry image yet, so build them and push
  them to your own registry (or load them into a local cluster):

```bash
docker build -f collector/Dockerfile -t <registry>/agentward-collector:0.2.0 .
docker build -f gateway/Dockerfile   -t <registry>/agentward-gateway:0.2.0 .
docker push <registry>/agentward-collector:0.2.0
docker push <registry>/agentward-gateway:0.2.0
```

* `metrics-server` in the cluster if you want the HPAs to scale (most
  managed clusters have it).

## 1. Install the collector

Pick where checked spans should go. For a SigNoz installed with its own
Helm chart in the `platform` namespace, the default works as is. Otherwise
set `exporter.endpoint`:

```bash
kubectl create namespace agentward

helm install agentward deploy/helm/agentward -n agentward \
  --set collector.image.repository=<registry>/agentward-collector \
  --set exporter.endpoint=my-backend.observability.svc:4317
```

Backend options:

| backend | settings |
|---|---|
| SigNoz in the cluster | `exporter.endpoint=signoz-otel-collector.platform.svc.cluster.local:4317` (the default) |
| SigNoz Cloud | see `examples/values-signoz.yaml` (TLS plus an ingestion key from a Secret) |
| Jaeger | `exporter.endpoint=jaeger-collector.<ns>.svc:4317` |
| any OTLP/HTTP backend | `exporter.protocol=http`, `exporter.endpoint=http://host:4318` |

Check it:

```bash
kubectl -n agentward get pods,svc,hpa,pdb
```

You should see two `agentward-collector` pods, a Service with ports 4319
(OTLP/HTTP) and 4317 (OTLP/gRPC), an HPA and a PDB.

## 2. Point your agents at it

Inside the cluster:

```
OTLP/HTTP  http://agentward-collector.agentward.svc.cluster.local:4319/v1/traces
OTLP/gRPC  agentward-collector.agentward.svc.cluster.local:4317
```

With the SDK that is `configure_tracing("my-agent", endpoint="http://agentward-collector.agentward.svc.cluster.local:4319/v1/traces")`.

## 3. Change the policy

The Rego policy is in a ConfigMap. To use your own file:

```bash
helm upgrade agentward deploy/helm/agentward -n agentward --reuse-values \
  --set-file collector.policy.rego=my-policy.rego
```

The pods restart on their own, because the Deployment carries a checksum of
the config and the policy. Empty `collector.policy.rego` means the policy
that ships with the chart (`files/pii_egress.rego`, a copy of
`collector/policy/pii_egress.rego`; CI checks the two are the same).

## 4. Optional: write spans to a file too

```bash
--set collector.fileExport.enabled=true \
--set collector.fileExport.existingClaim=agentward-spans   # a PVC you made, or leave out for emptyDir
```

Each pod writes OTLP JSON lines to `/var/lib/agentward/spans.jsonl` (rotated
at 100 MB, 5 old files kept).

## 5. Optional: the routing tier

Turn it on when the policy tier has several pods and you want every span of
one agent run to land on the same policy pod (one place for a trace, and
room for per trace logic later):

```bash
--set routingTier.enabled=true
```

Then point agents at `agentward-routing` instead of `agentward-collector`.
It uses the `load_balancing` exporter with `routing_key: traceID` and finds
the policy pods through the headless Service `agentward-collector-headless`.
Set `routingTier.kind=DaemonSet` for one routing pod per node; agents then
reach the pod on their own node.

The same layout outside Kubernetes is in `collector/config.gateway-tier.yaml`.

## 6. Optional: the MCP gateway

The gateway needs keys. Create a Secret yourself (the chart never stores
keys in values):

```bash
kubectl -n agentward create secret generic agentward-keys \
  --from-literal=AGENTWARD_FPE_KEY=$(openssl rand -hex 32) \
  --from-literal=AGENTWARD_VAULT_KEY=$(openssl rand -hex 32) \
  --from-literal=AGENTWARD_GATEWAY_TOKEN=$(openssl rand -hex 16)
```

Then:

```bash
helm upgrade agentward deploy/helm/agentward -n agentward --reuse-values \
  --set gateway.enabled=true \
  --set gateway.image.repository=<registry>/agentward-gateway \
  --set gateway.existingSecret=agentward-keys \
  --set gateway.sessionStore.redisUrl=redis://my-redis:6379/0
```

* The gateway listens on port 8811. MCP clients use
  `http://agentward-gateway.agentward.svc:8811/mcp` with
  `Authorization: Bearer <AGENTWARD_GATEWAY_TOKEN>`.
* `/healthz` is used for the probes (no token needed).
* With `sessionStore.redisUrl` every replica shares the session taint, so
  the Service can spread requests freely. Without it, keep one replica or
  set `gateway.service.sessionAffinity=ClientIP`.
* If the Redis URL has a password, put the URL in the Secret and set
  `gateway.sessionStore.redisUrlSecretKey` to its key name instead.
* For reversible tokens shared by all replicas, set `gateway.vault.url`
  (`redis://...` or `postgresql://...`) and put `AGENTWARD_VAULT_KEY` in the
  Secret.
* The upstream MCP servers and tool rules come from `gateway.config` in the
  values (same format as `gateway/example-config.yaml`, see
  [mcp-gateway.md](mcp-gateway.md)).

## Try it on a laptop with kind

This is the setup used to test the chart:

```bash
kind create cluster --name agentward-test
docker compose build                                  # agentward-collector:local, agentward-demo:local
docker build -f gateway/Dockerfile -t agentward-gateway:local .
kind load docker-image agentward-collector:local agentward-demo:local agentward-gateway:local \
  jaegertracing/jaeger:2.21.0 --name agentward-test

kubectl create namespace agentward
kubectl -n agentward apply -f deploy/helm/agentward/examples/jaeger.yaml
helm install agentward deploy/helm/agentward -n agentward \
  -f deploy/helm/agentward/examples/values-jaeger.yaml

# send the breach demo (fake SSN and AWS key)
kubectl -n agentward apply -f deploy/helm/agentward/examples/demo-job.yaml
kubectl -n agentward logs job/agentward-demo

# look at it in Jaeger (26686, so it does not clash with a local Jaeger on 16686)
kubectl -n agentward port-forward svc/jaeger 26686:16686
```

Open http://localhost:26686, pick `agentward-hr-bot`. `ask_llm`,
`call_external_api` and `write_log` have `agentward.policy.violation=true`
and the raw SSN and key appear nowhere.

To add the gateway, follow the comments at the top of
`examples/values-gateway-kind.yaml` (Secret, Redis, then `helm upgrade`).

Delete the cluster when done: `kind delete cluster --name agentward-test`.

## Uninstall

```bash
helm uninstall agentward -n agentward
kubectl delete namespace agentward
```

## Main values

| value | default | what it does |
|---|---|---|
| `exporter.protocol` | `grpc` | `grpc` or `http` |
| `exporter.endpoint` | SigNoz in `platform` | where checked spans go |
| `exporter.insecure` | `true` | plain text inside the cluster |
| `collector.autoscaling.*` | 2 to 10 pods at 70% CPU | HPA |
| `collector.resources` | 500m / 256Mi request, 2 CPU / 512Mi limit | per pod |
| `collector.memoryLimiter.*` | 80% / 20% | refuse data before the pod runs out of memory |
| `collector.policy.rego` | empty (shipped policy) | your Rego policy |
| `collector.fileExport.enabled` | `false` | also write OTLP JSON lines |
| `collector.configOverride` | empty | your own full collector config |
| `routingTier.enabled` | `false` | traceID routing tier |
| `gateway.enabled` | `false` | MCP gateway |
| `gateway.existingSecret` | empty, required with the gateway | keys |
| `gateway.sessionStore.redisUrl` | empty | shared sessions |
| `gateway.config` | HR example | gateway.yaml content |
