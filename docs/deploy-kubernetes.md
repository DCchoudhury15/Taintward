# Deploy on Kubernetes

This guide installs Taintward on a Kubernetes cluster with the Helm chart in
`deploy/helm/taintward`. You get:

* the **policy collector**: an OTLP endpoint for your agents. It runs the
  Rego policy on every span, marks violations, removes raw PII and secrets,
  and sends the result to your trace backend (SigNoz, Jaeger, Tempo, or any
  OTLP backend). It has an HPA, a PodDisruptionBudget and health probes.
* optionally the **routing tier**: a small collector in front of the policy
  tier that sends all spans of one trace to the same policy pod.
* optionally the **MCP gateway**: the Taintward gateway over HTTP, with an
  HPA and a shared Redis for sessions.

How to size it is in [scaling.md](scaling.md).

## What you need

* A Kubernetes cluster (1.27 or newer) and `kubectl` pointed at it.
* Helm 3.
* Nothing to build. Each release publishes signed images to
  `registry.gitlab.com/divyanshuchoudhury51/taintward/collector` and
  `/gateway`, and the chart to
  `oci://registry.gitlab.com/divyanshuchoudhury51/taintward/charts/taintward`
  (how to check the signatures: [releasing.md](releasing.md)). The chart
  uses those images, tagged with its appVersion, by default.

* `metrics-server` in the cluster if you want the HPAs to scale (most
  managed clusters have it).

## 1. Install the collector

Pick where checked spans should go. For a SigNoz installed with its own
Helm chart in the `platform` namespace, the default works as is. Otherwise
set `exporter.endpoint`:

```bash
kubectl create namespace taintward

helm install taintward oci://registry.gitlab.com/divyanshuchoudhury51/taintward/charts/taintward \
  --version 0.2.0 -n taintward \
  --set exporter.endpoint=my-backend.observability.svc:4317
```

To use your own copy of the images (an air gapped cluster, for example),
set `collector.image.repository` and `gateway.image.repository`. To install
from a clone of the repo instead, use `deploy/helm/taintward` in place of
the `oci://` URL.

Backend options:

| backend | settings |
|---|---|
| SigNoz in the cluster | `exporter.endpoint=signoz-otel-collector.platform.svc.cluster.local:4317` (the default) |
| SigNoz Cloud | see `examples/values-signoz.yaml` (TLS plus an ingestion key from a Secret) |
| Jaeger | `exporter.endpoint=jaeger-collector.<ns>.svc:4317` |
| any OTLP/HTTP backend | `exporter.protocol=http`, `exporter.endpoint=http://host:4318` |

Check it:

```bash
kubectl -n taintward get pods,svc,hpa,pdb
```

You should see two `taintward-collector` pods, a Service with ports 4319
(OTLP/HTTP) and 4317 (OTLP/gRPC), an HPA and a PDB.

## 2. Point your agents at it

Inside the cluster:

```
OTLP/HTTP  http://taintward-collector.taintward.svc.cluster.local:4319/v1/traces
OTLP/gRPC  taintward-collector.taintward.svc.cluster.local:4317
```

With the SDK that is `configure_tracing("my-agent", endpoint="http://taintward-collector.taintward.svc.cluster.local:4319/v1/traces")`.

## 3. Change the policy

The Rego policy is in a ConfigMap. To use your own file:

```bash
helm upgrade taintward oci://registry.gitlab.com/divyanshuchoudhury51/taintward/charts/taintward --version 0.2.0 -n taintward --reuse-values \
  --set-file collector.policy.rego=my-policy.rego
```

The pods restart on their own, because the Deployment carries a checksum of
the config and the policy. Empty `collector.policy.rego` means the policy
that ships with the chart (`files/pii_egress.rego`, a copy of
`collector/policy/pii_egress.rego`; CI checks the two are the same).

## 4. Optional: write spans to a file too

```bash
--set collector.fileExport.enabled=true \
--set collector.fileExport.existingClaim=taintward-spans   # a PVC you made, or leave out for emptyDir
```

Each pod writes OTLP JSON lines to `/var/lib/taintward/spans.jsonl` (rotated
at 100 MB, 5 old files kept).

## 5. Optional: the routing tier

Turn it on when the policy tier has several pods and you want every span of
one agent run to land on the same policy pod (one place for a trace, and
room for per trace logic later):

```bash
--set routingTier.enabled=true
```

Then point agents at `taintward-routing` instead of `taintward-collector`.
It uses the `load_balancing` exporter with `routing_key: traceID` and finds
the policy pods through the headless Service `taintward-collector-headless`.
Set `routingTier.kind=DaemonSet` for one routing pod per node; agents then
reach the pod on their own node.

The same layout outside Kubernetes is in `collector/config.gateway-tier.yaml`.

## 6. Optional: the MCP gateway

The gateway needs keys. Create a Secret yourself (the chart never stores
keys in values):

```bash
kubectl -n taintward create secret generic taintward-keys \
  --from-literal=TAINTWARD_FPE_KEY=$(openssl rand -hex 32) \
  --from-literal=TAINTWARD_VAULT_KEY=$(openssl rand -hex 32) \
  --from-literal=TAINTWARD_GATEWAY_TOKEN=$(openssl rand -hex 16)
```

Then:

```bash
helm upgrade taintward oci://registry.gitlab.com/divyanshuchoudhury51/taintward/charts/taintward --version 0.2.0 -n taintward --reuse-values \
  --set gateway.enabled=true \
  --set gateway.existingSecret=taintward-keys \
  --set gateway.sessionStore.redisUrl=redis://my-redis:6379/0
```

* The gateway listens on port 8811. MCP clients use
  `http://taintward-gateway.taintward.svc:8811/mcp` with
  `Authorization: Bearer <TAINTWARD_GATEWAY_TOKEN>`.
* `/healthz` is used for the probes (no token needed).
* With `sessionStore.redisUrl` every replica shares the session taint, so
  the Service can spread requests freely. Without it, keep one replica or
  set `gateway.service.sessionAffinity=ClientIP`.
* If the Redis URL has a password, put the URL in the Secret and set
  `gateway.sessionStore.redisUrlSecretKey` to its key name instead.
* For reversible tokens shared by all replicas, set `gateway.vault.url`
  (`redis://...` or `postgresql://...`) and put `TAINTWARD_VAULT_KEY` in the
  Secret.
* The upstream MCP servers and tool rules come from `taintward.gateway.config` in the
  values (same format as `taintward/gateway/example-config.yaml`, see
  [mcp-gateway.md](mcp-gateway.md)).

## Try it on a laptop with kind

This is the setup used to test the chart:

```bash
kind create cluster --name taintward-test
docker compose build                                  # taintward-collector:local, taintward-demo:local
docker build -f deploy/gateway.Dockerfile -t taintward-gateway:local .
kind load docker-image taintward-collector:local taintward-demo:local taintward-gateway:local \
  jaegertracing/jaeger:2.21.0 --name taintward-test

kubectl create namespace taintward
kubectl -n taintward apply -f deploy/helm/taintward/examples/jaeger.yaml
helm install taintward deploy/helm/taintward -n taintward \
  -f deploy/helm/taintward/examples/values-jaeger.yaml

# send the breach demo (fake SSN and AWS key)
kubectl -n taintward apply -f deploy/helm/taintward/examples/demo-job.yaml
kubectl -n taintward logs job/taintward-demo

# look at it in Jaeger (26686, so it does not clash with a local Jaeger on 16686)
kubectl -n taintward port-forward svc/jaeger 26686:16686
```

Open http://localhost:26686, pick `taintward-hr-bot`. `ask_llm`,
`call_external_api` and `write_log` have `taintward.policy.violation=true`
and the raw SSN and key appear nowhere.

To add the gateway, follow the comments at the top of
`examples/values-gateway-kind.yaml` (Secret, Redis, then `helm upgrade`).

Delete the cluster when done: `kind delete cluster --name taintward-test`.

## Uninstall

```bash
helm uninstall taintward -n taintward
kubectl delete namespace taintward
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
| `taintward.gateway.config` | HR example | gateway.yaml content |
