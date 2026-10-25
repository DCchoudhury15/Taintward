# Helm chart check on kind

2026-10-24 and 2026-10-25, kind v0.20.0 (Kubernetes 1.27.3), Helm 3.20,
metrics-server v0.7.2, images built from this tree and loaded with
`kind load docker-image`. Backend: `examples/jaeger.yaml`.

## Collector

* `helm install` with `examples/values-jaeger.yaml`: 2 collector pods ready,
  Service (4319, 4317), headless Service, HPA, PDB.
* Breach demo (`examples/demo-job.yaml`), checked through the Jaeger API:

```
raw SSN/AWS key hits: 0
ask_llm              dest=llm       violation=True  reasons=transfer,pii_egress
call_external_api    dest=external  violation=True  reasons=transfer,pii_egress
internal_store       dest=internal  violation=False reasons=
query_db             dest=internal  violation=False reasons=
rag_retrieve         dest=rag       violation=False reasons=
write_log            dest=log       violation=True  reasons=pii_egress
```

* Policy change with `--set-file collector.policy.rego=...`: the
  `checksum/config` annotation changed and the pods rolled.
* Routing tier on: the demo sent to `taintward-routing` gave the same table.
  It was run again while the policy pods were rolling: same table, and no
  "Dropping data" in the routing pods' logs.
* HPA: telemetrygen in the cluster (4 workers at 1000 spans/s each) pushed
  CPU to 346% of the request and the HPA went from 2 to 4 pods:

```
Normal  SuccessfulRescale  horizontal-pod-autoscaler  New size: 4; reason: cpu resource utilization (percentage of request) above target
```

## Gateway

With `examples/values-gateway-kind.yaml` (2 replicas, Redis sessions, keys
from a Secret):

* `/healthz` returns 200 without a token; `POST /mcp` without the token
  returns 401.
* A session opened on pod A was used on pod B (shared Redis):

```
session opened on pod A: 200
get_employee on A: 200 raw SSN in result: False raw AWS key: False
send_email on pod B with the same session: 200 blocked by session taint: -32001
unknown session on B: 404
```

* Gateway spans in Jaeger: `send_email` has
  `taintward.policy.violation=true` (`transfer,pii_egress`), no raw SSN or key.
* HPA and PDB exist for the gateway (2 to 3 pods).

## Problem found and fixed in deploy/gateway.Dockerfile

The first gateway image let the raw SSN and key through. A fresh
`pip install` picks preshed 3.0.14, with which spaCy 3.8.16 fails to load its
model (`OverflowError: Python int too large to convert to C ssize_t`).
`taintward/sdk/detect.py` catches that error and returns no findings, so nothing was
masked, and because the spans were not marked sensitive the collector did
not redact them either. The gateway image now pins `preshed<3.0.14` and the
build fails if detection does not find an SSN and an AWS key. Any other
image or virtualenv installed fresh from pyproject.toml (the demo image, CI)
can hit the same problem.
