# Control plane and tenants

The control plane is one service that holds, for many tenants (teams or
customers):

- the **tool policy**: the destination map the SDK uses, with every version
  kept. Apps pull it, so a policy change does not need a redeploy;
- the **spans** apps upload, with raw values masked before anything is
  stored;
- each tenant's **evidence log** (violations, Merkle proofs), **report**
  (with the [compliance mappings](compliance.md)) and
  [**offline audit**](audit.md).

The tenant always comes from the API token, never from the data a client
sends. Each tenant's data is in its own directory, so no request path can
reach another tenant's files.

It runs as `taintward-control` (standard library HTTP server, no extra
dependency except PyYAML for a YAML config). Run it yourself, or host it
for others.

## Run it

```bash
pip install "taintward[control]"

taintward-control new-token      # once per token you need
# token:  twc_3q...   give this to the app or person
# sha256: 5e1c...     put only this in the config
```

`control.yaml`:

```yaml
data_dir: /var/lib/taintward-control
max_body_bytes: 8388608           # largest upload, also after decompression
tenants:
  acme:
    home: [eu]                    # sinks elsewhere are marked cross-border in audits
    tokens:
      - {name: support-bot, role: agent, sha256: 5e1c...}
      - {name: dpo, role: reader, sha256: 9a40...}
      - {name: platform, role: admin, sha256: c71f...}
  globex:
    tokens:
      - {name: ops, role: admin, sha256: 0b8d...}
```

```bash
taintward-control check --config control.yaml
taintward-control serve --config control.yaml --listen 0.0.0.0:8820 \
    --tls-cert tls.crt --tls-key tls.key
```

The config file is read again when it changes, so adding a tenant or
revoking a token needs no restart. A broken edit is logged and the last good
config stays in use. Without `--tls-cert`, put the service behind a TLS
proxy or ingress: tokens and policies must not cross a network in clear
text.

### Roles

| role | can |
|---|---|
| `agent` | read the policy, upload spans. What an app needs |
| `reader` | read the policy and its history, reports, evidence and proofs; run audits. For a data protection officer or auditor |
| `admin` | all of the above, and change the policy |

### On Kubernetes

The Helm chart runs it as one pod with a persistent volume:

```yaml
controlPlane:
  enabled: true
  tlsSecret: control-tls          # or TLS at the Ingress
  tenants:
    acme:
      home: [eu]
      tokens:
        - {name: support-bot, role: agent, sha256: 5e1c...}
```

The tenants and token hashes become a Secret (`control.yaml`); or point
`controlPlane.existingSecret` at your own Secret with that key. See
[Kubernetes and Helm](deploy-kubernetes.md).

## Connect an app

```bash
export TAINTWARD_CONTROL_URL=https://control.example.com
export TAINTWARD_CONTROL_TOKEN=twc_3q...           # an agent token
export TAINTWARD_CONTROL_CACHE=/var/cache/app/taintward-policy.json
export TAINTWARD_CONTROL_REFRESH_SECONDS=60
```

```python
import taintward as tw

ward = tw.init("support-bot")   # no destinations: they come from the control plane
```

With `TAINTWARD_CONTROL_URL` set, `tw.init()`:

- reads the tenant's policy (tool map, default destination and
  jurisdictions) and builds the `Ward` from it;
- checks for a new version every `TAINTWARD_CONTROL_REFRESH_SECONDS` (an
  unchanged policy costs one `304` response);
- sends spans to `<url>/v1/traces` with the token. Pass `endpoint=` to send
  them to your own collector instead.

If the control plane cannot be reached at start, the last policy in
`TAINTWARD_CONTROL_CACHE` is used. With no cache either, the app starts with
an empty map: every tool is `external` and everything is redacted. A missing
policy never sends data raw. A wrong token is an error, not an empty policy.

`taintward.sdk.control.ward_from_control()` does the same for code that
builds its own `Ward`.

## API

Every request except `GET /healthz` needs `Authorization: Bearer <token>`.

| method and path | role | does |
|---|---|---|
| `GET /v1/policy` | agent, reader, admin | the current policy, with `ETag`; `If-None-Match` gives `304` when unchanged. Version 0 (empty map) before the first write |
| `PUT /v1/policy` | admin | store a new version. `If-Match: "<etag>"` gives `412` when someone else wrote a newer one. The same policy again is not a new version |
| `GET /v1/policy/history` | agent, reader, admin | versions, newest first: number, ETag, time, token name, tool count |
| `POST /v1/traces` | agent, admin | OTLP/HTTP spans, JSON or protobuf, optionally gzip. What the OpenTelemetry exporters send |
| `GET /v1/report` | reader, admin | the [report](evidence-report.md): `?since=7d` or `?start=...&end=...`, `&format=html\|json`, `&frameworks=gdpr,eu-ai-act,hipaa,soc2` or `all` |
| `POST /v1/audit` | reader, admin | the [audit](audit.md) against the current policy and the uploaded spans: `{"tools": <MCP tools/list>, "max_hops": 3, "since": "30d"}`; `?format=md` for Markdown |
| `GET /v1/evidence` | reader, admin | the tenant's evidence log shard heads |
| `GET /v1/evidence/proof?trace_id=&span_id=` | reader, admin | the evidence record of one violation and its Merkle inclusion proof, which can be checked offline |

A policy document is the SDK destination map with its defaults:

```json
{
  "destinations": {
    "lookup_customer": "internal",
    "send_email": ["external", "us"],
    "post_message": {"destination": "external", "allow": ["channel"]}
  },
  "default_destination": "external",
  "default_jurisdiction": "",
  "llm_jurisdiction": "us"
}
```

```bash
curl -X PUT https://control.example.com/v1/policy \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  --data @policy.json
```

An unknown key, destination or a malformed jurisdiction is refused with
`400` and changes nothing.

## What happens to an upload

1. The token gives the tenant. The `taintward.tenant` resource attribute is
   set to it; any tenant the client sent is dropped.
2. Every string attribute (resource, span, events, links) and the status
   message is scanned with the report's raw value patterns (SSN, email,
   phone, card, AWS key, GitHub token, private key). Each hit is replaced by
   `[<TYPE>]`. The span gets `taintward.control.raw_masked` (how many), and
   hits in the call's recorded input go to `taintward.control.raw_input` as
   types and keyed fingerprints, so the tenant's report still counts the
   call as one that sent raw data.
3. The spans are appended to the tenant's span files, and every violation is
   added once to the tenant's evidence log (an exporter retry does not add
   it twice).

The SDK already masks what it records, so step 2 normally finds nothing. It
is a backstop for a misconfigured client. The response headers
`X-Taintward-Spans` and `X-Taintward-Raw-Masked` say what happened, and the
server logs a warning per upload that had raw values.

## Tenants outside the control plane

The tenant also matters where several tenants share infrastructure:

- **Spans.** `tw.init(tenant="acme")` or `TAINTWARD_TENANT=acme` puts
  `taintward.tenant` on the resource and on every span, so a shared SigNoz
  or Jaeger can be filtered by it, and `taintward-report --tenant acme`
  reports on one tenant only.
- **Shared vault.** With `TAINTWARD_TENANT` set, the SQLite, Postgres and
  Redis vaults keep each tenant's rows apart: two tenants writing the same
  token do not overwrite each other, a lookup never returns another
  tenant's row, erasing a subject only touches this tenant's rows, and
  `taintward-keys reseal` only reseals this tenant's rows. Give each tenant
  its own vault key ring as well: the tenant prefix keeps rows apart, but
  only separate keys stop someone with direct database access from reading
  another tenant's rows.
- **Evidence log.** The sharded log already keeps one log per tenant per day
  (`taintward-evidence record --tenant`).
- **Gateway.** Run one gateway per tenant (one Helm release each); the
  per-client tokens of one gateway separate clients, not tenants.

## Data on disk

```text
<data_dir>/tenants/<tenant>/
    policy/000001.json ...    every policy version
    spans/<YYYY-MM-DD>.jsonl  uploaded spans, by day received (OTLP JSON lines)
    evidence/<tenant>/...     the evidence log (sharded Merkle log)
    fingerprint.key           HMAC key for raw value fingerprints (mode 0600)
```

Back up the directory as a whole. To keep spans for a limited time, delete
old files under `spans/`; reports then cover only what is left, while the
evidence log keeps every violation. Signed checkpoints work as for any
sharded log: `taintward-evidence checkpoint --evidence-dir
<data_dir>/tenants/<tenant>/evidence`.

## Limits

- One server process with files on local disk. It is fine for a team or a
  small hosted service; there is no database backend and no replication
  yet, so run one replica with a persistent volume.
- No rate limit per tenant. An agent token can upload as much as
  `max_body_bytes` per request allows.
- Upload masking only knows the regex types above. Names and street
  addresses a misconfigured client sends are stored as sent.
- Whoever holds an admin token decides which tools are `internal`, which
  means unredacted. Treat admin tokens like the code that holds the
  destination map.
- The TypeScript SDK has no control plane client yet; set its map in code
  and send its spans to `<url>/v1/traces` with the token header.

Code: `taintward/control/` (server), `taintward/sdk/control.py` (client).
