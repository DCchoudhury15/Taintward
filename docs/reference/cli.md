# Command line

The package installs four commands. Each one can also be run as a module
(`python -m ...`), which is handy in a virtualenv that is not on `PATH`.

| command | module | does |
|---|---|---|
| `taintward-gateway` | `taintward.gateway` | MCP gateway over stdio or HTTP |
| `taintward-report` | `taintward.evidence.report` | compliance report from spans |
| `taintward-evidence` | `taintward.evidence.log` | tamper-evident evidence log and checkpoints |
| `taintward-fix` | `taintward.fix_suggester.suggest` | finds unguarded egress calls in Python source |

Options below are taken from each command's `--help` output for version
0.2.0, with the defaults from the code.

## taintward-gateway

```text
taintward-gateway --config CONFIG [--listen HOST:PORT]
                  [--shutdown-timeout SECONDS] [--otlp-endpoint URL]
                  [--log-level LEVEL]
```

| option | default | meaning |
|---|---|---|
| `--config CONFIG` | required | path to the gateway YAML config ([reference](../mcp-gateway.md#config-reference)) |
| `--listen HOST:PORT` | stdio | serve streamable HTTP on `HOST:PORT` (for example `0.0.0.0:8811`) instead of stdio |
| `--shutdown-timeout SECONDS` | `25` | HTTP mode: seconds to let in-flight requests finish on SIGTERM |
| `--otlp-endpoint URL` | `$TAINTWARD_OTLP_ENDPOINT` | OTLP/HTTP traces endpoint, for example `http://localhost:4318/v1/traces`; no export when unset |
| `--log-level LEVEL` | `WARNING` | Python log level; logs go to stderr |

Over stdio, stdout carries the MCP protocol. Over HTTP the endpoint is
`POST /mcp`, and `GET /healthz` returns 200. Environment:
`TAINTWARD_GATEWAY_TOKEN`, `TAINTWARD_SESSION_STORE`, `TAINTWARD_FAIL_CLOSED`,
the key and vault variables ([Configuration](configuration.md#mcp-gateway)).

## taintward-report

```text
taintward-report [--source {jaeger,otlp-file,clickhouse}] [--service SERVICE] ...
```

Data source:

| option | default | meaning |
|---|---|---|
| `--source` | `jaeger` | `jaeger`, `otlp-file` or `clickhouse` (SigNoz) |
| `--service SERVICE` | none | service name; repeat for several. With `jaeger` and no `--service`, `taintward-hr-bot` (the demo) is used |
| `--jaeger-url URL` | `http://localhost:16686` | Jaeger query API |
| `--jaeger-search-depth N` | `1000` | maximum traces per Jaeger query; a window that hits it is split in two and fetched again |
| `--otlp-file PATH` | none | OTLP JSON lines file or directory (`*.json`, `*.jsonl`, `*.json.gz`); repeat for several |
| `--clickhouse-url URL` | none: `docker exec` into the container | ClickHouse HTTP URL, for example `http://host:8123` |
| `--clickhouse-container NAME` | `signoz-telemetrystore-clickhouse-0-0` | container used for `clickhouse-client` |
| `--clickhouse-user`, `--clickhouse-password` | none | ClickHouse credentials |

Time window (UTC):

| option | default | meaning |
|---|---|---|
| `--since SINCE` | `24h` | window length ending now, for example `7d`, `30d` |
| `--start START` | none | ISO 8601 start, for example `2026-10-01T00:00:00Z`; overrides `--since` |
| `--end END` | now | ISO 8601 end |

Output:

| option | default | meaning |
|---|---|---|
| `--format {html,json}` | `html` | HTML report or the same data as JSON |
| `--out OUT` | stdout | output file |
| `--title TITLE` | `Sensitive data flow report` | report title |
| `--org ORG` | empty | organization name in the header |
| `--system SYSTEM` | the service names | system name in the header |
| `--deep-scan` | off | also scan sent inputs with the Presidio detectors (needs the spaCy model) |
| `--max-rows N` | `500` | rows in the violation list |

Evidence log:

| option | default | meaning |
|---|---|---|
| `--evidence-dir DIR` | none | sharded evidence log to include |
| `--log-file FILE` | none | single-file evidence log to include |
| `--public-key FILE` | none | verify the evidence log checkpoints with this key |

What the report contains: [Compliance report and evidence log](../evidence-report.md).

## taintward-evidence

```text
taintward-evidence [--log-file LOG_FILE] COMMAND [options]
```

`--log-file` (default `$TAINTWARD_EVIDENCE_LOG`, else `violations.logl`)
selects the single-file log for the commands that use it. Commands that take
`--evidence-dir` work on the sharded log; its default is
`$TAINTWARD_EVIDENCE_DIR`.

### Record and inspect

| command | options | does |
|---|---|---|
| `record` | `--source {clickhouse,jaeger,otlp-file}` (default `clickhouse`), `--service` (repeat), `--since-mins N` (default `10`), `--jaeger-url`, `--jaeger-search-depth`, `--otlp-file`, `--clickhouse-url`, `--clickhouse-container`, `--clickhouse-user`, `--clickhouse-password`, `--evidence-dir`, `--tenant` (default `default`), `--checkpoint`, `--private-key` | copy recent policy violations into the log; without `--evidence-dir` the single-file log is used; duplicates are skipped |
| `count` | | number of records in the single-file log |
| `root` | `--size N` | Merkle root (hex) of the first `N` records, or of all |
| `shards` | `--evidence-dir` (required) | list shards with size and root |
| `repair` | `--evidence-dir` | move a broken last line (left by a crash) to `<file>.corrupt`; without `--evidence-dir` repairs the single-file log |

### Proofs on the single-file log

| command | options | does |
|---|---|---|
| `prove INDEX` | `--size N` | print and verify the inclusion proof for one record |
| `verify PROOF_JSON` | `--root HEX` | verify a proof (the output of `prove`); default root: this log at the proof's tree size |
| `consistency` | `--old-size N` (required), `--old-root HEX` | prove the log still starts with its first `N` records |

### Signed checkpoints on the sharded log

| command | options | does |
|---|---|---|
| `keygen` | `--private-key FILE`, `--public-key FILE` (both required) | create an Ed25519 key pair; the private key is written with mode 0600 and never overwritten |
| `checkpoint` | `--evidence-dir` (required), `--private-key` (or `$TAINTWARD_EVIDENCE_KEY_FILE` / `$TAINTWARD_EVIDENCE_KEY`) | sign a checkpoint over every shard |
| `verify-checkpoints` | `--evidence-dir` (required), `--public-key` (or `$TAINTWARD_EVIDENCE_PUBLIC_KEY_FILE` / `$TAINTWARD_EVIDENCE_PUBLIC_KEY`), `--deep`, `--expect-head HASH` | verify the checkpoint chain and the shards; `--deep` checks against every checkpoint; `--expect-head` fails if that hash is not in the chain |
| `prove-shard` | `--evidence-dir` (required), `--tenant` (default `default`), `--day YYYY-MM-DD` (required), `--index N` (required), `--checkpoint-file` (default: newest) | inclusion proof for one record against a signed checkpoint |
| `verify-proof PROOF_FILE` | `--public-key` | verify a `prove-shard` output with only the public key |

Walkthrough: [The evidence log at scale](../evidence-report.md#the-evidence-log-at-scale).

## taintward-fix

```text
taintward-fix FILE.py [FILE.py ...]
```

Walks the Python AST and reports calls to external sinks (`*.post`,
`*.put`, `*.patch`, `*.delete`, `*.urlopen`) and LLM clients (dotted names
with `openai` or `anthropic` ending in `.create`) that are not inside a
function decorated with `@instrument_tool`, with a one-line fix for each.

Exit codes: `0` nothing found, `1` findings printed, `2` no file given.
There are no options yet; `--help` is not supported.

```bash
taintward-fix taintward/fix_suggester/sample_buggy_agent.py
```
