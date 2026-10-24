# Evidence report

A customer asks: "Do you send our customers' personal data to LLM providers?
Prove it." The evidence report is the document you attach. It is one HTML
file built from the spans AgentWard records, for a time window you choose.
It prints to PDF from any browser.

A sample, made from the quickstart demo (three runs of the HR bot), is in
[`sample-report.html`](sample-report.html).

## Generate it

From Jaeger (the quickstart stack):

```bash
python -m evidence.report --source jaeger --service agentward-hr-bot \
  --since 24h --org "Example Co." --out report.html
```

From OTLP JSON files written by the collector `file` exporter (one JSON
object per line; a directory reads every `*.json`, `*.jsonl` and `*.json.gz`
file in it):

```bash
python -m evidence.report --source otlp-file --otlp-file /var/lib/agentward/traces \
  --start 2026-10-01T00:00:00Z --end 2026-11-01T00:00:00Z --out october.html
```

From SigNoz (ClickHouse). The default runs `clickhouse-client` inside the
SigNoz ClickHouse container; `--clickhouse-url http://host:8123` uses the HTTP
interface instead:

```bash
python -m evidence.report --source clickhouse --service my-agent --since 30d \
  --evidence-dir evidence-log --public-key evidence.pub --out report.html
```

Useful options:

| option | what it does |
|---|---|
| `--since 7d` or `--start` / `--end` | the time window, in UTC |
| `--service NAME` | which service; repeat for several |
| `--format json` | machine readable output with the same numbers |
| `--evidence-dir DIR` / `--log-file FILE` | add the evidence log section |
| `--public-key FILE` | verify the evidence log while making the report |
| `--deep-scan` | also run the Presidio detectors in the raw value check |
| `--org`, `--system`, `--title` | names in the header |

Once the package is installed the same command is `agentward-report`.

**PDF:** open the HTML file in a browser, choose Print, then "Save as PDF".
The page is laid out for A4 and table headers repeat on each page.

## What each section means

1. **Summary.** The main statement and the key numbers. The statement is
   one of four:
   - `0 raw sensitive values were sent to external or LLM destinations in
     this period (N calls checked)`: printed only when every external and
     LLM call has its sent input recorded, no such call ran in audit-only
     mode on sensitive data, the scan found nothing, and the source did not
     cut the data short.
   - `N raw sensitive value(s) were found ...`: the scan found raw values.
     The findings table lists the calls.
   - `It could not be confirmed ...`: something was not measurable. The
     reasons are listed under the statement.
   - `No calls to external or LLM destinations were recorded`.
2. **Calls that touched sensitive data.** Calls marked `agentward.sensitive`,
   counted per class (`pii`, `secret`, ...). A call counts when sensitive
   data was found in its input or output, or when it ran later in a run that
   had already touched sensitive data.
3. **Calls by destination.** Calls per destination class: `internal`,
   `llm`, `external`, `log`, `rag`.
4. **Policy violations.** Calls where the policy says sensitive data must
   not reach that destination as is, and what happened:
   - *Redacted before sending*: the gate changed the input.
   - *Sent with no raw value left to redact*: the gate ran, but the input
     held no raw value, usually because an earlier step had already masked
     it (in the demo, the external API gets the LLM's summary, which was
     made from masked data).
   - *Blocked*: the MCP gateway refused the call.
   - *Audit only*: recorded but sent unchanged (gateway audit mode or SDK
     dry run).
5. **Cross-border transfers (GDPR Art. 44).** Calls per jurisdiction. A
   transfer flag means the policy marks that jurisdiction as not adequate
   for personal data and the call was part of a run that touched personal
   data. It does not by itself mean raw data went there; section 7 says
   whether it did.
6. **Recipients of data (GDPR Art. 30).** Every tool that received data,
   with destination, jurisdiction, classes and violations. This is the
   "recipients" part of a record of processing activities, taken from what
   actually ran.
7. **Raw value check.** See "How the raw value check works" below.
8. **Evidence log.** Whether each violation in the window is in the
   tamper-evident log, the newest signed checkpoint, the shard roots, and
   the commands to verify them.
9. **Method and limits.** What the numbers are based on and what they do
   not cover.
10. **List of violations.** One row per violation, with trace ids so each
    one can be looked up in Jaeger or SigNoz.

The footer has a SHA-256 digest of the report data. The data itself is
embedded in the file as JSON (element `agentward-report-data`), so a script
can read the numbers and check the digest: it is the SHA-256 of the canonical
JSON (sorted keys, no spaces) of that object without its `digest` field.

## How the raw value check works

For every call to an `llm`, `external`, `log` or `rag` destination, the
report reads the input recorded on the span (`gen_ai.tool.call.arguments`,
or `gen_ai.input.messages` for model calls). For SDK calls this is the input
after the redaction gate, so it is what the destination received. The
AgentWard collector does not rewrite this attribute, so it is stored as sent.

The input is scanned for: US SSN, AWS access key, GitHub token, email
address, phone number, card number (Luhn checked) and private key blocks.
These are the collector's redaction patterns plus two more. Masks such as
`[PII]` do not match. Findings show the type and a short SHA-256 fingerprint,
never the value.

Limits you should state to a customer:

- Only calls made through AgentWard are counted. A call that bypasses the
  SDK, adapters or gateway is not recorded.
- The fixed patterns do not match names, addresses or other free text
  personal data. `--deep-scan` adds the Presidio detectors (names,
  locations, and more), which are slower and give more false positives.
- MCP gateway arguments listed in `passthrough_args` are forwarded unchanged
  but stored masked, so the report cannot check them. Review that list.
- Sampling, retention and dropped spans reduce what is counted. The evidence
  log proves recorded violations were not changed later; it does not prove
  every call was recorded.

## The evidence log at scale

### Shards

One file with one writer does not scale. The sharded log stores one Merkle
log file per tenant per UTC day:

```
evidence-log/
  acme/2026-10-24.logl
  acme/2026-10-25.logl
  globex/2026-10-24.logl
  _checkpoints/0000000001.json
  _checkpoints/0000000002.json
```

Each shard is a normal Merkle log file (the same format as before), so
`agentward-evidence --log-file evidence-log/acme/2026-10-24.logl root` still
works on it. Several processes can append at once: each append takes a file
lock on the tenant folder. Recording the same window twice does not add
duplicates (records are matched by trace id and span id).

```bash
agentward-evidence record --source jaeger --service agentward-hr-bot \
  --since-mins 60 --evidence-dir evidence-log --tenant acme
```

`--source` can be `jaeger`, `otlp-file` or `clickhouse`. Without
`--evidence-dir` the old single-file log is used, as before.

### Signed checkpoints

A checkpoint lists every shard with its size and Merkle root, the time, and
the hash of the previous checkpoint, signed with Ed25519. Make a key pair
once:

```bash
agentward-evidence keygen --private-key evidence.key --public-key evidence.pub
```

The private key file is created with mode 0600 and is never overwritten.
Keep it out of the repo. The tools read it from `--private-key`, or from
`AGENTWARD_EVIDENCE_KEY_FILE` (a path), or `AGENTWARD_EVIDENCE_KEY` (PEM text
or a 64 hex character seed). The public key comes from `--public-key`,
`AGENTWARD_EVIDENCE_PUBLIC_KEY_FILE` or `AGENTWARD_EVIDENCE_PUBLIC_KEY`.

Write a checkpoint on demand, after recording, or every N records:

```bash
agentward-evidence checkpoint --evidence-dir evidence-log --private-key evidence.key
agentward-evidence record ... --evidence-dir evidence-log --checkpoint --private-key evidence.key
```

In code: `ShardedLog(dir, signing_key=key, checkpoint_every=1000)`.

A good default is one checkpoint every few minutes from a scheduled job, and
one at the end of each UTC day.

### What verification catches

```bash
agentward-evidence verify-checkpoints --evidence-dir evidence-log \
  --public-key evidence.pub [--deep] [--expect-head <hash>]
```

| change | caught by |
|---|---|
| a record edited, reordered or removed in a shard | shard root no longer matches the signed root |
| a whole shard deleted | the signed checkpoint names it, the file is missing |
| a checkpoint edited, or signed with another key | signature check with the pinned public key |
| a checkpoint in the middle deleted | gap in the sequence numbers and the hash chain |
| the newest checkpoints deleted | `--expect-head` with a hash kept elsewhere (see below) |

Records appended after the newest checkpoint are reported as warnings, not
errors: they are simply not covered yet. `--deep` checks the shards against
every checkpoint, not only the newest one.

### Proving one record

A third party can check one record without the rest of the log:

```bash
agentward-evidence prove-shard --evidence-dir evidence-log --tenant acme \
  --day 2026-10-24 --index 4 > proof.json
agentward-evidence verify-proof proof.json --public-key evidence.pub
```

`proof.json` holds the record, its Merkle audit path and the signed
checkpoint. Verification needs only that file and the public key.

## How a third party verifies a report

1. Get the public key from the operator through a separate channel (for
   example their security page or a signed email), not with the report.
2. Get a copy of the evidence log (or, for spot checks, `proof.json` files
   for chosen violations from section 10).
3. Run `agentward-evidence verify-checkpoints --evidence-dir <dir>
   --public-key evidence.pub --expect-head <checkpoint hash from section 8>`.
   It must print `"ok": true`.
4. Check that the shard roots and counts in section 8 match
   `agentward-evidence shards --evidence-dir <dir>`.
5. For any violation, ask for a proof and run `verify-proof`.
6. Optionally recompute the numbers: run the report with `--format json`
   over the same window and source and compare, or read the JSON embedded in
   the HTML file.

## Syncing checkpoints to object storage

The checkpoint chain is only as strong as the place the newest checkpoint is
kept. Copy shards and checkpoints to object storage that the writing service
cannot delete from, for example an S3 bucket with Object Lock in compliance
mode, or a GCS bucket with a retention policy. AgentWard makes no cloud
calls itself; use your normal tools from a scheduled job:

```bash
# checkpoints are small and never change once written: copy every new one
aws s3 sync evidence-log/_checkpoints s3://acme-evidence/checkpoints/ \
  --exclude ".lock" --exclude "*.tmp"
# shards of past days no longer change; today's shard is re-uploaded as it grows
aws s3 sync evidence-log s3://acme-evidence/shards/ \
  --exclude "_checkpoints/*" --exclude "*/.lock"
```

```bash
gsutil -m rsync -r -x '.*\.lock$|.*\.tmp$' evidence-log gs://acme-evidence/log
```

Rules that keep this sound:

- Upload a checkpoint only after it is fully written (the tool writes to a
  `.tmp` file and renames it, so excluding `*.tmp` is enough).
- Give the writer credentials that can add objects but not delete or
  overwrite them.
- Publish the newest checkpoint hash somewhere outside your control from time
  to time (a customer, a ticket, the report itself). That hash is what
  `--expect-head` checks, and it is what makes deleting recent checkpoints
  visible.
