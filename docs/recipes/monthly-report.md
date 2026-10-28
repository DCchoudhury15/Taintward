# Generate the monthly report for a customer security review

**Goal:** a customer's security team asks, every month or once a year, "do
you send our customers' personal data to LLM providers or other third
parties?". You send them a report for the period, and they can check that
its evidence was not edited after the fact.

**Time:** one hour to set up, then a few minutes each month. **You need:**
Taintward spans for the whole month (SDK or gateway, with the collector), and
somewhere to run two scheduled jobs.

## 1. Make sure a month of spans exists

The report reads spans from the trace backend. The quickstart's Jaeger keeps
spans in memory only, so it is not enough. Use one of:

| source | how to keep a month |
|---|---|
| SigNoz (ClickHouse) | set trace retention to at least 31 days (more if you want to regenerate old reports) |
| OTLP JSON files | turn on the collector `file` exporter (`TAINTWARD_TRACE_EXPORTERS='[otlp_grpc/backend, file]'` or Helm `collector.fileExport.enabled=true`) and copy the rotated files to durable storage every day |
| Jaeger with persistent storage | retention of at least 31 days |

Sampling reduces what the report counts. Do not sample Taintward spans, or
say in the report what the sampling rate is.

## 2. Create the signing key once

```bash
taintward-evidence keygen --private-key evidence.key --public-key evidence.pub
```

`evidence.key` is created with mode 0600 and is never overwritten. Store it
in your secret manager; jobs read it from `TAINTWARD_EVIDENCE_KEY_FILE` (a
path) or `TAINTWARD_EVIDENCE_KEY` (PEM text or a 64 hex character seed).
Publish `evidence.pub` somewhere the customer can fetch it separately from
the report, for example your security page.

## 3. Record violations as they happen

An hourly job copies violations from the backend into the sharded evidence
log and signs a checkpoint. Overlapping windows are fine: records are matched
by trace id and span id, so nothing is added twice.

```bash
export TAINTWARD_EVIDENCE_DIR=/var/lib/taintward/evidence-log
export TAINTWARD_EVIDENCE_KEY_FILE=/run/secrets/evidence.key

taintward-evidence record --source clickhouse --service support-bot \
  --since-mins 70 --tenant acme --checkpoint
```

- `--source jaeger` (with `--jaeger-url`) or `--source otlp-file --otlp-file DIR`
  work the same way. The default source of `record` is `clickhouse`, which
  runs `clickhouse-client` in the container
  `signoz-telemetrystore-clickhouse-0-0`; use `--clickhouse-url http://host:8123`
  to use the HTTP interface instead.
- `--tenant` is one directory per customer (or per environment). Use one
  tenant per customer if you report per customer.
- Also run `taintward-evidence checkpoint` once just after midnight UTC, so
  each closed day is covered by a signed checkpoint.

Copy `evidence-log/` to storage the writer cannot delete from (for example
S3 with Object Lock); see
[Syncing checkpoints to object storage](../evidence-report.md#syncing-checkpoints-to-object-storage).

## 4. Generate the report

On the first working day of the month, for the month before:

```bash
taintward-report --source clickhouse --service support-bot \
  --start 2026-10-01T00:00:00Z --end 2026-11-01T00:00:00Z \
  --org "Example Co." --system "Support assistant" \
  --title "Sensitive data flow report, October 2026" \
  --evidence-dir /var/lib/taintward/evidence-log --public-key evidence.pub \
  --out report-2026-10.html

taintward-report ... --format json --out report-2026-10.json   # same options
```

- Repeat `--service` for every service in scope (agents and the gateway).
- `--deep-scan` also runs the Presidio detectors in the raw value check
  (names, locations). It is slower and gives more false findings; use it
  when the customer's data is mostly free text.
- `--public-key` verifies the evidence log while building the report; the
  result is in section 8.

Open the HTML file and print it to PDF if the customer wants a PDF (A4,
headers repeat on each page).

## 5. Read it before you send it

Check the summary statement first. It is one of four:

| statement starts with | meaning | what to do |
|---|---|---|
| `0 raw sensitive values were sent ...` | every external and LLM call had its input recorded and none held a raw value | send it |
| `N raw sensitive value(s) were found ...` | the findings table lists the calls (type and fingerprint, never the value) | investigate each call before sending; fix the tool map or allow list |
| `It could not be confirmed ...` | something was not measurable; the reasons are listed | fix the cause (audit mode left on, spans without input, a source that cut data short) or explain it to the customer |
| `No calls to external or LLM destinations were recorded` | nothing to check | check the `--service` names and the window |

Then check:

- section 8 (evidence log) says the log verified and every violation in the
  window is in the log;
- section 6 (recipients) lists only tools you expect, with the right
  destinations and jurisdictions; this is the "recipients" part of a GDPR
  Art. 30 record;
- section 9 (method and limits) matches how you run Taintward.

## 6. Send it

Send:

1. the report (HTML or PDF);
2. the newest checkpoint hash from section 8, in the message body, so the
   customer can later detect deleted checkpoints with `--expect-head`;
3. where to get `evidence.pub` (not the key itself in the same message).

Answer the usual follow-up questions with the report's own sections:

| question | answer from |
|---|---|
| which providers receive our data? | section 6, recipients, with jurisdictions |
| was anything sent raw? | section 7, raw value check, and the summary statement |
| was anything sent to the US? | section 5, cross-border transfers |
| how do we know you did not edit the records? | section 8 and the verification steps below |
| what does this not cover? | section 9: calls that bypass Taintward, data the detectors do not recognize, `passthrough_args` |

## 7. How the customer verifies it

If they ask for a copy of the evidence log (or proofs for chosen
violations):

```bash
taintward-evidence verify-checkpoints --evidence-dir evidence-log \
  --public-key evidence.pub --expect-head <checkpoint hash from section 8>
taintward-evidence shards --evidence-dir evidence-log     # compare with section 8

# one violation, without the rest of the log
taintward-evidence prove-shard --evidence-dir evidence-log --tenant acme \
  --day 2026-10-14 --index 3 > proof.json                 # you run this
taintward-evidence verify-proof proof.json --public-key evidence.pub   # they run this
```

`verify-checkpoints` must print `"ok": true`. The numbers can also be
recomputed: the HTML embeds its data as JSON (element `taintward-report-data`)
with a SHA-256 digest in the footer. The full procedure is in
[How a third party verifies a report](../evidence-report.md#how-a-third-party-verifies-a-report).

## Checklist

- [ ] Trace retention of at least 31 days, no sampling of Taintward spans.
- [ ] Signing key in a secret manager, public key published.
- [ ] Hourly `record --checkpoint` job and a daily checkpoint after midnight UTC.
- [ ] Evidence log copied to write-once storage.
- [ ] Report generated for the full month with every in-scope `--service`.
- [ ] Summary statement read and explained; sections 6, 8 and 9 checked.
- [ ] Report, checkpoint hash and public key location sent.
