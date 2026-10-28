# Evidence

Taintward produces three kinds of records. Each one answers a different
question from an auditor or a customer.

| record | answers | made by |
|---|---|---|
| spans | what happened on each call | SDK, gateway, collector |
| evidence log | were recorded violations changed or deleted later? | `taintward-evidence record` |
| report | over this period, did raw sensitive data reach an LLM or third party? | `taintward-report` |

## Spans

Every wrapped call emits one OpenTelemetry span with the destination, the
taint label, the policy decision and the (redacted) input and output. They
go to your normal trace backend. The attribute names are listed in
[Span attributes](../reference/span-attributes.md).

Spans are the raw material for everything else. They are only as complete as
your tracing: sampling, retention and dropped spans reduce what is counted.

## Evidence log

A Merkle tree log of violations, one JSON record per line. Each record is a
leaf; the root hash changes if any record is edited, reordered or removed.

- **Sharded:** one file per tenant per UTC day under an evidence directory,
  so many writers can append at once.
- **Signed checkpoints:** a checkpoint lists every shard with its size and
  root, the hash of the previous checkpoint, and an Ed25519 signature. It
  also holds a consistency proof (RFC 9162) for every shard that grew, so
  old records cannot be rewritten even by someone with the signing key
  without the check failing.
- **Proofs for one record:** `prove-shard` writes a small file with one
  record, its audit path and the signed checkpoint. A third party can verify
  it with only the public key.

The log proves that recorded violations were not changed later. It does not
prove that every call was recorded.

## Report

`taintward-report` reads spans from Jaeger, SigNoz (ClickHouse) or OTLP JSON
files for a time window and writes one HTML file (or JSON). The key part is
the **raw value check**: for every call to an `llm`, `external`, `log` or
`rag` destination it scans the recorded input for raw values. The summary
statement says "0 raw sensitive values were sent" only when every such call
had its input recorded, none ran in audit mode on sensitive data, and the
scan found nothing. Otherwise it says what could not be confirmed.

The report embeds its data as JSON with a SHA-256 digest, and can include the
evidence log section with the newest signed checkpoint.

Generating and reading it: [Compliance report and evidence log](../evidence-report.md)
and the recipe [Monthly report for a security review](../recipes/monthly-report.md).
