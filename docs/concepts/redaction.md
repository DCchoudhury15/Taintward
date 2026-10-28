# Placeholders, tokens and masks

Taintward replaces a sensitive value in one of three ways. Which one is used
depends only on the [destination](destinations.md) of the call.

| | token | placeholder | mask |
|---|---|---|---|
| example for `234-12-1234` | `103-48-0677` | `<SSN_1>` | `[PII]` |
| used for | `internal` | `llm` (SDK adapters, default) | `external`, `log`, `rag`, and `llm` when placeholders are off |
| reversible | yes, with the FPE key and the vault | yes, only inside the same run, in memory | no |
| same value, same output | yes (deterministic per key) | yes within one run | yes (all SSNs look alike) |
| keeps the shape | yes (digits stay digits, separators stay) | no | no |
| stored where | vault: memory, SQLite, Postgres or Redis | in memory for the run (or a vault for long chats) | nowhere |

## Tokens (internal)

A reversible format preserving token made with FF1 (NIST SP 800-38G). An
internal store can join and match on tokens, and the key holder can turn a
token back into the value with `get_redactor().reverse(token)` when it is
truly needed. The store never holds the raw value.

- Values too short for FF1 (fewer than 6 digits or 4 letters and digits)
  are masked instead, because a tiny domain is easy to brute force.
- Tokens need a key. Set `TAINTWARD_FPE_KEY`. Without it a random key is
  made per process and a warning is printed: tokens then change after a
  restart.
- Persistent vaults encrypt the original at rest with
  `TAINTWARD_VAULT_KEY` and support per-subject erasure for GDPR.

Full details: [Key management and the vault](../redaction-crypto.md).

## Placeholders (LLM)

With plain masks a model loses the meaning of the task: two different people
both look like `[PII]`. So the SDK adapters send typed, numbered placeholders
to the LLM (`<PERSON_1>`, `<EMAIL_2>`, `<AWS_KEY_1>`). In one run the same
value always gets the same placeholder.

The map from placeholder to value stays in your process. It is never sent to
the provider and never written to a span. The protected model or client
restores the model's answer (text and tool call arguments) before your code
sees it. A tool that receives a placeholder in its arguments gets what its
own destination allows: the token for `internal`, the mask for `external`,
the real value for an argument on its `allow` list.

What placeholders still reveal: the type of data (`<SSN_1>` says an SSN was
shared), how many values there are and which repeat, and the text around
them. Only detected values are replaced.

Turn them off with `tw.init(..., placeholders=False)`. The decorator path
(`@instrument_tool`) and the MCP gateway do not use placeholders; they send
masks to `llm` destinations.

Full details: [SDK integrations, Placeholders](../integrations.md#placeholders-the-model-can-still-do-its-job).

## Masks (everything else)

A fixed string per class: `[PII]` for personal data, `[SECRET]` for keys and
tokens. A mask cannot be reversed and does not tell the receiver how many
values there were.

Spans always get masks: the copy of a tool's input and output stored on a
span is masked even when the tool itself received a token or a raw allowed
value, because a span is a `log` destination.

## Detection is the limit

All three forms only apply to values the detector finds. A value that is
changed into a form the detectors do not recognize is not replaced. The chain
taint still flags the run (see [Taint and runs](taint-and-runs.md)). Measured
recall and false alarm rates are on the [Detection benchmark](../benchmark.md)
page.
