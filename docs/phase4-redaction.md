# Phase 4: reversible, context-aware redaction (the standout feature)

**Status:** done (local, 2026-09-04). Verified end-to-end in SigNoz plus 9 unit tests.

The same sensitive value gets treated differently depending on where it's
going, because Phase 2/3 taint tracking followed where the data actually
travels, not a static field-name mask. This is what actually differentiates
the project from MemGuard-style static redaction.

    internal sink        -> FF1 format-preserving REVERSIBLE token
                            (same length / alphabet / separators; decrypts back
                            to the original, so the internal store can still
                            use/correlate the value without holding raw PII)
    external / llm / log -> non-reversible [PII] / [SECRET] mask
    rag                  -> mask (embeddings are invertible, OWASP LLM08:2025)

## Where it runs

The **SDK-side egress gate** redacts the tool's *actual input args* before the
call (`instrument_tool` calls `redact_payload(args, destination)`), so the tool
operates on redacted data and raw PII never reaches the sink. The collector
stays the authoritative policy **decider** (Rego) and redaction **backstop** for
everything the SDK doesn't cover (source-tool results, non-instrumented agents).

## Pieces

- `sdk/redact.py`, the `Redactor`:
  - `_fpe_encrypt` / `_fpe_decrypt` via **FF1** (`sdk/ff1.py`), per-value radix
    (digits go to 10, alnum to 36), separators preserved in place, length
    preserved.
  - `redact_value(value, sensitivity, destination)`: internal sinks get a
    reversible FPE token (vaulted for exact reversal), everything else gets
    masked.
  - `redact_text`: per-detection, with overlap-dedup (if AWS_ACCESS_KEY and
    GENERIC_API_KEY both match the same region, keep the longest one).
  - `redact_payload(value, destination)`: recursive over dict/list/scalar.
  - a pluggable vault `token -> original` (`sdk/vault.py`: in-memory or
    encrypted SQLite) so reversal is **exact** (FPE alone loses letter case).
- `sdk/destinations.py`: a leaf module holding the `DEST_*` constants, which
  breaks the `redact <-> instrumentation` circular import.
- `demo/hr_bot/tools.py`: added `internal_store` (internal sink) so the demo
  shows a reversible token alongside the masks.
- `collector/processor/taintpolicy/processor.go`: `redactSpan` now **skips**
  `gen_ai.tool.call.arguments` (the SDK already redacts args; the collector is
  the backstop for the result attr and residuals).

**Crypto update (2026-10).** This phase first shipped with FF3 and an
in-process vault. FF3 is withdrawn by NIST, so it now uses **FF1** (checked
against the NIST sample vectors), a pluggable vault with an encrypted SQLite
backend, and no silent hardcoded key. Values shorter than 6 digits or 4
letters/digits are masked. Details, configuration and limits:
[redaction-crypto.md](redaction-crypto.md). The token values in the SigNoz
table below were made with FF3; FF1 tokens have the same shape but different
digits.

## The format-preserving-token collision (a real interaction worth noting)

The FPE token for an SSN (`234-12-1234` becomes `103-48-0677`) is itself a
valid SSN-shaped string, so the collector's regex redaction treated it as PII
and masked it to `[PII]`, over-redacting and destroying the token in
observability. The tool still received the real token (the internal cache has
it, and it reverses fine), but the stored span attr lost it. The fix: the
collector skips `gen_ai.tool.call.arguments` since the SDK already redacts
args, and stays the backstop for the result attr only. A production system
would instead use a token namespace that doesn't collide with PII regexes, or
a tokenization service the collector trusts.

## Verified end-to-end in SigNoz (breach via sidecar, Phase 4 active)

| span | dest | args (stored) | viol | transfer |
|---|---|---|---|---|
| internal_store | internal | `"ssn":"103-48-0677"`, `"deploy_key":"qsvdtnv..."`, names tokenized | false | false |
| ask_llm | llm | `'[PII]','ssn':'[PII]',...'[SECRET]'` | true | true |
| call_external_api | external | `'[PII]','ssn':'[PII]','deploy_key':'[SECRET]'` | true | true |
| write_log | log | masked | true | false |

- The SAME SSN going to the internal sink gets the **reversible** token
  `103-48-0677` (round-trips back to `234-12-1234` via the redactor vault);
  external/llm/log all get the non-reversible `[PII]` mask.
- Rego decisions still fire on the taint attrs (violation and transfer on the
  us sinks). The policy sees the original taint; only the stored values are
  redacted.
- **0 raw SSN/AWS values anywhere** in stored spans.

## Tests

- `tests/test_redact.py`: 9 tests covering internal SSN/AWS reversible and
  format-preserving behavior, external/rag non-reversible masking, same-value
  different-destination handling, payload recursion, and clean-value no-ops.
- Full suite: `python -m unittest discover tests` gives **31 green** (14 DOE +
  8 SDK + 9 redact). Go: `cd collector/processor/taintpolicy && go test ./...`
  gives 3 green.
- Added with the crypto update: `tests/test_ff1.py` (FF1 against the NIST
  sample vectors) and `tests/test_vault.py` (vault, keys, short values). See
  [redaction-crypto.md](redaction-crypto.md).
