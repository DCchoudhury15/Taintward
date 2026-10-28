# Python API

Generated from the docstrings in the source. Only the names listed on
[Stability and versioning](../operations/versioning.md#what-is-public-api) are
public API; everything else in the package can change in any release.

```python
import taintward as tw
```

`import taintward` loads nothing heavy. The names below are loaded on first
use, so `import taintward.core.doe` does not load Presidio or spaCy.

| name | where it lives |
|---|---|
| `tw.init`, `tw.run`, `tw.restore`, `tw.get_ward`, `tw.Ward` | `taintward.sdk.integrations` |
| `tw.wrap_langchain_tools`, `tw.protect_langchain_model` | `taintward.sdk.integrations` (needs the `langchain` extra) |
| `tw.wrap_function_tools` | `taintward.sdk.integrations` (needs the `openai-agents` extra) |
| `tw.protect_openai`, `tw.protect_anthropic` | `taintward.sdk.integrations` (needs the `llm` extra or the provider SDK) |
| `tw.health` | `taintward.sdk.detect` |

## Integrations

::: taintward.sdk.integrations
    options:
      show_root_heading: false
      members:
        - init
        - run
        - restore
        - get_ward
        - Ward
        - ToolPolicy
        - DEFAULT_DESTINATION
        - wrap_langchain_tools
        - protect_langchain_model
        - wrap_function_tools
        - protect_openai
        - protect_anthropic

## Decorator and low-level tracing

::: taintward.sdk.instrumentation
    options:
      show_root_heading: false
      members:
        - configure_tracing
        - instrument_tool
        - GuardedCall
        - begin_run
        - end_run
        - current_taint

## Detection

::: taintward.sdk.detect
    options:
      show_root_heading: false
      members:
        - health
        - is_degraded
        - DetectionDegradedError
        - set_pii_types
        - ignored_types
        - Detection
        - detect_text
        - detect_mapping
        - clear_cache
        - cache_info

## Redaction

::: taintward.sdk.redact
    options:
      show_root_heading: false
      members:
        - Redactor
        - get_redactor
        - redact_value
        - redact_text
        - redact_payload

## Token vault

::: taintward.sdk.vault
    options:
      show_root_heading: false
      members:
        - get_vault
        - Vault
        - MemoryVault
        - SQLiteVault
        - PostgresVault
        - RedisVault
        - VaultError

## Placeholders

::: taintward.sdk.placeholders
    options:
      show_root_heading: false
      members:
        - PlaceholderMap
        - restore

## Evidence log

::: taintward.evidence.shards
    options:
      show_root_heading: false
      members:
        - ShardedLog

::: taintward.evidence.merkle
    options:
      show_root_heading: false
      members:
        - MerkleLog
        - LogCorruptError
        - TornTailError
