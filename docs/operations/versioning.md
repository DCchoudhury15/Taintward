# Stability and versioning

## Version numbers

Taintward uses [semantic versioning](https://semver.org): `MAJOR.MINOR.PATCH`.

- **PATCH** (0.2.0 to 0.2.1): bug fixes and security fixes. No change to
  the public API, except to close a hole where raw data could leak (see
  "Security fixes" below).
- **MINOR** (0.2 to 0.3): new features. Before 1.0, a minor release may also
  make breaking changes; each one is listed under "Breaking" in the
  [changelog](../changelog.md) with what to change, and in the
  [upgrade guide](upgrade.md).
- **MAJOR** (1.0 to 2.0): after 1.0, breaking changes only happen here.

The project is at 0.x. Treat every minor release as possibly breaking and
read the changelog before you upgrade. Patch releases are always safe to
take.

The Python package, the collector image, the gateway image and the Helm chart
are released together with the same version number.

## What is public API

These are covered by the rules above. If you depend on anything else, pin an
exact version.

**Python**

- the names exported by `import taintward`: `init`, `run`, `restore`,
  `get_ward`, `Ward`, `wrap_langchain_tools`, `protect_langchain_model`,
  `wrap_function_tools`, `protect_openai`, `protect_anthropic`, `health`;
- `taintward.sdk.instrumentation`: `configure_tracing`, `instrument_tool`,
  `GuardedCall`, `begin_run`, `end_run`;
- `taintward.sdk.detect`: `health`, `is_degraded`, `DetectionDegradedError`,
  `set_pii_types`, `detect_text`, `detect_mapping`, `Detection`;
- `taintward.sdk.redact`: `Redactor` (including `reverse` and
  `forget_subject`), `get_redactor`, `redact_value`, `redact_text`,
  `redact_payload`;
- `taintward.sdk.vault`: `get_vault`, the `Vault` protocol and its four
  backends, `VaultError`;
- `taintward.sdk.placeholders.PlaceholderMap`;
- `taintward.evidence.shards.ShardedLog` and
  `taintward.evidence.merkle.MerkleLog`.

**Outside Python**

- the four commands and their options ([Command line](../reference/cli.md));
- the environment variables ([Configuration](../reference/configuration.md));
- the span attribute names and their meaning
  ([Span attributes](../reference/span-attributes.md));
- the gateway config file format;
- the Rego policy contract: `package taintward`, the input fields and
  `data.taintward.decision` with `redact` and `violations`;
- the `taint_policy` processor options (`policy_path`, `decision_cache_size`);
- Helm values listed under [Main values](../deploy-kubernetes.md#main-values);
- on-disk formats: evidence log lines, shard layout, checkpoint files, proof
  files, vault tables and Redis keys. A new version reads files written by
  the version before it;
- the report JSON, versioned by its `report_version` field.

**Not public API**

- any module, function or attribute whose name starts with `_`;
- modules not listed above, for example `taintward.sdk.regex_fallback`,
  `taintward.gateway.server`, `taintward.evidence.report` internals;
- the exact detection results. Detection is pattern and model based, and
  finding more (or fewer false alarms) is not a breaking change. Changes in
  detection quality are measured and written up on the
  [Detection benchmark](../benchmark.md) page;
- the exact text of masks inside free text, log messages, error messages and
  the HTML layout of the report;
- token values. Tokens depend on the key and on the FF1 tweak; a change of
  the token scheme is announced as breaking, because old tokens then only
  reverse through the vault.

## Deprecation policy

When a public name, option, environment variable or span attribute is
replaced:

1. The release that adds the replacement keeps the old name working and
   logs a warning (Python `DeprecationWarning` for code, a log line for
   settings) that names the replacement.
2. The changelog lists it under "Deprecated", with the version in which it
   will be removed.
3. It is removed no earlier than two minor releases later (before 1.0) or
   in the next major release (after 1.0).

Exception: the rename from AgentWard to Taintward in 0.2.0 was done without
aliases, because the old PyPI name belonged to another project. There will
be no other rename of that kind.

## Security fixes

A change that stops raw data from reaching a sink that the policy says must
not receive it is a bug fix, even if a configuration that relied on the leak
stops working. Such fixes ship in a patch release and are marked "Security"
in the changelog. Safer defaults (for example a new default of `external` for
unmapped tools) are treated as breaking and only change in a minor release.

## Supported versions

Only the newest minor release gets fixes. Security fixes may be backported to
the previous minor release when the upgrade is not trivial. Python 3.11 and
newer are supported; the tests run on 3.12.
