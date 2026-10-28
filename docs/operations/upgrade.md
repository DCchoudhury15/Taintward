# Upgrade guide

## Before any upgrade

1. Read the [changelog](../changelog.md) entries between your version and
   the new one, especially "Breaking", "Deprecated" and "Security".
2. Upgrade the parts in this order: **collector, then gateway, then SDK**.
   The collector accepts spans from older SDKs, so upgrading it first never
   loses data.
3. Keep the same `TAINTWARD_FPE_KEY`, `TAINTWARD_VAULT_KEY` and evidence
   signing key. A new version must reverse tokens and verify checkpoints
   made by the old one.
4. Back up persistent state first: the vault (SQLite file, Postgres table
   `taintward_vault_tokens`, or Redis), and the evidence log directory.
5. If you changed the Rego policy, compare your file with the new
   `collector/policy/pii_egress.rego` and merge new rules in.
6. Run your own tests that check no raw value reaches an external sink
   (see the test in [Protect a LangGraph support bot](../recipes/langgraph-support-bot.md#5-check-it)).
7. After the upgrade, run `verify-checkpoints` on the evidence log and
   generate a report for the last day to check nothing changed in the
   numbers you did not expect.

Packages:

```bash
pip install --upgrade "taintward[langchain]==0.2.*"     # SDK, gateway, evidence tools
helm upgrade taintward deploy/helm/taintward -n taintward --reuse-values \
  --set collector.image.tag=<new> --set gateway.image.tag=<new>
```

## From AgentWard (before 0.2.0) to Taintward 0.2.0

0.2.0 renamed the project. There are no compatibility aliases, so every
reference must change at once.

| what | before (AgentWard) | after (Taintward) |
|---|---|---|
| PyPI package | `agentward` (a different project now owns that name) | `taintward` |
| imports | `sdk`, `core`, `evidence`, `fix_suggester`, `gateway` as top-level packages | `taintward.sdk`, `taintward.core`, `taintward.evidence`, `taintward.fix_suggester`, `taintward.gateway`; `import taintward as tw` for the integrations |
| commands | the old command names | `taintward-report`, `taintward-gateway`, `taintward-evidence`, `taintward-fix` |
| environment variables | `AGENTWARD_*` | `TAINTWARD_*` (same suffixes) |
| span attributes | `agentward.*` | `taintward.*` |
| Rego package | `package agentward` | `package taintward` |
| Helm chart | the old chart directory | `deploy/helm/taintward` |
| gateway Dockerfile | the old location | `deploy/gateway.Dockerfile` |
| images and collector binary | the old names | `taintward-collector`, `taintward-gateway`, `taintward-demo` |

Steps:

1. **Collector first.** Deploy the new collector with the new policy. The new
   processor reads `taintward.*` attributes only, so spans from old SDKs are
   still masked by the regex backstop but are no longer evaluated by the
   policy: plan a short window, or upgrade agents right after.
2. **Custom policy.** Change `package agentward` to `package taintward` in
   your Rego file. The processor refuses to start with the old package name.
3. **Environment.** Rename every `AGENTWARD_*` variable in deployments,
   Secrets and CI. An old name is silently ignored, which for
   `AGENTWARD_FPE_KEY` means a random key per process (a warning is
   printed) and tokens that no longer match the old ones.
4. **Code.** `pip uninstall agentward && pip install taintward`, then replace
   imports. A search for `agentward` in your code, configs and dashboards
   should find nothing.
5. **Dashboards and alerts.** Update queries from `agentward.*` to
   `taintward.*`. Old spans keep the old names; queries across the switch
   need both.
6. **Evidence log.** Existing log files keep working (the file format did
   not change). Records written before the rename contain the old attribute
   names in their payload.

Behavior changes in 0.2.0 that can affect you even after the rename:

- `AGENTWARD_DRY_RUN=0` used to turn dry run **on**. On/off values are now
  parsed properly (`0`, `false`, `no`, `off` are off). Check what you set.
- Detection no longer treats `DATE_TIME`, `ORGANIZATION`, `URL`, `NRP` and
  `MEDICAL_LICENSE` as sensitive. Set `TAINTWARD_PII_EXTRA_TYPES` to turn any
  of them back on.
- Tokens are now FF1 (they were FF3). Tokens issued by an older build do not
  reverse with the new code except through a vault that stored the original.
- The public demo FPE key is no longer used silently. Without
  `TAINTWARD_FPE_KEY` you get a random key per process and a warning, unless
  `TAINTWARD_ALLOW_DEMO_KEY=1` is set.
