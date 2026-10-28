# Roll out in audit mode first, then enforce

**Goal:** add Taintward to an agent that is already in production without
changing what its tools and model receive, find out what *would* be redacted
or blocked, fix the configuration until that list is right, then switch
enforcement on.

**Time:** the setup takes an hour; plan one to two weeks of audit traffic so
rare tools and rare data show up.

!!! warning "Audit mode forwards raw data"
    In audit mode every sink receives exactly what it received before
    Taintward: raw values go to the LLM provider, third party APIs and logs.
    Audit mode changes nothing about your exposure; it only measures it.
    Spans are still masked, so the measurement itself does not store raw
    values. Do not leave audit mode on once you have the numbers.

## What "audit" means in each component

| component | how to turn audit on | what the sink gets | what the span says |
|---|---|---|---|
| SDK (adapters and `@instrument_tool`) | environment variable `TAINTWARD_DRY_RUN=1` | raw input, no tokens, no placeholders, no masks | `taintward.dry_run=true`, `taintward.violation=true` when it would have been a violation, `taintward.redacted=false` |
| MCP gateway | `mode: audit` in `defaults` or per tool rule | raw arguments; results are not masked either | `taintward.mode=audit`, `taintward.dry_run=true`, `taintward.violation`, `taintward.policy.rules`, `taintward.blocked=false` |
| collector | no audit mode; it always masks spans before storage | (not a sink) | `taintward.policy.violation`, `taintward.policy.transfer_violation`, `taintward.policy.reasons` |

`TAINTWARD_DRY_RUN` is read once, when `taintward.sdk.instrumentation` is
first imported. Set it in the process environment (container spec, systemd
unit), not with `os.environ` after import. Accepted values: `1`, `true`,
`yes`, `on` for on and `0`, `false`, `no`, `off` for off; anything else
keeps the default (off) and logs a warning.

Keep the collector in the path during audit. It is what makes sure the raw
values the SDK did not redact are still removed from the stored spans:

- `TAINTWARD_MASK_IN_SDK` must stay at its default (on). With dry run and
  in-process masking both on, the SDK stores masked copies on the span while
  the sink gets raw values.
- In dry run the SDK does not set `taintward.args_redacted`, so the
  collector masks the stored arguments too.

## Step 1: write the real configuration, in audit mode

Write the destination map and the gateway rules you intend to enforce, as if
you were enforcing today. Audit mode tells you whether they are right; it
cannot tell you what they should be.

SDK, with the map you plan to use:

```python
tw.init("billing-agent", endpoint="http://taintward-collector:4319/v1/traces",
        destinations={"get_invoice": "internal",
                      "send_reminder": {"destination": "external", "allow": ["to"]},
                      "post_to_slack": ("external", "us")},
        llm_jurisdiction="us")
```

and in the deployment:

```yaml
env:
  - name: TAINTWARD_DRY_RUN
    value: "1"
```

Gateway: set the mode you plan to use on each rule as a comment, and
`audit` for now:

```yaml
defaults:
  destination: external
  mode: audit            # target: redact
tools:
  - match: "get_*"
    destination: internal
    mode: audit          # target: redact
  - match: "send_*"
    destination: external
    jurisdiction: us
    mode: audit          # target: block
```

Deploy. Nothing changes for the agent's users.

## Step 2: read what would have happened

### In the trace backend

Every audit span carries `taintward.dry_run=true`. Filters:

| question | Jaeger "Tags" box | SigNoz trace filter |
|---|---|---|
| what would have been flagged | `taintward.dry_run=true taintward.violation=true` | `taintward.dry_run = true AND taintward.policy.violation = true` |
| cross-border transfers | `taintward.policy.transfer_violation=true` | `taintward.policy.transfer_violation = true` |
| what a gateway rule would have blocked | `taintward.mode=audit taintward.violation=true`, then look at `gen_ai.tool.name` against the rules whose target is `block` | same, grouped by `gen_ai.tool.name` |
| what data was involved | open the span: `taintward.taint.classes` (`pii`, `secret`) and the masked `gen_ai.tool.call.arguments` | same |

### In the report

The report counts audit calls as their own outcome. Generate the JSON for the
audit window (raise `--max-rows`, the default list is cut at 500):

```bash
taintward-report --source jaeger --service billing-agent --service taintward-mcp-gateway \
  --since 7d --format json --max-rows 100000 --out audit.json
```

(`--source clickhouse` for SigNoz, `--source otlp-file` for collector files;
see [Command line](../reference/cli.md).)

Totals per outcome. During audit nearly everything should be `audit_only`:

```bash
jq '.violations.by_outcome' audit.json
# {"redacted": 0, "nothing_to_redact": 0, "blocked": 0, "audit_only": 412}
```

Which tools would have been redacted or blocked, how often, and why:

```bash
jq '[.violation_list[] | select(.outcome == "audit_only")]
    | group_by(.tool)
    | map({tool: .[0].tool, destination: .[0].destination,
           calls: length, rules: (map(.rules) | add | unique),
           classes: (map(.classes) | add | unique)})
    | sort_by(-.calls)' audit.json
```

Every tool that ever received data, with its destination: `jq '.recipients' audit.json`.

The HTML version of the same report (drop `--format json`) shows the summary
statement "It could not be confirmed ..." with the reason "N external or LLM
call(s) ran in audit-only mode". That is expected during audit.

## Step 3: fix the configuration

Go through the grouped list tool by tool:

| what you see | likely cause | fix |
|---|---|---|
| a tool you own and trust is flagged on every call | it is unmapped, so it defaults to `external` | map it `internal` (it will get tokens) |
| a tool would break with a mask in one argument (an email tool's `to`, a lookup key) | the argument is personal data the tool needs raw | add that one argument to `allow` (SDK) or `passthrough_args` (gateway) |
| an `internal` tool is listed as a recipient of `secret` data it should never see | the agent passes keys around | fix the code or the prompt; Taintward will only tokenize the key |
| a send or post tool would be blocked after almost every read | session taint is coarse: one sensitive read taints every later call | use `redact` instead of `block` for that tool, or split the agent's work into separate runs or sessions |
| many flags with class `pii` on text that has no personal data | detection noise (for example a capitalized product name read as a person) | check the masked arguments on the span; report the case as a detection miss with fake data; do not turn detection off |
| a value you consider sensitive is never flagged | not detected | see the [Detection benchmark](../benchmark.md) for known gaps; `TAINTWARD_PII_EXTRA_TYPES=DATE_TIME` turns dates back on |

Redeploy with the fixes, still in audit mode, and repeat step 2 until the
list contains only calls you really want redacted or blocked.

## Step 4: enforce

Switch one component at a time, starting with the one with the least risk
of breaking the agent.

1. **SDK:** remove `TAINTWARD_DRY_RUN` (or set it to `0`) and restart. Tools
   now get tokens, masks or allowed raw values; the LLM gets placeholders.
2. **Gateway:** change each rule from `audit` to its target, `redact`
   first. Move a tool to `block` only after it has run cleanly in `redact`.
   The gateway reads its config at startup, so restart it.
3. **Optional:** set `TAINTWARD_FAIL_CLOSED=1` in the SDK and gateway
   processes, so calls to non-internal sinks are refused while detection is
   degraded (spaCy or Presidio failed to load). Check `tw.health()` reports
   `"mode": "full"` first.

## Step 5: confirm enforcement

Run the report again over a window that starts after the switch:

```bash
taintward-report --source jaeger --service billing-agent --service taintward-mcp-gateway \
  --start 2026-11-10T00:00:00Z --format json --out enforced.json
jq '.violations.by_outcome, .raw_check.claim' enforced.json
```

You should see `audit_only: 0`, the former audit calls now under `redacted`
or `blocked`, and a claim with `"status": "supported"` whose statement starts
with `0 raw sensitive values were sent to external or LLM destinations`. A
status of `not_confirmed` lists its reasons in `.raw_check.claim.reasons`;
`raw_found` means the findings table (`.raw_check.findings`) has calls to
look at. If `audit_only` is not zero, some process
still has `TAINTWARD_DRY_RUN` set or a rule is still in `audit`: filter on
`taintward.dry_run=true` to find it.

## Checklist

- [ ] Collector in the path, `TAINTWARD_MASK_IN_SDK` left on.
- [ ] Destination map and gateway rules written as they will be enforced.
- [ ] `TAINTWARD_DRY_RUN=1` set in the environment of every agent process (not in code).
- [ ] Gateway rules on `mode: audit`, target mode noted next to each.
- [ ] At least one week of audit traffic, covering every tool.
- [ ] Audit report generated with `--max-rows` high enough; grouped by tool.
- [ ] Every flagged tool reviewed: mapped `internal`, given an `allow` entry, or accepted as a real violation.
- [ ] `allow` and `passthrough_args` lists reviewed by a second person.
- [ ] `TAINTWARD_FPE_KEY` (and `TAINTWARD_VAULT_KEY` for a persistent vault) set from a secret manager before enforcing.
- [ ] SDK switched: `TAINTWARD_DRY_RUN` removed, processes restarted.
- [ ] Gateway switched to `redact`, then `block` where planned, restarted.
- [ ] Post-switch report shows `audit_only: 0` and the expected claim.
- [ ] Alert on `taintward.dry_run=true` so audit mode cannot come back unnoticed.
