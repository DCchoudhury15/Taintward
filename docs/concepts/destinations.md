# Destinations

Every tool call and model call in Taintward has a **destination**: the kind
of place the call's input goes. The destination decides what the call is
allowed to receive. It is the one thing you configure per tool.

| destination | means | what a sensitive value becomes |
|---|---|---|
| `internal` | a system you control and trust with the data (your database, an internal cache) | a reversible FF1 token of the same shape |
| `llm` | a model provider | a placeholder such as `<PERSON_1>` (SDK adapters), or a mask |
| `external` | a third party API, email, webhook, anything outside | a one-way mask: `[PII]`, `[SECRET]` |
| `log` | a log line, a span, a file | a one-way mask |
| `rag` | a vector store or retrieval index | a one-way mask (embeddings can be inverted, so this is treated as egress) |

Details of each form are on [Placeholders, tokens and masks](redaction.md).

## The default is `external`

A tool that is not in your map is treated as `external`. An unknown tool may
send data anywhere, so it gets masks and its span is flagged when the run has
touched sensitive data. Marking a tool `internal` is an explicit decision to
trust it with reversible tokens.

The failure modes are not equal, and that is why the default is what it is:

- a trusted tool you forgot to list sees `[PII]` and works less well;
- if the default were `internal`, a forgotten tool would get data it should
  not.

You can change the default with `init(..., default_destination=...)` in the
SDK or `defaults.destination` in the gateway config, but there is rarely a
good reason to.

## Jurisdiction

A destination can also carry a **jurisdiction**, a short lower case code such
as `us` or `eu`. The policy uses it for the cross-border transfer rule (GDPR
Art. 44): PII going to a jurisdiction in `non_adequate_jurisdictions` (by
default only `us`) is a `transfer` violation, in addition to any egress
violation. An empty jurisdiction never fires that rule.

## Where you set it

SDK (see [SDK integrations](../integrations.md)):

```python
tw.init("hr-agent", destinations={
    "search_db": "internal",
    "send_email": ("external", "us"),                          # (destination, jurisdiction)
    "notify": {"destination": "external", "allow": ["to"]},    # allow list
}, llm_jurisdiction="us")
```

Decorator, for code that does not use a framework:

```python
from taintward.sdk.instrumentation import instrument_tool

@instrument_tool(destination="external", jurisdiction="us")
def post_to_crm(record: dict) -> str: ...
```

Note that `@instrument_tool` defaults to `internal`, unlike the adapters.
Always pass `destination=` explicitly on the decorator.

MCP gateway (see [MCP gateway](../mcp-gateway.md)):

```yaml
defaults:
  destination: external
tools:
  - match: "get_*"
    destination: internal
  - match: "send_*"
    destination: external
    jurisdiction: us
    mode: block
```

## Allow lists

Some tools need one argument raw: the recipient address of an email tool, the
customer id a database query filters on. Name those arguments in `allow`
(SDK) or `passthrough_args` (gateway). They reach the tool as they are. They
are still scanned, so the taint label and the violation flag stay correct,
and the copy stored on the span is masked. Keep these lists short and review
them: they are the places raw data is allowed to leave.
