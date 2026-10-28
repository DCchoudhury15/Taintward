# Taint and runs

Detection answers "is there sensitive data in this value?". Taint answers a
different question: "has this chain of calls touched sensitive data at any
point?". Taintward needs both, because an LLM can rewrite data beyond
recognition. After a model summarizes a record, the SSN may be gone from the
text, but the summary still came from the record.

## Two layers

1. **Field level (detection).** Every tool input and output is scanned
   (Presidio plus secret patterns, see [Detection benchmark](../benchmark.md)).
   A hit adds a class to the call's label: `pii` or `secret`.
2. **Chain level (baggage).** Once a call is tainted, a small label rides in
   OpenTelemetry baggage to every later call in the same trace. It holds
   `taint.id` (a random id), `taint.classes` (`pii,secret`), `taint.level`
   (`low`, `medium`, `high`) and `taint.source` (the span that first found
   the data). It never holds the value.

A call is **sensitive** when either layer says so. That is what
`taintward.sensitive=true` on a span means.

Taint only grows within a run. It is never removed because a later value
looks clean. This is a safe over-approximation: after the agent has read one
SSN, every later call to an `external`, `llm` or `log` destination in that
run is a violation, even if its arguments look clean. In the SDK and the
gateway's `redact` mode the arguments are still redacted value by value, so
this flags more than it changes. In the gateway's `block` mode it blocks.

## Runs

A **run** is one task of your agent: one user request, one job. In the SDK:

```python
with tw.run("support-bot.run"):
    agent.invoke(...)
```

`run()`:

- opens one root span, so the whole task is one trace;
- starts with a clean taint slate, so one user's data does not taint the
  next user's run;
- keeps the run's taint visible across the threads and asyncio tasks that
  frameworks use to run tools (it lives in context variables, so concurrent
  runs do not mix and nested runs work);
- holds one placeholder map for the LLM (see
  [Placeholders, tokens and masks](redaction.md)).

Without `run()`, redaction still works, because it is based on what is
detected in each input. But the chain taint can be lost between tools, so a
later call that carries rewritten data may not be flagged. Always use a run.

Lower level code can use `taintward.sdk.instrumentation.begin_run()` and
`end_run()` instead of the context manager.

## Sessions in the gateway

The MCP gateway has no run object. It uses the MCP session instead: once any
argument or result in a session was sensitive, every later call in that
session is tainted. Over stdio one gateway process is one session. Over HTTP
each `Mcp-Session-Id` is one session, and the taint is kept in a session
store (memory, or Redis for several replicas). What is stored is only the set
of class names and a random taint id, never values.

## Nested tools

A wrapped tool that calls another wrapped tool takes on the inner call's
taint. If the inner tool returns an SSN and the outer one returns a clean
summary, the next external call is still a violation.

## Fan-out and fan-in

When work splits and joins (several retrievals feed one answer), the SDK can
add OpenTelemetry span links between the calls so the lineage is kept. With
`@instrument_tool`, pass `taintward_links=[span_context, ...]` when you call
the tool. The argument is consumed by the wrapper and not passed to the
tool.
