# Recipes

End-to-end walkthroughs for common jobs. Each one lists what you need,
the exact settings, how to check the result, and the limits that apply.

| recipe | for |
|---|---|
| [Protect a LangGraph support bot](langgraph-support-bot.md) | a LangChain or LangGraph agent with internal and external tools |
| [Put the gateway in front of a GitHub MCP server](github-mcp-gateway.md) | an MCP client using a third party MCP server, no code changes |
| [Roll out in audit mode first, then enforce](audit-then-enforce.md) | adding Taintward to an agent already in production |
| [Send traces to SigNoz, Grafana Tempo or Jaeger](trace-backends.md) | wiring the collector to your trace backend |
| [Generate the monthly report for a customer security review](monthly-report.md) | answering "do you send our data to LLM providers?" with evidence |

All examples use fake data. Never test with real personal data or real keys.
