"""LangGraph agent protected by AgentWard with a few lines of setup.

The setup is the block marked "AgentWard setup". Everything else is a normal
LangGraph agent. Runs offline: the model is a scripted fake that calls the
tools the way a real model would (look up a record, email it out, cache it).

    python demo/langgraph_example.py             # spans to SigNoz on :4318
    python demo/langgraph_example.py --console   # also print spans

To use a real model, replace FakeModel(...) with e.g. ChatOpenAI(model=...)
from langchain-openai and keep the protect_langchain_model() call.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.messages import AIMessage
from langchain_core.tools import tool

from sdk import integrations as agentward

OUTBOX: list[str] = []   # what the external email service received
CACHE: list[str] = []    # what the internal cache received
PROMPTS: list[str] = []  # what the LLM provider received


@tool
def search_db(employee: str) -> str:
    """Read an employee record from the HR database."""
    return f"{employee}: ssn 234-12-1234, aws key AKIAIOSFODNN7EXAMPLE"


@tool
def cache_record(record: str) -> str:
    """Save a record in the internal cache."""
    CACHE.append(record)
    return "cached"


@tool
def send_email(to: str, body: str) -> str:
    """Send an email to an outside address."""
    OUTBOX.append(body)
    return "sent"


class FakeModel(FakeMessagesListChatModel):
    """Scripted stand-in for a tool-calling chat model."""

    def bind_tools(self, tools, **kwargs):
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        PROMPTS.append(" | ".join(str(m.content) for m in messages))
        return super()._generate(messages, stop=stop, run_manager=run_manager, **kwargs)


def scripted_model() -> FakeModel:
    record = "alice: ssn 234-12-1234, aws key AKIAIOSFODNN7EXAMPLE"
    return FakeModel(responses=[
        AIMessage("", tool_calls=[{"name": "search_db", "args": {"employee": "alice"}, "id": "1"}]),
        AIMessage("", tool_calls=[{"name": "cache_record", "args": {"record": record}, "id": "2"}]),
        AIMessage("", tool_calls=[{"name": "send_email",
                                   "args": {"to": "auditor@example.com", "body": record}, "id": "3"}]),
        AIMessage("Done: record cached and sent to the auditor."),
    ])


def build_agent(tools, model):
    try:
        from langchain.agents import create_agent
        return create_agent(model, tools)
    except ImportError:  # langgraph only
        from langgraph.prebuilt import create_react_agent
        return create_react_agent(model, tools)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--console", action="store_true", help="also print spans")
    ap.add_argument("--endpoint", default=None, help="OTLP/HTTP traces endpoint")
    args = ap.parse_args()

    # --- AgentWard setup -------------------------------------------------
    agentward.init("langgraph-demo", endpoint=args.endpoint, console=args.console,
                   destinations={"search_db": "internal", "cache_record": "internal",
                                 "send_email": "external"})
    tools = agentward.wrap_langchain_tools([search_db, cache_record, send_email])
    model = agentward.protect_langchain_model(scripted_model())
    agent = build_agent(tools, model)
    # ---------------------------------------------------------------------

    with agentward.run("langgraph-demo.run"):
        result = agent.invoke({"messages": [("user", "Please send the record for alice to the auditor.")]})

    print("agent  :", result["messages"][-1].content)
    print("email  :", OUTBOX)  # masked: [PII] / [SECRET]
    print("cache  :", CACHE)   # reversible token in place of the SSN
    print("to LLM :", PROMPTS[-1])

    from opentelemetry import trace
    provider = trace.get_tracer_provider()
    if hasattr(provider, "force_flush"):
        provider.force_flush()


if __name__ == "__main__":
    main()
