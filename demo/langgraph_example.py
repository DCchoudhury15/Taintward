"""LangGraph agent protected by Taintward with a few lines of setup.

The setup is the block marked "Taintward setup". Everything else is a normal
LangGraph agent. Runs offline: the model is a scripted fake that answers the
way a real model would. It only ever sees placeholders such as <PERSON_1> and
<SSN_1>, never the real name, email or SSN, and it still finishes the task:
look up the employee, email her a reminder, save a note, and tell the user
what it did.

    python demo/langgraph_example.py             # spans to SigNoz on :4318
    python demo/langgraph_example.py --console   # also print spans
    python demo/langgraph_example.py --masks     # old behaviour: [PII] masks

To use a real model, replace scripted_model() with e.g. ChatOpenAI(model=...)
from langchain-openai and keep the protect_langchain_model() call.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.messages import AIMessage
from langchain_core.tools import tool

from taintward.sdk import integrations as taintward

OUTBOX: list[dict] = []  # what the external email service received
CACHE: list[str] = []    # what the internal cache received
PROMPTS: list[str] = []  # what the LLM provider received

USER_REQUEST = ("Remind Alice Lee (alice.lee@example.com) that her tax form is "
                "missing, and save a note in the HR cache.")


@tool
def search_db(employee: str) -> str:
    """Read an employee record from the HR database."""
    return f"{employee}: ssn 234-12-1234, tax form missing, aws key AKIAIOSFODNN7EXAMPLE"


@tool
def cache_record(record: str) -> str:
    """Save a record in the internal cache."""
    CACHE.append(record)
    return "cached"


@tool
def send_email(to: str, body: str) -> str:
    """Send an email to an outside address."""
    OUTBOX.append({"to": to, "body": body})
    return "sent"


class FakeModel(FakeMessagesListChatModel):
    """Scripted stand-in for a tool-calling chat model."""

    def bind_tools(self, tools, **kwargs):
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        PROMPTS.append(" | ".join(str(m.content) for m in messages))
        return super()._generate(messages, stop=stop, run_manager=run_manager, **kwargs)


def scripted_model(masks: bool = False) -> FakeModel:
    """The answers a real model gives when it sees the placeholder prompt.

    With masks the model only sees [PII], so the best it can do is copy the
    mask: the email goes nowhere and the user gets no useful answer."""
    def call(i, name, args):
        if masks:
            args = {k: re.sub(r"<[A-Z_]+_\d+>", "[PII]", v) for k, v in args.items()}
        return AIMessage("", tool_calls=[{"name": name, "args": args, "id": str(i)}])

    final = ("Done: I emailed <PERSON_1> at <EMAIL_1> about the missing tax form "
             "and saved a note in the HR cache.")
    if masks:
        final = re.sub(r"<[A-Z_]+_\d+>", "[PII]", final)
    return FakeModel(responses=[
        call(1, "search_db", {"employee": "<PERSON_1>"}),
        call(2, "send_email", {"to": "<EMAIL_1>",
                               "body": "Hi <PERSON_1>, your tax form is still missing. "
                                       "Please reply with the form."}),
        call(3, "cache_record", {"record": "Reminded <PERSON_1> (ssn <SSN_1>) about the tax form."}),
        AIMessage(final),
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
    ap.add_argument("--masks", action="store_true",
                    help="turn placeholders off (the LLM gets [PII] masks)")
    args = ap.parse_args()

    # --- Taintward setup -------------------------------------------------
    taintward.init("langgraph-demo", endpoint=args.endpoint, console=args.console,
                   placeholders=not args.masks,
                   destinations={
                       # the HR database needs the real name to run its query
                       "search_db": {"destination": "internal", "allow": ["employee"]},
                       "cache_record": "internal",
                       # the mail service needs the real address, nothing else
                       "send_email": {"destination": "external", "allow": ["to"]},
                   })
    tools = taintward.wrap_langchain_tools([search_db, cache_record, send_email])
    model = taintward.protect_langchain_model(scripted_model(masks=args.masks))
    agent = build_agent(tools, model)
    # ---------------------------------------------------------------------

    with taintward.run("langgraph-demo.run"):
        result = agent.invoke({"messages": [("user", USER_REQUEST)]})

    print("user   :", USER_REQUEST)
    print("to LLM :", PROMPTS[-1])            # placeholders only
    print("agent  :", result["messages"][-1].content)  # real values, for the user
    print("email  :", OUTBOX)                  # real address (allow), body masked
    print("cache  :", CACHE)                   # reversible tokens

    from opentelemetry import trace
    provider = trace.get_tracer_provider()
    if hasattr(provider, "force_flush"):
        provider.force_flush()


if __name__ == "__main__":
    main()
