# Protect a LangGraph support bot

**Goal:** a customer support agent built with LangGraph (or LangChain's
`create_agent`) looks up customers, writes notes in your CRM and opens
tickets in an outside helpdesk. Customer names, emails, card numbers and SSNs
must not reach the LLM provider or the helpdesk in raw form, and the bot must
still work.

**Time:** about 20 minutes. **You need:** Python 3.11+, an agent that uses
LangChain tools, and (for the spans) the quickstart Docker stack or any OTLP
endpoint.

## 1. Install

```bash
pip install "taintward[langchain]" langchain-openai
python -m spacy download en_core_web_sm
export TAINTWARD_FPE_KEY=$(python -c "import os; print(os.urandom(32).hex())")
```

Store the key in your secret manager. Tokens written to your CRM can only be
reversed with this key, and they change if the key changes. See
[Key management](../key-management.md).

## 2. List your tools and pick a destination for each

| tool | where its input goes | destination | allow |
|---|---|---|---|
| `lookup_customer(email)` | your customer database | `internal` | `email`: the query needs the real address |
| `save_note(customer_email, note)` | your CRM | `internal` | `customer_email`: the CRM keys records on it |
| `create_ticket(subject, body)` | a SaaS helpdesk in the US | `external`, jurisdiction `us` | none |
| the chat model | the LLM provider, in the US | `llm` (set by `protect_langchain_model`) | none |

Rules of thumb:

- If you are not sure, leave the tool out of the map. It is then `external`
  and gets masks. You can always loosen it later.
- Only put an argument in `allow` when the tool cannot work without the raw
  value. Every entry is a place where raw data leaves on purpose.

## 3. Wire it in

```python
import taintward as tw
from langchain.agents import create_agent
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI


@tool
def lookup_customer(email: str) -> dict:
    """Find a customer by email address."""
    return crm.find(email)              # your code


@tool
def save_note(customer_email: str, note: str) -> str:
    """Save a note on the customer record."""
    return crm.add_note(customer_email, note)


@tool
def create_ticket(subject: str, body: str) -> str:
    """Open a ticket in the outside helpdesk."""
    return helpdesk.create(subject=subject, body=body)


tw.init(
    "support-bot",
    endpoint="http://localhost:14319/v1/traces",   # the collector; SigNoz: :4318
    destinations={
        "lookup_customer": {"destination": "internal", "allow": ["email"]},
        "save_note": {"destination": "internal", "allow": ["customer_email"]},
        "create_ticket": ("external", "us"),
    },
    llm_jurisdiction="us",
)
tools = tw.wrap_langchain_tools([lookup_customer, save_note, create_ticket])
model = tw.protect_langchain_model(ChatOpenAI(model="gpt-4.1-mini"))
agent = create_agent(model, tools)     # or langgraph.prebuilt.create_react_agent


def handle(request: str) -> str:
    with tw.run("support-bot.run"):    # one run per user request
        result = agent.invoke({"messages": [("user", request)]})
    return result["messages"][-1].content
```

Put `tw.run()` around each user request, not around the whole process: it
starts a clean taint slate and a fresh placeholder map for that request.

## 4. What each part receives

For the request `alice.lee@example.com wants a refund, please open a ticket`,
with `lookup_customer` returning a fake record (`Alice Lee`, SSN
`234-12-1234`, card `4111 1111 1111 1111`):

| receiver | gets |
|---|---|
| LLM provider | `<EMAIL_1> wants a refund ...` and the record as `{"name": "<PERSON_1>", "email": "<EMAIL_1>", "ssn": "<SSN_1>", "card": "<CARD_1>", "plan": "pro"}` |
| `lookup_customer` | `email="alice.lee@example.com"` (allowed) |
| `save_note` | `customer_email="alice.lee@example.com"` (allowed), `note="c4lcr x7r asked about card 4378 8307 4206 0971"` (reversible tokens) |
| `create_ticket` | `subject="Refund for [PII]"`, `body="Card [PII], SSN [PII]"` |
| your code (`handle()` return) | `Done: ticket 1042 opened for Alice Lee.` (placeholders restored) |

The exact token strings depend on your key.

## 5. Check it

Run one request, then look at the trace in Jaeger (service `support-bot`) or
SigNoz:

- every `chat ...` span that carried customer data (here all of them, since
  the request holds an email address) has
  `taintward.violation=true`, `taintward.redacted=true`, and
  `gen_ai.input.messages` with placeholders only;
- `create_ticket` has `taintward.violation=true` and, after the collector,
  `taintward.policy.transfer_violation=true` (PII to `us`);
- `lookup_customer` and `save_note` have no violation (`internal`).

Add a test that fails if a raw value reaches the helpdesk. Fake models and
an in-memory exporter keep it offline:

```python
from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.messages import AIMessage
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter


class FakeModel(FakeMessagesListChatModel):
    def bind_tools(self, tools, **kwargs):
        return self


def test_helpdesk_gets_no_raw_data(monkeypatch):
    sent = []
    monkeypatch.setattr(helpdesk, "create", lambda **kw: sent.append(kw) or "ticket 1")
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tw.init("support-bot-test", tracer=provider.get_tracer("test"), destinations={...})  # same map

    call = lambda i, name, args: AIMessage("", tool_calls=[{"name": name, "args": args, "id": str(i)}])
    model = FakeModel(responses=[
        call(1, "lookup_customer", {"email": "<EMAIL_1>"}),
        call(2, "create_ticket", {"subject": "Refund for <PERSON_1>", "body": "SSN <SSN_1>"}),
        AIMessage("done"),
    ])
    agent = create_agent(tw.protect_langchain_model(model),
                         tw.wrap_langchain_tools([lookup_customer, create_ticket]))
    with tw.run("test"):
        agent.invoke({"messages": [("user", "alice.lee@example.com wants a refund")]})

    assert "234-12-1234" not in str(sent) and "Alice Lee" not in str(sent)
    assert any(s.attributes.get("taintward.violation") for s in exporter.get_finished_spans())
```

## 6. Before production

- Run in audit mode for a week first if the bot is already live:
  [Audit mode first, then enforce](audit-then-enforce.md).
- Streaming: if you use `model.stream()`, the streamed chunks are not
  restored. Collect the text and call `tw.restore(text)` inside the same
  `run()`.
- If the OpenAI Agents SDK or another library has its own tracing that
  uploads prompts, turn it off; Taintward only protects the calls it wraps.
- Callbacks attached to an unprotected model or tool see raw data.
- All limits: [SDK integrations, Limits](../integrations.md#limits).
