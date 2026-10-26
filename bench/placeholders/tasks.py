"""Tasks for the placeholder evaluation. Fake data only.

Each task is a small, realistic agent job. Taintward replaces the sensitive
values with placeholders before the request leaves, so the model only sees
<PERSON_1>, <EMAIL_1>, ... The checks say which real values must come back in
the final answer (or in a tool call) after restore.

Fields of a task:

    id, category
    system      optional system prompt of the app
    turns       user messages, sent one after another (multi-turn when > 1)
    tools       tool names offered to the model (see TOOLS)
    must        real values that must be in the final answer
    tool_args   (tool, argument, value): the tool must be called and the
                restored argument must contain the value
    json_fields (key, value): the final answer is JSON; the field must hold
                the value (dotted keys go into nested objects / list items)
    json_items  (key_a, a, key_b, b): the final answer is a JSON list with an
                item whose key_a holds a and whose key_b holds b (any order)
    pairs       (a, b): on the line of the answer that has value a, value b
                must be there too (catches swapped people in lists)
    raws        every sensitive value in the task; none may reach the model
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Person:
    name: str
    email: str
    ssn: str
    phone: str


MARIA = Person("Maria Garcia", "maria.garcia@example.com", "536-22-8491", "+1 415 555 0134")
WEI = Person("Wei Chen", "wei.chen@example.org", "412-73-1955", "+1 212 555 0178")
AISHA = Person("Aisha Okafor", "aisha.okafor@example.net", "233-41-6702", "+1 646 555 0199")
LUKAS = Person("Lukas Becker", "lukas.becker@example.com", "701-18-4420", "+1 303 555 0111")
PRIYA = Person("Priya Sharma", "priya.sharma@example.com", "612-30-5518", "+1 408 555 0162")
SOFIA = Person("Sofia Rossi", "sofia.rossi@example.org", "318-52-7740", "+1 617 555 0145")
DANIEL = Person("Daniel Kim", "daniel.kim@example.net", "455-61-2093", "+1 206 555 0127")
FATIMA = Person("Fatima Haddad", "fatima.haddad@example.com", "527-84-3316", "+1 312 555 0183")

AWS_1 = "AKIAEXAMPLEEXAMPLEE5"
AWS_2 = "AKIAEXAMPLEEXAMPLEE3"
GH_1 = "ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE6"
CARD_1 = "4111 1111 1111 1111"
CARD_2 = "5555 5555 5555 4444"
IBAN_1 = "DE89370400440532013000"


def _p(*people: Person, fields=("name", "email", "ssn", "phone")) -> list[str]:
    return [getattr(p, f) for p in people for f in fields]


@dataclass(frozen=True)
class Task:
    id: str
    category: str
    turns: tuple[str, ...]
    raws: tuple[str, ...]
    system: str | None = None
    tools: tuple[str, ...] = ()
    must: tuple[str, ...] = ()
    tool_args: tuple[tuple[str, str, str], ...] = ()
    json_fields: tuple[tuple[str, str], ...] = ()
    json_items: tuple[tuple[str, str, str, str], ...] = ()
    pairs: tuple[tuple[str, str], ...] = ()
    notes: str = ""
    extra: dict = field(default_factory=dict)


def T(id, category, turns, raws, **kw) -> Task:
    if isinstance(turns, str):
        turns = (turns,)
    conv = {k: tuple(tuple(x) if isinstance(x, list) else x for x in v)
            for k, v in kw.items()
            if k in ("must", "tool_args", "json_fields", "json_items", "pairs", "tools")}
    kw.update(conv)
    return Task(id, category, tuple(turns), tuple(raws), **kw)


SUPPORT = "You are a helpful assistant for a customer support team. Be brief."

# ---------------------------------------------------------------------------
# Tools offered to the model (OpenAI function schema) and fake implementations.
# ---------------------------------------------------------------------------

TOOLS = {
    "send_email": {
        "description": "Send an email.",
        "parameters": {"type": "object", "properties": {
            "to": {"type": "string", "description": "recipient email address"},
            "subject": {"type": "string"},
            "body": {"type": "string"}},
            "required": ["to", "subject", "body"]},
    },
    "lookup_customer": {
        "description": "Look up a customer record by social security number.",
        "parameters": {"type": "object", "properties": {
            "ssn": {"type": "string", "description": "the SSN, like 123-45-6789"}},
            "required": ["ssn"]},
    },
    "schedule_call": {
        "description": "Schedule a phone call with a person.",
        "parameters": {"type": "object", "properties": {
            "name": {"type": "string"}, "phone": {"type": "string"},
            "time": {"type": "string"}},
            "required": ["name", "phone", "time"]},
    },
    "create_ticket": {
        "description": "Create a support ticket for a customer.",
        "parameters": {"type": "object", "properties": {
            "customer_name": {"type": "string"}, "customer_email": {"type": "string"},
            "summary": {"type": "string"}},
            "required": ["customer_name", "customer_email", "summary"]},
    },
    "rotate_key": {
        "description": "Disable a leaked cloud access key.",
        "parameters": {"type": "object", "properties": {
            "access_key_id": {"type": "string"}}, "required": ["access_key_id"]},
    },
}

# Records returned by lookup_customer, keyed by SSN.
RECORDS = {
    WEI.ssn: {"name": WEI.name, "email": WEI.email, "plan": "pro", "balance": "120.00 USD"},
    AISHA.ssn: {"name": AISHA.name, "email": AISHA.email, "plan": "basic",
                "balance": "0.00 USD"},
    FATIMA.ssn: {"name": FATIMA.name, "email": FATIMA.email, "plan": "team",
                 "balance": "48.50 USD"},
}


def run_tool(name: str, args: dict) -> str:
    """The fake tools. They get the restored (real) arguments."""
    import json
    if name == "lookup_customer":
        rec = RECORDS.get(str(args.get("ssn", "")).strip())
        return json.dumps(rec if rec else {"error": "no customer with that SSN"})
    if name == "send_email":
        return json.dumps({"status": "sent", "to": args.get("to")})
    if name == "schedule_call":
        return json.dumps({"status": "scheduled", "with": args.get("name")})
    if name == "create_ticket":
        return json.dumps({"status": "created", "ticket": "T-1042"})
    if name == "rotate_key":
        return json.dumps({"status": "disabled"})
    return json.dumps({"error": "unknown tool"})


# ---------------------------------------------------------------------------
# The tasks
# ---------------------------------------------------------------------------

TASKS: list[Task] = [
    # --- emails and letters to a person -----------------------------------
    T("email-refund", "email",
      f"Write a short email to {MARIA.name} ({MARIA.email}) telling her that her refund "
      "was approved. Start with 'Dear' and her full name, and put her email address "
      "on a 'To:' line at the top.",
      [MARIA.name, MARIA.email], system=SUPPORT, must=[MARIA.name, MARIA.email]),
    T("email-missing-form", "email",
      f"Remind {WEI.name} that his tax form is missing. His SSN is {WEI.ssn}; mention "
      "the SSN in the letter so he knows which file it is. Address him by full name.",
      [WEI.name, WEI.ssn], must=[WEI.name, WEI.ssn]),
    T("letter-landlord", "email",
      f"Draft a formal letter from {LUKAS.name} to his landlord {SOFIA.name} asking to "
      "fix the heating. Sign it with the sender's full name and put the landlord's "
      "full name in the greeting.",
      [LUKAS.name, SOFIA.name], must=[LUKAS.name, SOFIA.name]),
    T("email-callback", "email",
      f"Write a two sentence note asking {AISHA.name} to call us back. Include her "
      f"phone number {AISHA.phone} so the agent can dial it.",
      [AISHA.name, AISHA.phone], system=SUPPORT, must=[AISHA.name, AISHA.phone]),
    T("email-card-blocked", "email",
      f"Tell {DANIEL.name} that the card {CARD_1} was blocked after a fraud alert. "
      "Repeat the card number so he can check it. Use his full name.",
      [DANIEL.name, CARD_1], system=SUPPORT, must=[DANIEL.name, CARD_1]),
    T("email-intro", "email",
      f"Write an email introducing {PRIYA.name} ({PRIYA.email}) to {DANIEL.name} "
      f"({DANIEL.email}). Mention both names and both email addresses.",
      _p(PRIYA, DANIEL, fields=("name", "email")),
      must=[PRIYA.name, PRIYA.email, DANIEL.name, DANIEL.email]),
    T("email-iban", "email",
      f"Write a payment reminder to {FATIMA.name}. The invoice must be paid to IBAN "
      f"{IBAN_1}. Include the IBAN exactly.",
      [FATIMA.name, IBAN_1], must=[FATIMA.name, IBAN_1]),
    T("email-reply-thread", "email",
      f"Here is an email I got:\n\nFrom: {SOFIA.email}\nHi, this is {SOFIA.name}. My "
      "order arrived broken. Can you send a new one?\n\nWrite my reply. Greet her by "
      "her full name.",
      [SOFIA.name, SOFIA.email], system=SUPPORT, must=[SOFIA.name]),

    # --- summaries of records ---------------------------------------------
    T("summary-ticket", "summary",
      f"Summarize this ticket in two sentences, naming the customer:\n\nCustomer: "
      f"{MARIA.name}\nEmail: {MARIA.email}\nIssue: charged twice for the March "
      "invoice, wants one charge refunded.",
      [MARIA.name, MARIA.email], must=[MARIA.name]),
    T("summary-hr", "summary",
      f"Summarize this HR note in one line and keep the employee name and SSN:\n"
      f"Employee {LUKAS.name}, SSN {LUKAS.ssn}, moves to the Berlin team on May 1.",
      [LUKAS.name, LUKAS.ssn], must=[LUKAS.name, LUKAS.ssn]),
    T("summary-call-log", "summary",
      f"Call log:\n09:10 {WEI.name} called from {WEI.phone} about a late delivery.\n"
      f"09:40 {AISHA.name} called from {AISHA.phone} to cancel her plan.\n\nWrite one "
      "bullet per call with the caller's name and number.",
      _p(WEI, AISHA, fields=("name", "phone")),
      must=[WEI.name, WEI.phone, AISHA.name, AISHA.phone],
      pairs=[(WEI.name, WEI.phone), (AISHA.name, AISHA.phone)]),
    T("summary-incident", "summary",
      f"Incident: the access key {AWS_1} was found in a public repo by {PRIYA.name}. "
      "Write a three line incident summary that names the key and who found it.",
      [AWS_1, PRIYA.name], must=[AWS_1, PRIYA.name]),
    T("summary-medical", "summary",
      f"Patient {FATIMA.name} (phone {FATIMA.phone}) missed two appointments. Write a "
      "short note for the clinic manager with the patient's name and phone.",
      [FATIMA.name, FATIMA.phone], must=[FATIMA.name, FATIMA.phone]),
    T("summary-payment", "summary",
      f"Payment record: payer {DANIEL.name}, card {CARD_2}, amount 89.00 USD, status "
      "declined. Rewrite it as one plain sentence that keeps the payer and the card.",
      [DANIEL.name, CARD_2], must=[DANIEL.name, CARD_2]),

    # --- JSON extraction --------------------------------------------------
    T("json-contact", "json",
      f"Extract the contact as JSON with keys name, email, phone. Reply with JSON "
      f"only.\n\nHi, I'm {SOFIA.name}, reach me at {SOFIA.email} or {SOFIA.phone}.",
      _p(SOFIA, fields=("name", "email", "phone")),
      json_fields=[("name", SOFIA.name), ("email", SOFIA.email), ("phone", SOFIA.phone)]),
    T("json-ssn", "json",
      f"Return JSON with keys employee and ssn for this line, JSON only: "
      f"'{LUKAS.name} - SSN {LUKAS.ssn} - joined 2021'.",
      [LUKAS.name, LUKAS.ssn],
      json_fields=[("employee", LUKAS.name), ("ssn", LUKAS.ssn)]),
    T("json-two-people", "json",
      f"Turn this into a JSON list of objects with keys name and email, JSON only:\n"
      f"{WEI.name} <{WEI.email}>\n{PRIYA.name} <{PRIYA.email}>",
      _p(WEI, PRIYA, fields=("name", "email")),
      json_items=[("name", WEI.name, "email", WEI.email),
                  ("name", PRIYA.name, "email", PRIYA.email)]),
    T("json-payment", "json",
      f"Extract JSON with keys payer, card, iban from: '{FATIMA.name} paid with card "
      f"{CARD_1}, refund to {IBAN_1}'. JSON only.",
      [FATIMA.name, CARD_1, IBAN_1],
      json_fields=[("payer", FATIMA.name), ("card", CARD_1), ("iban", IBAN_1)]),
    T("json-nested", "json",
      f"Make JSON {{\"customer\": {{\"name\": ..., \"ssn\": ...}}, \"agent\": ...}} "
      f"from: agent {DANIEL.name} helped customer {AISHA.name} (SSN {AISHA.ssn}). "
      "JSON only.",
      [DANIEL.name, AISHA.name, AISHA.ssn],
      json_fields=[("customer.name", AISHA.name), ("customer.ssn", AISHA.ssn),
                   ("agent", DANIEL.name)]),
    T("json-secret", "json",
      f"Config line: aws_access_key_id = {AWS_2}, owner = {MARIA.email}. Return it as "
      "JSON with keys key_id and owner. JSON only.",
      [AWS_2, MARIA.email],
      json_fields=[("key_id", AWS_2), ("owner", MARIA.email)]),

    # --- tool calling -----------------------------------------------------
    T("tool-send-email", "tool",
      f"Email {MARIA.name} at {MARIA.email} that her parcel ships tomorrow. Use the "
      "send_email tool.",
      [MARIA.name, MARIA.email], system=SUPPORT, tools=["send_email"],
      tool_args=[("send_email", "to", MARIA.email), ("send_email", "body", MARIA.name)]),
    T("tool-lookup-ssn", "tool",
      f"Look up the customer with SSN {WEI.ssn} and tell me their name and plan.",
      [WEI.ssn, WEI.name, WEI.email], system=SUPPORT, tools=["lookup_customer"],
      tool_args=[("lookup_customer", "ssn", WEI.ssn)], must=[WEI.name]),
    T("tool-lookup-then-email", "tool",
      f"Find the customer with SSN {AISHA.ssn} using lookup_customer, then email them "
      "with send_email that their balance is settled. Use the email from the record.",
      [AISHA.ssn, AISHA.name, AISHA.email], system=SUPPORT,
      tools=["lookup_customer", "send_email"],
      tool_args=[("lookup_customer", "ssn", AISHA.ssn), ("send_email", "to", AISHA.email)]),
    T("tool-schedule", "tool",
      f"Schedule a call with {LUKAS.name} at {LUKAS.phone} for 3pm Friday.",
      [LUKAS.name, LUKAS.phone], tools=["schedule_call"],
      tool_args=[("schedule_call", "name", LUKAS.name), ("schedule_call", "phone", LUKAS.phone)]),
    T("tool-ticket", "tool",
      f"Open a ticket: {SOFIA.name} ({SOFIA.email}) cannot log in since yesterday.",
      [SOFIA.name, SOFIA.email], system=SUPPORT, tools=["create_ticket"],
      tool_args=[("create_ticket", "customer_name", SOFIA.name),
                 ("create_ticket", "customer_email", SOFIA.email)]),
    T("tool-rotate-key", "tool",
      f"This key leaked in a log: {AWS_1}. Disable it now.",
      [AWS_1], tools=["rotate_key"], tool_args=[("rotate_key", "access_key_id", AWS_1)]),
    T("tool-pick-person", "tool",
      f"We have two customers: {WEI.name} ({WEI.email}) and {PRIYA.name} "
      f"({PRIYA.email}). Only {PRIYA.name} asked for the invoice. Email the invoice "
      "link https://example.com/inv/77 to the right one.",
      _p(WEI, PRIYA, fields=("name", "email")), system=SUPPORT, tools=["send_email"],
      tool_args=[("send_email", "to", PRIYA.email)]),
    T("tool-lookup-two", "tool",
      f"Look up both customers, SSN {WEI.ssn} and SSN {FATIMA.ssn}, and tell me "
      "which one has the higher balance, by name.",
      [WEI.ssn, FATIMA.ssn, WEI.name, FATIMA.name, WEI.email, FATIMA.email],
      system=SUPPORT, tools=["lookup_customer"],
      tool_args=[("lookup_customer", "ssn", WEI.ssn), ("lookup_customer", "ssn", FATIMA.ssn)],
      must=[WEI.name]),

    # --- multi-turn conversations -----------------------------------------
    T("multi-remember-name", "multi",
      [f"Hi, my name is {DANIEL.name} and my email is {DANIEL.email}.",
       "I want to change my delivery address to the office.",
       "Write the confirmation email for me. Put my email on a 'To:' line and greet me "
       "by my full name."],
      [DANIEL.name, DANIEL.email], system=SUPPORT, must=[DANIEL.name, DANIEL.email]),
    T("multi-two-people", "multi",
      [f"My manager is {SOFIA.name} and my colleague is {LUKAS.name}.",
       "Who is my manager? Answer with the full name only."],
      [SOFIA.name, LUKAS.name], must=[SOFIA.name]),
    T("multi-ssn-later", "multi",
      [f"I'm filing a claim. My SSN is {PRIYA.ssn}.",
       "Thanks. What SSN did I give you? Repeat it exactly."],
      [PRIYA.ssn], must=[PRIYA.ssn]),
    T("multi-correct", "multi",
      [f"Send the report to {WEI.email}.",
       f"Sorry, wrong address. Use {AISHA.email} instead. Which address will you use? "
       "Reply with the address only."],
      [WEI.email, AISHA.email], must=[AISHA.email]),
    T("multi-tool", "multi",
      [f"Customer {MARIA.name} wrote in, her email is {MARIA.email}.",
       "Please email her with send_email that her ticket is resolved."],
      [MARIA.name, MARIA.email], system=SUPPORT, tools=["send_email"],
      tool_args=[("send_email", "to", MARIA.email)]),

    # --- translation (placeholders must survive) --------------------------
    T("translate-es", "translate",
      f"Translate to Spanish: 'Please call {AISHA.name} at {AISHA.phone} before Friday.'",
      [AISHA.name, AISHA.phone], must=[AISHA.name, AISHA.phone]),
    T("translate-fr", "translate",
      f"Translate to French: 'Dear {LUKAS.name}, your new password was sent to "
      f"{LUKAS.email}.'",
      [LUKAS.name, LUKAS.email], must=[LUKAS.name, LUKAS.email]),
    T("translate-de", "translate",
      f"Translate into German: '{MARIA.name} and {WEI.name} will join the meeting.'",
      [MARIA.name, WEI.name], must=[MARIA.name, WEI.name]),
    T("translate-hi", "translate",
      f"Translate to Hindi: 'Your SSN {DANIEL.ssn} was verified, {DANIEL.name}.'",
      [DANIEL.name, DANIEL.ssn], must=[DANIEL.name, DANIEL.ssn]),
    T("translate-ja", "translate",
      f"Translate to Japanese: 'Please send the contract to {PRIYA.name} "
      f"({PRIYA.email}).'",
      [PRIYA.name, PRIYA.email], must=[PRIYA.name, PRIYA.email]),
    T("translate-zh", "translate",
      f"Translate to Chinese: '{FATIMA.name} paid with card {CARD_2}.'",
      [FATIMA.name, CARD_2], must=[FATIMA.name, CARD_2]),

    # --- lists of several people ------------------------------------------
    T("list-roster", "list",
      f"Team: {MARIA.name} ({MARIA.email}), {WEI.name} ({WEI.email}), {AISHA.name} "
      f"({AISHA.email}). Make a bullet list, one person per line, 'name - email'.",
      _p(MARIA, WEI, AISHA, fields=("name", "email")),
      must=[MARIA.name, WEI.name, AISHA.name, MARIA.email, WEI.email, AISHA.email],
      pairs=[(MARIA.name, MARIA.email), (WEI.name, WEI.email), (AISHA.name, AISHA.email)]),
    T("list-sort", "list",
      f"Sort these people by last name, one per line: {SOFIA.name}, {DANIEL.name}, "
      f"{LUKAS.name}, {FATIMA.name}.",
      [SOFIA.name, DANIEL.name, LUKAS.name, FATIMA.name],
      must=[SOFIA.name, DANIEL.name, LUKAS.name, FATIMA.name]),
    T("list-table", "list",
      f"Make a markdown table with columns Name and SSN:\n{PRIYA.name} {PRIYA.ssn}\n"
      f"{LUKAS.name} {LUKAS.ssn}\n{WEI.name} {WEI.ssn}",
      _p(PRIYA, LUKAS, WEI, fields=("name", "ssn")),
      must=[PRIYA.name, LUKAS.name, WEI.name, PRIYA.ssn, LUKAS.ssn, WEI.ssn],
      pairs=[(PRIYA.name, PRIYA.ssn), (LUKAS.name, LUKAS.ssn), (WEI.name, WEI.ssn)]),
    T("list-filter", "list",
      f"Customers: {MARIA.name} (plan pro), {DANIEL.name} (plan basic), {SOFIA.name} "
      "(plan pro). List only the names on the pro plan, one per line.",
      [MARIA.name, DANIEL.name, SOFIA.name], must=[MARIA.name, SOFIA.name]),

    # --- code that embeds a key -------------------------------------------
    T("code-boto3", "code",
      f"Write a Python snippet that creates a boto3 S3 client with access key id "
      f"{AWS_1}. Put the key id in the code as a string literal.",
      [AWS_1], must=[AWS_1]),
    T("code-github", "code",
      f"Write a curl command that lists my GitHub repos using the token {GH_1}. Put "
      "the token in the Authorization header.",
      [GH_1], must=[GH_1]),
    T("code-env", "code",
      f"Make a .env file with AWS_ACCESS_KEY_ID={AWS_2} and ADMIN_EMAIL={PRIYA.email}.",
      [AWS_2, PRIYA.email], must=[AWS_2, PRIYA.email]),
    T("code-fix", "code",
      f"Fix the bug in this code and return the full fixed code:\n\n"
      f"key = '{AWS_1}'\nowner = '{LUKAS.email}'\nprint('owner is' owner)\n",
      [AWS_1, LUKAS.email], must=[AWS_1, LUKAS.email]),
]


def by_id(task_id: str) -> Task:
    for t in TASKS:
        if t.id == task_id:
            return t
    raise KeyError(task_id)
