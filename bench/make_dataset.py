"""Generate the AgentWard detection benchmark dataset.

Everything here is synthetic and seeded, so running this script again gives a
byte-identical file. No real person's data is used: names are random pairs
from common first/last name lists, numbers are random digits that only follow
the right *format* (and checksum where the format has one, like Luhn for cards
or mod-97 for IBANs), keys and tokens are random characters in the right shape.

Output: bench/data/detection.jsonl, one example per line:

    {
      "id": "ex-0001",
      "format": "json" | "chat" | "log" | "email" | "code",
      "kind": "positive" | "negative" | "evasion",
      "tag": short label of what the example is about (e.g. "US_SSN",
             "neg:uuid", "evasion:fullwidth"),
      "text": the raw tool I/O string,
      "entities": [{"type": ..., "start": ..., "end": ..., "value": ...}]
    }

``start``/``end`` are character offsets into ``text`` (Python str indexing,
end exclusive). Negative examples have an empty ``entities`` list.

Usage:  python bench/make_dataset.py [--seed 1337] [--out bench/data/detection.jsonl]
"""

from __future__ import annotations

import argparse
import base64
import json
import random
import string
from pathlib import Path

ENTITY_TYPES = [
    "US_SSN", "EMAIL", "PHONE", "CREDIT_CARD", "IBAN", "PERSON", "ADDRESS",
    "AWS_ACCESS_KEY", "GITHUB_TOKEN", "GENERIC_API_KEY", "JWT", "PRIVATE_KEY",
]

FIRST = ["Maria", "James", "Priya", "Wei", "Fatima", "Lukas", "Sofia", "Daniel",
         "Aisha", "Mateo", "Hannah", "Kenji", "Olivia", "Arjun", "Elena", "Noah",
         "Chloe", "Omar", "Ingrid", "Samuel", "Yuki", "Grace", "Rahul", "Lena"]
LAST = ["Garcia", "Smith", "Sharma", "Chen", "Khan", "Muller", "Rossi", "Johnson",
        "Okafor", "Lopez", "Schmidt", "Tanaka", "Brown", "Patel", "Petrova",
        "Wilson", "Dubois", "Haddad", "Larsen", "Cohen", "Sato", "Kim", "Gupta",
        "Novak"]
STREETS = ["Maple", "Oak", "Cedar", "Pine", "Elm", "Willow", "Lakeview",
           "Hillcrest", "Sunset", "Riverside", "Park", "Washington", "Mill"]
STREET_SUFFIX = ["St", "Ave", "Rd", "Blvd", "Lane", "Drive", "Court"]
CITIES = [("Springfield", "IL"), ("Riverton", "WY"), ("Fairview", "TX"),
          ("Madison", "WI"), ("Georgetown", "KY"), ("Salem", "OR"),
          ("Franklin", "TN"), ("Clinton", "IA"), ("Greenville", "SC"),
          ("Arlington", "VA")]
AREA_CODES = ["212", "312", "415", "617", "646", "702", "713", "818", "206",
              "303", "404", "512", "720", "919"]
DOMAINS = ["example.com", "example.org", "example.net", "mail.example.com",
           "corp.example.org"]
B64 = string.ascii_letters + string.digits + "+/"
B64URL = string.ascii_letters + string.digits + "-_"
ALNUM = string.ascii_letters + string.digits


class Ent:
    """A labeled value to be placed into a template."""

    def __init__(self, etype: str, value: str):
        self.etype = etype
        self.value = value


class Builder:
    """Concatenate literal text and labeled entities, tracking char spans."""

    def __init__(self):
        self.parts: list[str] = []
        self.entities: list[dict] = []
        self.pos = 0

    def lit(self, s: str) -> "Builder":
        self.parts.append(s)
        self.pos += len(s)
        return self

    def ent(self, etype: str, value: str) -> "Builder":
        self.entities.append({"type": etype, "start": self.pos,
                              "end": self.pos + len(value), "value": value})
        return self.lit(value)

    def add(self, x) -> "Builder":
        if isinstance(x, Ent):
            return self.ent(x.etype, x.value)
        return self.lit(x)

    def seq(self, *items) -> "Builder":
        for x in items:
            self.add(x)
        return self

    def json(self, obj) -> "Builder":
        """Serialize obj as compact-ish JSON; Ent leaves become labeled spans
        (the span covers the JSON-escaped string body, without the quotes)."""
        if isinstance(obj, Ent):
            body = json.dumps(obj.value, ensure_ascii=False)[1:-1]
            self.lit('"')
            self.ent(obj.etype, body)
            return self.lit('"')
        if isinstance(obj, dict):
            self.lit("{")
            for i, (k, v) in enumerate(obj.items()):
                if i:
                    self.lit(", ")
                self.lit(json.dumps(k) + ": ")
                self.json(v)
            return self.lit("}")
        if isinstance(obj, list):
            self.lit("[")
            for i, v in enumerate(obj):
                if i:
                    self.lit(", ")
                self.json(v)
            return self.lit("]")
        return self.lit(json.dumps(obj, ensure_ascii=False))

    def text(self) -> str:
        return "".join(self.parts)


# ---------------------------------------------------------------------------
# Value generators
# ---------------------------------------------------------------------------


def luhn_complete(prefix: str, length: int, rng: random.Random) -> str:
    digits = prefix + "".join(rng.choice(string.digits) for _ in range(length - len(prefix) - 1))
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 0:  # these positions get doubled once the check digit is appended
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return digits + str((10 - total % 10) % 10)


def iban_for(country: str, bban: str) -> str:
    rearranged = bban + country + "00"
    num = "".join(str(int(c, 36)) for c in rearranged)
    check = 98 - int(num) % 97
    return f"{country}{check:02d}{bban}"


class Gen:
    def __init__(self, rng: random.Random):
        self.r = rng

    def digits(self, n: int) -> str:
        return "".join(self.r.choice(string.digits) for _ in range(n))

    def chars(self, alphabet: str, n: int) -> str:
        return "".join(self.r.choice(alphabet) for _ in range(n))

    def name(self) -> str:
        return f"{self.r.choice(FIRST)} {self.r.choice(LAST)}"

    def ssn(self, style: str = "dash") -> str:
        area = self.r.choice([a for a in range(1, 900) if a != 666])
        group = self.r.randint(1, 99)
        serial = self.r.randint(1, 9999)
        if style == "dash":
            return f"{area:03d}-{group:02d}-{serial:04d}"
        if style == "space":
            return f"{area:03d} {group:02d} {serial:04d}"
        return f"{area:03d}{group:02d}{serial:04d}"

    def email(self, name: str | None = None) -> str:
        first, last = (name or self.name()).lower().split()
        user = self.r.choice([f"{first}.{last}", f"{first[0]}{last}",
                              f"{first}{self.r.randint(1, 99)}", f"{last}.{first}"])
        return f"{user}@{self.r.choice(DOMAINS)}"

    def phone(self) -> str:
        style = self.r.choice(["paren", "dash", "intl", "dot", "uk", "in"])
        a = self.r.choice(AREA_CODES)
        e = f"{self.r.randint(2, 9)}{self.r.choice('0123456789')}{self.r.randint(2, 9)}"
        if e.endswith("55") or e == "555":
            e = "867"
        line = self.digits(4)
        if style == "paren":
            return f"({a}) {e}-{line}"
        if style == "dash":
            return f"{a}-{e}-{line}"
        if style == "intl":
            return f"+1 {a} {e} {line}"
        if style == "dot":
            return f"{a}.{e}.{line}"
        if style == "uk":
            return f"+44 20 7946 0{self.digits(3)}"
        return f"+91 98{self.digits(3)} {self.digits(5)}"

    def card(self, sep: str | None = None) -> str:
        kind = self.r.choice(["visa", "mc", "amex"])
        if kind == "visa":
            num = luhn_complete("4", 16, self.r)
        elif kind == "mc":
            num = luhn_complete(f"5{self.r.randint(1, 5)}", 16, self.r)
        else:
            num = luhn_complete(self.r.choice(["34", "37"]), 15, self.r)
        if sep is None:
            sep = self.r.choice(["", " ", "-"])
        if not sep:
            return num
        if len(num) == 15:
            return sep.join([num[:4], num[4:10], num[10:]])
        return sep.join(num[i:i + 4] for i in range(0, 16, 4))

    def iban(self) -> str:
        c = self.r.choice(["DE", "GB", "FR", "NL", "ES"])
        if c == "DE":
            raw = iban_for("DE", self.digits(18))
        elif c == "GB":
            raw = iban_for("GB", self.chars(string.ascii_uppercase, 4) + self.digits(14))
        elif c == "FR":
            raw = iban_for("FR", self.digits(23))
        elif c == "NL":
            raw = iban_for("NL", self.chars(string.ascii_uppercase, 4) + self.digits(10))
        else:
            raw = iban_for("ES", self.digits(20))
        if self.r.random() < 0.4:
            return " ".join(raw[i:i + 4] for i in range(0, len(raw), 4))
        return raw

    def address(self) -> str:
        city, st = self.r.choice(CITIES)
        return (f"{self.r.randint(10, 9899)} {self.r.choice(STREETS)} "
                f"{self.r.choice(STREET_SUFFIX)}, {city}, {st} {self.digits(5)}")

    def aws_key(self) -> str:
        return "AKIA" + self.chars(string.ascii_uppercase + "234567", 16)

    def github_token(self) -> str:
        if self.r.random() < 0.25:
            return "github_pat_" + self.chars(ALNUM, 22) + "_" + self.chars(ALNUM, 59)
        return "gh" + self.r.choice("pousr") + "_" + self.chars(ALNUM, 36)

    def api_key_value(self) -> str:
        style = self.r.choice(["hex", "sk", "alnum", "dashed"])
        if style == "hex":
            return self.chars("0123456789abcdef", 32)
        if style == "sk":
            return "sk_" + self.r.choice(["live", "test"]) + "_" + self.chars(ALNUM, 24)
        if style == "alnum":
            return self.chars(ALNUM, 40)
        return "-".join(self.chars(string.ascii_lowercase + string.digits, 8) for _ in range(4))

    def jwt(self) -> str:
        def b64u(obj) -> str:
            raw = json.dumps(obj, separators=(",", ":")).encode()
            return base64.urlsafe_b64encode(raw).decode().rstrip("=")
        header = {"alg": self.r.choice(["HS256", "RS256"]), "typ": "JWT"}
        payload = {"sub": self.digits(8), "iat": 1700000000 + self.r.randint(0, 9_999_999),
                   "scope": self.r.choice(["read", "read write", "admin"])}
        return f"{b64u(header)}.{b64u(payload)}.{self.chars(B64URL, 43)}"

    def private_key(self) -> str:
        kind = self.r.choice(["RSA PRIVATE KEY", "PRIVATE KEY", "OPENSSH PRIVATE KEY",
                              "EC PRIVATE KEY"])
        lines = [self.chars(B64, 64) for _ in range(self.r.randint(3, 6))]
        lines.append(self.chars(B64, self.r.randint(10, 60)) + "==")
        return f"-----BEGIN {kind}-----\n" + "\n".join(lines) + f"\n-----END {kind}-----"

    # hard negatives -------------------------------------------------------

    def uuid(self) -> str:
        h = self.chars("0123456789abcdef", 32)
        return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-{self.r.choice('89ab')}{h[17:20]}-{h[20:]}"

    def timestamp(self) -> str:
        y, mo, d = self.r.randint(2023, 2026), self.r.randint(1, 12), self.r.randint(1, 28)
        h, mi, s = self.r.randint(0, 23), self.r.randint(0, 59), self.r.randint(0, 59)
        return self.r.choice([
            f"{y}-{mo:02d}-{d:02d}T{h:02d}:{mi:02d}:{s:02d}Z",
            f"{y}-{mo:02d}-{d:02d} {h:02d}:{mi:02d}:{s:02d}.{self.digits(3)}",
            str(1700000000 + self.r.randint(0, 99_999_999)),
        ])

    def order_id(self) -> str:
        return self.r.choice([f"ORD-{self.r.randint(2023, 2026)}-{self.digits(6)}",
                              f"INV{self.digits(8)}", f"PO-{self.digits(5)}-{self.chars('ABCDEFGH', 2)}"])

    def version(self) -> str:
        return self.r.choice([f"v{self.r.randint(0, 9)}.{self.r.randint(0, 30)}.{self.r.randint(0, 99)}",
                              f"{self.r.randint(1, 5)}.{self.r.randint(0, 20)}.{self.r.randint(0, 9)}-rc{self.r.randint(1, 4)}"])

    def git_sha(self) -> str:
        return self.chars("0123456789abcdef", 40)

    def zip_code(self) -> str:
        return self.digits(5)

    def nine_digits(self) -> str:
        return str(self.r.randint(100_000_000, 999_999_999))

    def b64_blob(self) -> str:
        raw = bytes(self.r.randint(0, 255) for _ in range(self.r.randint(30, 90)))
        return base64.b64encode(raw).decode()

    def hex_hash(self) -> str:
        return self.chars("0123456789abcdef", self.r.choice([32, 64]))


# ---------------------------------------------------------------------------
# Per-class context: JSON field names, log keys, chat lead-ins.
# ---------------------------------------------------------------------------

CONTEXT = {
    "US_SSN": {"fields": ["ssn", "social_security_number", "tax_id", "national_id", "member_ref"],
               "leads": ["My SSN is", "Her social security number is", "The tax ID on file is",
                         "Please verify", "ID number:"]},
    "EMAIL": {"fields": ["email", "contact", "reply_to", "user"],
              "leads": ["You can reach me at", "Send the invoice to", "cc", "Forwarded from"]},
    "PHONE": {"fields": ["phone", "mobile", "contact_number", "tel"],
              "leads": ["Call me at", "My number is", "Customer phone:", "Text"]},
    "CREDIT_CARD": {"fields": ["card_number", "pan", "cc", "payment_card"],
                    "leads": ["Charge the card", "My card number is", "Card:", "Use"]},
    "IBAN": {"fields": ["iban", "account", "payout_account", "bank_account"],
             "leads": ["Wire it to IBAN", "Our account is", "Refund to", "IBAN:"]},
    "PERSON": {"fields": ["name", "full_name", "customer", "assignee"],
               "leads": ["This ticket was opened by", "Meeting with", "Approved by", "Hi"]},
    "ADDRESS": {"fields": ["address", "shipping_address", "home", "billing_address"],
                "leads": ["Ship it to", "I live at", "The office moved to", "Deliver to"]},
    "AWS_ACCESS_KEY": {"fields": ["aws_access_key_id", "access_key", "key_id", "credentials"],
                       "leads": ["Here is the key", "Use access key", "Rotated key:", "Leaked:"]},
    "GITHUB_TOKEN": {"fields": ["github_token", "gh_token", "auth", "pat"],
                     "leads": ["My GitHub token is", "Use this PAT", "Token for CI:", "Push with"]},
    "GENERIC_API_KEY": {"fields": ["api_key", "apiKey", "client_secret", "SECRET_KEY", "authorization"],
                        "leads": ["api_key:", "The API key is", "secret =", "Authorization: Bearer"]},
    "JWT": {"fields": ["id_token", "access_token", "jwt", "session"],
            "leads": ["Bearer", "Session token", "Here is my token", "Cookie: session="]},
    "PRIVATE_KEY": {"fields": ["private_key", "ssh_key", "tls_key", "pem"],
                    "leads": ["Here is the deploy key:", "Private key below", "Key:", ""]},
}


def value_for(g: Gen, etype: str) -> str:
    return {
        "US_SSN": lambda: g.ssn(g.r.choice(["dash", "dash", "dash", "space", "plain"])),
        "EMAIL": g.email,
        "PHONE": g.phone,
        "CREDIT_CARD": g.card,
        "IBAN": g.iban,
        "PERSON": g.name,
        "ADDRESS": g.address,
        "AWS_ACCESS_KEY": g.aws_key,
        "GITHUB_TOKEN": g.github_token,
        "GENERIC_API_KEY": g.api_key_value,
        "JWT": g.jwt,
        "PRIVATE_KEY": g.private_key,
    }[etype]()


# ---------------------------------------------------------------------------
# Format wrappers. Each takes (g, payload_builder_fn) and returns a Builder.
# ---------------------------------------------------------------------------


def wrap_json(g: Gen, field: str, item) -> Builder:
    rec = {"id": g.r.randint(1000, 99999), field: item,
           "status": g.r.choice(["active", "pending", "ok"])}
    obj = g.r.choice([
        {"result": rec},
        {"data": [rec], "count": 1},
        rec,
        {"tool": g.r.choice(["crm.lookup", "db.query", "billing.get"]), "output": rec},
    ])
    return Builder().json(obj)


def log_prefix(g: Gen, with_ts: bool) -> str:
    lvl = g.r.choice(["INFO", "DEBUG", "WARN", "ERROR"])
    svc = g.r.choice(["billing", "auth", "crm-sync", "worker", "gateway"])
    if with_ts:
        return f"{g.timestamp()} {lvl} [{svc}] "
    return f"level={lvl.lower()} svc={svc} "


def wrap_log(g: Gen, field: str, item) -> Builder:
    b = Builder().lit(log_prefix(g, g.r.random() < 0.5))
    b.lit(g.r.choice(["request handled ", "lookup ok ", "retrying call ", "payload "]))
    sep = g.r.choice(["=", ": "])
    quoted = isinstance(item, Ent) and ("\n" in item.value or " " in item.value)
    b.lit(f"{field}{sep}")
    if quoted:
        b.lit('"').add(item).lit('"')
    else:
        b.add(item)
    return b.lit(g.r.choice(["", f" took={g.r.randint(2, 900)}ms", " retry=0"]))


def wrap_chat(g: Gen, lead: str, item) -> Builder:
    b = Builder().lit(g.r.choice(["", "user: ", "agent: ", "[tool_result] "]))
    if lead:
        b.lit(lead + " ")
    b.add(item)
    return b.lit(g.r.choice([".", " thanks!", ", can you check it?", " - urgent", ""]))


def wrap_email(g: Gen, lead: str, item) -> Builder:
    subj = g.r.choice(["Re: account update", "Invoice question", "Onboarding", "Fwd: details"])
    b = Builder().lit(f"Subject: {subj}\n\nHello team,\n\n")
    if lead:
        b.lit(lead + " ")
    b.add(item)
    return b.lit("\n\nBest regards,\nSupport desk")


def wrap_code(g: Gen, field: str, item) -> Builder:
    style = g.r.choice(["py", "env", "yaml", "js"])
    b = Builder()
    if style == "py":
        b.lit("import requests\n\n").lit(f"{field.upper()} = \"").add(item).lit("\"\n")
        b.lit("resp = requests.get(URL, timeout=5)\n")
    elif style == "env":
        b.lit("# local overrides\nDEBUG=false\n").lit(f"{field.upper()}=").add(item).lit("\n")
    elif style == "yaml":
        b.lit("service:\n  name: billing\n").lit(f"  {field}: \"").add(item).lit("\"\n")
    else:
        b.lit("const config = {\n  region: 'us-east-1',\n").lit(f"  {field}: '").add(item).lit("',\n};\n")
    return b


def wrap_any(g: Gen, fmt: str, etype: str, item) -> Builder:
    ctx = CONTEXT[etype]
    field = g.r.choice(ctx["fields"])
    lead = g.r.choice(ctx["leads"])
    if fmt == "json":
        return wrap_json(g, field, item)
    if fmt == "log":
        return wrap_log(g, field, item)
    if fmt == "chat":
        return wrap_chat(g, lead, item)
    if fmt == "email":
        return wrap_email(g, lead, item)
    return wrap_code(g, field, item)


FORMATS = ["json", "chat", "log", "email", "code"]


# ---------------------------------------------------------------------------
# Example families
# ---------------------------------------------------------------------------


def positives(g: Gen, per_class: int) -> list[tuple[str, str, str, Builder]]:
    out = []
    for etype in ENTITY_TYPES:
        for i in range(per_class):
            fmt = FORMATS[i % len(FORMATS)]
            if etype == "PRIVATE_KEY" and fmt == "chat":
                fmt = "email"
            item = Ent(etype, value_for(g, etype))
            out.append((fmt, "positive", etype, wrap_any(g, fmt, etype, item)))
    return out


def multi_entity(g: Gen, n: int) -> list[tuple[str, str, str, Builder]]:
    """Realistic records carrying several entities at once (CRM rows etc.)."""
    out = []
    for i in range(n):
        name = g.name()
        if i % 3 == 0:
            b = Builder().json({
                "customer_id": g.r.randint(10000, 99999),
                "name": Ent("PERSON", name),
                "email": Ent("EMAIL", g.email(name)),
                "phone": Ent("PHONE", g.phone()),
                "address": Ent("ADDRESS", g.address()),
                "created_at": g.timestamp(),
                "order_id": g.order_id(),
            })
            fmt = "json"
        elif i % 3 == 1:
            b = Builder().lit(f"Subject: Payment details\n\nHi, this is ")
            b.ent("PERSON", name).lit(". Please update my card to ")
            b.ent("CREDIT_CARD", g.card()).lit(" and send the receipt to ")
            b.ent("EMAIL", g.email(name)).lit(".\n\nThanks")
            fmt = "email"
        else:
            b = Builder().lit(log_prefix(g, True) + "user=")
            b.ent("EMAIL", g.email(name)).lit(f" request_id={g.uuid()} ssn=")
            b.ent("US_SSN", g.ssn()).lit(f" version={g.version()}")
            fmt = "log"
        out.append((fmt, "positive", "multi", b))
    return out


NEGATIVE_KINDS = {
    "order_id": ("order_id", "Your order {} has shipped"),
    "uuid": ("request_id", "Trace {} completed"),
    "timestamp": ("created_at", "Last login was {}"),
    "version": ("version", "Upgraded the agent to {}"),
    "git_sha": ("commit", "Deployed commit {} to staging"),
    "zip_code": ("zip", "Weather for zip {} is sunny"),
    "nine_digits": ("tracking_number", "Parcel number {} is out for delivery"),
    "b64_blob": ("payload_b64", "Attachment body: {}"),
    "hex_hash": ("sha256", "File checksum {} matches"),
}


def negatives(g: Gen, per_kind: int) -> list[tuple[str, str, str, Builder]]:
    out = []
    for kind, (field, sentence) in NEGATIVE_KINDS.items():
        make = getattr(g, kind)
        for i in range(per_kind):
            fmt = FORMATS[i % len(FORMATS)]
            v = make()
            if fmt == "json":
                b = Builder().json({"ok": True, field: v, "items": g.r.randint(1, 9)})
            elif fmt == "log":
                b = Builder().lit(log_prefix(g, kind == "timestamp") + f"{field}={v} status=200")
            elif fmt == "chat":
                b = Builder().lit(sentence.format(v) + ".")
            elif fmt == "email":
                b = Builder().lit(f"Subject: Status\n\nHello team,\n\n{sentence.format(v)}.\n\nBest regards,\nOps")
            else:
                b = Builder().lit(f"{field.upper()} = \"{v}\"\nprint({field.upper()})\n")
            out.append((fmt, "negative", f"neg:{kind}", b))
    return out


FULLWIDTH = {c: chr(ord(c) + 0xFEE0) for c in string.digits + "-"}
ZW = ["​", "‌", "‍", "⁠", "﻿"]


def to_fullwidth(s: str) -> str:
    return "".join(FULLWIDTH.get(c, c) for c in s)


def with_zero_width(g: Gen, s: str) -> str:
    out = []
    for i, c in enumerate(s):
        out.append(c)
        if i < len(s) - 1 and g.r.random() < 0.35:
            out.append(g.r.choice(ZW))
    return "".join(out)


def spaced(s: str) -> str:
    return " ".join(s)


def evasions(g: Gen, n_each: int) -> list[tuple[str, str, str, Builder]]:
    out = []
    # 1. fullwidth digits
    for i in range(n_each):
        etype = ["US_SSN", "PHONE", "CREDIT_CARD"][i % 3]
        v = g.ssn() if etype == "US_SSN" else g.phone() if etype == "PHONE" else g.card("-")
        fmt = ["chat", "json", "log"][i % 3]
        out.append((fmt, "evasion", "evasion:fullwidth",
                    wrap_any(g, fmt, etype, Ent(etype, to_fullwidth(v)))))
    # 2. zero-width characters sprinkled into the value
    for i in range(n_each):
        etype = ["US_SSN", "EMAIL", "AWS_ACCESS_KEY", "CREDIT_CARD", "GITHUB_TOKEN"][i % 5]
        v = value_for(g, etype) if etype != "GITHUB_TOKEN" else "ghp_" + g.chars(ALNUM, 36)
        fmt = ["chat", "json", "log", "code", "email"][i % 5]
        out.append((fmt, "evasion", "evasion:zero_width",
                    wrap_any(g, fmt, etype, Ent(etype, with_zero_width(g, v)))))
    # 3. spaced-out digits
    for i in range(n_each):
        etype = ["US_SSN", "CREDIT_CARD", "PHONE"][i % 3]
        v = g.ssn() if etype == "US_SSN" else g.card("") if etype == "CREDIT_CARD" else g.phone()
        fmt = ["chat", "email", "log"][i % 3]
        out.append((fmt, "evasion", "evasion:spaced",
                    wrap_any(g, fmt, etype, Ent(etype, spaced(v)))))
    # 4. value split across JSON fields (span covers first part to last part)
    for i in range(n_each):
        kind = i % 3
        b = Builder()
        if kind == 0:
            a, gr, s = g.ssn().split("-")
            b.lit('{"customer": {"ssn_area": "')
            start = b.pos
            b.lit(f'{a}", "ssn_group": "{gr}", "ssn_serial": "{s}')
            etype, end = "US_SSN", b.pos
            b.lit('"}}')
        elif kind == 1:
            parts = g.card("-").split("-")
            b.lit('{"payment": {"pan_parts": ["')
            start = b.pos
            b.lit('", "'.join(parts))
            etype, end = "CREDIT_CARD", b.pos
            b.lit('"], "exp": "' + f"{g.r.randint(1, 12):02d}/{g.r.randint(27, 31)}" + '"}}')
        else:
            k = g.aws_key()
            b.lit('{"cfg": {"key_prefix": "')
            start = b.pos
            b.lit(f'{k[:10]}", "key_suffix": "{k[10:]}')
            etype, end = "AWS_ACCESS_KEY", b.pos
            b.lit('"}}')
        text = b.text()
        b.entities.append({"type": etype, "start": start, "end": end, "value": text[start:end]})
        out.append(("json", "evasion", "evasion:split_json", b))
    return out


def build(seed: int) -> list[dict]:
    g = Gen(random.Random(seed))
    rows = []
    rows += positives(g, per_class=20)
    rows += multi_entity(g, n=24)
    rows += negatives(g, per_kind=12)
    rows += evasions(g, n_each=12)
    examples = []
    for i, (fmt, kind, tag, b) in enumerate(rows, 1):
        text = b.text()
        for e in b.entities:
            assert text[e["start"]:e["end"]] == e["value"], (tag, e)
        examples.append({"id": f"ex-{i:04d}", "format": fmt, "kind": kind, "tag": tag,
                         "text": text, "entities": b.entities})
    return examples


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--out", default=str(Path(__file__).parent / "data" / "detection.jsonl"))
    args = ap.parse_args()
    examples = build(args.seed)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        for ex in examples:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")
    n_ent = sum(len(e["entities"]) for e in examples)
    kinds = {}
    for e in examples:
        kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
    print(f"wrote {len(examples)} examples ({n_ent} labeled entities) to {out}: {kinds}")


if __name__ == "__main__":
    main()
