"""Placeholder evaluation harness: run the tasks through the real product path.

The app side is plain: it builds OpenAI-style messages, calls a protected
client (``protect_openai`` / ``protect_anthropic`` / a protected LangChain
chat model), runs the fake tools with the arguments it gets back, and appends
the (restored) answers to the history like a real app would.

Every HTTP request and response is recorded at the transport, so the harness
sees exactly what left the process (to check that no raw value was sent) and
what the model really wrote (the placeholder version, before restore).

Backends:

    ollama      OpenAI client -> Ollama's OpenAI API (default http://localhost:11434/v1)
    openai      OpenAI client -> api.openai.com (needs OPENAI_API_KEY)
    anthropic   Anthropic client (needs ANTHROPIC_API_KEY)
    langchain   LangChain ChatOpenAI -> Ollama (needs langchain-openai)

Modes:

    baseline    no placeholder instruction, exact restore only (Taintward 0.2.0)
    hardened    the defaults: instruction on, tolerant restore, the check after restore
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx

from taintward.sdk import placeholders as ph
from taintward.sdk.integrations import Ward

try:  # the harness lives in bench/placeholders; run as a script or a package
    from . import tasks as T
except ImportError:  # pragma: no cover
    import tasks as T  # type: ignore[no-redef]

OLLAMA_URL = os.environ.get("OLLAMA_OPENAI_URL", "http://localhost:11434/v1")


# ---------------------------------------------------------------------------
# Recording transport
# ---------------------------------------------------------------------------


class Recorder(httpx.BaseTransport):
    """Wraps a transport and keeps every request and response body."""

    def __init__(self, inner: httpx.BaseTransport | None = None, hx=httpx):
        self.hx = hx
        self.inner = inner or httpx.HTTPTransport(retries=1)
        self.requests: list[str] = []
        self.responses: list[str] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request.content.decode("utf-8", "replace"))
        resp = self.inner.handle_request(request)
        body = resp.read()
        self.responses.append(body.decode("utf-8", "replace"))
        return self.hx.Response(resp.status_code, headers=resp.headers, content=body,
                                request=request)

    def close(self) -> None:
        self.inner.close()


# ---------------------------------------------------------------------------
# Backends: one chat call in, (restored answer, raw answer) out
# ---------------------------------------------------------------------------


@dataclass
class Reply:
    content: str
    tool_calls: list[dict]          # [{"id", "name", "arguments": dict}] (restored)
    raw_content: str = ""
    raw_tool_calls: list[dict] = field(default_factory=list)  # arguments as raw text


def _openai_raw(body: str) -> tuple[str, list[dict]]:
    try:
        msg = json.loads(body)["choices"][0]["message"]
    except (ValueError, KeyError, IndexError, TypeError):
        return "", []
    calls = [{"name": (c.get("function") or {}).get("name", ""),
              "arguments": (c.get("function") or {}).get("arguments", "")}
             for c in msg.get("tool_calls") or []]
    return msg.get("content") or "", calls


def _anthropic_raw(body: str) -> tuple[str, list[dict]]:
    try:
        blocks = json.loads(body)["content"]
    except (ValueError, KeyError, TypeError):
        return "", []
    text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
    calls = [{"name": b.get("name", ""), "arguments": json.dumps(b.get("input", {}))}
             for b in blocks if b.get("type") == "tool_use"]
    return text, calls


def _tool_schemas(names) -> list[dict]:
    return [{"type": "function", "function": {"name": n, **T.TOOLS[n]}} for n in names]


def _args(raw: Any) -> dict:
    if isinstance(raw, dict):
        return raw
    try:
        out = json.loads(raw or "{}")
        return out if isinstance(out, dict) else {"_": out}
    except ValueError:
        return {"_raw": raw}


class OpenAIBackend:
    """Any OpenAI-compatible server (Ollama, OpenAI, vLLM, ...)."""

    raw_parser = staticmethod(_openai_raw)

    def __init__(self, ward: Ward, model: str, base_url: str | None, api_key: str,
                 temperature: float = 0.0, max_tokens: int = 400,
                 transport: httpx.BaseTransport | None = None):
        import openai
        self.rec = Recorder(transport)
        self.model, self.temperature, self.max_tokens = model, temperature, max_tokens
        self.client = openai.OpenAI(
            base_url=base_url, api_key=api_key, max_retries=1, timeout=600,
            http_client=httpx.Client(transport=self.rec, timeout=600))
        ward.protect_openai(self.client)

    def chat(self, messages: list[dict], tools: list[str]) -> Reply:
        kw: dict[str, Any] = dict(model=self.model, messages=messages,
                                  temperature=self.temperature, max_tokens=self.max_tokens)
        if tools:
            kw["tools"] = _tool_schemas(tools)
        resp = self.client.chat.completions.create(**kw)
        msg = resp.choices[0].message
        calls = [{"id": c.id, "name": c.function.name, "arguments": _args(c.function.arguments)}
                 for c in msg.tool_calls or []]
        raw_c, raw_t = self.raw_parser(self.rec.responses[-1])
        return Reply(msg.content or "", calls, raw_c, raw_t)


class AnthropicBackend:
    def __init__(self, ward: Ward, model: str, temperature: float = 0.0,
                 max_tokens: int = 400):
        import anthropic
        try:  # newer anthropic SDKs use the httpx2 fork
            import httpx2 as hx
        except ImportError:
            hx = httpx
        rec_cls = Recorder if hx is httpx else type("Recorder2", (Recorder, hx.BaseTransport), {})
        self.rec = rec_cls(hx.HTTPTransport(retries=1), hx)
        self.model, self.temperature, self.max_tokens = model, temperature, max_tokens
        self.client = anthropic.Anthropic(
            max_retries=1, http_client=hx.Client(transport=self.rec, timeout=600))
        ward.protect_anthropic(self.client)

    @staticmethod
    def _convert(messages: list[dict]) -> tuple[str, list[dict]]:
        system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
        out: list[dict] = []
        for m in messages:
            if m["role"] == "system":
                continue
            if m["role"] == "tool":
                block = {"type": "tool_result", "tool_use_id": m["tool_call_id"],
                         "content": m["content"]}
                if out and out[-1]["role"] == "user" and isinstance(out[-1]["content"], list):
                    out[-1]["content"].append(block)
                else:
                    out.append({"role": "user", "content": [block]})
            elif m["role"] == "assistant" and m.get("tool_calls"):
                blocks: list[dict] = []
                if m.get("content"):
                    blocks.append({"type": "text", "text": m["content"]})
                for c in m["tool_calls"]:
                    blocks.append({"type": "tool_use", "id": c["id"],
                                   "name": c["function"]["name"],
                                   "input": json.loads(c["function"]["arguments"])})
                out.append({"role": "assistant", "content": blocks})
            else:
                out.append({"role": m["role"], "content": m["content"] or " "})
        return system, out

    def chat(self, messages: list[dict], tools: list[str]) -> Reply:
        system, msgs = self._convert(messages)
        kw: dict[str, Any] = dict(model=self.model, messages=msgs,
                                  temperature=self.temperature, max_tokens=self.max_tokens)
        if system:
            kw["system"] = system
        if tools:
            kw["tools"] = [{"name": n, "description": T.TOOLS[n]["description"],
                            "input_schema": T.TOOLS[n]["parameters"]} for n in tools]
        resp = self.client.messages.create(**kw)
        text = "".join(getattr(b, "text", "") for b in resp.content if b.type == "text")
        calls = [{"id": b.id, "name": b.name, "arguments": dict(b.input)}
                 for b in resp.content if b.type == "tool_use"]
        raw_c, raw_t = _anthropic_raw(self.rec.responses[-1])
        return Reply(text, calls, raw_c, raw_t)


class LangChainBackend:
    """LangChain ChatOpenAI pointed at an OpenAI-compatible server."""

    def __init__(self, ward: Ward, model: str, base_url: str | None, api_key: str,
                 temperature: float = 0.0, max_tokens: int = 400):
        from langchain_openai import ChatOpenAI
        self.rec = Recorder()
        base = ChatOpenAI(model=model, base_url=base_url, api_key=api_key,
                          temperature=temperature, max_tokens=max_tokens, max_retries=1,
                          http_client=httpx.Client(transport=self.rec, timeout=600))
        self.model = ward.protect_langchain_model(base)
        self._bound: dict[tuple, Any] = {}

    @staticmethod
    def _convert(messages: list[dict]):
        from langchain_core.messages import (
            AIMessage,
            HumanMessage,
            SystemMessage,
            ToolMessage,
        )
        out = []
        for m in messages:
            if m["role"] == "system":
                out.append(SystemMessage(m["content"]))
            elif m["role"] == "user":
                out.append(HumanMessage(m["content"]))
            elif m["role"] == "tool":
                out.append(ToolMessage(m["content"], tool_call_id=m["tool_call_id"]))
            else:
                calls = [{"name": c["function"]["name"], "id": c["id"],
                          "args": json.loads(c["function"]["arguments"])}
                         for c in m.get("tool_calls") or []]
                out.append(AIMessage(m.get("content") or "", tool_calls=calls))
        return out

    def chat(self, messages: list[dict], tools: list[str]) -> Reply:
        key = tuple(tools)
        if key not in self._bound:
            self._bound[key] = self.model.bind_tools(_tool_schemas(tools)) if tools else self.model
        msg = self._bound[key].invoke(self._convert(messages))
        content = msg.content if isinstance(msg.content, str) else json.dumps(msg.content)
        calls = [{"id": c.get("id") or f"call_{i}", "name": c["name"], "arguments": c["args"]}
                 for i, c in enumerate(msg.tool_calls or [])]
        raw_c, raw_t = _openai_raw(self.rec.responses[-1])
        return Reply(content, calls, raw_c, raw_t)


def provider_available(provider: str) -> str | None:
    """None when the provider can run, else the reason to skip it."""
    if provider == "openai" and not os.environ.get("OPENAI_API_KEY"):
        return "OPENAI_API_KEY is not set"
    if provider == "anthropic":
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return "ANTHROPIC_API_KEY is not set"
        try:
            import anthropic  # noqa: F401
        except ImportError:
            return "the anthropic package is not installed"
    if provider == "langchain":
        try:
            import langchain_openai  # noqa: F401
        except ImportError:
            return "langchain-openai is not installed"
    if provider in ("ollama", "langchain"):
        try:
            httpx.get(OLLAMA_URL.rsplit("/v1", 1)[0] + "/api/tags", timeout=3)
        except httpx.HTTPError:
            return f"no Ollama server at {OLLAMA_URL}"
    return None


def make_backend(provider: str, ward: Ward, model: str, **kw):
    if provider == "ollama":
        return OpenAIBackend(ward, model, OLLAMA_URL, "ollama", **kw)
    if provider == "openai":
        return OpenAIBackend(ward, model, None, os.environ["OPENAI_API_KEY"], **kw)
    if provider == "anthropic":
        return AnthropicBackend(ward, model, **kw)
    if provider == "langchain":
        return LangChainBackend(ward, model, OLLAMA_URL, "ollama", **kw)
    raise ValueError(f"unknown provider {provider!r}")


# ---------------------------------------------------------------------------
# Mode setup
# ---------------------------------------------------------------------------


def make_ward(mode: str, tracer=None) -> Ward:
    if mode == "baseline":
        return Ward(tracer=tracer, placeholder_instruction=False)
    if mode == "hardened":
        return Ward(tracer=tracer)
    raise ValueError(f"unknown mode {mode!r}")


def make_map(mode: str) -> ph.PlaceholderMap:
    return ph.PlaceholderMap(tolerant=(mode != "baseline"))


# ---------------------------------------------------------------------------
# Running one task
# ---------------------------------------------------------------------------

MAX_TOOL_ROUNDS = 4


def run_conversation(task: T.Task, backend) -> list[dict]:
    """Play the task like an app would. Returns one record per model call."""
    messages: list[dict] = []
    if task.system:
        messages.append({"role": "system", "content": task.system})
    calls: list[dict] = []
    for turn_no, user in enumerate(task.turns):
        messages.append({"role": "user", "content": user})
        for _ in range(MAX_TOOL_ROUNDS):
            reply = backend.chat(messages, list(task.tools))
            calls.append({"turn": turn_no, "content": reply.content,
                          "tool_calls": reply.tool_calls, "raw_content": reply.raw_content,
                          "raw_tool_calls": reply.raw_tool_calls})
            if not reply.tool_calls:
                messages.append({"role": "assistant", "content": reply.content})
                break
            messages.append({"role": "assistant", "content": reply.content or None,
                             "tool_calls": [{"id": c["id"], "type": "function", "function": {
                                 "name": c["name"], "arguments": json.dumps(c["arguments"])}}
                                 for c in reply.tool_calls]})
            for c in reply.tool_calls:
                messages.append({"role": "tool", "tool_call_id": c["id"],
                                 "content": T.run_tool(c["name"], c["arguments"])})
    return calls


def run_task(task: T.Task, backend, mode: str, exporter=None) -> dict:
    pmap = make_map(mode)
    n_req = len(backend.rec.requests)
    started = time.time()
    error = None
    with ph.scope(pmap):
        try:
            calls = run_conversation(task, backend)
        except Exception as e:  # strict mode, HTTP errors, ...
            calls = []
            error = f"{type(e).__name__}: {e}"[:300]
        known = dict(pmap._by_value)  # value -> placeholder, read before the scope clears it
    requests = backend.rec.requests[n_req:]
    flags = _span_flags(exporter) if exporter is not None else {}
    result = score(task, calls, requests, known)
    result.update(id=task.id, category=task.category, mode=mode, error=error,
                  seconds=round(time.time() - started, 1), calls=calls, flags=flags,
                  known=known, requests=requests,
                  instruction_sent=any(INSTRUCTION_MARK in r for r in requests))
    if error:
        result["restore_ok"] = False
    return result


INSTRUCTION_MARK = "Copy each placeholder exactly"


def _span_flags(exporter) -> dict:
    out: dict[str, list] = {"lost": [], "unknown": [], "repaired": []}
    for s in exporter.get_finished_spans():
        for k in out:
            v = (s.attributes or {}).get(f"taintward.placeholders.{k}")
            if v:
                out[k].extend(v if isinstance(v, (list, tuple)) else [v])
    exporter.clear()
    return out


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

LABEL_WORDS = ("PERSON|EMAIL|SSN|PHONE|AWS_KEY|GITHUB_TOKEN|API_KEY|CARD|IBAN|IP|"
               "BANK_ACCOUNT|LOCATION|DATE|URL|ORG|SECRET|PII|NAME|PERSONA|PERSONNE|"
               "CORREO|TELEFONO|TELEFON|KARTE|TARJETA|CARTE")
# Anything that still looks like a placeholder after restore.
LEFTOVER_RE = re.compile(
    r"(?:<|&lt;|\[|\{|\(|‹|〈|＜|«)\s*\\?[A-Za-z][A-Za-z\\_]*[\s\\_\-]*\d+\s*(?:>|&gt;|\]|\}|\)|›|〉|＞|»)"
    r"|(?<![A-Za-z0-9])[A-Z][A-Z]+(?:\\?_[A-Z]+)*\\?_\d+(?![0-9])"
    rf"|(?i:(?<![A-Za-z0-9])(?:{LABEL_WORDS})[ \-]\d{{1,3}}(?![0-9\-]))"
    rf"|<\s*(?:{LABEL_WORDS})\s*>"
)


def leftovers(text: str) -> list[str]:
    out = []
    for m in LEFTOVER_RE.finditer(text or ""):
        tok = m.group(0)
        if re.fullmatch(r"\(\s*\d+\s*\)", tok) or re.search(r"\d{4,}", tok):
            continue  # "(2)" list numbers, "(+1 415 ...)" real values
        out.append(tok)
    return out


def _near_form(placeholder: str, text: str) -> str | None:
    """A rewritten form of the placeholder in the model's raw text, if any."""
    m = re.fullmatch(r"<([A-Z_]+)_(\d+)>", placeholder)
    if not m:
        return None
    label, num = m.group(1), m.group(2)
    words = r"[\s_\-\\]*".join(re.escape(w) for w in label.split("_"))
    pat = re.compile(rf"(?i)(?<![A-Za-z0-9]){words}[\s_\-\\]*0*{num}(?![0-9])")
    hit = pat.search(text or "")
    return hit.group(0) if hit else None


def _raw_text(calls: list[dict]) -> str:
    return "\n".join([c["raw_content"] or "" for c in calls]
                     + [t["arguments"] for c in calls for t in c["raw_tool_calls"]])


def _restored_text(calls: list[dict]) -> str:
    return "\n".join([c["content"] or "" for c in calls]
                     + [json.dumps(t["arguments"], ensure_ascii=False)
                        for c in calls for t in c["tool_calls"]])


def _parse_json(text: str) -> Any:
    text = re.sub(r"```(?:json)?", "", text or "")
    for i, ch in enumerate(text):
        if ch in "{[":
            try:
                return json.JSONDecoder().raw_decode(text[i:])[0]
            except ValueError:
                continue
    return None


def _get(obj: Any, path: str) -> Any:
    for part in path.split("."):
        if isinstance(obj, list) and part.isdigit() and int(part) < len(obj):
            obj = obj[int(part)]
        elif isinstance(obj, dict):
            hit = [v for k, v in obj.items() if str(k).lower() == part.lower()]
            obj = hit[0] if hit else None
        else:
            return None
    return obj


def _kind(value: str, known: dict) -> str | None:
    p = known.get(value)
    return p.rsplit("_", 1)[0] if p else None


def _classify_wrong(slot: str, raw_slot: str, expected: str, task: T.Task,
                    known: dict) -> str | None:
    """'wrong_restore' when Taintward put another value in the slot, 'mixup'
    when the model itself referred to another value, None when no other value
    of the same kind is there."""
    kind = _kind(expected, known)
    for other in task.raws:
        if other == expected or other not in (slot or "") or _kind(other, known) != kind:
            continue
        ph_other = known.get(other)
        if ph_other and (ph_other in (raw_slot or "") or _near_form(ph_other, raw_slot)):
            return "mixup"
        if other in (raw_slot or ""):
            return "mixup"  # the value was sent raw (detector miss) and the model used it
        return "wrong_restore"
    return None


def score(task: T.Task, calls: list[dict], requests: list[str], known: dict) -> dict:
    sent = "\n".join(requests)
    # JSON escaping in the request body: compare against the escaped form too.
    def in_sent(v: str) -> bool:
        return v in sent or json.dumps(v)[1:-1] in sent

    leak_known = sorted({v for v in known if in_sent(v)})
    detector_miss = sorted({r for r in task.raws if r not in known and in_sent(r)})

    final = calls[-1]["content"] if calls else ""
    raw_final = calls[-1]["raw_content"] if calls else ""
    raw_all, restored_all = _raw_text(calls), _restored_text(calls)

    expected = list(task.must) + [v for _, _, v in task.tool_args] + \
        [v for _, v in task.json_fields] + [x for pair in task.pairs for x in pair] + \
        [x for it in task.json_items for x in (it[1], it[3])]
    expected = list(dict.fromkeys(expected))
    needed = [v for v in expected if v in known]

    survived, exact, rewritten, dropped = [], [], [], []
    for v in needed:
        p = known[v]
        if p in raw_all:
            exact.append(v)
        if v in restored_all:
            survived.append(v)
        else:
            near = _near_form(p, raw_all)
            (rewritten if near else dropped).append({"placeholder": p, "form": near})

    problems: list[str] = []
    wrong: list[dict] = []
    mixups: list[dict] = []

    for v in task.must:
        if v not in final:
            problems.append(f"missing {known.get(v, 'raw value')}")

    # tool calls
    tool_called = tool_args_ok = None
    tool_args_exact = None
    if task.tool_args:
        tool_called, tool_args_ok, tool_args_exact = True, True, True
        for name, arg, v in task.tool_args:
            pairs = [(t, r) for c in calls for t, r in zip(c["tool_calls"], c["raw_tool_calls"])
                     if t["name"] == name]
            if not pairs:
                tool_called = tool_args_ok = tool_args_exact = False
                problems.append(f"tool {name} not called")
                continue
            vals = [(str(t["arguments"].get(arg, "")), _args(r["arguments"]).get(arg, ""))
                    for t, r in pairs]
            if not any(v in got for got, _ in vals):
                tool_args_ok = False
                problems.append(f"{name}.{arg} != {known.get(v, 'value')}")
                for got, raw in vals:
                    kind = _classify_wrong(got, str(raw), v, task, known)
                    rec = {"slot": f"{name}.{arg}", "expected": known.get(v), "raw": str(raw)[:80]}
                    if kind == "wrong_restore":
                        wrong.append(rec)
                    elif kind == "mixup":
                        mixups.append(rec)
            p = known.get(v)
            if p and not any(p in str(raw) for _, raw in vals):
                tool_args_exact = False

    # JSON fields
    if task.json_fields:
        obj, raw_obj = _parse_json(final), _parse_json(raw_final)
        if obj is None:
            problems.append("answer is not JSON")
        for path, v in task.json_fields:
            got = _get(obj, path)
            got_s = got if isinstance(got, str) else json.dumps(got, ensure_ascii=False)
            if got is None or v not in got_s:
                problems.append(f"json {path} != {known.get(v, 'value')}")
                raw_got = _get(raw_obj, path)
                kind = _classify_wrong(got_s, json.dumps(raw_got, ensure_ascii=False), v,
                                       task, known) if got is not None else None
                rec = {"slot": f"json.{path}", "expected": known.get(v),
                       "raw": json.dumps(raw_got)[:80]}
                if kind == "wrong_restore":
                    wrong.append(rec)
                elif kind == "mixup":
                    mixups.append(rec)

    if task.json_items:
        obj, raw_obj = _parse_json(final), _parse_json(raw_final)
        items = obj if isinstance(obj, list) else (
            next((v for v in obj.values() if isinstance(v, list)), None)
            if isinstance(obj, dict) else None)
        if not isinstance(items, list):
            problems.append("answer is not a JSON list")
            items = []
        raw_items = raw_obj if isinstance(raw_obj, list) else []
        for ka, a, kb, b in task.json_items:
            if a not in final or b not in final:
                problems.append(f"missing {known.get(a if a not in final else b, 'raw value')}")
                continue
            hit = [i for i, it in enumerate(items)
                   if isinstance(it, dict) and a in str(_get(it, ka) or "")]
            if not any(b in str(_get(items[i], kb) or "") for i in hit):
                problems.append(f"json item of {known.get(a)} has the wrong {kb}")
                for i in hit:
                    raw_it = json.dumps(raw_items[i]) if i < len(raw_items) else ""
                    kind = _classify_wrong(str(_get(items[i], kb)), raw_it, b, task, known)
                    rec = {"slot": f"json item {kb}", "expected": known.get(b),
                           "raw": raw_it[:80]}
                    if kind == "wrong_restore":
                        wrong.append(rec)
                    elif kind == "mixup":
                        mixups.append(rec)

    # pairs: b must be on the line of a, or on the next lines before the
    # next person starts (a list item can span a few lines)
    lines, raw_lines = final.splitlines(), raw_final.splitlines()
    starts = {x for x, _ in task.pairs}

    def block(src: list[str], i: int, a: str) -> str:
        out = [src[i]] if i < len(src) else []
        for ln in src[i + 1:]:
            if any(o in ln for o in starts if o != a) or not ln.strip():
                break
            out.append(ln)
        return "\n".join(out)

    for a, b in task.pairs:
        idx = [i for i, ln in enumerate(lines) if a in ln]
        if not idx:
            continue  # already reported as missing
        if not any(b in block(lines, i, a) for i in idx):
            problems.append(f"{known.get(a, a)} not next to {known.get(b, 'value')}")
            for i in idx:
                raw_ln = raw_lines[i] if i < len(raw_lines) else ""
                kind = _classify_wrong(block(lines, i, a), raw_ln, b, task, known)
                rec = {"slot": f"line of {known.get(a)}", "expected": known.get(b),
                       "raw": raw_ln[:80]}
                if kind == "wrong_restore":
                    wrong.append(rec)
                elif kind == "mixup":
                    mixups.append(rec)

    left = leftovers(final) + [x for c in calls for t in c["tool_calls"]
                               for x in leftovers(json.dumps(t["arguments"], ensure_ascii=False))]
    if left:
        problems.append(f"leftover placeholders {sorted(set(left))[:5]}")

    restore_ok = bool(calls) and not problems and not leak_known
    return {
        "leak_known": len(leak_known), "detector_miss": len(detector_miss),
        "needed": len(needed), "survived": len(survived), "exact": len(exact),
        "rewritten": rewritten, "dropped": dropped,
        "survival_ok": len(survived) == len(needed),
        "restore_ok": restore_ok, "problems": problems, "leftovers": left,
        "wrong_restore": wrong, "mixups": mixups,
        "tool_called": tool_called, "tool_args_ok": tool_args_ok,
        "tool_args_exact": tool_args_exact,
    }


# ---------------------------------------------------------------------------
# Running a model
# ---------------------------------------------------------------------------


def run_model(provider: str, model: str, mode: str, task_ids=None, *,
              progress: Callable[[dict], None] | None = None, backend=None,
              **backend_kw) -> dict:
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    tp = TracerProvider(resource=Resource.create({"service.name": "placeholder-eval"}))
    exporter = InMemorySpanExporter()
    tp.add_span_processor(SimpleSpanProcessor(exporter))
    ward = make_ward(mode, tracer=tp.get_tracer("taintward"))
    if backend is None:
        backend = make_backend(provider, ward, model, **backend_kw)
    else:
        backend = backend(ward)
    tasks = [T.by_id(i) for i in task_ids] if task_ids else T.TASKS
    results = []
    for t in tasks:
        r = run_task(t, backend, mode, exporter)
        results.append(r)
        if progress:
            progress(r)
    tp.shutdown()
    return {"provider": provider, "model": model, "mode": mode,
            "summary": summarize(results), "results": results}


def rescore(run: dict) -> dict:
    """Score saved model calls again with the current scoring rules (the
    answers are not changed: they are what the product returned then)."""
    out = []
    for r in run["results"]:
        if "known" not in r:
            out.append(r)
            continue
        new = dict(r)
        new.update(score(T.by_id(r["id"]), r["calls"], r["requests"], r["known"]))
        if r.get("error"):
            new["restore_ok"] = False
        out.append(new)
    return {**run, "results": out, "summary": summarize(out)}


def replay_tolerant(run: dict) -> dict:
    """Offline ablation: restore the saved baseline answers again with the
    tolerant restore (no new model calls, so no instruction). Tasks with tools
    are kept as they were, because the tool loop depends on the restored
    arguments."""
    out = []
    for r in run["results"]:
        task = T.by_id(r["id"])
        if "known" not in r or task.tools:
            out.append(r)
            continue
        pm = ph.PlaceholderMap(tolerant=True)
        for value, p in r["known"].items():
            pm._remember(p, ph._Entry(value, "", ph.Sensitivity.PII))
        calls = [{**c, "content": pm.restore_text(c["raw_content"] or "")} for c in r["calls"]]
        flags: dict[str, list] = {"lost": [], "unknown": [], "repaired": []}
        for c in r["calls"]:
            for k, v in pm.diagnose(c["raw_content"] or "").items():
                flags[k].extend(v)
        new = {**r, "calls": calls, "mode": "baseline + tolerant restore", "flags": flags}
        new.update(score(task, calls, r["requests"], r["known"]))
        out.append(new)
    return {**run, "mode": "replay", "results": out, "summary": summarize(out)}


def summarize(results: list[dict]) -> dict:
    n = len(results)
    tool = [r for r in results if r["tool_called"] is not None]
    called = [r for r in tool if r["tool_called"]]
    failed = [r for r in results if not r["restore_ok"]]
    flagged = [r for r in failed if r["flags"].get("lost") or r["flags"].get("unknown")]
    needed = sum(r["needed"] for r in results)
    return {
        "tasks": n,
        "restore_ok": sum(r["restore_ok"] for r in results),
        "survival_ok": sum(r["survival_ok"] for r in results),
        "placeholders_needed": needed,
        "placeholders_survived": sum(r["survived"] for r in results),
        "placeholders_exact": sum(r["exact"] for r in results),
        "rewritten": sum(len(r["rewritten"]) for r in results),
        "dropped": sum(len(r["dropped"]) for r in results),
        "wrong_restore": sum(len(r["wrong_restore"]) for r in results),
        "mixups": sum(len(r["mixups"]) for r in results),
        "leftover_tasks": sum(bool(r["leftovers"]) for r in results),
        "tool_tasks": len(tool), "tool_called": len(called),
        "tool_args_ok": sum(bool(r["tool_args_ok"]) for r in tool),
        "leak_known": sum(r["leak_known"] for r in results),
        "detector_miss": sum(r["detector_miss"] for r in results),
        "errors": sum(bool(r["error"]) for r in results),
        "failed_flagged": f"{len(flagged)}/{len(failed)}",
        "by_category": {c: f"{sum(r['restore_ok'] for r in results if r['category'] == c)}/"
                           f"{sum(1 for r in results if r['category'] == c)}"
                        for c in dict.fromkeys(r["category"] for r in results)},
    }
