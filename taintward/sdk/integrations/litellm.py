"""LiteLLM adapter: the Python SDK and the proxy (as a guardrail).

SDK. ``protect_litellm()`` patches ``litellm.completion`` and
``litellm.acompletion`` in place (call them as ``litellm.completion(...)``;
a name imported before the patch is not covered). Each request is redacted
for the ``llm`` destination and recorded as a ``chat <model>`` span, the same
way as ``protect_openai``. With placeholders on, the returned
``ModelResponse`` is restored: message text and tool call arguments get the
real values back. Streamed responses are not restored (the request still is).

Proxy. ``TaintwardGuardrail`` is a LiteLLM custom guardrail. In the proxy
config::

    guardrails:
      - guardrail_name: taintward
        litellm_params:
          guardrail: taintward.sdk.integrations.litellm.TaintwardGuardrail
          mode: [pre_call, post_call]
          default_on: true

``pre_call`` redacts ``messages`` before the request goes to the provider and
records the span; ``post_call`` restores the placeholders in the answer, so
the client gets real values and the provider never sees them. Streaming
requests get plain masks instead of placeholders, because the streamed
answer is not restored. Each request has its own placeholder map, kept in
memory between the two hooks (at most ``max_pending`` requests, oldest
dropped first) and never sent anywhere.
"""

from __future__ import annotations

import functools
import inspect
import threading
import uuid
from collections import OrderedDict
from typing import Any

import litellm
from litellm.integrations.custom_guardrail import CustomGuardrail

from taintward.sdk import placeholders as ph
from taintward.sdk.integrations import Ward, _resolve
from taintward.sdk.integrations._common import finish_llm, instruction, llm_call
from taintward.sdk.integrations._payload import to_plain

_MARK = "__taintward_patched__"
_FIELDS = ("messages",)


def _model(kwargs: dict) -> str:
    return str(kwargs.get("model", ""))


def _view(resp: Any) -> Any:
    choices = getattr(resp, "choices", None)
    if choices is not None:
        return [to_plain(getattr(c, "message", c)) for c in choices]
    return to_plain(resp)


def _with_line(messages: list, line: str | None) -> list:
    if not line:
        return messages
    msgs = list(messages)
    first = msgs[0] if msgs else None
    if isinstance(first, dict) and first.get("role") == "system" and isinstance(
            first.get("content"), str):
        msgs[0] = {**first, "content": f"{first['content']}\n\n{line}"}
    else:
        msgs.insert(0, {"role": "system", "content": line})
    return msgs


def _bind(original, args, kwargs) -> dict:
    """completion(model, messages, ...) also works with positional args."""
    if not args:
        return dict(kwargs)
    try:
        sig = inspect.signature(original)
        named = dict(sig.bind_partial(*args, **kwargs).arguments)
    except (TypeError, ValueError):
        named = {}
    kinds = {n: p.kind for n, p in sig.parameters.items()} if named else {}
    if named and not any(kinds[n] == inspect.Parameter.VAR_POSITIONAL for n in named):
        extra = {n for n in named if kinds[n] == inspect.Parameter.VAR_KEYWORD}
        out = {n: v for n, v in named.items() if n not in extra}
        for n in extra:
            out.update(named[n])
        return out
    return {"model": args[0], **({"messages": args[1]} if len(args) > 1 else {}), **kwargs}


def _wrap(original, ward: Ward, is_async: bool):
    def start(kwargs):
        pmap = None if kwargs.get("stream") else ward.llm_placeholder_map()
        content = {k: kwargs[k] for k in _FIELDS if k in kwargs}
        return pmap, llm_call(ward, _model(kwargs), "litellm", "litellm", content, pmap)

    def send(call, kwargs, pmap):
        msgs = call.kwargs.get("messages")
        if msgs is not None:
            line = instruction(pmap, ward, msgs)
            if line:
                call.span.set_attribute("taintward.placeholders.instruction", True)
            return {**kwargs, "messages": _with_line(msgs, line)}
        return kwargs

    def end(call, kwargs, resp, pmap):
        if kwargs.get("stream"):
            return resp
        if finish_llm(call, ward, pmap, _view(resp)):
            resp = pmap.restore_inplace(resp)
        return resp

    if is_async:
        @functools.wraps(original)
        async def acompletion(*args, **kwargs):
            kwargs = _bind(original, args, kwargs)
            pmap, call = start(kwargs)
            with call:
                resp = await original(**send(call, kwargs, pmap))
                return end(call, kwargs, resp, pmap)
        setattr(acompletion, _MARK, True)
        return acompletion

    @functools.wraps(original)
    def completion(*args, **kwargs):
        kwargs = _bind(original, args, kwargs)
        pmap, call = start(kwargs)
        with call:
            resp = original(**send(call, kwargs, pmap))
            return end(call, kwargs, resp, pmap)
    setattr(completion, _MARK, True)
    return completion


def protect_litellm(module: Any = None, *, ward: Ward | None = None) -> Any:
    """Patch ``litellm.completion`` / ``litellm.acompletion`` in place and
    return the module. Calling it again does nothing."""
    mod = module or litellm
    w = _resolve(ward, None)
    for name, is_async in (("completion", False), ("acompletion", True)):
        fn = getattr(mod, name, None)
        if fn is not None and not getattr(fn, _MARK, False):
            setattr(mod, name, _wrap(fn, w, is_async))
    return mod


class TaintwardGuardrail(CustomGuardrail):
    """LiteLLM proxy guardrail: placeholders to the provider, real values to
    the client. Uses the global Ward (``taintward.init``) unless one is given."""

    def __init__(self, ward: Ward | None = None, max_pending: int = 10000, **kwargs):
        self._ward = ward
        self._pending: OrderedDict[str, ph.PlaceholderMap] = OrderedDict()
        self._lock = threading.Lock()
        self._max = max_pending
        super().__init__(**kwargs)

    @property
    def ward(self) -> Ward:
        return self._ward or _resolve(None, None)

    def _keep(self, pmap) -> str:
        rid = uuid.uuid4().hex
        with self._lock:
            self._pending[rid] = pmap
            while len(self._pending) > self._max:
                self._pending.popitem(last=False)
        return rid

    def _take(self, data: dict):
        rid = (data.get("metadata") or {}).get("taintward_request")
        if not rid:
            return None
        with self._lock:
            return self._pending.pop(rid, None)

    async def async_pre_call_hook(self, user_api_key_dict, cache, data: dict, call_type):
        messages = data.get("messages")
        if not isinstance(messages, list):
            return data
        ward = self.ward
        pmap = None if data.get("stream") or not ward.placeholders else ward.new_placeholder_map()
        with llm_call(ward, _model(data), "litellm-proxy", "litellm",
                      {"messages": messages}, pmap) as call:
            line = instruction(pmap, ward, call.kwargs["messages"])
            data["messages"] = _with_line(call.kwargs["messages"], line)
        if pmap is not None and len(pmap):
            data.setdefault("metadata", {})["taintward_request"] = self._keep(pmap)
        return data

    async def async_post_call_success_hook(self, data: dict, user_api_key_dict, response):
        pmap = self._take(data)
        if pmap is None:
            return response
        ph.check_output(pmap, _view(response),
                        strict=getattr(self.ward, "placeholder_strict", False))
        return pmap.restore_inplace(response)

    async def async_post_call_failure_hook(self, request_data: dict, *args, **kwargs):
        self._take(request_data)


__all__ = ["protect_litellm", "TaintwardGuardrail"]
