"""Restoring streamed model answers.

A streamed answer comes in pieces, and a placeholder can be split across
two of them (``"<SS"`` + ``"N_1>"``). ``Pieces`` keeps one
``placeholders.StreamRestorer`` per text of the answer (a choice's content,
one tool call's arguments, ...), so every placeholder is restored whole. It
also keeps the text as the model wrote it, for the span and the placeholder
check at the end.

``StreamCall`` keeps the request's span open while the caller reads the
stream. The span is entered and ended in a private copy of the context, so
it never becomes the current span in the caller's code between two chunks
(the same reason as ``_common.isolated_iter``). When the stream ends, the
answer is recorded on the span (the placeholder version, masked) and
checked; in strict mode ``PlaceholderRestoreError`` is raised after the last
chunk.

``guard_stream`` does this for a provider SDK stream object (OpenAI,
Anthropic, LiteLLM) without replacing it: the object gets a small subclass
whose ``__next__`` / ``__anext__`` hand out restored copies of the chunks,
so ``with`` blocks, ``.response``, ``close()`` and ``isinstance`` checks keep
working. The provider's own chunk objects are never changed (LiteLLM keeps
them for its logging callbacks, which must not see real values).

A handler turns the provider's items into restored items:

* ``item(raw) -> list``: the items to hand out for one raw item (usually
  one restored copy; sometimes an extra piece of held text before it),
* ``end() -> list``: extra items when the stream ends without the
  provider's own end marker,
* ``view()``: the answer as the model wrote it, for the span and the check,
* ``annotate(span)`` (optional): extra span attributes, such as usage.
"""

from __future__ import annotations

import asyncio
import contextvars
import copy
import inspect
import logging
import weakref
from collections import deque
from typing import Any, Callable

from taintward.sdk import instrumentation as instr
from taintward.sdk import placeholders as ph

log = logging.getLogger("taintward.sdk")

_GUARD = "_taintward_stream_guard"


def clone(obj: Any) -> Any:
    """A deep copy of one streamed item (pydantic models, dicts, ...)."""
    copier = getattr(obj, "model_copy", None)
    if callable(copier):
        try:
            return copier(deep=True)
        except Exception:
            pass
    return copy.deepcopy(obj)


class Pieces:
    """The texts of one streamed answer, each restored piece by piece.

    ``pmap=None`` (placeholders off, or none were sent) keeps the text as it
    is and only collects it for the span."""

    def __init__(self, pmap) -> None:
        self.pmap = pmap if pmap is not None and len(pmap) else None
        self._restorers: dict[Any, ph.StreamRestorer] = {}
        self._raw: dict[Any, list[str]] = {}

    def push(self, key: Any, text: Any, mode: str = "text") -> Any:
        """Restore one piece of the text ``key``; returns what to hand out."""
        if not isinstance(text, str) or not text:
            return text
        self._raw.setdefault(key, []).append(text)
        if self.pmap is None:
            return text
        r = self._restorers.get(key)
        if r is None:
            r = self._restorers[key] = ph.StreamRestorer(self.pmap, mode)
        return r.push(text)

    def touch(self, key: Any) -> None:
        """Note that the text ``key`` exists, even while it is still empty."""
        self._raw.setdefault(key, [])

    def flush(self, key: Any) -> str:
        """The held end of the text ``key`` (the text is complete)."""
        r = self._restorers.get(key)
        return r.flush() if r is not None else ""

    def holding(self, match: Callable[[Any], bool] | None = None) -> list:
        """Keys whose restorer still holds text."""
        return [k for k, r in self._restorers.items()
                if r.holding and (match is None or match(k))]

    def raw(self, key: Any) -> str | None:
        """The text ``key`` as the model wrote it so far."""
        parts = self._raw.get(key)
        return "".join(parts) if parts is not None else None

    def keys(self) -> list:
        return list(self._raw)

    def restore_full(self, value: Any) -> Any:
        """Restore a complete value (a done event's full text)."""
        if self.pmap is None:
            return value
        if isinstance(value, str):
            return self.pmap.restore_text(value, spaced=False)
        return self.pmap.restore_inplace(value)


class StreamCall:
    """One model request whose answer is streamed. Its ``GuardedCall`` stays
    open until the stream ends, in a private copy of the context."""

    def __init__(self, call, ward, pmap) -> None:
        self.call = call
        self.pmap = pmap
        self.strict = bool(getattr(ward, "placeholder_strict", False))
        self.ctx = contextvars.copy_context()
        self.ended = False

    def enter(self):
        self.ctx.run(self.call.__enter__)
        return self.call

    def run(self, fn: Callable, *args, **kwargs) -> Any:
        return self.ctx.run(fn, *args, **kwargs)

    async def arun(self, awaitable) -> Any:
        async def wait():
            return await awaitable
        return await asyncio.create_task(wait(), context=self.ctx)

    def end(self, view: Any, *, exc: BaseException | None = None, check: bool = True,
            annotate: Callable[[Any], None] | None = None,
            propagate: bool = True) -> BaseException | None:
        """Record the answer, check it and end the span (once). Returns the
        strict-mode error for the caller to raise, if any.

        ``propagate``: the caller's context is the one that goes on (the
        code that read the stream). Outside a run, the call's outgoing taint
        is kept in a context variable, so it is copied back from the private
        context. Inside a run it already went to the shared run box."""
        if self.ended:
            return None
        self.ended = True
        error = self.ctx.run(self._end, view, exc, check, annotate)
        if propagate:
            _carry_loose_taint(self.ctx)
        return error

    def _end(self, view, exc, check, annotate):
        call = self.call
        error = None
        try:
            if view is not None:
                call.record_result(view, view=view)
            if annotate is not None:
                annotate(call.span)
            if check and view is not None and self.pmap is not None and len(self.pmap):
                ph.check_output(self.pmap, view, span=call.span, strict=self.strict,
                                spaced=False)
        except BaseException as e:
            error = e
        failure = exc if exc is not None else error
        call.__exit__(type(failure) if failure is not None else None, failure,
                      failure.__traceback__ if failure is not None else None)
        return error


def _carry_loose_taint(ctx: contextvars.Context) -> None:
    label = ctx.get(instr._LOOSE_TAINT)
    if label is None or instr._RUN_TAINT.get() is not None:
        return
    prev = instr._LOOSE_TAINT.get()
    if prev is not label:
        instr._LOOSE_TAINT.set(label if prev is None else prev.merge(label))


class Guard:
    """Hands out the restored items of one stream and ends its StreamCall."""

    def __init__(self, sc: StreamCall, handler) -> None:
        self.sc = sc
        self.handler = handler
        self.queue: deque = deque()
        self.done = False
        self.error: BaseException | None = None

    def _take(self, item: Any) -> None:
        try:
            self.queue.extend(self.handler.item(item))
        except BaseException as e:
            self.finish(e, complete=False)
            raise

    def finish(self, exc: BaseException | None = None, *, complete: bool = True,
               propagate: bool = True) -> None:
        """``complete``: the stream ended by itself (not closed early, no error)."""
        if self.done:
            return
        self.done = True
        if complete and exc is None:
            self.queue.extend(self.handler.end())
        err = self.sc.end(self.handler.view(), exc=exc, check=complete and exc is None,
                          annotate=getattr(self.handler, "annotate", None),
                          propagate=propagate)
        if err is not None and complete:
            self.error = err

    def close(self) -> None:
        """The caller stopped reading early (``close()``, ``with`` exit)."""
        self._stop(propagate=True)

    def collect(self) -> None:
        """The stream object was dropped without being read to the end."""
        self._stop(propagate=False)

    def _stop(self, *, propagate: bool) -> None:
        try:
            self.finish(complete=False, propagate=propagate)
        except Exception:  # pragma: no cover - never raise from close or GC
            log.debug("taintward: could not end a stream span", exc_info=True)

    def _out(self, stop: type[BaseException]) -> Any:
        if self.queue:
            return self.queue.popleft()
        if self.error is not None:
            err, self.error = self.error, None
            raise err
        raise stop

    def next(self, pull: Callable[[], Any]) -> Any:
        while not self.queue and not self.done:
            try:
                item = pull()
            except StopIteration:
                self.finish()
                break
            except BaseException as e:
                self.finish(e, complete=False)
                raise
            self._take(item)
        return self._out(StopIteration)

    async def anext(self, pull: Callable[[], Any]) -> Any:
        while not self.queue and not self.done:
            try:
                item = await pull()
            except StopAsyncIteration:
                self.finish()
                break
            except BaseException as e:
                self.finish(e, complete=False)
                raise
            self._take(item)
        return self._out(StopAsyncIteration)


_CLASSES: dict[type, type] = {}


def _guarded_class(base: type) -> type:
    cls = _CLASSES.get(base)
    if cls is not None:
        return cls
    ns: dict[str, Any] = {}

    if hasattr(base, "__next__"):
        def __next__(self):
            return self.__dict__[_GUARD].next(super(cls, self).__next__)

        def __iter__(self):
            while True:
                try:
                    yield self.__next__()
                except StopIteration:
                    return
        ns.update(__next__=__next__, __iter__=__iter__)

    if hasattr(base, "__anext__"):
        async def __anext__(self):
            return await self.__dict__[_GUARD].anext(super(cls, self).__anext__)

        async def __aiter__(self):
            while True:
                try:
                    item = await self.__anext__()
                except StopAsyncIteration:
                    return
                yield item
        ns.update(__anext__=__anext__, __aiter__=__aiter__)

    for name in ("close", "aclose"):
        original = getattr(base, name, None)
        if original is None:
            continue
        if inspect.iscoroutinefunction(original):
            def make_async(name=name):
                async def closer(self, *args, **kwargs):
                    try:
                        return await getattr(super(cls, self), name)(*args, **kwargs)
                    finally:
                        self.__dict__[_GUARD].close()
                return closer
            ns[name] = make_async()
        else:
            def make_sync(name=name):
                def closer(self, *args, **kwargs):
                    try:
                        return getattr(super(cls, self), name)(*args, **kwargs)
                    finally:
                        self.__dict__[_GUARD].close()
                return closer
            ns[name] = make_sync()

    cls = type(f"Taintward{base.__name__}", (base,), ns)
    cls.__qualname__ = cls.__name__
    _CLASSES[base] = cls
    return cls


def is_stream(obj: Any) -> bool:
    return hasattr(obj, "__next__") or hasattr(obj, "__anext__")


def guard_stream(stream: Any, sc: StreamCall, handler) -> Any:
    """Make ``stream`` hand out restored items and end ``sc`` when it ends.
    Returns the same object when it can, else a generator over it."""
    guard = Guard(sc, handler)
    try:
        cls = _guarded_class(type(stream))
        stream.__dict__[_GUARD] = guard
        stream.__class__ = cls
    except (TypeError, AttributeError):
        if isinstance(getattr(stream, "__dict__", None), dict):
            stream.__dict__.pop(_GUARD, None)
        return _wrapped(stream, guard)
    try:
        weakref.finalize(stream, guard.collect)
    except TypeError:  # pragma: no cover - no weak references
        pass
    return stream


def _wrapped(stream: Any, guard: Guard) -> Any:
    if hasattr(stream, "__anext__"):
        async def agen():
            try:
                while True:
                    try:
                        item = await guard.anext(stream.__anext__)
                    except StopAsyncIteration:
                        return
                    yield item
            finally:
                guard.close()
        return agen()

    def gen():
        try:
            while True:
                try:
                    item = guard.next(stream.__next__)
                except StopIteration:
                    return
                yield item
        finally:
            guard.close()
    return gen()


def sync_items(guard: Guard, pull: Callable[[], Any], on_close: Callable[[], None] | None = None):
    """A generator over ``guard`` (for framework streams that are generators)."""
    try:
        while True:
            try:
                item = guard.next(pull)
            except StopIteration:
                return
            yield item
    finally:
        guard.close()
        if on_close is not None:
            on_close()


async def async_items(guard: Guard, pull: Callable[[], Any], on_close=None):
    try:
        while True:
            try:
                item = await guard.anext(pull)
            except StopAsyncIteration:
                return
            yield item
    finally:
        guard.close()
        if on_close is not None:
            await on_close()


def get(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def put(obj: Any, name: str, value: Any) -> None:
    if isinstance(obj, dict):
        obj[name] = value
    else:
        setattr(obj, name, value)


_USAGE = (
    ("prompt_tokens", "gen_ai.usage.input_tokens"),
    ("input_tokens", "gen_ai.usage.input_tokens"),
    ("completion_tokens", "gen_ai.usage.output_tokens"),
    ("output_tokens", "gen_ai.usage.output_tokens"),
)


def set_usage(span, usage: Any) -> None:
    """gen_ai.usage.* attributes from an OpenAI / Anthropic style usage."""
    if usage is None:
        return
    for src, dst in _USAGE:
        v = get(usage, src)
        if isinstance(v, int) and not isinstance(v, bool):
            span.set_attribute(dst, v)


def json_format(value: Any) -> bool:
    """Does a response_format / text.format ask for a JSON answer?"""
    if isinstance(value, type):  # a pydantic model class (structured output)
        return True
    fmt = get(value, "format") if isinstance(value, dict) and "format" in value else value
    return get(fmt, "type") in ("json_object", "json_schema")


# Text fields of an OpenAI chat delta (reasoning_content: DeepSeek and other
# OpenAI compatible servers, through LiteLLM too).
_DELTA_TEXT = ("content", "refusal", "reasoning_content", "reasoning")


class ChatChunks:
    """Handler for OpenAI chat completion chunks, also LiteLLM's
    ``ModelResponseStream`` (the same shape).

    Per choice: the text fields and each tool call's arguments are restored
    piece by piece. Held text is added to the choice's ``finish_reason``
    chunk; a stream that ends without one gets one extra chunk."""

    def __init__(self, pmap, *, json_content: bool = False) -> None:
        self.p = Pieces(pmap)
        self.json_content = json_content
        self.names: dict[tuple, str] = {}
        self.usage: Any = None
        self.last: Any = None          # last chunk with choices: template for a tail
        self.tool_template: Any = None  # a tool call delta: template for held arguments

    def item(self, chunk: Any) -> list:
        usage = get(chunk, "usage")
        if usage is not None:
            self.usage = usage
        if not get(chunk, "choices"):
            return [chunk]
        chunk = clone(chunk)
        self.last = chunk
        for pos, choice in enumerate(get(chunk, "choices")):
            i = get(choice, "index")
            i = pos if i is None else i
            delta = get(choice, "delta")
            if delta is not None:
                self._delta(i, delta)
                if get(choice, "finish_reason"):
                    self._flush(i, delta)
        return [chunk]

    def _delta(self, i: int, delta: Any) -> None:
        for f in _DELTA_TEXT:
            v = get(delta, f)
            if isinstance(v, str) and v:
                mode = "json" if f == "content" and self.json_content else "text"
                put(delta, f, self.p.push((i, f), v, mode))
        for pos, tc in enumerate(get(delta, "tool_calls") or []):
            j = get(tc, "index")
            j = pos if j is None else j
            fn = get(tc, "function")
            if fn is None:
                continue
            if self.tool_template is None:
                self.tool_template = clone(tc)
            name = get(fn, "name")
            if isinstance(name, str) and name:
                self.names[(i, j)] = self.names.get((i, j), "") + name
            args = get(fn, "arguments")
            if isinstance(args, str) and args:
                put(fn, "arguments", self.p.push((i, "tool", j), args, "json"))
            else:
                self.p.touch((i, "tool", j))  # a call with no arguments yet
        fc = get(delta, "function_call")  # the older functions API
        if fc is not None:
            name = get(fc, "name")
            if isinstance(name, str) and name:
                self.names[(i, "function_call")] = name
            args = get(fc, "arguments")
            if isinstance(args, str) and args:
                put(fc, "arguments", self.p.push((i, "function_call"), args, "json"))

    def _flush(self, i: int, delta: Any) -> None:
        for key in self.p.holding(lambda k: k[0] == i):
            rest = self.p.flush(key)
            if not rest:
                continue
            kind = key[1]
            if kind in _DELTA_TEXT:
                put(delta, kind, (get(delta, kind) or "") + rest)
            elif kind == "function_call":
                fc = get(delta, "function_call")
                if fc is None:
                    put(delta, "function_call", {"arguments": rest})
                else:
                    put(fc, "arguments", (get(fc, "arguments") or "") + rest)
            elif kind == "tool":
                tcs = list(get(delta, "tool_calls") or [])
                hit = next((tc for p, tc in enumerate(tcs)
                            if (get(tc, "index") if get(tc, "index") is not None else p) == key[2]
                            and get(tc, "function") is not None), None)
                if hit is not None:
                    fn = get(hit, "function")
                    put(fn, "arguments", (get(fn, "arguments") or "") + rest)
                else:
                    tcs.append(self._tool_delta(key[2], rest))
                    put(delta, "tool_calls", tcs)

    def _tool_delta(self, index: int, args: str) -> Any:
        if self.tool_template is None:
            return {"index": index, "function": {"arguments": args}}
        tc = clone(self.tool_template)
        put(tc, "index", index)
        for f in ("id", "type"):
            if get(tc, f) is not None:
                put(tc, f, None)
        fn = get(tc, "function")
        put(fn, "name", None)
        put(fn, "arguments", args)
        return tc

    def end(self) -> list:
        keys = self.p.holding()
        if not keys or self.last is None:
            return []
        tail = clone(self.last)
        template = get(tail, "choices")[0]
        choices = []
        for i in sorted({k[0] for k in keys}):
            c = clone(template)
            put(c, "index", i)
            put(c, "finish_reason", None)
            d = get(c, "delta")
            for f in (*_DELTA_TEXT, "tool_calls", "function_call", "role"):
                if get(d, f) is not None:
                    put(d, f, None)
            self._flush(i, d)
            choices.append(c)
        put(tail, "choices", choices)
        if get(tail, "usage") is not None:
            put(tail, "usage", None)
        return [tail]

    def view(self) -> list:
        """The answer as the model wrote it: one message per choice."""
        keys = self.p.keys()
        out = []
        for i in sorted({k[0] for k in keys}):
            msg: dict[str, Any] = {"role": "assistant"}
            for f in _DELTA_TEXT:
                text = self.p.raw((i, f))
                if text:
                    msg[f] = text
            tools = sorted(k[2] for k in keys if k[0] == i and k[1] == "tool")
            if tools:
                msg["tool_calls"] = [
                    {"type": "function", "function": {
                        "name": self.names.get((i, j), ""),
                        "arguments": self.p.raw((i, "tool", j)) or ""}}
                    for j in tools]
            if (i, "function_call") in keys:
                msg["function_call"] = {"name": self.names.get((i, "function_call"), ""),
                                        "arguments": self.p.raw((i, "function_call")) or ""}
            out.append(msg)
        return out

    def annotate(self, span) -> None:
        set_usage(span, self.usage)


__all__ = ["Pieces", "StreamCall", "Guard", "guard_stream", "is_stream", "clone",
           "sync_items", "async_items", "ChatChunks", "set_usage", "json_format"]
