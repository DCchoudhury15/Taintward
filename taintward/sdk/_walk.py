"""Small helpers shared by the payload walkers (detect, mask, redact).

They answer two questions the same way everywhere: which values are
containers to walk into, and how to build a container of the same type
again from new items.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence, Set
from typing import Any, Iterable

# Never walked into: text and binary values are leaves, and a range is a
# leaf too (walking a large range item by item would be slow for no gain).
_LEAF_SEQUENCES = (str, bytes, bytearray, memoryview, range)


def is_mapping(value: Any) -> bool:
    return isinstance(value, Mapping)


def is_collection(value: Any) -> bool:
    """A list, tuple (including namedtuples), set, frozenset or other
    Sequence / Set that should be walked item by item."""
    if isinstance(value, (list, tuple, set, frozenset)):
        return True
    if isinstance(value, _LEAF_SEQUENCES):
        return False
    return isinstance(value, (Sequence, Set))


def is_scalar_leaf(value: Any) -> bool:
    """None and booleans are never sensitive and are kept as they are."""
    return value is None or isinstance(value, bool)


def rebuild_collection(value: Any, items: list) -> Any:
    """A container of the same type as ``value`` holding ``items``.

    namedtuples are rebuilt with ``t(*items)``. Types that cannot be built
    from a list fall back to a plain list, tuple, set or frozenset.
    """
    t = type(value)
    if t is list:
        return items
    if t is tuple:
        return tuple(items)
    if isinstance(value, tuple) and hasattr(value, "_fields"):
        try:
            return t(*items)
        except Exception:
            return tuple(items)
    try:
        return t(items)
    except Exception:
        pass
    if isinstance(value, tuple):
        return tuple(items)
    if isinstance(value, frozenset):
        return frozenset(items)
    if isinstance(value, Set):
        return set(items)
    return list(items)


def rebuild_mapping(value: Any, pairs: Iterable[tuple[Any, Any]]) -> Any:
    """A mapping like ``value`` holding ``pairs``.

    ``dict`` subclasses (OrderedDict, defaultdict, Counter, ...) keep their
    type and settings (for example the defaultdict factory). Any other
    Mapping becomes a plain dict.
    """
    pairs = list(pairs)
    if type(value) is dict or not isinstance(value, dict):
        return dict(pairs)
    try:
        new = copy.copy(value)
        new.clear()
        new.update(pairs)
        return new
    except Exception:
        return dict(pairs)


def unique_keys(items: Iterable[tuple[Any, Any, Any]]) -> list[tuple[Any, Any]]:
    """Resolve ``(old_key, new_key, value)`` triples into ``(key, value)``
    pairs with unique keys.

    Keys that did not change keep their name. A changed (redacted) key that
    clashes with another key gets a numeric suffix: ``[PII]``, ``[PII]_2``,
    ``[PII]_3``. Only changed keys are renamed, so a key the caller can see
    in the input is never renamed.
    """
    items = list(items)
    used: set = set()
    for old, new, _ in items:
        if new == old:
            used.add(new)
    out: list[tuple[Any, Any]] = []
    for old, new, value in items:
        if new != old:
            if new in used:
                n = 2
                while f"{new}_{n}" in used:
                    n += 1
                new = f"{new}_{n}"
            used.add(new)
        out.append((new, value))
    return out
