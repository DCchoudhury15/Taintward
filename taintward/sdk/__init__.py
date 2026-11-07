"""Taintward SDK: detection, taint propagation, and OTel instrumentation.

The submodules are loaded on first use, so code that only needs a light
part (``taintward.sdk.destinations``, ``taintward.sdk.vault``) does not load
the detectors.
"""

from __future__ import annotations

import importlib
from typing import Any

__all__ = ["detect", "instrumentation", "taint"]


def __getattr__(name: str) -> Any:
    if name in __all__:
        module = importlib.import_module(f"taintward.sdk.{name}")
        globals()[name] = module
        return module
    raise AttributeError(f"module 'taintward.sdk' has no attribute {name!r}")
