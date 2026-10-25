"""Taintward core: the formal, substrate-independent model.

The core package holds the mathematical anchor shared with AgentRaft
(arXiv:2603.07557): the Data Over-Exposure (DOE) definition. It depends on no
runtime, no observability stack, and no I/O so the formal model can be tested
and cited in isolation.
"""

from taintward.core.doe import (
    DOEResult,
    DOESets,
    Field,
    Sensitivity,
    classify,
    sensitive_fields,
)

__all__ = [
    "DOEResult",
    "DOESets",
    "Field",
    "Sensitivity",
    "classify",
    "sensitive_fields",
]