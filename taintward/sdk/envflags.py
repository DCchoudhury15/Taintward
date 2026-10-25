"""Reading on/off settings from environment variables.

Every boolean ``TAINTWARD_*`` flag in the SDK goes through :func:`env_flag`,
so ``TAINTWARD_DRY_RUN=0`` or ``=false`` really means off.
"""

from __future__ import annotations

import logging
import os

log = logging.getLogger("taintward.sdk")

TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
FALSE_VALUES = frozenset({"0", "false", "no", "off"})


def env_flag(name: str, default: bool = False) -> bool:
    """Read a boolean environment variable.

    ``1``, ``true``, ``yes`` and ``on`` (any case) are True; ``0``,
    ``false``, ``no`` and ``off`` are False. Unset or empty gives
    ``default``. Any other value also gives ``default`` and logs a warning,
    so a typo never turns a safety flag that is on by default off.
    """
    raw = os.environ.get(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if not value:
        return default
    if value in TRUE_VALUES:
        return True
    if value in FALSE_VALUES:
        return False
    log.warning("taintward: %s=%r is not a boolean (use 1/0, true/false, yes/no, "
                "on/off); using the default %s", name, raw, default)
    return default
