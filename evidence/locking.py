"""File locks and fsync helpers shared by the evidence log modules.

Locks use ``flock`` (POSIX). On systems without it the helpers do nothing,
so the log is then safe for one writer process only.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

try:
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]


def flock(fd: int, exclusive: bool = True) -> None:
    """Block until ``fd`` holds a shared or exclusive lock. Closing the fd
    releases it."""
    if fcntl is not None:
        fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)


@contextmanager
def locked(lock_path: str | os.PathLike) -> Iterator[None]:
    """Exclusive lock on a separate lock file (created if missing)."""
    lock_path = Path(lock_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        flock(fd)
        yield
    finally:
        os.close(fd)


def fsync_dir(path: str | os.PathLike) -> None:
    """fsync a directory so a newly created or renamed file in it survives a
    crash. Best effort: some systems do not allow opening a directory."""
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)
