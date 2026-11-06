"""Portable best-effort file locking (no fcntl/msvcrt).

Used by the log appender and registry identity mutations so concurrent
writers cannot lose updates. A crashed holder leaves a stale lock;
acquirers raise TimeoutError after `timeout` seconds — delete the stale
lockfile to recover.
"""

from __future__ import annotations

import os
import time
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Iterator

DEFAULT_TIMEOUT = 5.0


@contextmanager
def file_lock(resource_path: Path, timeout: float = DEFAULT_TIMEOUT) -> Iterator[None]:
    """Mutually exclude other holders for the same resource path via an
    exclusively-created sibling lockfile (`<name>.lock`)."""
    lock_path = resource_path.parent / (resource_path.name + ".lock")
    deadline = time.monotonic() + timeout
    fd = None
    while fd is None:
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            if time.monotonic() >= deadline:
                raise TimeoutError(f"{lock_path} is held — stale lock?")
            time.sleep(0.05)
    try:
        yield
    finally:
        os.close(fd)
        with suppress(OSError):
            lock_path.unlink()
