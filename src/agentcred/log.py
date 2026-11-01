"""Append-only, hash-chained attestation log (v0.2).

One JSON object per line (JSONL). Every record commits to its predecessor,
so any edit, deletion, or reordering of history is detectable:

    {"index": 0, "prev": "000...0", "entry": {...}, "hash": "..."}

`hash` is SHA-256 over the canonical JSON of the record without its own
`hash` field. The first record points at 64 zeroes (genesis). See
docs/spec.md §8.
"""

from __future__ import annotations

import json
import os
import time
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from .canonical import canonical

GENESIS = "0" * 64
LOCK_TIMEOUT = 5.0


class LogTamperError(Exception):
    """Raised when a log's chain does not verify."""

    def __init__(self, index: int, reason: str):
        self.index = index
        self.reason = reason
        super().__init__(f"record {index}: {reason}")


@contextmanager
def _log_lock(log_path: Path):
    """Best-effort mutual exclusion via an exclusively-created lockfile.

    Portable (no fcntl/msvcrt). A crashed writer can leave a stale lock;
    append then raises TimeoutError after LOCK_TIMEOUT seconds — delete the
    stale lockfile to recover.
    """
    lock_path = log_path.parent / (log_path.name + ".lock")
    deadline = time.monotonic() + LOCK_TIMEOUT
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


@dataclass(frozen=True)
class LogRecord:
    index: int
    prev: str
    entry: dict
    hash: str

    def line(self) -> bytes:
        return canonical(self.__dict__) + b"\n"

    @classmethod
    def from_line(cls, line: str) -> "LogRecord":
        try:
            obj = json.loads(line)
            return cls(
                index=obj["index"], prev=obj["prev"], entry=obj["entry"], hash=obj["hash"]
            )
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise LogTamperError(-1, f"malformed record: {exc}") from exc


def record_hash(index: int, prev: str, entry: dict) -> str:
    """SHA-256 over the canonical form of {index, prev, entry}."""
    return sha256(canonical({"index": index, "prev": prev, "entry": entry})).hexdigest()


def load(log_path: str | Path) -> list[LogRecord]:
    path = Path(log_path)
    if not path.exists():
        return []
    return [LogRecord.from_line(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def append(log_path: str | Path, entry: dict) -> LogRecord:
    """Append an entry under the log lock; returns the committed record."""
    path = Path(log_path)
    with _log_lock(path):
        records = load(path)
        prev = records[-1].hash if records else GENESIS
        index = len(records)
        record = LogRecord(
            index=index, prev=prev, entry=entry, hash=record_hash(index, prev, entry)
        )
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(record.line().decode("utf-8"))
    return record


def verify_chain(records: list[LogRecord]) -> None:
    """Raise LogTamperError on the first inconsistency; silent if intact."""
    prev = GENESIS
    for expected_index, record in enumerate(records):
        if record.index != expected_index:
            raise LogTamperError(record.index, f"expected index {expected_index}")
        if record.prev != prev:
            raise LogTamperError(record.index, "broken link to predecessor")
        if record.hash != record_hash(record.index, record.prev, record.entry):
            raise LogTamperError(record.index, "entry/hash mismatch — history was edited")
        prev = record.hash
