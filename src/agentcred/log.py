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
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from .canonical import canonical

GENESIS = "0" * 64


class LogTamperError(Exception):
    """Raised when a log's chain does not verify."""

    def __init__(self, index: int, reason: str):
        self.index = index
        self.reason = reason
        super().__init__(f"record {index}: {reason}")


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
        obj = json.loads(line)
        return cls(
            index=obj["index"], prev=obj["prev"], entry=obj["entry"], hash=obj["hash"]
        )


def _record_hash(index: int, prev: str, entry: dict) -> str:
    return sha256(canonical({"index": index, "prev": prev, "entry": entry})).hexdigest()


def load(log_path: str | Path) -> list[LogRecord]:
    path = Path(log_path)
    if not path.exists():
        return []
    return [LogRecord.from_line(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def append(log_path: str | Path, entry: dict) -> LogRecord:
    """Append an entry; returns the committed record."""
    records = load(log_path)
    prev = records[-1].hash if records else GENESIS
    index = len(records)
    record = LogRecord(index=index, prev=prev, entry=entry, hash=_record_hash(index, prev, entry))
    with open(log_path, "a", encoding="utf-8") as fh:
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
        if record.hash != _record_hash(record.index, record.prev, record.entry):
            raise LogTamperError(record.index, "entry/hash mismatch — history was edited")
        prev = record.hash
